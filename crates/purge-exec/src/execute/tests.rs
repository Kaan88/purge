//! Tests of the execute pipeline on real objects, unelevated. Each test works in its own fresh temp
//! directory (files, a relaxed store, a real journal) and, for registry items, below its own fresh
//! `HKU\<current SID>\Software\PurgeTest-<random>` key; both are removed on drop and nothing else on
//! the machine is written. Packages, Restart Manager, the restore point and the boot-time move list are
//! stand-ins: no package is installed or removed, no restore point is requested, and the system's
//! `PendingFileRenameOperations` is never touched.

use std::cell::{Cell, RefCell};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use purge_guard::canon::{GuardEnv, ProfileEnv};
use purge_model::exec::journal::{AbortReason, Record, UndoConflict};
use purge_model::exec::op::Inverse;
use purge_model::exec::session::RestorePointOutcome;
use purge_model::{Action, Band, Blocker, Candidate, Target};
use purge_win::appx::{AppxPackage, SignatureKind};
use purge_win::appx_write::{RemovalScope, RemoveOutcome};
use purge_win::fs::FileHandle;
use purge_win::os::Win32Error;
use purge_win::reg::{REG_MULTI_SZ, REG_SZ, RegRoot, RegView};
use purge_win::reg_write::{KeyAccess, WKey};
use purge_win::rm::{LockerList, RebootReasons};
use purge_win::sid::current_user_sid;
use purge_win::sr::SrOutcome;

use super::*;
use crate::act_fs::RETRY_DELAYS;
use crate::act_typed::{ListError, PackageInfo};
use crate::journal::{self, JournalRead, Phase};
use crate::locked::MemoryPendingRenames;
use crate::plan_in::tests::{candidate, cid, key, path, request, safe, scan_doc, value};
use crate::plan_in::{NotSelectable, Selection};
use crate::prepare::RestorePointSetting;
use crate::report::data_volume;
use crate::storage::{JOURNAL_FILE, REG_BACKUP_DIR, REPORT_FILE};

// ---------------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------------

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "{tag}-{:x}-{nanos:x}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// The `\\?\` form of an absolute path.
fn ext(path: &str) -> PathBuf {
    purge_win::secure::extended_path(Path::new(path)).unwrap()
}

fn exists(path: &str) -> bool {
    std::fs::symlink_metadata(ext(path)).is_ok()
}

/// A fresh directory below the temp directory (its final, long-form path), removed on drop; junctions
/// below it are removed as links.
struct Scratch {
    root: String,
}

impl Scratch {
    fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(unique(&format!("purge-exec-{tag}")));
        std::fs::create_dir(&dir).unwrap();
        Scratch::at(&dir)
    }

    /// The scratch directory `dir`, which exists.
    fn at(dir: &Path) -> Scratch {
        let final_path = FileHandle::open(dir).unwrap().final_path().unwrap();
        let root = final_path
            .strip_prefix(r"\\?\")
            .unwrap_or(&final_path)
            .to_owned();
        Scratch { root }
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
        let _ = std::fs::remove_dir_all(ext(&self.root));
    }
}

fn junction(link: &str, target: &str) {
    let status = Command::new("cmd")
        .args(["/c", "mklink", "/J", link, target])
        .stdout(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success(), "mklink /J {link} {target}");
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

/// A fresh `HKU\<SID>\Software\PurgeTest-<random>` key, removed with everything below it on drop.
struct TestKey {
    sid: String,
    name: String,
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
        TestKey { sid, name }
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

    fn open(&self, sub: &str, access: KeyAccess) -> WKey {
        WKey::open(RegRoot::Hku, &self.rel(sub), RegView::K64, access).unwrap()
    }

    fn exists(&self, sub: &str) -> bool {
        match WKey::open(RegRoot::Hku, &self.rel(sub), RegView::K64, KeyAccess::READ) {
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

    fn nuke(key: &WKey) {
        for sub in key.subkey_names().unwrap_or_default() {
            if let Ok(child) = key.open_subkey(&sub, KeyAccess::DELETE) {
                Self::nuke(&child);
            }
        }
        let _ = key.delete();
    }
}

impl Drop for TestKey {
    fn drop(&mut self) {
        if let Ok(root) = WKey::open(RegRoot::Hku, &self.rel(""), RegView::K64, KeyAccess::DELETE) {
            Self::nuke(&root);
        }
    }
}

/// The bytes of a NUL-terminated UTF-16 string.
fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// The bytes of a `REG_MULTI_SZ` holding `segments`.
fn multi_sz(segments: &[&str]) -> Vec<u8> {
    let mut data: Vec<u8> = segments.iter().flat_map(|s| utf16z(s)).collect();
    data.extend([0, 0]);
    data
}

/// A scripted package backend: nothing real is listed or removed.
#[derive(Default)]
struct FakePackages {
    packages: RefCell<Vec<PackageInfo>>,
    removed: RefCell<Vec<String>>,
}

impl PackageBackend for FakePackages {
    fn list(&self, _: RemovalScope) -> Result<Vec<PackageInfo>, ListError> {
        Ok(self.packages.borrow().clone())
    }

    fn remove(&self, full_name: &str, _: RemovalScope) -> RemoveOutcome {
        self.removed.borrow_mut().push(full_name.to_owned());
        self.packages
            .borrow_mut()
            .retain(|p| !p.package.full_name.eq_ignore_ascii_case(full_name));
        RemoveOutcome::Removed
    }
}

const PACKAGE: &str = "Vendor.App_1.0.0.0_x64__abcdefghjkmnp";

fn package_info(full_name: &str) -> PackageInfo {
    PackageInfo {
        package: AppxPackage {
            full_name: full_name.to_owned(),
            family_name: "Vendor.App_abcdefghjkmnp".to_owned(),
            installed_location: Some(r"C:\Program Files\Vendor\App".to_owned()),
            effective_external_path: Some(r"C:\Program Files\Vendor\App".to_owned()),
            signature_kind: Some(SignatureKind::Developer),
            is_framework: false,
            is_resource_package: false,
            users: Vec::new(),
            dependencies: None,
        },
        dependencies: Some(Vec::new()),
    }
}

/// A Restart Manager stand-in: every query names `holders`.
#[derive(Default)]
struct FakeRm {
    holders: RefCell<Vec<purge_win::rm::Locker>>,
    calls: Cell<u32>,
}

impl LockerQuery for FakeRm {
    fn query(&self, _: &[PathBuf]) -> Result<LockerList, Win32Error> {
        self.calls.set(self.calls.get() + 1);
        Ok(LockerList {
            lockers: self.holders.borrow().clone(),
            reboot_reasons: RebootReasons(0),
        })
    }
}

fn holder(pid: u32, name: &str) -> purge_win::rm::Locker {
    purge_win::rm::Locker {
        pid,
        start_time: 1,
        app_name: name.to_owned(),
        service_name: None,
        kind: purge_win::rm::LockerKind::MainWindow,
        restartable: false,
        ts_session: Some(1),
    }
}

/// A restore-point backend that counts its calls and answers "created, sequence 7".
struct FakeRestore(std::sync::Arc<AtomicU32>);

impl RestorePointBackend for FakeRestore {
    fn create(&self, _: &str) -> SrOutcome {
        self.0.fetch_add(1, Ordering::SeqCst);
        SrOutcome::Created { seq: 7 }
    }
}

/// Everything a run needs besides the request. The scratch directory drops last.
struct Rig {
    roots: StorageRoots,
    deny: DenyList,
    packages: FakePackages,
    rm: FakeRm,
    pending: MemoryPendingRenames,
    restore_calls: std::sync::Arc<AtomicU32>,
    s: Scratch,
}

impl Rig {
    fn new(tag: &str) -> Rig {
        let s = Scratch::new(tag);
        let roots = StorageRoots::install_relaxed(Path::new(&s.path("data"))).unwrap();
        Rig::with(s, roots)
    }

    fn with(s: Scratch, roots: StorageRoots) -> Rig {
        let deny = DenyList::compile(&live_env(roots.data_root().to_str().unwrap()));
        Rig {
            roots,
            deny,
            packages: FakePackages::default(),
            rm: FakeRm::default(),
            pending: MemoryPendingRenames::with_pairs(&[]),
            restore_calls: std::sync::Arc::new(AtomicU32::new(0)),
            s,
        }
    }

    /// The environment of a run: no sleeping between retries, no waiting for the restore point.
    fn env<'a>(&'a mut self, progress: Option<&'a dyn Fn(&Progress<'_>)>) -> ExecEnv<'a> {
        ExecEnv {
            retry: Retry::with(RETRY_DELAYS.to_vec(), |_| {}),
            progress,
            restore_point_wait: Duration::from_secs(5),
            restore_point_finish_wait: Duration::ZERO,
            ..ExecEnv::new(
                &self.roots,
                &self.deny,
                &self.packages,
                &self.rm,
                &mut self.pending,
            )
        }
    }

    /// The environment of a recovery or a retry: no sleeping between retries, and no restart of
    /// Windows since the system started long before any run.
    fn recover_env(&mut self) -> crate::recover::RecoverEnv<'_> {
        crate::recover::RecoverEnv {
            retry: Retry::with(RETRY_DELAYS.to_vec(), |_| {}),
            system_started: Some(purge_model::FileTime(0)),
            ..crate::recover::RecoverEnv::new(
                &self.roots,
                &self.deny,
                &self.packages,
                &self.rm,
                &mut self.pending,
            )
        }
    }

    fn try_run(
        &mut self,
        request: ExecRequest,
        progress: Option<&dyn Fn(&Progress<'_>)>,
    ) -> Result<ExecOutput, ExecError> {
        let restore = FakeRestore(self.restore_calls.clone());
        execute(request, self.env(progress), restore)
    }

    fn run(&mut self, request: ExecRequest) -> ExecOutput {
        self.try_run(request, None).unwrap()
    }

    fn sessions(&self) -> Vec<SessionId> {
        self.roots.list_sessions().unwrap().sessions
    }

    fn session(&self, id: &SessionId) -> SessionDir {
        self.roots.open_session(id).unwrap()
    }

    fn journal(&self, id: &SessionId) -> JournalRead {
        journal::read(&self.session(id)).unwrap()
    }
}

/// A request over `items` (all Safe and preselected unless built otherwise) with the right confirm hash
/// and no restore point.
fn preselected(items: Vec<Candidate>, absorbed: Vec<Candidate>) -> ExecRequest {
    let scan = scan_doc(items, absorbed);
    let mut request = request(&scan, Selection::Preselected);
    request.settings.restore_point = RestorePointSetting::Off;
    request
}

fn quarantine(id: &str, p: &str) -> Candidate {
    safe(id, path(p), Action::Quarantine)
}

/// The outcome of every op, in op order, as the journal records it.
fn outcomes(read: &JournalRead) -> Vec<Option<ItemOutcome>> {
    read.state.ops().map(|op| op.outcome.clone()).collect()
}

fn gate_blocked(outcome: &ItemOutcome) -> Option<&Blocker> {
    match outcome {
        ItemOutcome::Skipped {
            reason: SkipReason::GateBlocked { blocker },
        } => Some(blocker),
        _ => None,
    }
}

/// Where the journal says op `n`'s item went.
fn quarantine_path(read: &JournalRead, n: u32) -> String {
    match &read
        .state
        .op(OpId(n))
        .unwrap()
        .intent
        .as_ref()
        .unwrap()
        .inverse
    {
        Inverse::MoveBack {
            quarantine_path, ..
        } => quarantine_path.clone(),
        other => panic!("{other:?}"),
    }
}

/// The report must be the journal read out: one item per journalled op, same order, same outcome.
fn assert_report_is_the_journal(report: &ExecReport, read: &JournalRead) {
    let journalled: Vec<_> = read
        .state
        .ops()
        .map(|op| {
            (
                op.op,
                op.item.clone(),
                op.target.clone(),
                op.outcome.clone(),
            )
        })
        .collect();
    let reported: Vec<_> = report
        .items
        .iter()
        .map(|i| {
            (
                i.op,
                i.item.clone(),
                i.target.clone(),
                Some(i.outcome.clone()),
            )
        })
        .collect();
    assert_eq!(reported, journalled);
    assert_eq!(report.counts, read.state.counts());
    assert_eq!(report.counts, report.tally());
    assert_eq!(report.session, *read.state.session());
}

// ---------------------------------------------------------------------------------------------------
// Refusals before any session
// ---------------------------------------------------------------------------------------------------

#[test]
fn a_request_that_does_not_bind_is_refused_before_any_session_exists() {
    let mut rig = Rig::new("refuse");
    let a = rig.s.file(r"app\a.txt", b"a");
    let b = rig.s.file(r"app\b.txt", b"b");
    let scan = scan_doc(
        vec![
            quarantine("c-1", &a),
            candidate("c-2", path(&b), Action::Quarantine, Band::Likely, false),
            candidate("c-3", path(&b), Action::Quarantine, Band::Blocked, false),
        ],
        Vec::new(),
    );
    let off = |mut request: ExecRequest| {
        request.settings.restore_point = RestorePointSetting::Off;
        request
    };
    let good = off(request(&scan, Selection::Preselected));

    let wrong_confirm = ExecRequest {
        confirm: scan.plan_hash.clone(),
        ..good.clone()
    };
    let mut altered_plan = good.clone();
    altered_plan.scan.items[0].target = path(&b);
    let altered_selection = ExecRequest {
        selection: Selection::Ids(vec![cid("c-1"), cid("c-2")]),
        ..good.clone()
    };
    let forbidden = off(request(&scan, Selection::Ids(vec![cid("c-1"), cid("c-3")])));

    let refusals = [
        (wrong_confirm, PlanRefusal::ConfirmMismatch),
        (altered_selection, PlanRefusal::ConfirmMismatch),
        (
            forbidden,
            PlanRefusal::NotSelectable {
                id: cid("c-3"),
                why: NotSelectable::Blocked,
            },
        ),
    ];
    for (request, expected) in refusals {
        match rig.try_run(request, None) {
            Err(ExecError::Plan(refusal)) => assert_eq!(refusal, expected),
            other => panic!("expected {expected:?}, got {other:?}"),
        }
    }
    assert!(matches!(
        rig.try_run(altered_plan, None),
        Err(ExecError::Plan(PlanRefusal::PlanHashMismatch { .. }))
    ));

    assert!(rig.sessions().is_empty(), "no session may exist");
    assert!(rig.roots.read_index().unwrap().sessions.is_empty());
    assert!(exists(&a) && exists(&b));
    assert_eq!(rig.rm.calls.get(), 0);

    // The same plan with its own confirmation runs.
    let output = rig.run(good);
    assert_eq!(output.report.state, SessionState::Committed);
    assert!(!exists(&a) && exists(&b));
}

// ---------------------------------------------------------------------------------------------------
// A mixed run
// ---------------------------------------------------------------------------------------------------

/// The items of the mixed run: a file, a directory tree with absorbed children, an empty directory,
/// their parent (empty once the three are gone), a key tree, a value, a segment and an empty key.
fn mixed_plan(s: &Scratch, k: &TestKey) -> (Vec<Candidate>, Vec<Candidate>) {
    let file = s.file(r"app\a.txt", b"hello");
    s.file(r"app\tree\one.bin", b"111");
    s.file(r"app\tree\deep\two.bin", b"2222");
    let tree = s.path(r"app\tree");
    let empty = s.dir(r"app\empty");
    let app = s.path("app");

    k.create(r"Tree\Sub\Leaf");
    k.set("Tree", "Name", REG_SZ, &utf16z("vendor"));
    k.set(r"Tree\Sub", "N", REG_SZ, &utf16z("1"));
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
    k.create("Empty");

    let mut tree_item = quarantine("c-tree", &tree);
    tree_item.children = vec![cid("c-tree-1"), cid("c-tree-2")];
    let absorbed = vec![
        quarantine("c-tree-1", &s.path(r"app\tree\one.bin")),
        quarantine("c-tree-2", &s.path(r"app\tree\deep\two.bin")),
    ];
    let items = vec![
        quarantine("c-file", &file),
        tree_item,
        safe("c-empty", path(&empty), Action::RemoveDirIfEmpty),
        safe("c-app", path(&app), Action::RemoveDirIfEmpty),
        safe("c-key", key(&k.wire("Tree")), Action::DeleteKey),
        safe("c-val", value(&k.wire("Vals"), "Gone"), Action::DeleteValue),
        safe(
            "c-seg",
            Target::RegMultiSzSegment {
                path: k.wire("Seg"),
                name: "List".into(),
                segment: "vendor".into(),
                index: None,
            },
            Action::EditSegment,
        ),
        safe(
            "c-emptykey",
            key(&k.wire("Empty")),
            Action::RemoveDirIfEmpty,
        ),
    ];
    (items, absorbed)
}

#[test]
fn a_mixed_run_ends_with_a_report_that_matches_the_journal() {
    let mut rig = Rig::new("mixed");
    let k = TestKey::new();
    let (items, absorbed) = mixed_plan(&rig.s, &k);
    let request = preselected(items, absorbed);
    let scan = request.scan.clone();

    // The scan copy: present, equal to the document, and there before any intent is journalled.
    let session_path = RefCell::new(PathBuf::new());
    let copy_checked = Cell::new(false);
    let progress = |event: &Progress<'_>| match event {
        Progress::SessionCreated { path, items, .. } => {
            assert_eq!(*items, 8);
            *session_path.borrow_mut() = path.to_path_buf();
        }
        Progress::ItemStarting { op: OpId(1), .. } => {
            let dir = session_path.borrow();
            let copy: ScanDoc =
                serde_json::from_slice(&std::fs::read(dir.join(SCAN_FILE)).unwrap()).unwrap();
            assert_eq!(copy, scan);
            let journal = std::fs::read_to_string(dir.join(JOURNAL_FILE)).unwrap();
            assert!(journal.contains(r#""rec":"validated""#));
            assert!(!journal.contains(r#""rec":"intent""#));
            assert!(!journal.contains(r#""rec":"done""#));
            copy_checked.set(true);
        }
        _ => {}
    };
    let output = rig.try_run(request, Some(&progress)).unwrap();
    assert!(copy_checked.get());

    let report = &output.report;
    assert_eq!(report.state, SessionState::Committed, "{report:#?}");
    assert!(output.report_written && output.index_updated);
    let read = rig.journal(&output.session);
    assert_eq!(read.state.phase(), Phase::Committed);
    assert_eq!(
        outcomes(&read),
        vec![Some(ItemOutcome::Done); 8],
        "{:#?}",
        report.warnings
    );
    assert_report_is_the_journal(report, &read);
    assert_eq!(report.counts.done, 8);
    assert_eq!(report.restore_point, RestorePointOutcome::NotRequested);
    assert!(!report.pending_reboot);
    assert_eq!(rig.restore_calls.load(Ordering::SeqCst), 0);

    // The record order: header, the run's settings, eight validated, then intent/done pairs, one
    // group, commit.
    let names: Vec<&str> = read.records.iter().map(Record::name).collect();
    let mut expected = vec!["header", "settings"];
    expected.extend(["validated"; 8]);
    for _ in 0..8 {
        expected.extend(["intent", "done"]);
    }
    expected.extend(["group_end", "commit"]);
    assert_eq!(names, expected);

    // The system: everything selected is gone, everything else is as it was.
    assert!(!exists(&rig.s.path("app")));
    assert!(!k.exists("Tree") && !k.exists("Empty"));
    assert_eq!(k.get("Vals", "Gone"), None);
    assert_eq!(k.get("Vals", "Stays"), Some((REG_SZ, utf16z("hi"))));
    assert_eq!(
        k.get("Seg", "List"),
        Some((REG_MULTI_SZ, multi_sz(&["keep", "also"])))
    );

    // The quarantine holds the file and the whole tree; the backups exist; the bytes add up.
    let file_q = quarantine_path(&read, 1);
    assert_eq!(std::fs::read(ext(&file_q)).unwrap(), b"hello");
    let tree_q = quarantine_path(&read, 2);
    assert_eq!(
        std::fs::read(ext(&format!(r"{tree_q}\deep\two.bin"))).unwrap(),
        b"2222"
    );
    let session = rig.session(&output.session);
    for n in [5u32, 6, 7, 8] {
        let op = read.state.op(OpId(n)).unwrap();
        let backup = op.intent.as_ref().unwrap().inverse.backup().unwrap();
        assert!(backup.path.starts_with(REG_BACKUP_DIR));
        assert_eq!(
            session.open_file(&backup.path).unwrap().size().unwrap(),
            backup.bytes
        );
    }
    assert_eq!(report.items[0].backup_bytes, 5);
    assert_eq!(report.items[1].backup_bytes, 7);
    assert_eq!(report.items[2].backup_bytes, 0);
    assert!(report.items[4].backup_bytes > 0);
    let total: u64 = report.items.iter().map(|i| i.backup_bytes).sum();
    assert_eq!(report.backup_bytes, total);
    assert_eq!(read.state.commit().unwrap().backup_bytes, total);

    // The session's files: the scan copy and the report, which round-trips through the model type.
    assert_eq!(read_scan_copy(&session).unwrap(), scan);
    let text = session
        .open_file(REPORT_FILE)
        .unwrap()
        .read_all(1 << 20)
        .unwrap();
    let parsed: ExecReport = serde_json::from_slice(&text).unwrap();
    assert_eq!(&parsed, report);
    let again: ExecReport = serde_json::from_str(&serde_json::to_string(&parsed).unwrap()).unwrap();
    assert_eq!(again, parsed);
    let raw: serde_json::Value = serde_json::from_slice(&text).unwrap();
    assert_eq!(raw["schema"], "purge.exec/1");
    assert_eq!(raw["state"], "Committed");
    assert_eq!(raw["items"].as_array().unwrap().len(), 8);

    // The index entry is the journal's summary.
    let index = rig.roots.read_index().unwrap();
    let entry = index.get(&output.session).unwrap();
    assert_eq!(entry.state, SessionState::Committed);
    assert_eq!(entry.counts, read.state.counts());
    assert_eq!(entry.backup_bytes, total);
    assert_eq!(entry.plan_hash.to_string(), scan.plan_hash);
    assert_eq!(entry.usage.iter().map(|u| u.bytes).sum::<u64>(), total);
    assert_eq!(entry.owner.as_ref().unwrap().display_name, "Vendor App");
    // M7: the entry marks the journal it summarises, and the journal is read against that mark.
    let mark = entry.journal.as_ref().expect("a durable journal is marked");
    assert_eq!(*mark, read.state.mark());
    assert_eq!(mark.records, read.line_heads.len() as u64);
    journal::check_mark(&read, mark).unwrap();
    journal::read_indexed(&session, Some(mark)).unwrap();
}

fn run_shape(report: &ExecReport) -> String {
    let items: Vec<String> = report
        .items
        .iter()
        .map(|item| format!("{} {} {:?}", item.item.0, item.op.0, item.outcome))
        .collect();
    format!(
        "{:?} {:?} {:?} {} {} {:?}",
        report.state,
        report.counts,
        report.restore_point,
        report.pending_reboot,
        report.warnings.len(),
        items
    )
}

fn empty_fingerprint() -> purge_model::Fingerprint {
    serde_json::from_value(serde_json::json!({
        "schema": "purge.fp/0",
        "app": {"program_id": "HKLM|64|VendorApp", "display_name": "Vendor App"},
        "identity": {"names": [], "vendors": [], "tokens": [], "mega_vendor": false},
        "os": {"edition": "Professional", "build": 26340, "ubr": 9882},
        "user_sid": "S-1-5-21-1-2-3-1001"
    }))
    .unwrap()
}

/// `execute_bound` runs the object `bind` made and gives the report `execute` gives for the request
/// that object was bound from: the same items, outcomes, counts and state on the M2 mixed fixture, run
/// twice on two stores (a run consumes its files).
#[test]
fn execute_and_execute_bound_give_equal_reports() {
    let mut by_request = Rig::new("eq-request");
    let k1 = TestKey::new();
    let (items, absorbed) = mixed_plan(&by_request.s, &k1);
    let first = by_request.run(preselected(items, absorbed));

    let mut by_object = Rig::new("eq-bound");
    let k2 = TestKey::new();
    let (items, absorbed) = mixed_plan(&by_object.s, &k2);
    let request = preselected(items, absorbed);
    let bound = std::sync::Arc::new(crate::plan_in::bind(&request).unwrap());
    let restore = FakeRestore(by_object.restore_calls.clone());
    let second = execute_bound(
        bound.clone(),
        request.settings.clone(),
        &empty_fingerprint(),
        by_object.env(None),
        restore,
    )
    .unwrap();

    assert_eq!(first.report.state, SessionState::Committed);
    assert_eq!(run_shape(&first.report), run_shape(&second.report));
    assert!(second.closed && second.report_written && second.index_updated);
    // The journal names the plan object that was handed over, not one derived again.
    let read = by_object.journal(&second.session);
    assert_eq!(read.state.header().plan_hash, bound.plan_hash());
    assert_eq!(read.state.header().selection_hash, bound.selection_hash());
    assert_report_is_the_journal(&second.report, &read);
}

/// `execute_bound` refuses a plan whose objects the fingerprint does not vouch for before any session
/// exists; the same plan through `execute` (the rig path, no fingerprint) is not asked.
#[test]
fn execute_bound_refuses_an_unvouched_object_before_a_session_exists() {
    let mut rig = Rig::new("unvouched");
    let identity = purge_model::TaskIdentity {
        path: r"\Vendor\Update".into(),
        actions: Vec::new(),
    };
    let mut task = safe(
        "c-task",
        Target::Task {
            path: identity.path.clone(),
        },
        Action::DeleteKey,
    );
    task.object_fp = Some(identity.fp());
    let request = preselected(vec![task], Vec::new());
    let bound = std::sync::Arc::new(crate::plan_in::bind(&request).unwrap());
    let restore = FakeRestore(rig.restore_calls.clone());
    let result = execute_bound(
        bound,
        request.settings.clone(),
        &empty_fingerprint(),
        rig.env(None),
        restore,
    );
    assert!(
        matches!(&result, Err(ExecError::ObjectsUnbound(ids)) if ids == &["c-task".to_owned()]),
        "{result:?}"
    );
    assert!(rig.sessions().is_empty(), "no session was created");
}

#[test]
fn a_second_run_of_the_same_plan_finds_everything_vanished() {
    let mut rig = Rig::new("again");
    let k = TestKey::new();
    let (items, absorbed) = mixed_plan(&rig.s, &k);
    let request = preselected(items, absorbed);
    let first = rig.run(request.clone());
    assert_eq!(first.report.counts.done, 8);

    let second = rig.run(request);
    assert_ne!(second.session, first.session);
    assert_eq!(second.report.state, SessionState::Committed);
    let read = rig.journal(&second.session);
    assert_eq!(outcomes(&read), vec![Some(ItemOutcome::Vanished); 8]);
    assert_report_is_the_journal(&second.report, &read);
    assert_eq!(second.report.counts.vanished, 8);
    assert_eq!(second.report.backup_bytes, 0);
    // Nothing was acted on, so nothing was journalled as an intent and nothing was backed up.
    assert!(read.records.iter().all(|r| r.name() != "intent"));
    assert_eq!(rig.roots.read_index().unwrap().sessions.len(), 2);
}

// ---------------------------------------------------------------------------------------------------
// One item's failure does not harm another
// ---------------------------------------------------------------------------------------------------

#[test]
fn per_item_failures_do_not_stop_the_run() {
    let mut rig = Rig::new("isolate");
    let first = rig.s.file(r"app\first.txt", b"1");
    let locked = rig.s.file(r"app\locked.txt", b"in use");
    let gone = rig.s.path(r"app\never-there.txt");
    let goes = rig.s.file(r"app\goes.txt", b"g");
    let target = rig.s.dir("elsewhere");
    rig.s.file(r"elsewhere\precious.txt", b"keep");
    let link = rig.s.path(r"app\link");
    junction(&link, &target);
    let last = rig.s.file(r"app\last.txt", b"9");

    let request = preselected(
        vec![
            quarantine("c-1", &first),
            quarantine("c-2", &locked),
            quarantine("c-3", &gone),
            quarantine("c-4", &link),
            quarantine("c-5", &goes),
            quarantine("c-6", &last),
        ],
        Vec::new(),
    );

    // Held open without delete sharing: the acting handle cannot be opened.
    let holder = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(ext(&locked))
        .unwrap();
    // Op 5 vanishes between its validation and its turn.
    let progress = |event: &Progress<'_>| {
        if let Progress::ItemStarting { op: OpId(5), .. } = event {
            std::fs::remove_file(ext(&goes)).unwrap();
        }
    };
    let output = rig.try_run(request, Some(&progress)).unwrap();
    drop(holder);

    let report = &output.report;
    assert_eq!(report.state, SessionState::Committed, "{report:#?}");
    let read = rig.journal(&output.session);
    assert_report_is_the_journal(report, &read);
    let got = outcomes(&read);
    assert_eq!(got[0], Some(ItemOutcome::Done));
    // In a directory users can write to, a boot-time move is never registered: held for the next run.
    assert_eq!(
        got[1],
        Some(ItemOutcome::HeldRetry),
        "{:#?}",
        report.warnings
    );
    assert_eq!(got[2], Some(ItemOutcome::Vanished));
    assert!(
        gate_blocked(got[3].as_ref().unwrap()).is_some(),
        "{:?}",
        got[3]
    );
    assert_eq!(got[4], Some(ItemOutcome::Vanished));
    assert_eq!(got[5], Some(ItemOutcome::Done));
    assert_eq!(
        (report.counts.done, report.counts.held_retry),
        (2, 1),
        "{:?}",
        report.counts
    );
    assert_eq!((report.counts.vanished, report.counts.skipped), (2, 1));

    // The held item has an intent (its move back is recorded) and was not moved; nothing was
    // registered for the next restart; the junction and what it points at are untouched.
    assert!(read.state.op(OpId(2)).unwrap().intent.is_some());
    assert_eq!(std::fs::read(ext(&locked)).unwrap(), b"in use");
    assert_eq!(rig.pending.registers, 0);
    assert!(exists(&link) && exists(&rig.s.path(r"elsewhere\precious.txt")));
    assert!(read.state.op(OpId(4)).unwrap().intent.is_none());
    assert!(!exists(&first) && !exists(&last));
    assert!(report.warnings.iter().any(|w| w.contains("c-4")));
    assert_eq!(read.state.held_retry().count(), 1);
    // The validated records: the gone item is absent, the junction was refused at validation and says
    // by what; neither binds anything.
    assert_eq!(
        read.state.op(OpId(3)).unwrap().validated().facts,
        ItemFacts::Absent
    );
    let refused = read.state.op(OpId(4)).unwrap().validated().facts;
    assert!(
        matches!(
            refused,
            ItemFacts::Refused {
                blocker: Some(_),
                ..
            }
        ),
        "{refused:?}"
    );
    assert!(!refused.is_actionable());
    assert!(
        read.state
            .op(OpId(1))
            .unwrap()
            .validated()
            .facts
            .is_actionable()
    );
}

#[test]
fn a_locked_file_names_its_holders_and_nothing_is_closed() {
    let mut rig = Rig::new("holders");
    let locked = rig.s.file(r"app\busy.dll", b"in use");
    rig.rm
        .holders
        .borrow_mut()
        .push(holder(4242, "Vendor Tray"));
    let request = preselected(vec![quarantine("c-1", &locked)], Vec::new());
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(ext(&locked))
        .unwrap();

    // The user even agrees to close the program: the answer is recorded, nothing is closed.
    let asked = Cell::new(0);
    let consent = |ask: &locked::ConsentRequest<'_>| {
        let locked::ConsentRequest::CloseLockers { op, lockers, .. } = ask;
        assert_eq!((*op, lockers.len()), (OpId(1), 1));
        asked.set(asked.get() + 1);
        locked::Consent::Allow
    };
    let restore = FakeRestore(rig.restore_calls.clone());
    let mut env = rig.env(None);
    env.consent = &consent;
    let output = execute(request, env, restore).unwrap();

    assert_eq!(asked.get(), 1);
    let report = &output.report;
    assert_eq!(report.items[0].outcome, ItemOutcome::HeldRetry);
    let lockers = &report.items[0].lockers;
    assert_eq!(lockers.len(), 1, "{report:#?}");
    assert_eq!(
        (lockers[0].pid, lockers[0].name.as_str()),
        (4242, "Vendor Tray")
    );
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.contains("c-1") && w.contains("nothing is closed")),
        "{:#?}",
        report.warnings
    );
    // Still held by the same handle, still in place.
    assert_eq!(std::fs::read(ext(&locked)).unwrap(), b"in use");
    drop(handle);
    assert_eq!(rig.pending.registers, 0);
}

#[test]
fn a_directory_in_use_is_held_under_the_intent_already_written() {
    let mut rig = Rig::new("dirbusy");
    let dir = rig.s.dir(r"app\live");
    let inner = rig.s.file(r"app\live\open.dat", b"open");
    let after = rig.s.file(r"app\after.txt", b"a");
    let request = preselected(
        vec![quarantine("c-dir", &dir), quarantine("c-after", &after)],
        Vec::new(),
    );
    // Even full sharing below a directory stops its rename: the lock is met after the intent.
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(7)
        .open(ext(&inner))
        .unwrap();
    let output = rig.run(request);
    drop(handle);

    let read = rig.journal(&output.session);
    assert_eq!(
        outcomes(&read),
        [Some(ItemOutcome::HeldRetry), Some(ItemOutcome::Done)],
        "{:#?}",
        output.report.warnings
    );
    // One intent for the op, written by the file action; the ladder's outcome closed it.
    let intents = read
        .records
        .iter()
        .filter(|r| matches!(r, Record::Intent(intent) if intent.op == OpId(1)))
        .count();
    assert_eq!(intents, 1);
    assert_eq!(std::fs::read(ext(&inner)).unwrap(), b"open");
    assert!(!exists(&after));
    assert_report_is_the_journal(&output.report, &read);
}

#[test]
fn a_file_inside_a_selected_directory_runs_first_and_the_directory_follows() {
    let mut rig = Rig::new("nested");
    let inner = rig.s.file(r"app\data\inner.txt", b"i");
    rig.s.file(r"app\data\other.txt", b"o");
    let dir = rig.s.path(r"app\data");
    let request = preselected(
        vec![quarantine("c-inner", &inner), quarantine("c-dir", &dir)],
        Vec::new(),
    );
    let output = rig.run(request);
    let read = rig.journal(&output.session);
    assert_eq!(
        outcomes(&read),
        vec![Some(ItemOutcome::Done); 2],
        "{:#?}",
        output.report.warnings
    );
    assert!(!exists(&dir));
    assert!(exists(&format!(r"{}\other.txt", quarantine_path(&read, 2))));
}

// ---------------------------------------------------------------------------------------------------
// Skips that are not errors
// ---------------------------------------------------------------------------------------------------

/// Changed by M1B-X-INTEG: services, scheduled tasks and firewall rules have executors. One whose
/// candidate carries no scan-time digest (`object_fp`) is still selectable and is journalled as
/// skipped (`ChangedSinceScan`, "no object fingerprint") without any intent, and without object
/// backends in the process.
#[test]
fn typed_targets_without_an_object_fingerprint_are_journalled_as_skipped() {
    let mut rig = Rig::new("no-object-fp");
    let file = rig.s.file(r"app\a.txt", b"a");
    let request = preselected(
        vec![
            safe(
                "c-task",
                Target::Task {
                    path: r"\PurgeTest\NoSuchTask".into(),
                },
                Action::DeleteKey,
            ),
            safe(
                "c-svc",
                Target::Service {
                    name: "PurgeTestNoSuchService".into(),
                },
                Action::DeleteKey,
            ),
            safe(
                "c-fw",
                Target::FirewallRule {
                    id: "{11111111-2222-3333-4444-555555555555}".into(),
                },
                Action::DeleteKey,
            ),
            quarantine("c-file", &file),
        ],
        Vec::new(),
    );
    let output = rig.run(request);
    let report = &output.report;
    assert_eq!(report.state, SessionState::Committed);
    let read = rig.journal(&output.session);
    let got = outcomes(&read);
    for outcome in &got[..3] {
        assert_eq!(
            outcome,
            &Some(ItemOutcome::Skipped {
                reason: SkipReason::ChangedSinceScan
            })
        );
    }
    assert_eq!(got[3], Some(ItemOutcome::Done));
    assert_eq!(read.state.counts().skipped, 3);
    assert!(read.records.iter().filter(|r| r.name() == "intent").count() == 1);

    // Every op is an item of the report; these are listed without an executor op. The items, the
    // report's counts and the journal's `done` records agree.
    let listed: Vec<(&str, bool)> = report
        .items
        .iter()
        .map(|i| (i.item.0.as_str(), i.exec_op.is_some()))
        .collect();
    assert_eq!(
        listed,
        [
            ("c-task", false),
            ("c-svc", false),
            ("c-fw", false),
            ("c-file", true)
        ]
    );
    assert_eq!(report.counts, report.tally());
    assert_eq!(report.counts, read.state.counts());
    // Their validated records say why nothing binds them.
    for op in 1..=3 {
        assert!(matches!(
            &read.state.op(OpId(op)).unwrap().facts,
            ItemFacts::Refused {
                blocker: Some(Blocker::ChangedSinceScan),
                reason,
                os_error: None,
            } if reason == "exec.no-object-fp"
        ));
    }
    for id in ["c-task", "c-svc", "c-fw"] {
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains(id) && w.contains(gate::reason::NO_OBJECT_FP)),
            "{id}: {:#?}",
            report.warnings
        );
    }
    // The index entry counts what the journal counts.
    let index = rig.roots.read_index().unwrap();
    assert_eq!(index.get(&output.session).unwrap().counts.skipped, 3);
}

#[test]
fn a_package_is_removed_only_with_the_irreversible_acknowledgement() {
    let mut rig = Rig::new("package");
    rig.packages
        .packages
        .borrow_mut()
        .push(package_info(PACKAGE));
    let item = || {
        vec![safe(
            "c-pkg",
            Target::AppxPackage {
                full_name: PACKAGE.into(),
            },
            Action::RemovePackage,
        )]
    };

    let without = rig.run(preselected(item(), Vec::new()));
    let read = rig.journal(&without.session);
    assert_eq!(
        gate_blocked(outcomes(&read)[0].as_ref().unwrap()),
        Some(&Blocker::ReversibilityNone)
    );
    assert!(read.state.op(OpId(1)).unwrap().intent.is_none());
    assert!(rig.packages.removed.borrow().is_empty());
    assert!(!read.state.header().allow_irreversible);
    assert_report_is_the_journal(&without.report, &read);

    let mut acknowledged = preselected(item(), Vec::new());
    acknowledged.allow_irreversible = true;
    let with = rig.run(acknowledged);
    let read = rig.journal(&with.session);
    assert_eq!(outcomes(&read), [Some(ItemOutcome::Done)]);
    assert_eq!(*rig.packages.removed.borrow(), [PACKAGE.to_owned()]);
    let intent = read.state.op(OpId(1)).unwrap().intent.clone().unwrap();
    assert_eq!(intent.inverse, Inverse::None);
    let definition = intent.definition.unwrap();
    assert_eq!(with.report.items[0].backup_bytes, definition.bytes);
    assert!(read.state.header().allow_irreversible);
}

// ---------------------------------------------------------------------------------------------------
// Aborts
// ---------------------------------------------------------------------------------------------------

/// Three items: a value, a key tree and a file. The progress callback breaks something when op 2
/// starts.
fn abort_plan(rig: &Rig, k: &TestKey) -> (ExecRequest, String) {
    k.create("Vals");
    k.set("Vals", "Gone", REG_SZ, &utf16z("bye"));
    k.create(r"Tree\Sub");
    let file = rig.s.file(r"app\untouched.txt", b"u");
    let request = preselected(
        vec![
            safe("c-val", value(&k.wire("Vals"), "Gone"), Action::DeleteValue),
            safe("c-key", key(&k.wire("Tree")), Action::DeleteKey),
            quarantine("c-file", &file),
        ],
        Vec::new(),
    );
    (request, file)
}

#[test]
fn a_backup_that_cannot_be_written_aborts_the_run() {
    let mut rig = Rig::new("abort-backup");
    let k = TestKey::new();
    let (request, file) = abort_plan(&rig, &k);

    // Op 2's backup file name is taken when its turn comes, by a file that is not a backup and that
    // another handle holds without sharing delete: it can be neither adopted nor deleted and written
    // anew, and the store never replaces a file in place.
    let session_path = RefCell::new(PathBuf::new());
    let holder = RefCell::new(None);
    let aborting = Cell::new(None);
    let progress = |event: &Progress<'_>| match event {
        Progress::SessionCreated { path, .. } => *session_path.borrow_mut() = path.to_path_buf(),
        Progress::ItemStarting { op: OpId(2), .. } => {
            let taken = session_path
                .borrow()
                .join(REG_BACKUP_DIR)
                .join("000002.regbackup.json");
            std::fs::write(&taken, b"not a backup").unwrap();
            let held = std::fs::OpenOptions::new()
                .read(true)
                .share_mode(1)
                .open(&taken)
                .unwrap();
            *holder.borrow_mut() = Some(held);
        }
        Progress::Aborting { reason } => aborting.set(Some(*reason)),
        _ => {}
    };
    let output = rig.try_run(request, Some(&progress)).unwrap();
    drop(holder.borrow_mut().take());

    let report = &output.report;
    assert_eq!(report.state, SessionState::Aborted, "{report:#?}");
    assert_eq!(aborting.get(), Some(AbortReason::BackupWriteFailed));
    let read = rig.journal(&output.session);
    assert_eq!(read.state.phase(), Phase::Aborted);
    assert_eq!(
        read.state.aborted().unwrap().reason,
        AbortReason::BackupWriteFailed
    );
    // Op 1 ran and stays undoable (its intent and verified backup are there); op 2 and op 3 have no
    // record after their validation and were not touched.
    assert_eq!(
        outcomes(&read),
        [Some(ItemOutcome::Done), None, None],
        "{:#?}",
        report.warnings
    );
    let backup = read.state.op(OpId(1)).unwrap().intent.as_ref().unwrap();
    assert!(backup.inverse.backup().is_some());
    assert!(read.state.op(OpId(2)).unwrap().intent.is_none());
    assert_eq!(k.get("Vals", "Gone"), None);
    assert!(k.exists(r"Tree\Sub"));
    assert_eq!(std::fs::read(ext(&file)).unwrap(), b"u");

    // The report says so, item by item, and the index has the session as aborted.
    let not_attempted = ItemOutcome::Skipped {
        reason: SkipReason::NotAttempted,
    };
    let reported: Vec<&ItemOutcome> = report.items.iter().map(|i| &i.outcome).collect();
    assert_eq!(
        reported,
        [&ItemOutcome::Done, &not_attempted, &not_attempted]
    );
    assert_eq!(report.counts, report.tally());
    assert!(report.warnings.iter().any(|w| w.contains("aborted")));
    assert!(output.report_written);
    let index = rig.roots.read_index().unwrap();
    assert_eq!(
        index.get(&output.session).unwrap().state,
        SessionState::Aborted
    );
}

/// Opens the journal a second time and locks all of it, so the writer's next write fails as a disk
/// error would. Dropping the file releases the lock.
fn lock_journal(session: &Path) -> std::fs::File {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(7)
        .open(session.join(JOURNAL_FILE))
        .unwrap();
    file.lock().unwrap();
    file
}

#[test]
fn a_journal_that_cannot_be_written_aborts_the_run_and_records_it_when_it_can() {
    let mut rig = Rig::new("abort-journal");
    let k = TestKey::new();
    let (request, file) = abort_plan(&rig, &k);

    // The journal refuses writes from op 2's turn until the run gives up.
    let session_path = RefCell::new(PathBuf::new());
    let lock = RefCell::new(None);
    let progress = |event: &Progress<'_>| match event {
        Progress::SessionCreated { path, .. } => *session_path.borrow_mut() = path.to_path_buf(),
        Progress::ItemStarting { op: OpId(2), .. } => {
            *lock.borrow_mut() = Some(lock_journal(&session_path.borrow()));
        }
        Progress::Aborting { reason } => {
            assert_eq!(*reason, AbortReason::JournalWriteFailed);
            lock.borrow_mut().take();
        }
        _ => {}
    };
    let output = rig.try_run(request, Some(&progress)).unwrap();

    assert_eq!(output.report.state, SessionState::Aborted);
    // The `aborted` record was written: the session is closed (review M2 M21).
    assert!(output.closed);
    let read = rig.journal(&output.session);
    assert_eq!(read.torn_tail, 0);
    assert_eq!(
        read.state.aborted().unwrap().reason,
        AbortReason::JournalWriteFailed
    );
    // Op 2's intent could not be written, so op 2 was not acted on; op 3 was never reached.
    assert_eq!(outcomes(&read), [Some(ItemOutcome::Done), None, None]);
    assert!(read.state.op(OpId(2)).unwrap().intent.is_none());
    assert!(k.exists(r"Tree\Sub"));
    assert_eq!(std::fs::read(ext(&file)).unwrap(), b"u");
    assert_eq!(output.report.items.len(), 3);
    // The abort was recorded, so the index entry marks the journal.
    let index = rig.roots.read_index().unwrap();
    let mark = index.get(&output.session).unwrap().journal.unwrap();
    assert_eq!(mark, read.state.mark());
}

#[test]
fn a_journal_that_stays_unwritable_still_stops_the_run() {
    let mut rig = Rig::new("abort-journal-hard");
    let k = TestKey::new();
    let (request, file) = abort_plan(&rig, &k);

    let session_path = RefCell::new(PathBuf::new());
    let lock = RefCell::new(None);
    let progress = |event: &Progress<'_>| match event {
        Progress::SessionCreated { path, .. } => *session_path.borrow_mut() = path.to_path_buf(),
        Progress::ItemStarting { op: OpId(2), .. } => {
            *lock.borrow_mut() = Some(lock_journal(&session_path.borrow()));
        }
        _ => {}
    };
    let output = rig.try_run(request, Some(&progress)).unwrap();

    // The report says aborted and says the journal could not record it; the output says the session
    // is not closed (review M2 M21), whatever the report's state reads.
    assert_eq!(output.report.state, SessionState::Aborted);
    assert!(!output.closed);
    assert!(
        output
            .report
            .warnings
            .iter()
            .any(|w| w.contains("could not record")),
        "{:#?}",
        output.report.warnings
    );
    assert!(k.exists(r"Tree\Sub"));
    assert_eq!(std::fs::read(ext(&file)).unwrap(), b"u");

    // Once readable again, the journal is whole and has no end record: an open session for recovery.
    lock.borrow_mut().take();
    let read = rig.journal(&output.session);
    assert_eq!(read.torn_tail, 0);
    assert!(!read.state.is_finished());
    assert_eq!(outcomes(&read), [Some(ItemOutcome::Done), None, None]);
    assert!(read.state.op(OpId(2)).unwrap().intent.is_none());
    // The summary does not describe what the journal holds, so its entry carries no mark.
    let index = rig.roots.read_index().unwrap();
    assert_eq!(index.get(&output.session).unwrap().journal, None);
}

// ---------------------------------------------------------------------------------------------------
// Groups, prepare, cap
// ---------------------------------------------------------------------------------------------------

#[test]
fn intents_are_grouped_by_64() {
    let mut rig = Rig::new("groups");
    let items: Vec<Candidate> = (0..130)
        .map(|n| {
            let file = rig.s.file(&format!(r"app\f{n:03}.txt"), b"x");
            quarantine(&format!("c-{n:03}"), &file)
        })
        .collect();
    let output = rig.run(preselected(items, Vec::new()));
    assert_eq!(output.report.counts.done, 130);
    let read = rig.journal(&output.session);
    let groups: Vec<(u32, u32)> = read
        .records
        .iter()
        .filter_map(|record| match record {
            Record::GroupEnd(end) => Some((end.group, end.ops)),
            _ => None,
        })
        .collect();
    assert_eq!(groups, [(1, 64), (2, 64), (3, 2)]);
    // No group is ever left open with more than 64 intents.
    let mut open = 0;
    for record in &read.records {
        match record {
            Record::Intent(_) => open += 1,
            Record::GroupEnd(_) => open = 0,
            _ => {}
        }
        assert!(open <= 64);
    }
    assert_eq!(read.state.phase(), Phase::Committed);
}

#[test]
fn the_restore_point_follows_the_setting_and_never_gates_an_item() {
    let mut rig = Rig::new("restore");
    let file = rig.s.file(r"app\a.txt", b"a");
    let mut request = preselected(vec![quarantine("c-1", &file)], Vec::new());
    request.settings.restore_point = RestorePointSetting::Always;
    let output = rig.run(request);
    assert_eq!(rig.restore_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        output.report.restore_point,
        RestorePointOutcome::Created { sequence: 7 }
    );
    assert_eq!(output.report.counts.done, 1);
    // The file was a plain file, so Restart Manager was asked about it (query only).
    assert_eq!(rig.rm.calls.get(), 1);
}

#[test]
fn the_budget_limits_each_volume_separately() {
    let unknown = Budget(None);
    assert!(unknown.allows(1, u64::MAX));

    let mut budget = Budget(Some(BTreeMap::from([(1, 100), (2, 0)])));
    assert!(budget.allows(1, 100) && !budget.allows(1, 101));
    assert!(budget.allows(2, 0) && !budget.allows(2, 1));
    // A volume the pre-flight did not see is not limited here; the file action judges it.
    assert!(budget.allows(3, u64::MAX));
    budget.spend(1, 60);
    assert!(budget.allows(1, 40) && !budget.allows(1, 41));
    budget.spend(1, 1000);
    assert!(!budget.allows(1, 1));
}

#[test]
fn an_item_over_the_volume_budget_is_skipped_and_the_rest_run() {
    let mut rig = Rig::new("cap");
    let big = rig.s.file(r"app\big.bin", &[7u8; 4096]);
    let small = rig.s.file(r"app\small.txt", b"s");
    let request = preselected(
        vec![quarantine("c-big", &big), quarantine("c-small", &small)],
        Vec::new(),
    );
    let mut run = Run::start(request, rig.env(None)).unwrap();
    run.validate().unwrap();
    let (serial, bytes) = run.move_size(OpId(1)).unwrap();
    assert_eq!(bytes, 4096);
    run.budget = Budget(Some(BTreeMap::from([(serial, 100)])));
    assert_eq!(
        run.run_item(OpId(1)).unwrap(),
        ItemStep::Finished(ItemOutcome::Skipped {
            reason: SkipReason::CapExceeded
        })
    );
    assert_eq!(
        run.run_item(OpId(2)).unwrap(),
        ItemStep::Finished(ItemOutcome::Done)
    );
    assert!(run.budget.allows(serial, 99) && !run.budget.allows(serial, 100));
    let output = run.finish();
    assert_eq!(output.report.state, SessionState::Committed);
    assert!(exists(&big) && !exists(&small));
}

/// The system's volume facts, except that reading the volume of a path below `failing` is refused.
#[derive(Debug)]
struct VolumeUnreadableBelow {
    failing: String,
}

impl crate::storage::VolumeProbe for VolumeUnreadableBelow {
    fn volume(
        &self,
        path: &Path,
    ) -> Result<crate::storage::VolumeFacts, purge_win::fs_write::FsError> {
        let text = path.to_string_lossy();
        let text = text.strip_prefix(r"\\?\").unwrap_or(&text);
        if purge_guard::prefix::is_same_or_inside(text, &self.failing) {
            return Err(purge_win::fs_write::FsError::AccessDenied);
        }
        crate::storage::VolumeProbe::volume(&crate::storage::SystemVolumes, path)
    }
}

#[test]
fn an_item_without_a_backup_location_says_why_in_the_journal_and_the_report() {
    let s = Scratch::new("nolocation");
    let f = s.file(r"src\a.txt", b"stays");
    let roots = StorageRoots::install_relaxed(Path::new(&s.path("data")))
        .unwrap()
        .with_volume_probe(std::sync::Arc::new(VolumeUnreadableBelow {
            failing: s.path("src"),
        }));
    let mut rig = Rig::with(s, roots);
    let output = rig.run(preselected(vec![quarantine("c-1", &f)], Vec::new()));
    assert_eq!(
        output.report.items[0].outcome,
        ItemOutcome::Skipped {
            reason: SkipReason::GateBlocked {
                blocker: Blocker::CannotBackUp
            }
        }
    );
    assert!(exists(&f));
    // The journal's done record names the failed step and the Win32 error; the report says the same.
    let read = rig.journal(&output.report.session);
    let details: Vec<&str> = read
        .records
        .iter()
        .filter_map(|r| match r {
            Record::Done(done) => Some(done.detail.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(details.len(), 1);
    assert!(
        details[0].contains("read the volume of") && details[0].contains("Win32 error 5"),
        "{details:?}"
    );
    assert!(
        output
            .report
            .warnings
            .iter()
            .any(|w| w.contains(details[0])),
        "{:?}",
        output.report.warnings
    );
}

// ---------------------------------------------------------------------------------------------------
// Resume
// ---------------------------------------------------------------------------------------------------

#[test]
fn a_stopped_run_is_resumed_through_the_per_item_function() {
    let mut rig = Rig::new("resume");
    let k = TestKey::new();
    k.create("Vals");
    k.set("Vals", "Gone", REG_SZ, &utf16z("bye"));
    let a = rig.s.file(r"app\a.txt", b"a");
    let b = rig.s.file(r"app\b.txt", b"b");
    let request = preselected(
        vec![
            quarantine("c-a", &a),
            safe("c-val", value(&k.wire("Vals"), "Gone"), Action::DeleteValue),
            quarantine("c-b", &b),
        ],
        Vec::new(),
    );
    let scan = request.scan.clone();
    let settings = request.settings.clone();

    // A run that stops after its first item, without an end record.
    let mut run = Run::start(request, rig.env(None)).unwrap();
    run.validate().unwrap();
    assert_eq!(
        run.run_item(OpId(1)).unwrap(),
        ItemStep::Finished(ItemOutcome::Done)
    );
    assert_eq!(run.run_item(OpId(1)).unwrap(), ItemStep::AlreadyDone);
    assert_eq!(run.run_item(OpId(9)).unwrap(), ItemStep::NotInRun);
    let id = run.session().id().clone();
    drop(run);
    assert!(!rig.journal(&id).state.is_finished());

    // Recovery: the session's own scan copy and journal are all it needs.
    let session = rig.session(&id);
    let copy = read_scan_copy(&session).unwrap();
    assert_eq!(copy, scan);
    let mut run = Run::resume(rig.env(None), session, &copy).unwrap();
    assert_eq!(run.plan().items().len(), 3);
    // The settings are the journal's, as the first run wrote them.
    assert_eq!(run.settings(), &settings);
    assert_eq!(run.run_item(OpId(1)).unwrap(), ItemStep::AlreadyDone);
    assert_eq!(
        run.run_item(OpId(2)).unwrap(),
        ItemStep::Finished(ItemOutcome::Done)
    );
    assert_eq!(
        run.run_item(OpId(3)).unwrap(),
        ItemStep::Finished(ItemOutcome::Done)
    );
    let output = run.finish();
    assert_eq!(output.report.state, SessionState::Committed);
    let read = rig.journal(&id);
    assert_eq!(outcomes(&read), vec![Some(ItemOutcome::Done); 3]);
    assert_report_is_the_journal(&output.report, &read);
    assert!(!exists(&a) && !exists(&b));
    assert_eq!(k.get("Vals", "Gone"), None);

    // A finished session is not resumed, and a journal is not resumed with another plan.
    let session = rig.session(&id);
    assert!(matches!(
        Run::resume(rig.env(None), session, &copy),
        Err(ExecError::NotResumable(_))
    ));
}

#[test]
fn a_journal_is_not_resumed_with_another_document() {
    let mut rig = Rig::new("resume-other");
    let a = rig.s.file(r"app\a.txt", b"a");
    let b = rig.s.file(r"app\b.txt", b"b");
    let request = preselected(
        vec![quarantine("c-a", &a), quarantine("c-b", &b)],
        Vec::new(),
    );
    let mut run = Run::start(request.clone(), rig.env(None)).unwrap();
    run.validate().unwrap();
    let id = run.session().id().clone();
    drop(run);

    let mut other = request.scan.clone();
    other.items.swap(0, 1);
    crate::plan_in::tests::rehash(&mut other);
    let session = rig.session(&id);
    assert!(matches!(
        Run::resume(rig.env(None), session, &other),
        Err(ExecError::Plan(PlanRefusal::JournalMismatch(_)))
    ));
    let mut tampered = request.scan.clone();
    tampered.items[1].target = path(&a);
    let session = rig.session(&id);
    assert!(matches!(
        Run::resume(rig.env(None), session, &tampered),
        Err(ExecError::Plan(PlanRefusal::PlanHashMismatch { .. }))
    ));
    assert!(exists(&a) && exists(&b));
}

#[test]
fn the_time_is_a_filetime_of_today() {
    // 2026-01-01 and 2100-01-01 as FILETIME ticks.
    let ticks = now().0;
    assert!(ticks > 134_116_992_000_000_000 && ticks < 157_469_184_000_000_000);
}

// ---------------------------------------------------------------------------------------------------
// Fault points: the pipeline is driven to a declared point in a child process, which dies there
// ---------------------------------------------------------------------------------------------------

/// Set only in a child process of the test binary: the scratch directory the child works in.
const CHILD_ROOT: &str = "PURGE_TEST_EXEC_CHILD_ROOT";

/// The plan of the crash tests: three files below `<root>\app`.
fn crash_request(s: &Scratch) -> ExecRequest {
    preselected(
        (1..=3)
            .map(|n| quarantine(&format!("c-{n}"), &s.path(&format!(r"app\f{n}.txt"))))
            .collect(),
        Vec::new(),
    )
}

/// The child half of the crash tests: executes [`crash_request`] in the scratch directory the parent
/// made. Does nothing when run as an ordinary test.
#[test]
fn child_execute_scenario() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let s = Scratch::at(Path::new(&root));
    let roots = StorageRoots::relaxed(Path::new(&s.path("data"))).unwrap();
    // The parent owns the scratch directory; the child must not remove it.
    let mut rig = std::mem::ManuallyDrop::new(Rig::with(s, roots));
    let request = crash_request(&rig.s);
    rig.run(request);
}

#[cfg(feature = "fault-inject")]
mod crash {
    use super::*;

    /// The exit code of a process ended by `std::process::abort` on Windows (`__fastfail`).
    const ABORT_CODE: i32 = 0xC000_0409_u32 as i32;

    /// A rig with the three files of [`crash_request`], and the child's exit code after it ran the
    /// plan with the fault `at`.
    fn crashed(tag: &str, at: &str) -> Rig {
        let rig = Rig::new(tag);
        for n in 1..=3 {
            rig.s.file(&format!(r"app\f{n}.txt"), b"data");
        }
        let code = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "execute::tests::child_execute_scenario",
                "--test-threads=1",
            ])
            .env(CHILD_ROOT, &rig.s.root)
            .env(fault::ENV_AT, at)
            .env_remove(fault::ENV_PAUSE)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .code();
        assert_eq!(code, Some(ABORT_CODE), "{at}");
        rig
    }

    fn at_source(rig: &Rig) -> [bool; 3] {
        [1, 2, 3].map(|n| exists(&rig.s.path(&format!(r"app\f{n}.txt"))))
    }

    /// Changed (M2 recovery fix pass): the header and the run's settings are flushed together, and a
    /// run that stopped there is resumed as if it had never been interrupted (before, it could not be
    /// resumed at all).
    #[test]
    fn a_crash_at_the_header_resumes_as_an_uninterrupted_run() {
        let mut rig = crashed("crash-header", fault::JOURNAL_HEADER);
        let request = crash_request(&rig.s);
        let [id] = rig.sessions().try_into().unwrap();
        let read = rig.journal(&id);
        assert_eq!(read.records.len(), 2);
        assert!(read.state.settings().is_some());
        assert_eq!(read.state.phase(), Phase::Validating);
        // The scan copy is durable before the journal exists.
        assert_eq!(read_scan_copy(&rig.session(&id)).unwrap(), request.scan);
        assert_eq!(at_source(&rig), [true; 3]);

        // Nothing was validated: resume validates every item now, then runs them.
        let session = rig.session(&id);
        let mut run = Run::resume(rig.env(None), session, &request.scan).unwrap();
        assert_eq!(run.state().validated_count(), 3);
        for n in 1..=3 {
            assert_eq!(
                run.run_item(OpId(n)).unwrap(),
                ItemStep::Finished(ItemOutcome::Done)
            );
        }
        let output = run.finish();
        assert_eq!(output.report.state, SessionState::Committed);
        assert_eq!(output.report.counts.done, 3);
        assert_eq!(at_source(&rig), [false; 3]);
        // One validated record per item: none was written twice.
        let read = rig.journal(&id);
        let validated = read
            .records
            .iter()
            .filter(|r| matches!(r, Record::Validated(_)))
            .count();
        assert_eq!(validated, 3);
    }

    #[test]
    fn a_crash_before_the_second_act_leaves_an_open_intent_and_the_rest_untouched() {
        let mut rig = crashed("crash-act", "act.before:2");
        let request = crash_request(&rig.s);
        let [id] = rig.sessions().try_into().unwrap();
        let read = rig.journal(&id);
        let status = |n: u32| read.state.op(OpId(n)).unwrap().status();
        assert_eq!(status(1), OpStatus::Done(&ItemOutcome::Done));
        assert_eq!(status(2), OpStatus::IntentOnly);
        assert_eq!(status(3), OpStatus::Validated);
        assert!(!read.state.is_finished());
        assert_eq!(read.state.open_intents().count(), 1);
        // The intent was flushed and the action had not started.
        assert_eq!(at_source(&rig), [false, true, true]);

        // The next package takes it from here: the open intent is recovery's, the rest runs through
        // the per-item function.
        let session = rig.session(&id);
        let mut run = Run::resume(rig.env(None), session, &request.scan).unwrap();
        assert_eq!(run.run_item(OpId(1)).unwrap(), ItemStep::AlreadyDone);
        assert_eq!(run.run_item(OpId(2)).unwrap(), ItemStep::OpenIntent);
        assert_eq!(
            run.run_item(OpId(3)).unwrap(),
            ItemStep::Finished(ItemOutcome::Done)
        );
        assert!(run.journal_mut().resume_intent(OpId(2)).is_some());
        drop(run);
        assert_eq!(at_source(&rig), [false, true, false]);
        assert!(!rig.journal(&id).state.is_finished());
    }

    #[test]
    fn a_crash_before_the_commit_leaves_every_item_done_and_the_run_open() {
        let mut rig = crashed("crash-commit", fault::COMMIT_BEFORE);
        let request = crash_request(&rig.s);
        let [id] = rig.sessions().try_into().unwrap();
        let read = rig.journal(&id);
        assert_eq!(outcomes(&read), vec![Some(ItemOutcome::Done); 3]);
        assert!(!read.state.is_finished());
        assert_eq!(read.state.open_group_intents(), 0);
        assert_eq!(at_source(&rig), [false; 3]);
        // No report and no index entry were written; resuming only has the commit left to do.
        assert!(rig.session(&id).open_file(REPORT_FILE).is_err());
        let session = rig.session(&id);
        let run = Run::resume(rig.env(None), session, &request.scan).unwrap();
        let output = run.finish();
        assert_eq!(output.report.state, SessionState::Committed);
        assert_eq!(output.report.counts.done, 3);
        assert_eq!(rig.journal(&id).state.phase(), Phase::Committed);
    }
}

// ---------------------------------------------------------------------------------------------------
// Gap pass: refused facts, the unstarted session, resume settings and cap
// ---------------------------------------------------------------------------------------------------

#[test]
fn an_item_that_did_not_pass_validation_is_journalled_with_refused_facts() {
    use purge_guard::live::Refusal;
    assert_eq!(
        refused_facts(Some(&GateOutcome::Vanished)),
        ItemFacts::Absent
    );
    assert_eq!(
        refused_facts(Some(&GateOutcome::Refused(Refusal {
            blocker: Blocker::ChangedSinceScan,
            reason: "live.identity-changed",
        }))),
        ItemFacts::Refused {
            blocker: Some(Blocker::ChangedSinceScan),
            reason: "live.identity-changed".into(),
            os_error: None,
        }
    );
    assert_eq!(
        refused_facts(Some(&GateOutcome::Failed(Win32Error(5)))),
        ItemFacts::Refused {
            blocker: None,
            reason: OPEN_FAILED.into(),
            os_error: Some(5),
        }
    );
    // No executor op (an object item without its scan-time digest): not looked at, changed since the
    // scan as far as the run can tell.
    assert_eq!(
        refused_facts(None),
        ItemFacts::Refused {
            blocker: Some(Blocker::ChangedSinceScan),
            reason: NO_OBJECT_FP.into(),
            os_error: None,
        }
    );
    // A record of such an item binds nothing, as one of an absent item.
    for facts in [refused_facts(None), ItemFacts::Absent] {
        assert_eq!(gate::Stamp::from_item_facts(&facts), None);
    }
}

#[test]
fn a_refused_validated_record_is_accepted_on_resume_and_binds_nothing() {
    let mut rig = Rig::new("resume-refused");
    let a = rig.s.file(r"app\a.txt", b"a");
    let target = rig.s.dir("elsewhere");
    let link = rig.s.path(r"app\link");
    junction(&link, &target);
    let request = preselected(
        vec![quarantine("c-a", &a), quarantine("c-link", &link)],
        Vec::new(),
    );
    let mut run = Run::start(request, rig.env(None)).unwrap();
    run.validate().unwrap();
    let id = run.session().id().clone();
    drop(run);
    let read = rig.journal(&id);
    assert!(matches!(
        read.state.op(OpId(2)).unwrap().validated().facts,
        ItemFacts::Refused { .. }
    ));

    let session = rig.session(&id);
    let copy = read_scan_copy(&session).unwrap();
    let mut run = Run::resume(rig.env(None), session, &copy).unwrap();
    // GateCtx::record took the refused record without a complaint.
    assert!(
        run.ledger.notes.details.is_empty(),
        "{:?}",
        run.ledger.notes.details
    );
    // Nothing is bound to op 2, so it is never acted on.
    let step = run.run_item(OpId(2)).unwrap();
    assert!(
        matches!(
            step,
            ItemStep::Finished(ItemOutcome::Skipped { .. } | ItemOutcome::Failed { .. })
        ),
        "{step:?}"
    );
    assert_eq!(
        run.run_item(OpId(1)).unwrap(),
        ItemStep::Finished(ItemOutcome::Done)
    );
    let output = run.finish();
    assert_eq!(output.report.state, SessionState::Committed);
    assert!(exists(&link) && !exists(&a));
}

#[test]
fn a_run_that_fails_before_its_journal_removes_its_session_dir() {
    // The scan copy's name is taken: the run fails before the header, and the directory, which holds
    // only that name, is removed by handle.
    let mut rig = Rig::new("unstarted-gone");
    let a = rig.s.file(r"app\a.txt", b"a");
    let request = preselected(vec![quarantine("c-a", &a)], Vec::new());
    let session_path = RefCell::new(PathBuf::new());
    let progress = |event: &Progress<'_>| {
        if let Progress::SessionCreated { path, .. } = event {
            *session_path.borrow_mut() = path.to_path_buf();
            std::fs::write(path.join(crate::storage::SCAN_FILE), b"taken").unwrap();
        }
    };
    assert!(rig.try_run(request, Some(&progress)).is_err());
    assert!(!session_path.borrow().as_os_str().is_empty());
    assert!(!session_path.borrow().exists());
    assert!(rig.sessions().is_empty());
    assert!(exists(&a));

    // The journal's name is taken by an empty file: the run fails at the header, and the directory,
    // which holds the scan copy and a zero-byte journal (no run started), is removed by handle (M2
    // recovery fix pass; it was kept before).
    let mut rig = Rig::new("unstarted-empty");
    let a = rig.s.file(r"app\a.txt", b"a");
    let request = preselected(vec![quarantine("c-a", &a)], Vec::new());
    let session_path = RefCell::new(PathBuf::new());
    let progress = |event: &Progress<'_>| {
        if let Progress::SessionCreated { path, .. } = event {
            *session_path.borrow_mut() = path.to_path_buf();
            std::fs::write(path.join(JOURNAL_FILE), b"").unwrap();
        }
    };
    assert!(matches!(
        rig.try_run(request, Some(&progress)),
        Err(ExecError::Journal(_))
    ));
    assert!(!session_path.borrow().exists());
    assert!(rig.sessions().is_empty());
    assert!(exists(&a));

    // The journal's name is taken by a file with bytes in it: the directory, which holds what may be a
    // run's journal, stays as it is.
    let mut rig = Rig::new("unstarted-kept");
    let a = rig.s.file(r"app\a.txt", b"a");
    let request = preselected(vec![quarantine("c-a", &a)], Vec::new());
    let session_path = RefCell::new(PathBuf::new());
    let progress = |event: &Progress<'_>| {
        if let Progress::SessionCreated { path, .. } = event {
            *session_path.borrow_mut() = path.to_path_buf();
            std::fs::write(path.join(JOURNAL_FILE), b"{").unwrap();
        }
    };
    assert!(matches!(
        rig.try_run(request, Some(&progress)),
        Err(ExecError::Journal(_))
    ));
    let mut left: Vec<String> = std::fs::read_dir(&*session_path.borrow())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, [JOURNAL_FILE, crate::storage::SCAN_FILE]);
    assert_eq!(rig.sessions().len(), 1);
    assert!(exists(&a));
}

#[test]
fn a_journal_without_run_settings_is_not_resumed() {
    // A journal as written before the settings record existed: the same header and validated records.
    let mut rig = Rig::new("resume-old");
    let a = rig.s.file(r"app\a.txt", b"a");
    let request = preselected(vec![quarantine("c-a", &a)], Vec::new());
    let mut run = Run::start(request, rig.env(None)).unwrap();
    run.validate().unwrap();
    let id = run.session().id().clone();
    drop(run);
    let read = rig.journal(&id);
    let copy = read_scan_copy(&rig.session(&id)).unwrap();

    let old = rig.roots.create_session().unwrap();
    write_scan_copy(&old, &copy).unwrap();
    let header = Header {
        session: old.id().clone(),
        ..read.state.header().clone()
    };
    let mut writer = JournalWriter::create(&old, header).unwrap();
    for op in read.state.ops() {
        writer.validated(op.validated()).unwrap();
    }
    drop(writer);
    let err = Run::resume(rig.env(None), old, &copy).unwrap_err();
    assert!(
        matches!(&err, ExecError::NotResumable(why) if why.contains("settings")),
        "{err}"
    );
    assert!(exists(&a));
}

/// Item 1 of the M2 recovery fix pass: a run that stopped in its validate pass is resumed as if never
/// interrupted. The selection is found again from the header's selection hash (one candidate between
/// the validated ones is not selected), the journalled `validated` record is kept as it is and never
/// written again, and only the items without one are validated. Before the pass such a run could not
/// be resumed (`NotResumable`).
#[test]
fn a_run_stopped_in_its_validation_resumes_with_its_journalled_records() {
    let mut rig = Rig::new("resume-validating");
    let files: Vec<String> = ["a", "b", "c", "d"]
        .iter()
        .map(|n| rig.s.file(&format!(r"app\{n}.txt"), n.as_bytes()))
        .collect();
    let scan = scan_doc(
        files
            .iter()
            .zip(["c-a", "c-b", "c-c", "c-d"])
            .map(|(file, id)| quarantine(id, file))
            .collect(),
        Vec::new(),
    );
    let mut request = request(
        &scan,
        Selection::Ids(vec![cid("c-a"), cid("c-c"), cid("c-d")]),
    );
    request.settings.restore_point = RestorePointSetting::Off;
    let mut run = Run::start(request, rig.env(None)).unwrap();
    run.validate().unwrap();
    let id = run.session().id().clone();
    drop(run);
    let full = rig.journal(&id);
    let copy = read_scan_copy(&rig.session(&id)).unwrap();

    // The same run, stopped after the first validated record.
    let cut = rig.roots.create_session().unwrap();
    write_scan_copy(&cut, &copy).unwrap();
    let header = Header {
        session: cut.id().clone(),
        ..full.state.header().clone()
    };
    let settings = full.state.settings().unwrap().clone();
    let mut writer = JournalWriter::create_with_settings(&cut, header, settings).unwrap();
    let first = full.state.op(OpId(1)).unwrap().validated();
    writer.validated(first.clone()).unwrap();
    writer.sync().unwrap();
    drop(writer);
    let cut_id = cut.id().clone();

    let mut run = Run::resume(rig.env(None), cut, &copy).unwrap();
    assert_eq!(run.state().validated_count(), 3);
    assert_eq!(run.state().op(OpId(1)).unwrap().validated(), first);
    let ops: Vec<CandidateId> = run
        .plan()
        .items()
        .iter()
        .map(|item| run.plan().candidate(item).unwrap().id.clone())
        .collect();
    assert_eq!(ops, [cid("c-a"), cid("c-c"), cid("c-d")]);
    for n in 1..=3 {
        assert_eq!(
            run.run_item(OpId(n)).unwrap(),
            ItemStep::Finished(ItemOutcome::Done)
        );
    }
    let output = run.finish();
    assert_eq!(output.report.state, SessionState::Committed);
    let read = rig.journal(&cut_id);
    let validated = read
        .records
        .iter()
        .filter(|r| matches!(r, Record::Validated(_)))
        .count();
    assert_eq!(validated, 3);
    assert_eq!(
        files.iter().map(|f| exists(f)).collect::<Vec<_>>(),
        [false, true, false, false]
    );
}

/// Review M2 M3: a run stopped at its header is resumed with any selection. 31 selectable items, ten
/// selected and the first one not: the search over the header's selection hash would hash about
/// fourteen million combinations before this one and gives up; the selection journalled in the settings
/// record binds directly. The same journal without the journalled ids (as written before the field
/// existed) is still read as before and refused.
#[test]
fn a_run_stopped_at_its_header_resumes_with_any_selection() {
    let mut rig = Rig::new("resume-anysel");
    let files: Vec<String> = (0..31)
        .map(|n| rig.s.file(&format!(r"app\f{n:02}.txt"), b"x"))
        .collect();
    let ids: Vec<String> = (0..31).map(|n| format!("c-{n:02}")).collect();
    let scan = scan_doc(
        files
            .iter()
            .zip(&ids)
            .map(|(file, id)| quarantine(id, file))
            .collect(),
        Vec::new(),
    );
    let selected: Vec<CandidateId> = ids[1..11].iter().map(|id| cid(id)).collect();
    let mut request = request(&scan, Selection::Ids(selected.clone()));
    request.settings.restore_point = RestorePointSetting::Off;
    let run = Run::start(request, rig.env(None)).unwrap();
    let id = run.session().id().clone();
    drop(run);
    let full = rig.journal(&id);
    let settings = full.state.settings().unwrap().clone();
    assert_eq!(settings.selected, selected);
    let copy = read_scan_copy(&rig.session(&id)).unwrap();

    // The same run, stopped right after its header and settings, with and without the journalled ids.
    let cut = |settings: purge_model::exec::journal::RunSettings| {
        let session = rig.roots.create_session().unwrap();
        write_scan_copy(&session, &copy).unwrap();
        let header = Header {
            session: session.id().clone(),
            ..full.state.header().clone()
        };
        let mut writer = JournalWriter::create_with_settings(&session, header, settings).unwrap();
        writer.sync().unwrap();
        drop(writer);
        session
    };
    let with_ids = cut(settings.clone());
    let old = cut(purge_model::exec::journal::RunSettings {
        selected: Vec::new(),
        ..settings
    });
    let run = Run::resume(rig.env(None), with_ids, &copy).unwrap();
    assert_eq!(run.state().validated_count(), 10);
    let bound: Vec<CandidateId> = run
        .plan()
        .items()
        .iter()
        .map(|item| run.plan().candidate(item).unwrap().id.clone())
        .collect();
    assert_eq!(bound, selected);
    drop(run);

    let err = Run::resume(rig.env(None), old, &copy).unwrap_err();
    assert!(
        matches!(
            &err,
            ExecError::Plan(PlanRefusal::JournalMismatch(why)) if why.contains("cannot be found")
        ),
        "{err}"
    );
    assert!(files.iter().all(|f| exists(f)));
}

/// Review M2 M5: an empty op directory left by a run that stopped before the op's intent (here made
/// by hand, as a crash after the directory would leave it) is adopted when the item is found locked on
/// resume, as the file action adopts one; before, every resume aborted with `OpDirExists`.
#[test]
fn a_locked_item_adopts_the_empty_op_directory_of_an_interrupted_run() {
    let mut rig = Rig::new("lock-opdir");
    let locked = rig.s.file(r"app\busy.dll", b"in use");
    let mut request = preselected(vec![quarantine("c-1", &locked)], Vec::new());
    request.settings.restore_point = RestorePointSetting::Off;
    let mut run = Run::start(request, rig.env(None)).unwrap();
    run.validate().unwrap();
    let id = run.session().id().clone();
    drop(run);
    let serial = FileHandle::open(&ext(&locked))
        .unwrap()
        .file_id()
        .unwrap()
        .volume_serial;
    drop(
        rig.session(&id)
            .create_op_dir(Path::new(&locked), serial, OpId(1))
            .unwrap(),
    );
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(ext(&locked))
        .unwrap();
    let copy = read_scan_copy(&rig.session(&id)).unwrap();
    let session = rig.session(&id);
    let mut run = Run::resume(rig.env(None), session, &copy).unwrap();
    assert_eq!(
        run.run_item(OpId(1)).unwrap(),
        ItemStep::Finished(ItemOutcome::HeldRetry)
    );
    let output = run.finish();
    assert_eq!(output.report.state, SessionState::Committed);
    assert!(output.closed);
    drop(handle);
    assert_eq!(std::fs::read(ext(&locked)).unwrap(), b"in use");
}

/// Review M2 M5: a ladder that decides without acting takes the op directory made for it away again
/// at once, while it is empty; one the ladder acts on stays.
#[test]
fn a_locked_item_decided_without_acting_leaves_no_op_directory() {
    let mut rig = Rig::new("lock-decided");
    let locked = rig.s.file(r"app\busy.dll", b"in use");
    let request = preselected(vec![quarantine("c-1", &locked)], Vec::new());
    let mut run = Run::start(request, rig.env(None)).unwrap();
    run.validate().unwrap();
    let op_dir = run
        .env
        .roots
        .quarantine_path()
        .join(run.session().id().as_str())
        .join(OpId(1).file_stem());
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(ext(&locked))
        .unwrap();
    let prepared = prepare_fs(&run.ctx, &run.session, OpId(1), &run.env.retry).unwrap();
    let FsPrepared::Locked(mut item) = prepared else {
        panic!("{prepared:?}");
    };
    // The same item, but an open error that does not mean "in use": the ladder decides at once.
    item.locked.error = Win32Error(5);
    let outcome = run.locked_item(*item, None).unwrap();
    assert!(
        matches!(
            outcome,
            ItemOutcome::Failed {
                code: FailCode::AccessDenied,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert!(!op_dir.exists(), "{}", op_dir.display());
    drop(run);

    // A held item keeps its op directory: the intent records the quarantine path in it.
    let request = preselected(vec![quarantine("c-1", &locked)], Vec::new());
    let mut run = Run::start(request, rig.env(None)).unwrap();
    run.validate().unwrap();
    let op_dir = run
        .env
        .roots
        .quarantine_path()
        .join(run.session().id().as_str())
        .join(OpId(1).file_stem());
    assert_eq!(
        run.run_item(OpId(1)).unwrap(),
        ItemStep::Finished(ItemOutcome::HeldRetry)
    );
    assert!(op_dir.is_dir());
    drop(run);
    drop(handle);
    assert_eq!(std::fs::read(ext(&locked)).unwrap(), b"in use");
}

/// Review M2 M24: a key item counts its validated direct subkeys and itself toward the restore-point
/// rule's `Classes` limit; without validated facts it counts as one key.
#[test]
fn a_validated_key_counts_its_subkeys_toward_the_classes_limit() {
    let sid = current_user_sid().unwrap();
    let scan = scan_doc(
        vec![safe(
            "c-k",
            key(&format!(r"HKU\{sid}\Software\Classes\VendorApp.Document")),
            Action::DeleteKey,
        )],
        Vec::new(),
    );
    let plan = plan_in::bind(&request(&scan, Selection::Preselected)).unwrap();
    let facts = |subkeys: u32| {
        ItemFacts::Key(purge_model::exec::journal::RegFacts {
            subkeys,
            values: 0,
            is_link: false,
            owner: "S-1-5-32-544".into(),
            last_write_time: purge_model::FileTime(1),
            tree_sha256: None,
        })
    };
    let reasons = |facts_of: &dyn Fn(OpId) -> Option<ItemFacts>| {
        prepare::risk_reasons(&risk_items(&plan, facts_of), scan.mode)
    };
    assert!(reasons(&|_| None).is_empty());
    assert!(reasons(&|_| Some(facts(499))).is_empty());
    assert_eq!(
        reasons(&|_| Some(facts(500))),
        [prepare::RiskReason::ClassesKeys { keys: 501 }]
    );
}

#[test]
fn a_resumed_run_keeps_to_the_size_cap() {
    let mut rig = Rig::new("resume-cap");
    let a = rig.s.file(r"app\a.bin", &[1u8; 4096]);
    let b = rig.s.file(r"app\b.bin", &[2u8; 4096]);
    let request = preselected(
        vec![quarantine("c-a", &a), quarantine("c-b", &b)],
        Vec::new(),
    );
    let mut run = Run::start(request, rig.env(None)).unwrap();
    run.validate().unwrap();
    let (serial, bytes) = run.move_size(OpId(1)).unwrap();
    assert_eq!(bytes, 4096);
    // Nothing else is in the index: what the budget holds is the volume's cap.
    let cap = run.budget.0.as_ref().unwrap()[&serial];
    assert!(cap > 2 * 4096);
    assert_eq!(
        run.run_item(OpId(1)).unwrap(),
        ItemStep::Finished(ItemOutcome::Done)
    );
    let id = run.session().id().clone();
    drop(run);

    // Another session holds all but 8191 bytes of the cap: op 2 fits next to it, but not next to it
    // and what op 1 already moved. A stale entry of this session itself is not counted twice.
    let summary = |id: SessionId, bytes: u64| purge_model::exec::session::SessionSummary {
        started: id.started(),
        expires: purge_model::exec::session::Expiry::from_start(id.started()),
        id,
        app: "app".into(),
        owner: None,
        plan_hash: purge_model::exec::op::Sha256Hex([7; 32]),
        state: SessionState::Committed,
        finished: None,
        counts: Default::default(),
        undone: 0,
        backup_bytes: bytes,
        usage: vec![purge_model::exec::session::VolumeUsage {
            serial,
            root: String::new(),
            bytes,
        }],
        purged: Vec::new(),
        pending_reboot: false,
        journal: None,
    };
    let other = rig.roots.create_session().unwrap();
    rig.roots
        .update_index(|index| {
            index.upsert(summary(other.id().clone(), cap - 2 * 4096 + 1));
            index.upsert(summary(id.clone(), cap));
        })
        .unwrap();

    let session = rig.session(&id);
    let copy = read_scan_copy(&session).unwrap();
    let mut run = Run::resume(rig.env(None), session, &copy).unwrap();
    assert!(!run.budget.allows(serial, 4096) && run.budget.allows(serial, 4095));
    assert_eq!(
        run.run_item(OpId(2)).unwrap(),
        ItemStep::Finished(ItemOutcome::Skipped {
            reason: SkipReason::CapExceeded
        })
    );
    let output = run.finish();
    assert_eq!(output.report.state, SessionState::Committed);
    assert!(exists(&b) && !exists(&a));

    // Without the other session the same resume would have let op 2 through.
    let mut index = rig.roots.read_index().unwrap();
    index.remove(&id);
    let state = rig.journal(&id).state;
    let spent = report::usage(&state, data_volume(&rig.roots).as_ref());
    let without_other = {
        index.remove(other.id());
        resume_budget(&rig.roots, &state, Some(index), &spent)
    };
    assert!(without_other.allows(serial, 4096));
}

// ---------------------------------------------------------------------------------------------------
// Registry items of one run that depend on each other
// ---------------------------------------------------------------------------------------------------

/// The registry items of a chain, inner items first:
///
/// - (a) `App`'s two values and its subkey, then `App` if empty (ops 1-4);
/// - (b) a segment of `Seg`'s list, then that list value, then `Seg`'s other value (ops 5-7);
/// - (c) then `Seg`'s tree, whose remaining value is kept in its backup (op 8).
fn chain_plan(k: &TestKey) -> Vec<Candidate> {
    k.create(r"App\Sub");
    k.set("App", "a", REG_SZ, &utf16z("a"));
    k.set("App", "b", REG_SZ, &utf16z("b"));
    k.set(r"App\Sub", "s", REG_SZ, &utf16z("s"));
    k.create("Seg");
    k.set(
        "Seg",
        "List",
        REG_MULTI_SZ,
        &multi_sz(&["keep", "vendor", "also"]),
    );
    k.set("Seg", "Other", REG_SZ, &utf16z("o"));
    k.set("Seg", "Stays", REG_SZ, &utf16z("s"));
    vec![
        safe("c-a", value(&k.wire("App"), "a"), Action::DeleteValue),
        safe("c-b", value(&k.wire("App"), "b"), Action::DeleteValue),
        safe("c-sub", key(&k.wire(r"App\Sub")), Action::DeleteKey),
        safe("c-app", key(&k.wire("App")), Action::RemoveDirIfEmpty),
        safe(
            "c-seg",
            Target::RegMultiSzSegment {
                path: k.wire("Seg"),
                name: "List".into(),
                segment: "vendor".into(),
                index: None,
            },
            Action::EditSegment,
        ),
        safe("c-list", value(&k.wire("Seg"), "List"), Action::DeleteValue),
        safe(
            "c-other",
            value(&k.wire("Seg"), "Other"),
            Action::DeleteValue,
        ),
        safe("c-segkey", key(&k.wire("Seg")), Action::DeleteKey),
    ]
}

/// A key's values as (name, type, data), sorted by name, and its subkey names.
type KeyContent = (Vec<(String, u32, Vec<u8>)>, Vec<String>);

/// The content of `sub`: what a restore must bring back, whatever order the values are enumerated in.
fn key_content(k: &TestKey, sub: &str) -> KeyContent {
    let key = k.open(sub, KeyAccess::READ);
    let mut values: Vec<_> = key
        .values()
        .unwrap()
        .into_iter()
        .map(|v| (v.name, v.ty, v.data))
        .collect();
    values.sort();
    (values, key.subkey_names().unwrap())
}

/// Undoes ops `ops` of session `id`, in that order, through the registry undo functions of `act_reg`,
/// with a gate context given the journal's `validated` records, as an undo driver does; journals each
/// undo and returns its result.
fn undo_registry(
    rig: &Rig,
    id: &SessionId,
    ops: impl IntoIterator<Item = u32>,
) -> Vec<crate::act_reg::RegUndoResult> {
    use crate::act_reg::{RegUndoPrepared, RegUndoResult, prepare_undo_reg, run_undo_reg};
    let session = rig.session(id);
    let mut journal = JournalWriter::open_append(&session).unwrap();
    let state = journal.state().clone();
    let scope = rig.roots.store_scope::<&Path>(id, &[]).unwrap();
    let deny = DenyList::compile(&live_env(rig.roots.data_root().to_str().unwrap()));
    let selected: Vec<ExecOp> = state
        .ops()
        .filter_map(|op| op.intent.as_ref().map(|intent| intent.exec_op.clone()))
        .collect();
    let mut ctx = GateCtx::new(deny, &selected, scope).unwrap();
    for op in state.ops() {
        if let Some(intent) = &op.intent {
            ctx.record(&intent.exec_op, &op.validated(), 5_000).unwrap();
        }
    }
    let mut results = Vec::new();
    for n in ops {
        let op = state.op(OpId(n)).unwrap();
        let intent = op.intent.as_ref().expect("an op with an intent");
        let result = match prepare_undo_reg(&ctx, &session, intent, op.outcome.as_ref()).unwrap() {
            RegUndoPrepared::Decided(result) => {
                match &result {
                    RegUndoResult::Done { outcome, .. } => journal
                        .undo_done_without_intent(OpId(n), outcome.clone())
                        .unwrap(),
                    RegUndoResult::Conflict { conflict, detail } => journal
                        .undo_conflict_without_intent(OpId(n), conflict.clone(), detail.clone())
                        .unwrap(),
                }
                result
            }
            RegUndoPrepared::Ready(inverse) => {
                let token = journal.undo_intent(OpId(n)).unwrap();
                let result = run_undo_reg(inverse, &token);
                match &result {
                    RegUndoResult::Done { outcome, .. } => {
                        journal.undo_done(token, outcome.clone()).unwrap()
                    }
                    RegUndoResult::Conflict { conflict, detail } => journal
                        .undo_conflict(token, conflict.clone(), detail.clone())
                        .unwrap(),
                }
                result
            }
        };
        results.push(result);
    }
    results
}

#[track_caller]
fn assert_restored(results: &[crate::act_reg::RegUndoResult]) {
    for result in results {
        assert!(
            matches!(
                result,
                crate::act_reg::RegUndoResult::Done {
                    outcome: purge_model::exec::journal::UndoOutcome::Restored,
                    ..
                }
            ),
            "{result:?}"
        );
    }
}

#[test]
fn dependent_registry_items_run_in_one_execute_and_undo_in_reverse_order() {
    let mut rig = Rig::new("reg-chain");
    let k = TestKey::new();
    let items = chain_plan(&k);
    let before = (key_content(&k, "App"), key_content(&k, r"App\Sub"));
    let seg_before = key_content(&k, "Seg");
    let output = rig.run(preselected(items, Vec::new()));
    assert_eq!(output.report.state, SessionState::Committed);
    let read = rig.journal(&output.session);
    assert_eq!(outcomes(&read), vec![Some(ItemOutcome::Done); 8]);
    assert_report_is_the_journal(&output.report, &read);
    assert!(!k.exists("App") && !k.exists("Seg"));

    // Reverse op order: each key comes back before what was inside it.
    assert_restored(&undo_registry(&rig, &output.session, (1..=8).rev()));
    assert_eq!(
        (key_content(&k, "App"), key_content(&k, r"App\Sub")),
        before
    );
    assert_eq!(key_content(&k, "Seg"), seg_before);
}

#[test]
fn an_outside_change_inside_a_chain_is_still_refused_in_one_execute() {
    let mut rig = Rig::new("reg-chain-outside");
    let k = TestKey::new();
    let items = chain_plan(&k);
    // Before the key ops act, someone else adds a value to each key.
    let progress = |event: &Progress<'_>| match event {
        Progress::ItemStarting { op: OpId(4), .. } => {
            k.set("App", "late", REG_SZ, &utf16z("late"));
        }
        Progress::ItemStarting { op: OpId(8), .. } => {
            k.set("Seg", "late", REG_SZ, &utf16z("late"));
        }
        _ => {}
    };
    let output = rig
        .try_run(preselected(items, Vec::new()), Some(&progress))
        .unwrap();
    let read = rig.journal(&output.session);
    let mut expected = vec![Some(ItemOutcome::Done); 8];
    expected[3] = Some(ItemOutcome::Skipped {
        reason: SkipReason::NoLongerEmpty,
    });
    expected[7] = Some(ItemOutcome::Skipped {
        reason: SkipReason::ChangedSinceScan,
    });
    assert_eq!(outcomes(&read), expected);
    assert_eq!(k.get("App", "late"), Some((REG_SZ, utf16z("late"))));
    assert_eq!(k.get("Seg", "late"), Some((REG_SZ, utf16z("late"))));
    assert_eq!(k.get("Seg", "Stays"), Some((REG_SZ, utf16z("s"))));
}

/// A run stopped in the middle of a chain: one op's intent is open (the action ran, no `done`), and
/// recovery ends it through `journal_mut` after the resume. The ops after it are judged with the effects
/// of every completed op, the one recovery ended included.
#[test]
fn a_chain_resumed_in_the_middle_completes() {
    let mut rig = Rig::new("reg-chain-resume");
    let k = TestKey::new();
    let items = chain_plan(&k);
    let before = (key_content(&k, "App"), key_content(&k, r"App\Sub"));
    let request = preselected(items, Vec::new());

    let mut run = Run::start(request, rig.env(None)).unwrap();
    run.validate().unwrap();
    assert_eq!(
        run.run_item(OpId(1)).unwrap(),
        ItemStep::Finished(ItemOutcome::Done)
    );
    // Op 2 acts after its intent is durable, and the run stops before its `done`.
    let RegPrepared::Ready(action) =
        prepare_reg(&run.ctx, &run.session, OpId(2), run.settings.key_limit).unwrap()
    else {
        panic!("op 2 was decided");
    };
    let token = run.ledger.intent(action.intent().clone()).unwrap();
    assert_eq!(act_reg(action, &token).outcome, ItemOutcome::Done);
    drop(token);
    let id = run.session().id().clone();
    drop(run);
    assert_eq!(k.get("App", "b"), None);

    let session = rig.session(&id);
    let copy = read_scan_copy(&session).unwrap();
    let mut run = Run::resume(rig.env(None), session, &copy).unwrap();
    assert_eq!(run.run_item(OpId(2)).unwrap(), ItemStep::OpenIntent);
    // Recovery found the value gone and ends the open intent.
    let token = run.journal_mut().resume_intent(OpId(2)).unwrap();
    run.journal_mut().done(token, ItemOutcome::Done).unwrap();
    for n in 3..=8 {
        assert_eq!(
            run.run_item(OpId(n)).unwrap(),
            ItemStep::Finished(ItemOutcome::Done),
            "op {n}"
        );
    }
    let output = run.finish();
    assert_eq!(output.report.state, SessionState::Committed);
    assert!(!k.exists("App") && !k.exists("Seg"));

    assert_restored(&undo_registry(&rig, &id, (1..=8).rev()));
    assert_eq!(
        (key_content(&k, "App"), key_content(&k, r"App\Sub")),
        before
    );
}

// ---------------------------------------------------------------------------------------------------
// Scan-time identity (`Candidate::item_fp`) and the plan's exemptions
// ---------------------------------------------------------------------------------------------------

/// The identity of the file or directory at `p` as a scan records it (`Candidate::item_fp`).
fn scan_identity_of(p: &str) -> purge_model::ItemFp {
    let id = FileHandle::open(&ext(p)).unwrap().file_id().unwrap();
    purge_model::ItemFp {
        file_id: purge_model::exec::op::FileIdHex(id.id),
        volume_serial: id.volume_serial,
    }
}

/// `fp` with one byte of its file id changed.
fn other_file_id(fp: purge_model::ItemFp) -> purge_model::ItemFp {
    let mut file_id = fp.file_id;
    file_id.0[0] ^= 0x5a;
    purge_model::ItemFp { file_id, ..fp }
}

/// Asserts that op `n` was refused at validation for its scan-time identity, never had an intent and was
/// skipped as changed since the scan.
#[track_caller]
fn assert_refused_for_scan_identity(read: &JournalRead, n: u32) {
    let op = read.state.op(OpId(n)).unwrap();
    assert_eq!(
        op.facts,
        ItemFacts::Refused {
            blocker: Some(Blocker::ChangedSinceScan),
            reason: gate::reason::SCAN_IDENTITY.into(),
            os_error: None,
        },
        "op {n}"
    );
    assert!(op.intent.is_none(), "op {n} has an intent");
    assert_eq!(
        op.outcome,
        Some(ItemOutcome::Skipped {
            reason: SkipReason::ChangedSinceScan
        }),
        "op {n}"
    );
}

#[test]
fn a_path_item_runs_only_when_it_is_the_object_the_scan_read() {
    let mut rig = Rig::new("scan-id");
    let same = rig.s.file(r"app\same.txt", b"same");
    let bad_id = rig.s.file(r"app\bad-id.txt", b"id");
    let bad_serial = rig.s.file(r"app\bad-serial.txt", b"serial");
    let zero_serial = rig.s.file(r"app\zero-serial.txt", b"zero");
    let tree = rig.s.dir(r"app\tree");
    rig.s.file(r"app\tree\inside.bin", b"in");
    let other_tree = rig.s.dir(r"app\other-tree");
    let other_inside = rig.s.file(r"app\other-tree\inside.bin", b"in");
    let empty = rig.s.dir(r"app\empty");
    let none = rig.s.file(r"app\none.txt", b"none");

    let with_fp = |mut c: Candidate, fp| {
        c.item_fp = Some(fp);
        c
    };
    let fp = scan_identity_of(&bad_serial);
    let serial_changed = purge_model::ItemFp {
        volume_serial: fp.volume_serial ^ 1,
        ..fp
    };
    let serial_zero = purge_model::ItemFp {
        volume_serial: 0,
        ..scan_identity_of(&zero_serial)
    };
    let items = vec![
        with_fp(quarantine("c-same", &same), scan_identity_of(&same)),
        with_fp(
            quarantine("c-bad-id", &bad_id),
            other_file_id(scan_identity_of(&bad_id)),
        ),
        with_fp(quarantine("c-bad-serial", &bad_serial), serial_changed),
        with_fp(quarantine("c-zero-serial", &zero_serial), serial_zero),
        with_fp(quarantine("c-tree", &tree), scan_identity_of(&tree)),
        with_fp(
            quarantine("c-other-tree", &other_tree),
            other_file_id(scan_identity_of(&other_tree)),
        ),
        with_fp(
            safe("c-empty", path(&empty), Action::RemoveDirIfEmpty),
            other_file_id(scan_identity_of(&empty)),
        ),
        quarantine("c-none", &none),
    ];
    let output = rig.run(preselected(items, Vec::new()));
    assert_eq!(output.report.state, SessionState::Committed);
    let read = rig.journal(&output.session);
    assert_report_is_the_journal(&output.report, &read);

    let done = Some(ItemOutcome::Done);
    let changed = Some(ItemOutcome::Skipped {
        reason: SkipReason::ChangedSinceScan,
    });
    assert_eq!(
        outcomes(&read),
        [
            done.clone(),
            changed.clone(),
            changed.clone(),
            changed.clone(),
            done.clone(),
            changed.clone(),
            changed,
            done,
        ]
    );
    for n in [2, 3, 4, 6, 7] {
        assert_refused_for_scan_identity(&read, n);
    }
    // The matching items and the item without a scan-time identity were moved; nothing refused was
    // touched.
    assert!(!exists(&same) && !exists(&tree) && !exists(&none));
    assert_eq!(std::fs::read(ext(&bad_id)).unwrap(), b"id");
    assert_eq!(std::fs::read(ext(&bad_serial)).unwrap(), b"serial");
    assert_eq!(std::fs::read(ext(&zero_serial)).unwrap(), b"zero");
    assert_eq!(std::fs::read(ext(&other_inside)).unwrap(), b"in");
    assert!(exists(&empty));
    assert_eq!(
        read.records.iter().filter(|r| r.name() == "intent").count(),
        3
    );
}

#[test]
fn a_file_replaced_between_scan_and_run_is_caught_by_its_scan_time_identity() {
    let mut rig = Rig::new("scan-id-replaced");
    let f = rig.s.file(r"app\settings.ini", b"scanned");
    let mut item = quarantine("c-ini", &f);
    item.item_fp = Some(scan_identity_of(&f));
    // After the scan, the file is deleted and another one is created under the same name: at the start
    // of the run the path, its final path and its handle agree, only the object is another.
    std::fs::remove_file(ext(&f)).unwrap();
    std::fs::write(ext(&f), b"replaced").unwrap();
    assert_ne!(Some(scan_identity_of(&f)), item.item_fp);
    let request = preselected(vec![item], Vec::new());

    let mut run = Run::start(request, rig.env(None)).unwrap();
    // The start-of-run facts alone pass: the same item without its scan-time identity validates.
    let exec_op = run.plan.items()[0].exec_op.clone().unwrap();
    let look = gate::validate(&run.ctx, &GateItem::new(&exec_op, run.exemptions(OpId(1))));
    assert!(matches!(look, GateOutcome::Pass(_)), "{look:?}");
    // With it, the item is refused at validation and never acted on, also when the run is resumed.
    let validated = run.validate().unwrap();
    assert_eq!(
        validated[0].facts,
        ItemFacts::Refused {
            blocker: Some(Blocker::ChangedSinceScan),
            reason: gate::reason::SCAN_IDENTITY.into(),
            os_error: None,
        }
    );
    assert_eq!(run.ctx.stamp(OpId(1)), None);
    let id = run.session().id().clone();
    drop(run);
    let session = rig.session(&id);
    let copy = read_scan_copy(&session).unwrap();
    let mut run = Run::resume(rig.env(None), session, &copy).unwrap();
    assert_eq!(
        run.run_item(OpId(1)).unwrap(),
        ItemStep::Finished(ItemOutcome::Skipped {
            reason: SkipReason::ChangedSinceScan
        })
    );
    let output = run.finish();
    assert_eq!(output.report.state, SessionState::Committed);
    let read = rig.journal(&id);
    assert_refused_for_scan_identity(&read, 1);
    assert!(read.records.iter().all(|r| r.name() != "intent"));
    assert_eq!(std::fs::read(ext(&f)).unwrap(), b"replaced");
}

#[test]
fn the_journalled_exemptions_are_those_the_plan_derives() {
    use purge_model::{Evidence, EvidenceKind, Scope, SourceTrust};
    let evidence = |kind, scope, trust| Evidence::new(kind, scope, trust, "test").unwrap();
    let with = |mut c: Candidate, e: Vec<Evidence>| {
        c.evidence = e;
        c
    };
    let mut rig = Rig::new("exemptions");
    let sid = current_user_sid().unwrap();
    // Registry items below a key that does not exist: validation finds them gone, which journals the
    // exemptions all the same, and nothing in the registry is written.
    let base = format!(r"HKU\{sid}\Software\{}", unique("PurgeTestAbsent"));
    let lnk = rig.s.file(r"menu\Vendor App.lnk", b"lnk");
    let user_lnk = rig.s.file(r"menu\User App.lnk", b"lnk");
    let emptied = rig.s.dir(r"menu\Vendor");
    let plain = rig.s.file(r"app\plain.txt", b"p");
    let items = vec![
        with(
            safe("c-skel", key(&format!(r"{base}\shell")), Action::DeleteKey),
            vec![evidence(
                EvidenceKind::ProvenOwnedSkeleton,
                Scope::Key,
                SourceTrust::AdminOnly,
            )],
        ),
        safe(
            "c-seg",
            Target::RegMultiSzSegment {
                path: format!(r"{base}\Env"),
                name: "Path".into(),
                segment: r"C:\Vendor\bin".into(),
                index: None,
            },
            Action::EditSegment,
        ),
        with(
            quarantine("c-lnk", &lnk),
            vec![evidence(
                EvidenceKind::InsideInstallRoot,
                Scope::Path,
                SourceTrust::AdminOnly,
            )],
        ),
        // User-writable evidence earns the exemption only on a per-user target (Rule T), which depends
        // on the run's user.
        with(
            quarantine("c-user-lnk", &user_lnk),
            vec![evidence(
                EvidenceKind::InsideInstallRoot,
                Scope::Path,
                SourceTrust::UserWritable,
            )],
        ),
        with(
            safe("c-emptied", path(&emptied), Action::RemoveDirIfEmpty),
            vec![evidence(
                EvidenceKind::EmptyAfterPlan,
                Scope::Path,
                SourceTrust::AdminOnly,
            )],
        ),
        quarantine("c-plain", &plain),
    ];

    let deny = rig.deny.clone();
    let mut seen = Exemptions::default();
    for (user_sid, long_names_resolved) in [
        (None, false),
        (Some(sid.clone()), false),
        (None, true),
        (Some(sid.clone()), true),
    ] {
        let mut request = preselected(items.clone(), Vec::new());
        request.settings.user_sid = user_sid.clone();
        request.settings.long_names_resolved = long_names_resolved;
        let mut run = Run::start(request, rig.env(None)).unwrap();
        let validated = run.validate().unwrap();
        assert_eq!(validated.len(), items.len());
        for (record, candidate) in validated.iter().zip(&items) {
            assert_eq!(record.item, candidate.id);
            let derived = purge_plan::decide::deny_exemptions(
                candidate,
                deny.env(),
                user_sid.as_deref(),
                long_names_resolved,
            );
            assert_eq!(
                record.exemptions,
                gate::exemptions_to_journal(&derived),
                "{} (user {user_sid:?}, long names {long_names_resolved})",
                candidate.id.0
            );
            assert_eq!(
                run.state().op(record.op).unwrap().exemptions,
                record.exemptions
            );
            seen.proven_owned_skeleton |= derived.proven_owned_skeleton;
            seen.environment_segment_edit |= derived.environment_segment_edit;
            seen.tier_a_start_menu_entry |= derived.tier_a_start_menu_entry;
            seen.long_names_resolved |= derived.long_names_resolved;
        }
        drop(run);
    }
    // Every exemption was granted somewhere, so each is pinned.
    assert_eq!(
        seen,
        Exemptions {
            proven_owned_skeleton: true,
            environment_segment_edit: true,
            tier_a_start_menu_entry: true,
            long_names_resolved: true,
            ..Exemptions::default()
        }
    );
    // Nothing was acted on.
    assert!(exists(&lnk) && exists(&user_lnk) && exists(&emptied) && exists(&plain));
}

// ---------------------------------------------------------------------------------------------------
// M2 recovery fix pass: forward completion, held items, an indeterminate boot move at undo
// ---------------------------------------------------------------------------------------------------

/// Starts a run of `request`, validates it and journals op 1's intent from its prepared file action,
/// then stops: the crash between the intent and the act. Returns the session and the intent.
fn crash_after_the_first_intent(rig: &mut Rig, request: ExecRequest) -> (SessionId, Intent) {
    let mut run = Run::start(request, rig.env(None)).unwrap();
    run.validate().unwrap();
    let FsPrepared::Ready(action) =
        prepare_fs(&run.ctx, &run.session, OpId(1), &run.env.retry).unwrap()
    else {
        panic!("op 1 was decided");
    };
    let intent = action.intent().clone();
    let _open = run.ledger.intent(intent.clone()).unwrap();
    drop(action);
    let id = run.session().id().clone();
    drop(run);
    (id, intent)
}

/// Item 6: a move whose intent a crash left open, and whose file is in use when recovery completes it,
/// goes to the locked-file ladder with the journalled intent (the holders are named, nothing is
/// registered); recovery of the crashed run then never retries the held item, and
/// `recover::retry_held` moves it once the lock is gone, to exactly the quarantine path its intent
/// records.
#[test]
fn a_move_in_use_at_forward_completion_is_held_and_moved_by_the_retry() {
    let mut rig = Rig::new("complete-held");
    let busy = rig.s.file(r"app\busy.dll", b"in use");
    let other = rig.s.file(r"app\other.txt", b"o");
    rig.rm
        .holders
        .borrow_mut()
        .push(holder(4242, "Vendor Tray"));
    let request = preselected(
        vec![quarantine("c-busy", &busy), quarantine("c-other", &other)],
        Vec::new(),
    );
    let (id, intent) = crash_after_the_first_intent(&mut rig, request);
    let copy = read_scan_copy(&rig.session(&id)).unwrap();

    // The file is taken in use before recovery.
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(ext(&busy))
        .unwrap();
    let session = rig.session(&id);
    let mut run = Run::resume(rig.env(None), session, &copy).unwrap();
    let settled = run.settle_open(OpId(1)).unwrap().unwrap();
    assert_eq!(settled.probe, Probe::NotDone);
    assert_eq!(settled.outcome, ItemOutcome::HeldRetry);
    // The ladder ran: the holders were asked for and named.
    let named = run.ledger.notes.lockers.get(&OpId(1)).cloned().unwrap();
    assert_eq!(named[0].pid, 4242);
    assert_eq!(
        run.run_item(OpId(2)).unwrap(),
        ItemStep::Finished(ItemOutcome::Done)
    );
    // The second crash, before the commit; the lock goes away.
    drop(run);
    drop(lock);
    assert_eq!(rig.pending.registers, 0);

    // Recovery ends the run and leaves the held item where it is.
    let out = crate::recover::resume(&id, rig.recover_env()).unwrap();
    assert!(out.settled.is_empty() && out.retries.is_empty(), "{out:#?}");
    assert_eq!(out.state, Some(SessionState::Committed));
    assert!(exists(&busy) && !exists(&other));
    let read = rig.journal(&id);
    assert_eq!(read.state.held_retry().count(), 1);
    let intents = read
        .records
        .iter()
        .filter(|r| matches!(r, Record::Intent(i) if i.op == OpId(1)))
        .count();
    assert_eq!(intents, 1);

    // The retry moves it.
    let retried = crate::recover::retry_held(&id, rig.recover_env()).unwrap();
    assert_eq!(
        retried.retried,
        [locked::Retried {
            op: OpId(1),
            outcome: ItemOutcome::Done
        }],
        "{retried:#?}"
    );
    assert!(retried.index_updated);
    assert!(!exists(&busy));
    let Inverse::MoveBack {
        quarantine_path, ..
    } = &intent.inverse
    else {
        panic!("{intent:?}");
    };
    assert_eq!(std::fs::read(ext(quarantine_path)).unwrap(), b"in use");
    let read = rig.journal(&id);
    assert_eq!(read.state.held_retry().count(), 0);
    assert_eq!(read.state.retries_in_flight().count(), 0);
    // Nothing is left to try.
    let again = crate::recover::retry_held(&id, rig.recover_env()).unwrap();
    assert!(again.retried.is_empty());
    assert_eq!(rig.pending.registers, 0);
}

/// Item 6: a held item still in use at the retry stays held; one that changed since is skipped and
/// left as it is.
#[test]
fn a_retry_of_a_held_item_still_in_use_keeps_it_held() {
    let mut rig = Rig::new("retry-held");
    let busy = rig.s.file(r"app\busy.dll", b"in use");
    let request = preselected(vec![quarantine("c-busy", &busy)], Vec::new());
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(ext(&busy))
        .unwrap();
    let output = rig.run(request);
    let id = output.session.clone();
    assert_eq!(output.report.items[0].outcome, ItemOutcome::HeldRetry);

    let retried = crate::recover::retry_held(&id, rig.recover_env()).unwrap();
    assert_eq!(retried.retried[0].outcome, ItemOutcome::HeldRetry);
    assert!(exists(&busy));
    drop(lock);

    // Replaced by another file of the same name: not the validated object, so not moved.
    std::fs::remove_file(ext(&busy)).unwrap();
    std::fs::write(ext(&busy), b"new").unwrap();
    let retried = crate::recover::retry_held(&id, rig.recover_env()).unwrap();
    assert!(
        matches!(retried.retried[0].outcome, ItemOutcome::Skipped { .. }),
        "{retried:#?}"
    );
    assert_eq!(std::fs::read(ext(&busy)).unwrap(), b"new");
}

/// Item 8: a boot-time move whose state cannot be told at undo (the list cannot be read) is the
/// conflict `GateBlocked{DenyListed{lock.boot-move-indeterminate}}` with its reason, which the journal
/// keeps; it is not settled, so a later undo tries again. Before the pass the undo ended
/// `Failed{VerifyFailed}`.
#[test]
fn an_indeterminate_boot_move_at_undo_is_a_conflict_of_its_own() {
    let mut rig = Rig::new("undo-indeterminate");
    let file = rig.s.file(r"app\boot.dll", b"b");
    let request = preselected(vec![quarantine("c-boot", &file)], Vec::new());
    let mut run = Run::start(request, rig.env(None)).unwrap();
    run.validate().unwrap();
    let FsPrepared::Ready(action) =
        prepare_fs(&run.ctx, &run.session, OpId(1), &run.env.retry).unwrap()
    else {
        panic!("op 1 was decided");
    };
    let intent = action.intent().clone();
    drop(action);
    let token = run.ledger.intent(intent.clone()).unwrap();
    let Inverse::MoveBack {
        quarantine_path,
        original_path,
        ..
    } = &intent.inverse
    else {
        panic!("{intent:?}");
    };
    let pair =
        purge_win::fs_write::pending_pair(Path::new(original_path), Path::new(quarantine_path))
            .unwrap();
    let pending = ItemOutcome::PendingReboot {
        pair: purge_model::exec::op::BootMovePair {
            src: pair.src,
            dst: pair.dst,
        },
        confirmed: true,
    };
    run.ledger.done(token, pending, String::new()).unwrap();
    let output = run.finish();
    assert_eq!(output.report.state, SessionState::Committed);
    let id = output.session.clone();

    rig.pending.fail = Some(purge_win::fs_write::FsError::AccessDenied);
    let request = crate::undo::UndoRequest {
        session: id.clone(),
        selection: crate::undo::UndoSelection::All,
        plan_hash: None,
    };
    let env = crate::undo::UndoEnv {
        retry: Retry::with(RETRY_DELAYS.to_vec(), |_| {}),
        ..crate::undo::UndoEnv::new(&rig.roots, &rig.deny, &mut rig.pending)
    };
    let undone = crate::undo::undo(&request, env).unwrap();
    let [item] = undone.report.items.as_slice() else {
        panic!("{undone:#?}");
    };
    let indeterminate = UndoConflict::GateBlocked {
        blocker: Blocker::DenyListed {
            rule: locked::reason::BOOT_MOVE_INDETERMINATE.to_owned(),
        },
    };
    let purge_model::exec::session::UndoResult::Conflict { conflict, detail } = &item.result else {
        panic!("{item:#?}");
    };
    assert_eq!(conflict, &indeterminate);
    assert!(!detail.is_empty());
    let read = rig.journal(&id);
    let op = read.state.op(OpId(1)).unwrap();
    assert_eq!(op.undo, crate::journal::UndoState::Conflict(indeterminate));
    assert_eq!(
        read.state.undo_conflict_detail(OpId(1)),
        Some(detail.as_str())
    );
    assert!(!op.undo.is_settled());
    assert_eq!(read.state.undo_plan(), Some(&[OpId(1)][..]));
    assert!(read.state.undo_unfinished().is_empty());
}

/// Review M2 M7: a rollback whose probe found the op's boot-time move listed twice (`Attention`) ends
/// the op `Failed{VerifyFailed}`; its undo then does not say `AlreadyRestored` while the pair is
/// listed, but a conflict naming the pair, and nothing is removed. A later undo that finds the pair
/// once takes exactly that pair back before the op settles.
#[test]
fn a_move_back_never_settles_while_its_boot_move_is_listed() {
    let mut rig = Rig::new("undo-listed");
    let file = rig.s.file(r"app\boot.dll", b"b");
    let request = preselected(vec![quarantine("c-boot", &file)], Vec::new());
    let (id, intent) = crash_after_the_first_intent(&mut rig, request);
    let Inverse::MoveBack {
        quarantine_path,
        original_path,
        ..
    } = &intent.inverse
    else {
        panic!("{intent:?}");
    };
    let pair =
        purge_win::fs_write::pending_pair(Path::new(original_path), Path::new(quarantine_path))
            .unwrap();
    let foreign = (r"\??\C:\Other\a.tmp", r"\??\C:\Other\b.tmp");
    let ours = (pair.src.as_str(), pair.dst.as_str());
    rig.pending = MemoryPendingRenames::with_pairs(&[ours, foreign, ours]);
    let before = rig.pending.bytes().to_vec();

    let out = crate::recover::rollback(&id, rig.recover_env()).unwrap();
    assert!(
        matches!(
            out.settled[0].outcome,
            ItemOutcome::Failed {
                code: FailCode::VerifyFailed,
                ..
            }
        ),
        "{out:#?}"
    );
    let [item] = out.undone.as_slice() else {
        panic!("{out:#?}");
    };
    let indeterminate = UndoConflict::GateBlocked {
        blocker: Blocker::DenyListed {
            rule: locked::reason::BOOT_MOVE_INDETERMINATE.to_owned(),
        },
    };
    let purge_model::exec::session::UndoResult::Conflict { conflict, detail } = &item.result else {
        panic!("{item:#?}");
    };
    assert_eq!(conflict, &indeterminate);
    assert!(
        detail.contains(&pair.src) && detail.contains("2 times"),
        "{detail}"
    );
    assert_eq!(rig.pending.bytes(), before.as_slice());
    assert_eq!(rig.pending.removals, 0);
    assert!(
        !rig.journal(&id)
            .state
            .op(OpId(1))
            .unwrap()
            .undo
            .is_settled()
    );
    assert_eq!(std::fs::read(ext(&file)).unwrap(), b"b");

    // The list holds the pair once now: the undo takes exactly it back, the foreign pair stays.
    rig.pending = MemoryPendingRenames::with_pairs(&[foreign, ours]);
    let request = crate::undo::UndoRequest {
        session: id.clone(),
        selection: crate::undo::UndoSelection::All,
        plan_hash: None,
    };
    let env = crate::undo::UndoEnv {
        retry: Retry::with(RETRY_DELAYS.to_vec(), |_| {}),
        ..crate::undo::UndoEnv::new(&rig.roots, &rig.deny, &mut rig.pending)
    };
    let undone = crate::undo::undo(&request, env).unwrap();
    let [item] = undone.report.items.as_slice() else {
        panic!("{undone:#?}");
    };
    assert!(
        matches!(
            item.result,
            purge_model::exec::session::UndoResult::Finished {
                outcome: purge_model::exec::journal::UndoOutcome::AlreadyRestored
            }
        ),
        "{item:#?}"
    );
    assert_eq!(
        rig.pending.bytes(),
        MemoryPendingRenames::with_pairs(&[foreign]).bytes()
    );
    assert_eq!(rig.pending.removals, 1);
    let read = rig.journal(&id);
    let op = read.state.op(OpId(1)).unwrap();
    assert!(op.undo.is_settled());
    // The removal ran under an undo intent.
    assert!(
        read.records
            .iter()
            .any(|r| matches!(r, Record::UndoIntent(u) if u.op == OpId(1)))
    );
    assert_eq!(std::fs::read(ext(&file)).unwrap(), b"b");
}

/// F11 of the M2 fix-round review: the detail a `done` record carries is cut at a fixed length (at a
/// character boundary, marked); a short one is kept whole. Before the fix it had no bound.
#[test]
fn a_done_detail_is_cut_at_a_fixed_length() {
    assert_eq!(journal_detail("short"), "short");
    let exact = "x".repeat(MAX_DONE_DETAIL);
    assert_eq!(journal_detail(&exact), exact);
    // A path of two-byte characters, longer than the bound by far.
    let long = format!(r"C:\{}", "é".repeat(40_000));
    let cut = journal_detail(&long);
    assert!(cut.len() <= MAX_DONE_DETAIL, "{}", cut.len());
    assert!(cut.ends_with(" [...]"));
    assert!(long.starts_with(cut.trim_end_matches(" [...]")));
}

// ---------------------------------------------------------------------------------------------------
// M3-UNDO: what a dialog is shown before an undo or a recovery, and the runs that must do exactly that
// ---------------------------------------------------------------------------------------------------

fn undo_env(rig: &mut Rig) -> crate::undo::UndoEnv<'_> {
    crate::undo::UndoEnv {
        retry: Retry::with(RETRY_DELAYS.to_vec(), |_| {}),
        ..crate::undo::UndoEnv::new(&rig.roots, &rig.deny, &mut rig.pending)
    }
}

fn op_of(read: &JournalRead, item: &str) -> OpId {
    read.state
        .ops()
        .find(|op| op.item == cid(item))
        .unwrap_or_else(|| panic!("no op for {item}"))
        .op
}

/// A finished session over `app\sub\{a,b}.txt`, `other\c.txt`, the directory `sub` and the directory
/// `app`, in that order.
fn directory_session(rig: &mut Rig) -> (SessionId, [String; 4]) {
    let a = rig.s.file(r"app\sub\a.txt", b"aaa");
    let b = rig.s.file(r"app\sub\b.txt", b"bbb");
    let other = rig.s.file(r"other\c.txt", b"ccc");
    let sub = rig.s.path(r"app\sub");
    let app = rig.s.path("app");
    let request = preselected(
        vec![
            quarantine("c-a", &a),
            quarantine("c-b", &b),
            quarantine("c-other", &other),
            safe("c-sub", path(&sub), Action::RemoveDirIfEmpty),
            safe("c-app", path(&app), Action::RemoveDirIfEmpty),
        ],
        Vec::new(),
    );
    let id = rig.run(request).session;
    (id, [a, b, other, app])
}

#[test]
fn an_undo_preview_names_the_ops_the_run_then_puts_back() {
    let mut rig = Rig::new("m3undo-preview");
    let (id, [a, b, other, app]) = directory_session(&mut rig);
    let read = rig.journal(&id);
    let op = |item: &str| op_of(&read, item);
    assert!(!exists(&a) && !exists(&app));

    let preview = crate::undo::preview(&rig.roots, &id, Some(&[op("c-a")])).unwrap();
    assert_eq!(preview.put_back, [op("c-app"), op("c-sub"), op("c-a")]);
    assert_eq!(preview.pulled_in, [op("c-sub"), op("c-app")]);
    assert!(preview.already_undone.is_empty());
    assert_eq!(
        preview.expect.ops,
        [op("c-a"), op("c-sub"), op("c-app")],
        "op order"
    );
    assert_eq!(preview.expect.mark, read.state.mark());
    assert_eq!(preview.plan.plan_hash(), read.state.header().plan_hash);
    assert_eq!(
        preview.request.plan_hash,
        Some(read.state.header().plan_hash)
    );
    // A preview changes nothing.
    assert!(!exists(&a) && !exists(&app));
    assert_eq!(rig.journal(&id).state.mark(), read.state.mark());

    let done =
        crate::undo::undo_expecting(&preview.request, undo_env(&mut rig), &preview.expect).unwrap();
    let ran: Vec<OpId> = done.report.items.iter().map(|item| item.op).collect();
    assert_eq!(ran, preview.put_back, "the run goes through what was shown");
    assert!(exists(&a) && exists(&app));
    assert!(!exists(&b) && !exists(&other));

    // Everything is put back or settled: nothing is left to show.
    let all = crate::undo::preview(&rig.roots, &id, None).unwrap();
    assert_eq!(all.put_back, [op("c-other"), op("c-b")]);
    assert_eq!(all.already_undone, [op("c-a"), op("c-sub"), op("c-app")]);
}

#[test]
fn an_undo_that_is_not_what_the_preview_read_is_refused_before_it_changes_anything() {
    let mut rig = Rig::new("m3undo-notasshown");
    let (id, [a, b, _other, app]) = directory_session(&mut rig);
    let read = rig.journal(&id);
    let op = |item: &str| op_of(&read, item);
    let for_a = crate::undo::preview(&rig.roots, &id, Some(&[op("c-a")])).unwrap();
    let for_b = crate::undo::preview(&rig.roots, &id, Some(&[op("c-b")])).unwrap();

    // The shown ops are another selection's: the journal is the same, the run would not be.
    let err =
        crate::undo::undo_expecting(&for_b.request, undo_env(&mut rig), &for_a.expect).unwrap_err();
    assert!(matches!(err, crate::undo::UndoError::NotAsShown), "{err}");
    assert!(!exists(&a) && !exists(&b) && !exists(&app));
    assert_eq!(rig.journal(&id).state.mark(), read.state.mark());

    // Someone else's undo changed the journal after the preview.
    let other = crate::undo::UndoRequest {
        session: id.clone(),
        selection: crate::undo::UndoSelection::Items(vec![cid("c-other")]),
        plan_hash: None,
    };
    crate::undo::undo(&other, undo_env(&mut rig)).unwrap();
    let changed = rig.journal(&id).state.mark();
    assert_ne!(changed, read.state.mark());
    let err =
        crate::undo::undo_expecting(&for_a.request, undo_env(&mut rig), &for_a.expect).unwrap_err();
    assert!(matches!(err, crate::undo::UndoError::NotAsShown), "{err}");
    assert!(!exists(&a) && !exists(&app));
    assert_eq!(rig.journal(&id).state.mark(), changed);
}

#[test]
fn an_undo_preview_refuses_what_the_run_refuses() {
    let mut rig = Rig::new("m3undo-refused");
    let (id, _) = directory_session(&mut rig);
    let err = crate::undo::preview(&rig.roots, &id, Some(&[OpId(99)])).unwrap_err();
    assert!(
        matches!(err, crate::undo::UndoError::UnknownItem(_)),
        "{err}"
    );
    let stranger = SessionId::new(purge_model::FileTime(1), 7);
    assert!(crate::undo::preview(&rig.roots, &stranger, None).is_err());

    // A run that did not end is recovery's.
    let files: Vec<String> = (1..=3)
        .map(|n| rig.s.file(&format!(r"crash\f{n}.txt"), b"data"))
        .collect();
    let request = preselected(
        files
            .iter()
            .enumerate()
            .map(|(n, file)| quarantine(&format!("c-{}", n + 1), file))
            .collect(),
        Vec::new(),
    );
    let (open, _) = crash_after_the_first_intent(&mut rig, request);
    let err = crate::undo::preview(&rig.roots, &open, None).unwrap_err();
    assert!(
        matches!(err, crate::undo::UndoError::NeedsRecovery(_)),
        "{err}"
    );
}

#[test]
fn the_ops_a_run_goes_through_beyond_the_preview_change_nothing() {
    let mut rig = Rig::new("m3undo-nochange");
    let real = rig.s.file(r"app\real.txt", b"real");
    let gone = rig.s.path(r"app\gone.txt");
    let request = preselected(
        vec![quarantine("c-gone", &gone), quarantine("c-real", &real)],
        Vec::new(),
    );
    let id = rig.run(request).session;
    let read = rig.journal(&id);
    let preview = crate::undo::preview(&rig.roots, &id, None).unwrap();
    assert_eq!(preview.put_back, [op_of(&read, "c-real")]);
    assert_eq!(
        preview.expect.ops,
        [op_of(&read, "c-gone"), op_of(&read, "c-real")]
    );
    let done =
        crate::undo::undo_expecting(&preview.request, undo_env(&mut rig), &preview.expect).unwrap();
    let outcome_of = |item: &str| {
        let op = op_of(&read, item);
        done.report
            .items
            .iter()
            .find(|i| i.op == op)
            .unwrap()
            .result
            .clone()
    };
    assert_eq!(
        outcome_of("c-gone"),
        purge_model::exec::session::UndoResult::Finished {
            outcome: purge_model::exec::journal::UndoOutcome::NothingToUndo
        }
    );
    assert!(exists(&real));
}

/// M3-R2 point 2: a recovery with nothing to change on the machine runs without a dialog, so it must
/// be bound to the journal its preview read. An `Unindexed` session (its run ended, its report was
/// never written) whose journal changed after the preview is refused before anything is written.
#[test]
fn an_unindexed_recovery_whose_journal_changed_after_the_preview_is_not_as_shown() {
    use crate::recover::{self, PendingKind, Want};
    let mut rig = Rig::new("m3undo-unindexed");
    let (id, [a, _b, other, app]) = directory_session(&mut rig);
    let read = rig.journal(&id);
    std::fs::remove_file(rig.session(&id).path().join(REPORT_FILE)).unwrap();
    let preview = recover::preview(&rig.roots, &id, Want::Resume).unwrap();
    assert_eq!(preview.kind, Some(PendingKind::Unindexed));
    assert!(
        preview.ops.is_empty(),
        "only Purge's own records are missing"
    );
    assert_eq!(preview.mark, read.state.mark());

    // The journal moved on after the preview.
    {
        let session = rig.session(&id);
        let mut journal = JournalWriter::open_append(&session).unwrap();
        journal
            .undo_plan(crate::storage::now(), vec![op_of(&read, "c-other")])
            .unwrap();
    }
    let changed = rig.journal(&id).state.mark();
    assert_ne!(changed, preview.mark);
    for run in [recover::resume_expecting, recover::rollback_expecting] {
        let err = run(&id, rig.recover_env(), &preview.mark).unwrap_err();
        assert!(matches!(err, recover::RecoverError::NotAsShown), "{err}");
    }
    assert!(!exists(&a) && !exists(&other) && !exists(&app));
    assert_eq!(
        rig.journal(&id).state.mark(),
        changed,
        "nothing was written"
    );
}

/// A session of three files whose run stopped after the first intent.
fn crashed_session(rig: &mut Rig) -> (SessionId, [String; 3]) {
    let files = [1, 2, 3].map(|n| rig.s.file(&format!(r"app\f{n}.txt"), b"data"));
    let request = crash_request(&rig.s);
    let (id, _) = crash_after_the_first_intent(rig, request);
    (id, files)
}

#[test]
fn a_resume_preview_lists_what_is_still_to_do_and_the_run_is_bound_to_the_journal_it_read() {
    use crate::recover::{self, PendingKind, Want};
    let mut rig = Rig::new("m3undo-resume");
    let (id, files) = crashed_session(&mut rig);
    let preview = recover::preview(&rig.roots, &id, Want::Resume).unwrap();
    assert_eq!(preview.kind, Some(PendingKind::Run));
    assert_eq!(preview.effective, Want::Resume);
    assert_eq!(preview.ops, [OpId(1), OpId(2), OpId(3)]);
    assert_eq!((preview.done, preview.total), (0, 3));
    assert!(preview.plan.is_some());
    assert_eq!(preview.mark, rig.journal(&id).state.mark());

    // The journal moved on after the preview: the run is not started.
    let stale = recover::preview(&rig.roots, &id, Want::Resume).unwrap();
    recover::rollback(&id, rig.recover_env()).unwrap();
    let err = recover::resume_expecting(&id, rig.recover_env(), &stale.mark).unwrap_err();
    assert!(matches!(err, recover::RecoverError::NotAsShown), "{err}");
    assert!(
        files.iter().all(|f| exists(f)),
        "the rollback put them back"
    );

    let (id, files) = {
        let files = [1, 2, 3].map(|n| rig.s.file(&format!(r"again\f{n}.txt"), b"data"));
        let request = preselected(
            files
                .iter()
                .enumerate()
                .map(|(n, file)| quarantine(&format!("c-{}", n + 1), file))
                .collect(),
            Vec::new(),
        );
        let (id, _) = crash_after_the_first_intent(&mut rig, request);
        (id, files)
    };
    let preview = recover::preview(&rig.roots, &id, Want::Resume).unwrap();
    let out = recover::resume_expecting(&id, rig.recover_env(), &preview.mark).unwrap();
    assert_eq!(out.state, Some(SessionState::Committed));
    assert!(files.iter().all(|f| !exists(f)));
    // Nothing is left to recover.
    let err = recover::preview(&rig.roots, &id, Want::Resume).unwrap_err();
    assert!(matches!(err, recover::RecoverError::Refused(_)), "{err}");
}

#[test]
fn a_rollback_preview_lists_the_ops_that_stand_changed_and_the_run_puts_them_back() {
    use crate::recover::{self, Want};
    let mut rig = Rig::new("m3undo-rollback");
    let (id, files) = crashed_session(&mut rig);
    let preview = recover::preview(&rig.roots, &id, Want::Rollback).unwrap();
    assert_eq!(preview.effective, Want::Rollback);
    assert_eq!(preview.ops, [OpId(1)], "only the op with an intent");
    let out = recover::rollback_expecting(&id, rig.recover_env(), &preview.mark).unwrap();
    assert_eq!(out.state, Some(SessionState::Undone));
    let undone: Vec<OpId> = out.undone.iter().map(|item| item.op).collect();
    assert_eq!(undone, preview.ops);
    assert!(files.iter().all(|f| exists(f)));
}

#[test]
fn an_interrupted_undo_is_previewed_as_a_put_back_of_the_ops_it_had_not_reached() {
    use crate::recover::{self, PendingKind, Want};
    let mut rig = Rig::new("m3undo-undo-open");
    let (id, [a, b, other, _app]) = directory_session(&mut rig);
    let read = rig.journal(&id);
    {
        let session = rig.session(&id);
        let mut journal = JournalWriter::open_append(&session).unwrap();
        journal
            .undo_plan(
                crate::storage::now(),
                vec![op_of(&read, "c-other"), op_of(&read, "c-b")],
            )
            .unwrap();
    }
    for want in [Want::Resume, Want::Rollback] {
        let preview = recover::preview(&rig.roots, &id, want).unwrap();
        assert_eq!(preview.kind, Some(PendingKind::Undo));
        assert_eq!(
            preview.effective,
            Want::Rollback,
            "an undo is put-back work"
        );
        assert_eq!(preview.ops, [op_of(&read, "c-other"), op_of(&read, "c-b")]);
    }
    let preview = recover::preview(&rig.roots, &id, Want::Resume).unwrap();
    let out = recover::resume_expecting(&id, rig.recover_env(), &preview.mark).unwrap();
    let undone: Vec<OpId> = out.undone.iter().map(|item| item.op).collect();
    assert_eq!(undone, preview.ops);
    assert!(exists(&other) && !exists(&a));
    //  lies in a directory this undo never put back: a conflict, nothing is put below it.
    assert!(!exists(&b));
    assert!(matches!(
        out.undone[1].result,
        purge_model::exec::session::UndoResult::Conflict { .. }
    ));
}

#[test]
fn a_retry_preview_names_the_held_items_and_waits_for_recovery_first() {
    use crate::recover::{self, Want};
    let mut rig = Rig::new("m3undo-retry");
    let busy = rig.s.file(r"app\busy.dll", b"in use");
    let other = rig.s.file(r"app\other.txt", b"o");
    rig.rm
        .holders
        .borrow_mut()
        .push(holder(4242, "Vendor Tray"));
    let request = preselected(
        vec![quarantine("c-busy", &busy), quarantine("c-other", &other)],
        Vec::new(),
    );
    let (id, _) = crash_after_the_first_intent(&mut rig, request);

    // The run did not end: a retry has to wait.
    let err = recover::preview(&rig.roots, &id, Want::RetryHeld).unwrap_err();
    assert!(
        matches!(err, recover::RecoverError::NeedsRecovery(_)),
        "{err}"
    );

    let lock = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(ext(&busy))
        .unwrap();
    recover::resume(&id, rig.recover_env()).unwrap();
    let read = rig.journal(&id);
    assert_eq!(read.state.held_retry().count(), 1);
    let preview = recover::preview(&rig.roots, &id, Want::RetryHeld).unwrap();
    assert_eq!(preview.kind, None);
    assert_eq!(preview.effective, Want::RetryHeld);
    assert_eq!(preview.ops, [op_of(&read, "c-busy")]);
    assert!(preview.plan.is_some());

    drop(lock);
    let out = recover::retry_held_expecting(&id, rig.recover_env(), &preview.mark).unwrap();
    assert_eq!(out.retried.len(), 1);
    assert!(!exists(&busy));
    let err = recover::retry_held_expecting(&id, rig.recover_env(), &preview.mark).unwrap_err();
    assert!(matches!(err, recover::RecoverError::NotAsShown), "{err}");
    let none = recover::preview(&rig.roots, &id, Want::RetryHeld).unwrap();
    assert!(none.ops.is_empty());
}

#[test]
fn an_undo_never_overwrites_what_stands_in_an_items_place_and_says_so() {
    let mut rig = Rig::new("m3undo-conflict");
    let (id, [_a, _b, other, _app]) = directory_session(&mut rig);
    let read = rig.journal(&id);
    // Something new stands where the quarantined file was.
    std::fs::write(ext(&other), b"new data").unwrap();
    let preview = crate::undo::preview(&rig.roots, &id, None).unwrap();
    assert!(preview.put_back.contains(&op_of(&read, "c-other")));
    let done =
        crate::undo::undo_expecting(&preview.request, undo_env(&mut rig), &preview.expect).unwrap();
    let result = done
        .report
        .items
        .iter()
        .find(|item| item.op == op_of(&read, "c-other"))
        .unwrap();
    assert!(
        matches!(
            result.result,
            purge_model::exec::session::UndoResult::Conflict {
                conflict: UndoConflict::DestinationExists,
                ..
            }
        ),
        "{result:?}"
    );
    assert_eq!(std::fs::read(ext(&other)).unwrap(), b"new data");
    assert_eq!(done.report.counts.conflicts, 1);
}
