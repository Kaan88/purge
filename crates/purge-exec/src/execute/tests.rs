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
use std::time::Duration;

use purge_guard::canon::{GuardEnv, ProfileEnv};
use purge_model::exec::journal::{AbortReason, Record};
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
use crate::journal::{JournalRead, Phase};
use crate::locked::MemoryPendingRenames;
use crate::plan_in::tests::{candidate, cid, key, path, request, safe, scan_doc, value};
use crate::plan_in::{NotSelectable, Selection};
use crate::prepare::RestorePointSetting;
use crate::storage::{JOURNAL_FILE, REG_BACKUP_DIR};

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

    // The record order: header, eight validated, then intent/done pairs, one group, commit.
    let names: Vec<&str> = read.records.iter().map(Record::name).collect();
    let mut expected = vec!["header"];
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

#[test]
fn targets_without_an_executor_are_journalled_as_skipped() {
    let mut rig = Rig::new("unsupported");
    let file = rig.s.file(r"app\a.txt", b"a");
    let request = preselected(
        vec![
            safe(
                "c-task",
                Target::Task {
                    path: r"\PurgeTest\NoSuchTask".into(),
                },
                Action::Quarantine,
            ),
            safe(
                "c-svc",
                Target::Service {
                    name: "PurgeTestNoSuchService".into(),
                },
                Action::Quarantine,
            ),
            safe(
                "c-fw",
                Target::FirewallRule {
                    id: "{11111111-2222-3333-4444-555555555555}".into(),
                },
                Action::Quarantine,
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
            gate_blocked(outcome.as_ref().unwrap()),
            Some(&Blocker::CannotBackUp)
        );
    }
    assert_eq!(got[3], Some(ItemOutcome::Done));
    assert_eq!(read.state.counts().skipped, 3);
    assert!(read.records.iter().filter(|r| r.name() == "intent").count() == 1);

    // The model's item report needs an executor op, which these have none of: they are named in the
    // warnings, and the items and counts of the report still agree with each other.
    assert_eq!(report.items.len(), 1);
    assert_eq!(report.items[0].item, cid("c-file"));
    assert_eq!(report.counts, report.tally());
    for id in ["c-task", "c-svc", "c-fw"] {
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains(id) && w.contains("not supported in this version")),
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

    // Op 2's backup file name is taken when its turn comes; the store never replaces a file.
    let session_path = RefCell::new(PathBuf::new());
    let aborting = Cell::new(None);
    let progress = |event: &Progress<'_>| match event {
        Progress::SessionCreated { path, .. } => *session_path.borrow_mut() = path.to_path_buf(),
        Progress::ItemStarting { op: OpId(2), .. } => {
            let taken = session_path
                .borrow()
                .join(REG_BACKUP_DIR)
                .join("000002.regbackup.json");
            std::fs::write(taken, b"not a backup").unwrap();
        }
        Progress::Aborting { reason } => aborting.set(Some(*reason)),
        _ => {}
    };
    let output = rig.try_run(request, Some(&progress)).unwrap();

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

    // The report says aborted and says the journal could not record it.
    assert_eq!(output.report.state, SessionState::Aborted);
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
    let mut run = Run::resume(rig.env(None), session, &copy, settings.clone()).unwrap();
    assert_eq!(run.plan().items().len(), 3);
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
        Run::resume(rig.env(None), session, &copy, settings.clone()),
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
    let settings = request.settings.clone();
    let mut run = Run::start(request.clone(), rig.env(None)).unwrap();
    run.validate().unwrap();
    let id = run.session().id().clone();
    drop(run);

    let mut other = request.scan.clone();
    other.items.swap(0, 1);
    crate::plan_in::tests::rehash(&mut other);
    let session = rig.session(&id);
    assert!(matches!(
        Run::resume(rig.env(None), session, &other, settings.clone()),
        Err(ExecError::Plan(PlanRefusal::JournalMismatch(_)))
    ));
    let mut tampered = request.scan.clone();
    tampered.items[1].target = path(&a);
    let session = rig.session(&id);
    assert!(matches!(
        Run::resume(rig.env(None), session, &tampered, settings),
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

    #[test]
    fn a_crash_at_the_header_leaves_the_scan_copy_and_nothing_else() {
        let mut rig = crashed("crash-header", fault::JOURNAL_HEADER);
        let request = crash_request(&rig.s);
        let [id] = rig.sessions().try_into().unwrap();
        let read = rig.journal(&id);
        assert_eq!(read.records.len(), 1);
        assert_eq!(read.state.phase(), Phase::Validating);
        // The scan copy is durable before the journal exists.
        assert_eq!(read_scan_copy(&rig.session(&id)).unwrap(), request.scan);
        assert_eq!(at_source(&rig), [true; 3]);
        // Nothing was validated, so there is nothing to resume.
        let session = rig.session(&id);
        assert!(matches!(
            Run::resume(rig.env(None), session, &request.scan, request.settings),
            Err(ExecError::NotResumable(_))
        ));
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
        let mut run = Run::resume(rig.env(None), session, &request.scan, request.settings).unwrap();
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
        let run = Run::resume(rig.env(None), session, &request.scan, request.settings).unwrap();
        let output = run.finish();
        assert_eq!(output.report.state, SessionState::Committed);
        assert_eq!(output.report.counts.done, 3);
        assert_eq!(rig.journal(&id).state.phase(), Phase::Committed);
    }
}
