//! M1B-X-INTEG: services, scheduled tasks and firewall rules through the executor's run, journal,
//! recovery and undo.
//!
//! Every test runs over in-memory backends (`act_service::fake::FakeServices`,
//! `act_firewall::fake::FakeFirewall` and the scripted task fake below) behind [`Spy`], which logs each
//! call and can "crash" the run by panicking before or after a chosen call (the run is caught with
//! `catch_unwind`: the journal is left exactly as a process that died there leaves it, since nothing
//! is written on unwinding). The store is relaxed, below the temp directory. No service, task or
//! firewall rule of this machine is read, created, changed or deleted.
//!
//! The process-kill crash matrix over the real fault points stays the rig's (gate G6): `tests/crash.rs`
//! marks `objdelete.after`, `svcrestore.mid` and `fwrestore.mid` NotDriven. `crash_matrix_unit` here
//! drives the same places in process with the mock backends.

#![cfg(feature = "test-support")]

mod common;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};

use common::{
    FakeRestore, Rig, filetime_now, live_env, outcomes, package, quarantine, request, safe,
};
use purge_exec::act_firewall::fake::FakeFirewall;
use purge_exec::act_firewall::{self, FirewallBackend, FwPrepared, FwValidated};
use purge_exec::act_service::fake::{FakeService, FakeServices, dword, sz};
use purge_exec::act_service::{
    self, DeleteResult, ObjErr as SvcErr, ScmDefinition, ServiceBackend, ServiceLive, WriteBack,
    tree_difference,
};
use purge_exec::act_task::{self, ObjErr as TaskErr, Register, TaskBackend, TaskLive, TaskXml};
use purge_exec::durable;
use purge_exec::execute::{ExecError, ExecOutput, ObjectBackends, execute};
use purge_exec::gate::GateCtx;
use purge_exec::journal::{JournalRead, JournalWriter, sha256_bytes};
use purge_exec::objdef::TaskDef;
use purge_exec::plan_in::ExecRequest;
use purge_exec::recover::{self, RecoverOutput};
use purge_exec::regbackup::CaptureError;
use purge_exec::storage::BackupKind;
use purge_exec::undo::{self, UndoOutput, UndoRequest, UndoSelection};
use purge_guard::deny::DenyList;
use purge_model::exec::journal::{
    GateExemptions, Header, ItemFacts, JournalSchema, Record, UndoConflict, Validated,
};
use purge_model::exec::op::{ExecOp, FailCode, ItemOutcome, OpId, SkipReason};
use purge_model::exec::regbackup::RegBackup;
use purge_model::exec::session::{SessionId, SessionState, UndoResult};
use purge_model::object::fold;
use purge_model::{
    Action, Candidate, FirewallIdentity, ScanMode, Target, TaskAction, TaskIdentity,
};
use purge_win::reg::{REG_DWORD, REG_EXPAND_SZ, REG_SZ};
use purge_win::scm::{Config2Item, ScmCreate};

// ---------------------------------------------------------------------------------------------------
// The objects
// ---------------------------------------------------------------------------------------------------

const ROOT: &str = r"C:\Program Files\Vendor";
const SVC: &str = "VendorUpdate";
const IMAGE: &str = r#""C:\Program Files\Vendor\update.exe" -service"#;
const TASK: &str = r"\Vendor\Update Check";
const EXE: &str = r"C:\Program Files\Vendor\update.exe";
const SDDL: &str =
    "O:BAG:S-1-5-21-1-2-3-513D:(A;ID;0x1f019f;;;BA)(A;ID;0x1f019f;;;SY)(A;ID;FA;;;BA)";
const FW: &str = "{0B7AC2E8-3A6B-4C1D-9E58-7F7B2B1E7A10}";
const RULE: &str = r"v2.33|Action=Allow|Active=TRUE|Dir=In|Protocol=6|App=C:\Program Files\Vendor\app.exe|Name=Vendor App|";

/// A plain own-process service with a description, a `Parameters` subtree and a value the SCM never
/// writes.
fn vendor_service() -> FakeService {
    let mut s = FakeService::new(SVC, IMAGE, None);
    s.set_value("Description", REG_SZ, sz("Keeps Vendor up to date"));
    s.set_value("VendorTag", REG_SZ, sz("stable"));
    s.scm.config2.description = Some("Keeps Vendor up to date".into());
    let params = s.add_key(0, "Parameters", vec![("Channel", REG_SZ, sz("beta"))]);
    s.add_key(params, "Sub", vec![("Depth", REG_DWORD, dword(2))]);
    s
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FakeTask {
    live: TaskLive,
    xml: TaskXml,
}

fn vendor_task() -> FakeTask {
    let actions = vec![TaskAction::Exec {
        path: EXE.into(),
        arguments: Some("/check".into()),
        working_dir: None,
    }];
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n<Task version=\"1.2\" \
         xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n  <Triggers>\
         <LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>\r\n  <Principals>\
         <Principal id=\"Author\"><LogonType>InteractiveToken</LogonType></Principal></Principals>\
         \r\n  <Settings><Enabled>true</Enabled></Settings>\r\n  <Actions Context=\"Author\"><Exec>\
         <Command>{EXE}</Command><Arguments>/check</Arguments></Exec></Actions>\r\n</Task>"
    );
    FakeTask {
        live: TaskLive {
            identity: TaskIdentity {
                path: TASK.into(),
                actions,
            },
            running: false,
            stored_password: false,
            enabled: true,
            logon_type: 3,
        },
        xml: TaskXml {
            xml,
            sddl: SDDL.into(),
        },
    }
}

/// A scripted Task Scheduler.
#[derive(Default)]
struct FakeTasks {
    tasks: RefCell<BTreeMap<String, FakeTask>>,
}

impl FakeTasks {
    fn with(tasks: Vec<FakeTask>) -> FakeTasks {
        let fake = FakeTasks::default();
        for t in tasks {
            fake.put(t);
        }
        fake
    }

    fn put(&self, t: FakeTask) {
        self.tasks
            .borrow_mut()
            .insert(fold(&t.live.identity.path), t);
    }

    fn get(&self, path: &str) -> Option<FakeTask> {
        self.tasks.borrow().get(&fold(path)).cloned()
    }
}

impl TaskBackend for FakeTasks {
    fn read(&self, path: &str) -> Result<Option<TaskLive>, TaskErr> {
        Ok(self.get(path).map(|t| t.live))
    }

    fn definition(&self, path: &str) -> Result<Option<TaskXml>, TaskErr> {
        Ok(self.get(path).map(|t| t.xml))
    }

    fn delete(&self, path: &str) -> Result<(), TaskErr> {
        self.tasks.borrow_mut().remove(&fold(path));
        Ok(())
    }

    fn register(&self, def: &TaskDef, mode: Register) -> Result<(), TaskErr> {
        assert_eq!(mode, Register::CreateOnly);
        if self.get(&def.path).is_some() {
            return Err(TaskErr::AlreadyExists);
        }
        self.put(FakeTask {
            live: TaskLive {
                identity: TaskIdentity {
                    path: def.path.clone(),
                    actions: def.actions.clone(),
                },
                running: false,
                stored_password: def.stored_password,
                enabled: def.enabled,
                logon_type: def.logon_type,
            },
            xml: TaskXml {
                xml: def.xml.clone(),
                sddl: def.sddl.clone(),
            },
        });
        Ok(())
    }

    fn flush(&self, _path: &str) -> Result<(), TaskErr> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------------
// The spy: a call log, the `done` records written at each flush, and an injected crash
// ---------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum When {
    Before,
    After,
}

/// A crash: a panic before or after the `nth` call (from 1, counted since it was armed) named `call`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Crash {
    call: &'static str,
    nth: u32,
    when: When,
}

struct Objects {
    services: FakeServices,
    tasks: FakeTasks,
    firewall: FakeFirewall,
    /// The store's `sessions` directory, to count `done` records at each flush.
    sessions: PathBuf,
    crash: Cell<Option<Crash>>,
    counts: RefCell<BTreeMap<&'static str, u32>>,
    log: RefCell<Vec<String>>,
    /// When set, the object calls fail as if the backend refused them.
    deny_deletes: Cell<bool>,
}

/// `done` records in every journal below `dir`.
fn done_records(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .map(|e| e.path().join("journal.jsonl"))
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .map(|text| text.matches(r#""rec":"done""#).count())
        .sum()
}

impl Objects {
    fn arm(&self, crash: Option<Crash>) {
        self.crash.set(crash);
        self.counts.borrow_mut().clear();
    }

    fn take_log(&self) -> Vec<String> {
        std::mem::take(&mut *self.log.borrow_mut())
    }

    fn call<T>(&self, name: &'static str, f: impl FnOnce() -> T) -> T {
        let n = {
            let mut counts = self.counts.borrow_mut();
            let n = counts.entry(name).or_insert(0);
            *n += 1;
            *n
        };
        if name.ends_with(".flush") {
            let done = done_records(&self.sessions);
            self.log.borrow_mut().push(format!("{name} done={done}"));
        } else {
            self.log.borrow_mut().push(name.to_owned());
        }
        let due = |when| {
            self.crash
                .get()
                .is_some_and(|c| c.call == name && c.nth == n && c.when == when)
        };
        if due(When::Before) {
            self.crash.set(None);
            panic!("injected crash before {name} #{n}");
        }
        let out = f();
        if due(When::After) {
            self.crash.set(None);
            panic!("injected crash after {name} #{n}");
        }
        out
    }

    fn backends(&self) -> ObjectBackends<'_> {
        ObjectBackends {
            services: self,
            tasks: self,
            firewall: self,
        }
    }
}

fn refused() -> SvcErr {
    SvcErr::new(act_service::ObjErrKind::Other, Some(5), "access denied")
}

impl ServiceBackend for Objects {
    fn read(&self, name: &str) -> Result<Option<ServiceLive>, SvcErr> {
        self.call("svc.read", || ServiceBackend::read(&self.services, name))
    }
    fn definition(&self, name: &str) -> Result<ScmDefinition, SvcErr> {
        self.call("svc.definition", || self.services.definition(name))
    }
    fn capture_key(&self, name: &str, limit: usize) -> Result<Option<RegBackup>, CaptureError> {
        self.call("svc.capture", || self.services.capture_key(name, limit))
    }
    fn delete(&self, name: &str) -> Result<DeleteResult, SvcErr> {
        if self.deny_deletes.get() {
            return Err(refused());
        }
        self.call("svc.delete", || {
            ServiceBackend::delete(&self.services, name)
        })
    }
    fn create(&self, args: &ScmCreate) -> Result<(), SvcErr> {
        self.call("svc.create", || self.services.create(args))
    }
    fn apply_config2(&self, name: &str, item: &Config2Item) -> Result<(), SvcErr> {
        self.call("svc.config2", || self.services.apply_config2(name, item))
    }
    fn apply_security(&self, name: &str, sddl: &str) -> Result<(), SvcErr> {
        self.call("svc.security", || self.services.apply_security(name, sddl))
    }
    fn write_back(&self, name: &str, writes: &[WriteBack]) -> Result<(), SvcErr> {
        self.call("svc.write_back", || self.services.write_back(name, writes))
    }
    fn flush_system(&self) -> Result<(), SvcErr> {
        self.call("svc.flush", || ServiceBackend::flush_system(&self.services))
    }
}

impl TaskBackend for Objects {
    fn read(&self, path: &str) -> Result<Option<TaskLive>, TaskErr> {
        self.call("task.read", || TaskBackend::read(&self.tasks, path))
    }
    fn definition(&self, path: &str) -> Result<Option<TaskXml>, TaskErr> {
        self.call("task.definition", || {
            TaskBackend::definition(&self.tasks, path)
        })
    }
    fn delete(&self, path: &str) -> Result<(), TaskErr> {
        if self.deny_deletes.get() {
            return Err(TaskErr::Api {
                code: Some(0x8007_0005),
                detail: "access denied".into(),
            });
        }
        self.call("task.delete", || TaskBackend::delete(&self.tasks, path))
    }
    fn register(&self, def: &TaskDef, mode: Register) -> Result<(), TaskErr> {
        self.call("task.register", || self.tasks.register(def, mode))
    }
    fn flush(&self, path: &str) -> Result<(), TaskErr> {
        self.call("task.flush", || self.tasks.flush(path))
    }
}

impl FirewallBackend for Objects {
    fn read(&self, id: &str) -> Result<Option<FirewallIdentity>, SvcErr> {
        self.call("fw.read", || FirewallBackend::read(&self.firewall, id))
    }
    fn delete_by_instance_id(&self, id: &str) -> Result<u32, SvcErr> {
        if self.deny_deletes.get() {
            return Err(refused());
        }
        self.call("fw.delete", || self.firewall.delete_by_instance_id(id))
    }
    fn create_with_instance_id(&self, id: &str, fields: &[(String, String)]) -> Result<(), SvcErr> {
        self.call("fw.create", || {
            self.firewall.create_with_instance_id(id, fields)
        })
    }
    fn flush_system(&self) -> Result<(), SvcErr> {
        self.call("fw.flush", || FirewallBackend::flush_system(&self.firewall))
    }
}

// ---------------------------------------------------------------------------------------------------
// The world: a rig, the objects, and the run, recovery and undo with them
// ---------------------------------------------------------------------------------------------------

struct World {
    obj: Objects,
    rig: Rig,
}

fn world(tag: &str) -> World {
    let rig = Rig::new(tag);
    let sessions = rig.roots.sessions_path().to_path_buf();
    World {
        obj: Objects {
            services: FakeServices::with([vendor_service()]),
            tasks: FakeTasks::with(vec![vendor_task()]),
            firewall: FakeFirewall::with([(FW, RULE)]),
            sessions,
            crash: Cell::new(None),
            counts: RefCell::new(BTreeMap::new()),
            log: RefCell::new(Vec::new()),
            deny_deletes: Cell::new(false),
        },
        rig,
    }
}

fn svc_cand() -> Candidate {
    let mut c = safe(
        "c-svc",
        Target::Service { name: SVC.into() },
        Action::DeleteKey,
    );
    c.object_fp = Some(vendor_service().identity().fp());
    c
}

fn task_cand() -> Candidate {
    let mut c = safe(
        "c-task",
        Target::Task { path: TASK.into() },
        Action::DeleteKey,
    );
    c.object_fp = Some(vendor_task().live.identity.fp());
    c
}

fn fw_cand() -> Candidate {
    let mut c = safe(
        "c-fw",
        Target::FirewallRule { id: FW.into() },
        Action::DeleteKey,
    );
    c.object_fp = Some(
        FirewallIdentity {
            id: FW.into(),
            rule: RULE.into(),
        }
        .fp(),
    );
    c
}

/// A request for `items` (in plan order) with the app's program roots.
fn typed_request(mut items: Vec<Candidate>) -> ExecRequest {
    purge_plan::order::sort(&mut items);
    let mut req = request(items, Vec::new());
    req.settings.program_roots = vec![ROOT.to_owned()];
    req
}

impl World {
    fn try_run(&mut self, req: ExecRequest) -> Result<ExecOutput, String> {
        let mut env = self.rig.exec_env();
        env.objects = Some(self.obj.backends());
        execute(req, env, FakeRestore).map_err(|e| e.to_string())
    }

    fn run(&mut self, req: ExecRequest) -> ExecOutput {
        self.try_run(req).unwrap()
    }

    /// The run with `crash` armed; panics unless it crashed. Returns the session it left open.
    fn crash_run(&mut self, req: ExecRequest, crash: Crash) -> SessionId {
        self.obj.arm(Some(crash));
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let _ = self.try_run(req);
        }))
        .is_err();
        assert!(crashed, "{crash:?} was not reached");
        self.obj.arm(None);
        let sessions = self.rig.sessions();
        assert_eq!(sessions.len(), 1);
        sessions[0].clone()
    }

    fn resume(&mut self, id: &SessionId) -> RecoverOutput {
        let mut env = self.rig.recover_env();
        env.objects = Some(self.obj.backends());
        recover::resume(id, env).unwrap()
    }

    fn undo_all(&mut self, id: &SessionId) -> UndoOutput {
        let mut env = self.rig.undo_env();
        env.objects = Some(self.obj.backends());
        let request = UndoRequest {
            session: id.clone(),
            selection: UndoSelection::All,
            plan_hash: None,
        };
        undo::undo(&request, env).unwrap()
    }

    /// The undo with `crash` armed; panics unless it crashed.
    fn crash_undo(&mut self, id: &SessionId, crash: Crash) {
        self.obj.arm(Some(crash));
        let crashed = catch_unwind(AssertUnwindSafe(|| {
            let mut env = self.rig.undo_env();
            env.objects = Some(self.obj.backends());
            let request = UndoRequest {
                session: id.clone(),
                selection: UndoSelection::All,
                plan_hash: None,
            };
            let _ = undo::undo(&request, env);
        }))
        .is_err();
        assert!(crashed, "{crash:?} was not reached");
        self.obj.arm(None);
    }

    fn journal(&self, id: &SessionId) -> JournalRead {
        self.rig.journal(id)
    }

    /// Whether each object is as before the run.
    fn pre_state(&self) -> [bool; 3] {
        let svc = self.obj.services.service(SVC).is_some_and(|live| {
            live.identity().fp() == vendor_service().identity().fp()
                && tree_difference(&vendor_service().tree, &live.tree).is_none()
        });
        let task = self.obj.tasks.get(TASK).is_some_and(|t| t == vendor_task());
        let fw = self.obj.firewall.rule(FW).as_deref() == Some(RULE);
        [svc, task, fw]
    }

    fn present(&self) -> [bool; 3] {
        [
            self.obj.services.service(SVC).is_some(),
            self.obj.tasks.get(TASK).is_some(),
            self.obj.firewall.rule(FW).is_some(),
        ]
    }
}

fn changed() -> ItemOutcome {
    ItemOutcome::Skipped {
        reason: SkipReason::ChangedSinceScan,
    }
}

fn names(read: &JournalRead, op: OpId) -> Vec<&'static str> {
    read.records
        .iter()
        .filter(|r| r.op() == Some(op))
        .map(Record::name)
        .collect()
}

fn intent_ops(read: &JournalRead) -> Vec<ExecOp> {
    read.records
        .iter()
        .filter_map(|r| match r {
            Record::Intent(i) => Some(i.exec_op.clone()),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------------------------------

/// Each typed target is routed to its object op and deleted through its backend.
#[test]
fn route_typed_ops() {
    let mut w = world("route");
    let out = w.run(typed_request(vec![svc_cand(), task_cand(), fw_cand()]));
    assert_eq!(out.report.state, SessionState::Committed);
    let read = w.journal(&out.session);
    assert_eq!(outcomes(&read), vec![Some(ItemOutcome::Done); 3]);
    let ops: Vec<ExecOp> = out
        .report
        .items
        .iter()
        .map(|i| i.exec_op.clone().unwrap())
        .collect();
    assert_eq!(
        ops,
        [
            ExecOp::DeleteTask { path: TASK.into() },
            ExecOp::DeleteFirewallRule { id: FW.into() },
            ExecOp::DeleteService { name: SVC.into() },
        ]
    );
    assert_eq!(intent_ops(&read), ops);
    assert_eq!(w.present(), [false; 3]);
    // The header holds the program roots.
    assert_eq!(read.state.header().program_roots, [ROOT]);
}

/// A typed item without its scan-time digest is skipped before anything is backed up: no backend
/// call, no definition file, no intent.
#[test]
fn typed_without_object_fp_skipped_before_backup() {
    let mut w = world("no-fp");
    let mut items = vec![svc_cand(), task_cand(), fw_cand()];
    for c in &mut items {
        c.object_fp = None;
    }
    let out = w.run(typed_request(items));
    let read = w.journal(&out.session);
    assert_eq!(outcomes(&read), vec![Some(changed()); 3]);
    assert!(w.obj.take_log().is_empty());
    assert!(intent_ops(&read).is_empty());
    for op in 1..=3 {
        let def = w
            .rig
            .session(&out.session)
            .path()
            .join(purge_exec::storage::backup_rel(
                BackupKind::Definition,
                OpId(op),
            ));
        assert!(!def.exists(), "{}", def.display());
        assert_eq!(names(&read, OpId(op)), ["validated", "done"]);
    }
    assert!(
        out.report
            .warnings
            .iter()
            .filter(|w| w.contains("no object fingerprint"))
            .count()
            >= 3,
        "{:#?}",
        out.report.warnings
    );
    assert_eq!(w.present(), [true; 3]);
}

/// Per kind: `validated`, then the definition file, then `intent` (naming that file), then `done`.
#[test]
fn sequence_records_validated_backup_intent_done_in_order() {
    for cand in [svc_cand(), task_cand(), fw_cand()] {
        let mut w = world(&format!("seq-{}", cand.id.0));
        let out = w.run(typed_request(vec![cand.clone()]));
        let read = w.journal(&out.session);
        assert_eq!(
            names(&read, OpId(1)),
            ["validated", "intent", "done"],
            "{}",
            cand.id.0
        );
        let intent = read.state.op(OpId(1)).unwrap().intent.clone().unwrap();
        let backups: Vec<_> = intent.backups().cloned().collect();
        assert!(
            !backups.is_empty(),
            "the intent names its backup: {intent:?}"
        );
        for backup in backups {
            let file = w.rig.session(&out.session).path().join(&backup.path);
            let bytes = std::fs::read(&file).unwrap();
            assert_eq!(sha256_bytes(&bytes), backup.sha256, "{}", file.display());
        }
        assert!(matches!(intent.pre, ItemFacts::Object { .. }), "{intent:?}");
        assert_eq!(outcomes(&read), [Some(ItemOutcome::Done)]);
    }
}

/// Per kind, from the call log: the delete, then the flush of the object's store, with no `done`
/// record written yet.
#[test]
fn flush_before_done_per_kind() {
    for (cand, delete, flush) in [
        (svc_cand(), "svc.delete", "svc.flush"),
        (task_cand(), "task.delete", "task.flush"),
        (fw_cand(), "fw.delete", "fw.flush"),
    ] {
        let mut w = world(&format!("flush-{}", cand.id.0));
        let out = w.run(typed_request(vec![cand]));
        let log = w.obj.take_log();
        let at_delete = log.iter().position(|l| l == delete).unwrap();
        let flushes: Vec<(usize, &String)> = log
            .iter()
            .enumerate()
            .filter(|(_, l)| l.starts_with(flush))
            .collect();
        assert!(!flushes.is_empty(), "{log:?}");
        assert!(flushes.iter().all(|(i, _)| *i > at_delete), "{log:?}");
        assert_eq!(flushes[0].1, &format!("{flush} done=0"), "{log:?}");
        let read = w.journal(&out.session);
        assert_eq!(outcomes(&read), [Some(ItemOutcome::Done)]);
    }
}

thread_local! {
    static HIVES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn observe_hive(label: &str) {
    HIVES.with(|h| h.borrow_mut().push(label.to_owned()));
}

fn take_hives() -> Vec<String> {
    HIVES.with(|h| std::mem::take(&mut *h.borrow_mut()))
}

/// The journal's group flush covers SYSTEM when a service (or firewall rule) ran; a task alone
/// flushes SOFTWARE and not SYSTEM.
#[test]
fn group_end_flushes_system_when_service_ran() {
    // The observer is process-wide; it records on the flushing thread only.
    durable::set_flush_observer(Some(observe_hive));
    for (cand, system) in [(svc_cand(), true), (fw_cand(), true), (task_cand(), false)] {
        let id = cand.id.0.clone();
        let mut w = world(&format!("hive-{id}"));
        take_hives();
        let out = w.run(typed_request(vec![cand]));
        let hives = take_hives();
        assert_eq!(out.report.state, SessionState::Committed);
        let has = |label: &str| hives.iter().any(|h| h.eq_ignore_ascii_case(label));
        assert_eq!(has(r"HKLM\SYSTEM"), system, "{id}: {hives:?}");
        if !system {
            assert!(has(r"HKLM\SOFTWARE"), "{id}: {hives:?}");
        }
    }
}

/// Plan order, and so the run's: Task, FirewallRule, FileSystem, Service, Package.
#[test]
fn stage_order_with_mixed_plan() {
    let mut w = world("stage");
    w.rig.packages.install();
    let file = w.rig.s.file(r"app\a.txt", b"a");
    let mut req = typed_request(vec![
        package("c-pkg"),
        svc_cand(),
        quarantine("c-file", &file),
        fw_cand(),
        task_cand(),
    ]);
    req.allow_irreversible = true;
    let out = w.run(req);
    let read = w.journal(&out.session);
    let kinds: Vec<&str> = intent_ops(&read)
        .iter()
        .map(|op| match op {
            ExecOp::DeleteTask { .. } => "task",
            ExecOp::DeleteFirewallRule { .. } => "fw",
            ExecOp::QuarantineMove { .. } => "file",
            ExecOp::DeleteService { .. } => "svc",
            ExecOp::RemovePackage { .. } => "pkg",
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(kinds, ["task", "fw", "file", "svc", "pkg"]);
    assert!(
        outcomes(&read)
            .iter()
            .all(|o| o.as_ref().is_some_and(ItemOutcome::is_success)),
        "{:?}",
        outcomes(&read)
    );
}

/// Without object backends (an unelevated process) a run with a typed item is refused before its
/// session exists; a run without one is not affected.
#[test]
fn unelevated_run_with_typed_item_fails_before_header() {
    let mut w = world("unelevated");
    let file = w.rig.s.file(r"app\a.txt", b"a");
    let req = typed_request(vec![svc_cand(), quarantine("c-file", &file)]);
    let env = w.rig.exec_env();
    assert!(env.objects.is_none());
    match execute(req, env, FakeRestore) {
        Err(ExecError::NeedsElevation(1)) => {}
        other => panic!("{:?}", other.map(|o| o.report.state)),
    }
    assert!(w.rig.sessions().is_empty());
    assert!(w.obj.take_log().is_empty());
    let out = w.rig.run(typed_request(vec![quarantine("c-file", &file)]));
    assert_eq!(out.report.state, SessionState::Committed);
}

/// A typed delete the backend refuses fails the item and nothing else: the session commits.
#[test]
fn typed_failure_fails_the_item_only() {
    let mut w = world("refused");
    w.obj.deny_deletes.set(true);
    let file = w.rig.s.file(r"app\a.txt", b"a");
    let out = w.run(typed_request(vec![
        svc_cand(),
        task_cand(),
        fw_cand(),
        quarantine("c-file", &file),
    ]));
    assert_eq!(out.report.state, SessionState::Committed);
    // Plan order: task, firewall rule, file, service.
    let got = outcomes(&w.journal(&out.session));
    for i in [0, 1, 3] {
        assert!(
            matches!(got[i], Some(ItemOutcome::Failed { .. })),
            "{got:?}"
        );
    }
    assert_eq!(got[2], Some(ItemOutcome::Done));
    assert_eq!(w.present(), [true; 3]);
}

// ---------------------------------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------------------------------

/// A crash after the intent and before the delete: resume runs the act-time gate again; an object
/// that changed after the probe is not deleted.
#[test]
fn recover_typed_not_done_reruns_gate() {
    let mut w = world("rec-gate");
    let id = w.crash_run(
        typed_request(vec![svc_cand()]),
        Crash {
            call: "svc.delete",
            nth: 1,
            when: When::Before,
        },
    );
    assert_eq!(names(&w.journal(&id), OpId(1)), ["validated", "intent"]);
    // After recovery's probe reads it, the service is repointed.
    w.obj.services.after("read", |world| {
        for s in world.services.values_mut() {
            s.set_value(
                "ImagePath",
                REG_EXPAND_SZ,
                sz(r#""C:\Program Files\Vendor\other.exe" -service"#),
            );
        }
    });
    w.obj.take_log();
    let out = w.resume(&id);
    let read = w.journal(&id);
    assert_eq!(outcomes(&read), [Some(changed())], "{out:?}");
    let log = w.obj.take_log();
    assert!(
        log.iter().filter(|l| *l == "svc.read").count() >= 2,
        "{log:?}"
    );
    assert!(!log.iter().any(|l| l == "svc.delete"), "{log:?}");
    assert!(w.present()[0]);
    assert!(read.state.is_finished());

    // Unchanged, the gate passes and the delete completes.
    let mut w = world("rec-gate-pass");
    let id = w.crash_run(
        typed_request(vec![svc_cand()]),
        Crash {
            call: "svc.delete",
            nth: 1,
            when: When::Before,
        },
    );
    w.resume(&id);
    assert_eq!(outcomes(&w.journal(&id)), [Some(ItemOutcome::Done)]);
    assert!(!w.present()[0]);
}

/// A crash after the delete returned and before its flush and `done`: the probe finds the object gone
/// and recovery records it done; the undo then puts it back.
#[test]
fn recover_typed_done_completes() {
    for (cand, delete, k) in [
        (svc_cand(), "svc.delete", 0),
        (task_cand(), "task.delete", 1),
        (fw_cand(), "fw.delete", 2),
    ] {
        let mut w = world(&format!("rec-done-{}", cand.id.0));
        let id = w.crash_run(
            typed_request(vec![cand]),
            Crash {
                call: delete,
                nth: 1,
                when: When::After,
            },
        );
        assert!(!w.present()[k]);
        let out = w.resume(&id);
        let read = w.journal(&id);
        assert_eq!(outcomes(&read), [Some(ItemOutcome::Done)], "{out:?}");
        assert_eq!(out.state, Some(SessionState::Committed), "{out:?}");
        w.undo_all(&id);
        assert!(w.pre_state()[k], "{delete}");
    }
}

/// A probe that cannot tell (the firewall rule at the id is another rule now) stops that item only:
/// it is left as it is, and the run goes on with the next item.
#[test]
fn recover_typed_attention_stops_item_only() {
    let mut w = world("rec-attention");
    let file = w.rig.s.file(r"app\a.txt", b"a");
    let id = w.crash_run(
        typed_request(vec![fw_cand(), quarantine("c-file", &file)]),
        Crash {
            call: "fw.delete",
            nth: 1,
            when: When::Before,
        },
    );
    let other = RULE.replace("Dir=In", "Dir=Out");
    w.obj.firewall.set_rule(FW, &other);
    let out = w.resume(&id);
    let read = w.journal(&id);
    let got = outcomes(&read);
    assert!(
        matches!(
            &got[0],
            Some(ItemOutcome::Failed {
                code: FailCode::VerifyFailed,
                ..
            })
        ),
        "{got:?} {out:?}"
    );
    assert_eq!(got[1], Some(ItemOutcome::Done));
    assert_eq!(w.obj.firewall.rule(FW).as_deref(), Some(other.as_str()));
    assert!(!Path::new(&file).exists());
}

// ---------------------------------------------------------------------------------------------------
// Undo
// ---------------------------------------------------------------------------------------------------

/// The undo dispatches each kind to its module: all three come back as they were, in reverse order.
#[test]
fn undo_dispatch_per_kind() {
    let mut w = world("undo");
    let out = w.run(typed_request(vec![svc_cand(), task_cand(), fw_cand()]));
    assert_eq!(w.present(), [false; 3]);
    w.obj.take_log();
    let undone = w.undo_all(&out.session);
    assert_eq!(undone.report.counts.restored, 3, "{:?}", undone.report);
    assert_eq!(undone.report.state, SessionState::Undone);
    assert_eq!(w.pre_state(), [true; 3]);
    // Reverse journal order: the service (last deleted) first, the task last.
    let log = w.obj.take_log();
    let first = |name: &str| log.iter().position(|l| l == name).unwrap();
    assert!(first("svc.create") < first("fw.create"), "{log:?}");
    assert!(first("fw.create") < first("task.register"), "{log:?}");
    // A second undo has nothing left to do.
    let again = w.undo_all(&out.session);
    assert_eq!(again.report.counts.restored, 0);
}

/// Hostile: a journal whose header names no program roots (written before M1b, or stripped). The
/// undo refuses to create the object again (`ProgramOutsideRoot`) and leaves it deleted.
#[test]
fn undo_without_header_roots_refuses_recreate() {
    let w = world("undo-noroots");
    let roots = &w.rig.roots;
    let session = roots.create_session().unwrap();
    let op = ExecOp::DeleteFirewallRule { id: FW.into() };
    let header = Header {
        schema: JournalSchema,
        session: session.id().clone(),
        created: filetime_now(),
        engine_version: "0.1.0".into(),
        app: "vendor-app".into(),
        plan_hash: sha256_bytes(b"plan"),
        selection_hash: sha256_bytes(b"selection"),
        policy_version: "m1b.1".into(),
        mode: ScanMode::Post,
        items: 1,
        allow_irreversible: false,
        volumes: Vec::new(),
        program_roots: Vec::new(),
    };
    let mut journal = JournalWriter::create(&session, header).unwrap();
    let deny = DenyList::compile(&live_env(roots.data_root().to_str().unwrap()));
    let scope = roots.store_scope(session.id(), &[] as &[&Path]).unwrap();
    let mut ctx = GateCtx::new(deny, std::slice::from_ref(&op), scope).unwrap();
    let cand = fw_cand();
    let fw = &w.obj.firewall;
    let facts = match act_firewall::validate(fw, ctx.deny(), &op, &cand) {
        FwValidated::Validated { facts, .. } => facts,
        FwValidated::Decided(r) => panic!("{r:?}"),
    };
    let record = Validated {
        op: OpId(1),
        item: cand.id.clone(),
        target: op.target(),
        facts,
        exemptions: GateExemptions::default(),
    };
    journal.validated(record.clone()).unwrap();
    ctx.record(&op, &record, 0).unwrap();
    // The act itself is given the roots (as a run of this build would be).
    let act_roots = vec![ROOT.to_owned()];
    let removal =
        match act_firewall::prepare_recorded(fw, ctx.deny(), &ctx, &session, OpId(1), &act_roots)
            .unwrap()
        {
            FwPrepared::Ready(removal) => removal,
            FwPrepared::Decided(r) => panic!("{r:?}"),
        };
    let token = journal.intent(removal.intent().clone()).unwrap();
    let result = act_firewall::act(fw, ctx.deny(), &session, removal, &token, &act_roots);
    assert_eq!(result.outcome, ItemOutcome::Done);
    journal.done(token, result.outcome).unwrap();
    journal.commit(filetime_now(), 0).unwrap();
    drop(journal);
    let id = session.id().clone();
    drop(session);
    assert!(fw.rule(FW).is_none());

    let mut w = w;
    let undone = w.undo_all(&id);
    let item = &undone.report.items[0];
    assert!(
        matches!(
            &item.result,
            UndoResult::Conflict {
                conflict: UndoConflict::ProgramOutsideRoot,
                ..
            }
        ),
        "{undone:?}"
    );
    assert!(w.obj.firewall.rule(FW).is_none());
    assert!(!w.obj.take_log().iter().any(|l| l == "fw.create"));
}

// ---------------------------------------------------------------------------------------------------
// The crash matrix, in process
// ---------------------------------------------------------------------------------------------------

/// The places of the typed fault points, as calls of the mock backend:
///
/// - `act.before` (and `intent.flushed`): before the delete;
/// - `objdelete.after`: after the delete, before the flush;
/// - `act.after` / `done.before`: after the flush;
/// - `undo.intent`: before the create;
/// - `svcrestore.mid` / `fwrestore.mid` (tasks: `undo.act.after`): after the create;
/// - `undo.act.after`: after the undo's flush.
///
/// For each kind and each place: the crash, then recovery (`resume`), then the undo, and the object
/// is as before the run. A clean run and undo of each kind first: every module fault point reachable
/// for the kind is hit.
///
/// Narrower than its name (M1b review R3b M7): the "crash" is a panic in the mock at six backend-call
/// boundaries per kind, and a panic unwinds where a kill does not; `backup.written`,
/// `backup.verified`, `intent.flushed`, `done.before`, `group.end`, `commit.before` and
/// `journal.header` are not stopped at for an object op. It is a unit test of the recovery paths, not
/// the crash matrix: it does not count toward K13, which needs the rig mode `m1b-x-crash`
/// (M1B-RIG-EXEC) killing the process at each real `fault::point`.
#[test]
fn crash_matrix_unit() {
    thread_local! {
        static TASK_POINTS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
    }
    fn task_point(name: &'static str) {
        TASK_POINTS.with(|p| p.borrow_mut().push(name));
    }
    act_task::set_fault_observer(Some(task_point));
    let kinds: [(Candidate, &str, &str, &str, usize); 3] = [
        (svc_cand(), "svc.delete", "svc.flush", "svc.create", 0),
        (task_cand(), "task.delete", "task.flush", "task.register", 1),
        (fw_cand(), "fw.delete", "fw.flush", "fw.create", 2),
    ];
    // The module fault points a clean run and undo hit.
    for (cand, _, _, _, k) in &kinds {
        let mut w = world(&format!("points-{}", cand.id.0));
        act_service::take_fault_trace();
        act_firewall::take_fault_trace();
        TASK_POINTS.with(|p| p.borrow_mut().clear());
        let out = w.run(typed_request(vec![cand.clone()]));
        w.undo_all(&out.session);
        assert!(w.pre_state()[*k]);
        let hit: Vec<&str> = match k {
            0 => act_service::take_fault_trace(),
            1 => TASK_POINTS.with(|p| std::mem::take(&mut *p.borrow_mut())),
            _ => act_firewall::take_fault_trace(),
        };
        let want: &[&str] = match k {
            0 => &[
                "objdelete.after",
                "act.after",
                "svcrestore.mid",
                "undo.act.after",
            ],
            1 => &["objdelete.after", "act.after", "undo.act.after"],
            _ => &[
                "objdelete.after",
                "act.after",
                "fwrestore.mid",
                "undo.act.after",
            ],
        };
        for point in want {
            assert!(
                hit.contains(point),
                "{}: {point} not hit: {hit:?}",
                cand.id.0
            );
        }
    }
    act_task::set_fault_observer(None);

    for (cand, delete, flush, create, k) in &kinds {
        // Crashes in the run.
        for (call, when) in [
            (*delete, When::Before),
            (*delete, When::After),
            (*flush, When::After),
        ] {
            let crash = Crash { call, nth: 1, when };
            let mut w = world(&format!("crash-{}-{call}-{when:?}", cand.id.0));
            let id = w.crash_run(typed_request(vec![cand.clone()]), crash);
            let out = w.resume(&id);
            assert_eq!(
                out.state,
                Some(SessionState::Committed),
                "{crash:?}: {out:?}"
            );
            assert_eq!(
                outcomes(&w.journal(&id)),
                [Some(ItemOutcome::Done)],
                "{crash:?}"
            );
            assert!(!w.present()[*k], "{crash:?}");
            w.undo_all(&id);
            assert!(w.pre_state()[*k], "{crash:?}");
        }
        // Crashes in the undo.
        for (call, when) in [
            (*create, When::Before),
            (*create, When::After),
            (*flush, When::After),
        ] {
            let crash = Crash { call, nth: 1, when };
            let mut w = world(&format!("ucrash-{}-{call}-{when:?}", cand.id.0));
            let out = w.run(typed_request(vec![cand.clone()]));
            w.crash_undo(&out.session, crash);
            let recovered = w.resume(&out.session);
            if !w.pre_state()[*k] {
                // Recovery left it for the undo (a conflict it may not force); a new undo finishes.
                let again = w.undo_all(&out.session);
                assert!(
                    w.pre_state()[*k],
                    "{crash:?}: {recovered:?} {:?}",
                    again.report
                );
            }
            let read = w.journal(&out.session);
            assert!(
                read.state.op(OpId(1)).unwrap().undo.is_settled(),
                "{crash:?}"
            );
        }
    }
}
