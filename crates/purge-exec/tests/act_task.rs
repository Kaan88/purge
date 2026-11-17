//! Scheduled-task action tests (M1B-X-TASK): validate, prepare, act, complete, probe and undo of
//! `ExecOp::DeleteTask` over a scripted fake [`TaskBackend`], with a relaxed store below the temp
//! directory and a real journal. No scheduled task of the host is read, created, changed or deleted: the
//! only test that uses the real backend is `#[ignore]`d and refuses to run outside the VM rig.

#![cfg(feature = "test-support")]

mod common;

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use common::{Scratch, live_env, safe};
use purge_exec::act_task::{
    Acted, ObjErr, Register, TaskBackend, TaskLive, TaskPrepared, TaskUndoPrepared, TaskValidate,
    TaskXml, act_task, complete_task, delete_task, prepare_task, prepare_undo_task, probe_task,
    run_undo_task, set_fault_observer, validate_task,
};
use purge_exec::act_typed::{TypedResult, TypedUndo};
use purge_exec::gate::{GateCtx, Stamp};
use purge_exec::journal::{self, JournalWriter, sha256_bytes};
use purge_exec::objdef::{TASKDEF_SCHEMA, TaskDef, write_def};
use purge_exec::recover::Probe;
use purge_exec::storage::{BackupKind, SessionDir, StorageRoots, backup_rel};
use purge_guard::deny::DenyList;
use purge_model::exec::journal::{
    GateExemptions, Header, Intent, ItemFacts, JournalSchema, UndoConflict, UndoOutcome, Validated,
};
use purge_model::exec::op::{ExecOp, FailCode, Inverse, ItemOutcome, OpId, SkipReason};
use purge_model::object::fold;
use purge_model::{
    Action, Blocker, Candidate, FileTime, ObjectKind, Reversibility, ScanMode, Target, TaskAction,
    TaskIdentity,
};

const PATH: &str = r"\Vendor\Update Check";
const EXE: &str = r"C:\Program Files\Vendor\update.exe";
const OTHER_EXE: &str = r"C:\Users\Public\evil.exe";
const ROOT: &str = r"C:\Program Files\Vendor";
const SDDL: &str =
    "O:BAG:S-1-5-21-1-2-3-513D:(A;ID;0x1f019f;;;BA)(A;ID;0x1f019f;;;SY)(A;ID;FA;;;BA)";

// ---------------------------------------------------------------------------------------------------
// The event log (fake calls and fault points, in order, per thread)
// ---------------------------------------------------------------------------------------------------

thread_local! {
    static EVENTS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

fn event(e: &str) {
    EVENTS.with(|log| log.borrow_mut().push(e.to_owned()));
}

fn fault_seen(name: &'static str) {
    event(&format!("fault:{name}"));
}

fn take_events() -> Vec<String> {
    EVENTS.with(|log| std::mem::take(&mut *log.borrow_mut()))
}

// ---------------------------------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------------------------------

fn exec(path: &str) -> TaskAction {
    TaskAction::Exec {
        path: path.into(),
        arguments: Some("/check".into()),
        working_dir: None,
    }
}

/// The registration XML of a task with `actions`, in Task Scheduler's form.
fn xml_for(actions: &[TaskAction], logon: &str, enabled: bool, extra: &str) -> String {
    let mut body = String::new();
    for action in actions {
        match action {
            TaskAction::Exec {
                path, arguments, ..
            } => {
                body.push_str(&format!("<Exec><Command>{path}</Command>"));
                if let Some(args) = arguments {
                    body.push_str(&format!("<Arguments>{args}</Arguments>"));
                }
                body.push_str("</Exec>");
            }
            TaskAction::ComHandler { clsid, .. } => {
                body.push_str(&format!(
                    "<ComHandler><ClassId>{clsid}</ClassId></ComHandler>"
                ));
            }
            TaskAction::Other { .. } => {
                body.push_str("<ShowMessage><Title>x</Title></ShowMessage>")
            }
        }
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n<Task version=\"1.2\" \
         xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n  <RegistrationInfo>\
         <Author>Vendor</Author></RegistrationInfo>\r\n  <Triggers><LogonTrigger><Enabled>true\
         </Enabled></LogonTrigger>{extra}</Triggers>\r\n  <Principals><Principal id=\"Author\">\
         <LogonType>{logon}</LogonType></Principal></Principals>\r\n  <Settings><Enabled>{enabled}\
         </Enabled><ExecutionTimeLimit>PT72H</ExecutionTimeLimit></Settings>\r\n  <Actions \
         Context=\"Author\">{body}</Actions>\r\n</Task>"
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FakeTask {
    live: TaskLive,
    xml: TaskXml,
}

fn task(path: &str, actions: Vec<TaskAction>) -> FakeTask {
    let xml = xml_for(&actions, "InteractiveToken", true, "");
    FakeTask {
        live: TaskLive {
            identity: TaskIdentity {
                path: path.into(),
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

fn vendor_task() -> FakeTask {
    task(PATH, vec![exec(EXE)])
}

/// The same task with its exec action repointed to `exe` (XML too).
fn repointed(mut t: FakeTask, exe: &str) -> FakeTask {
    t.live.identity.actions = vec![exec(exe)];
    t.xml.xml = xml_for(&t.live.identity.actions, "InteractiveToken", true, "");
    t
}

fn password_task() -> FakeTask {
    let mut t = vendor_task();
    t.live.stored_password = true;
    t.live.logon_type = 1;
    t.xml.xml = xml_for(&t.live.identity.actions, "Password", true, "");
    t
}

// ---------------------------------------------------------------------------------------------------
// The fake backend
// ---------------------------------------------------------------------------------------------------

type Tasks = BTreeMap<String, FakeTask>;
type Hook = Box<dyn Fn(&mut Tasks)>;

/// A scripted Task Scheduler.
#[derive(Default)]
struct Fake {
    tasks: RefCell<Tasks>,
    /// `read` of these paths fails as unreadable.
    unreadable: Cell<bool>,
    /// Run before the `read` call with this number (counted from 1).
    before_read: RefCell<Vec<(u32, Hook)>>,
    reads: Cell<u32>,
    /// Run after every `definition` call returned.
    after_definition: RefCell<Option<Hook>>,
    /// Run after `register` stored the task (to model a registration that is not exact).
    after_register: RefCell<Option<Hook>>,
    /// The delete call fails and leaves the task.
    delete_fails: Cell<bool>,
    deletes: Cell<u32>,
    registers: RefCell<Vec<Register>>,
}

impl Fake {
    fn with(tasks: Vec<FakeTask>) -> Fake {
        let fake = Fake::default();
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

    fn on_read(&self, n: u32, hook: impl Fn(&mut Tasks) + 'static) {
        self.before_read.borrow_mut().push((n, Box::new(hook)));
    }
}

impl TaskBackend for Fake {
    fn read(&self, path: &str) -> Result<Option<TaskLive>, ObjErr> {
        let n = self.reads.get() + 1;
        self.reads.set(n);
        for (at, hook) in self.before_read.borrow().iter() {
            if *at == n {
                hook(&mut self.tasks.borrow_mut());
            }
        }
        let found = self.get(path);
        if found.is_some() && self.unreadable.get() {
            return Err(ObjErr::Unreadable("access denied".into()));
        }
        Ok(found.map(|t| t.live))
    }

    fn definition(&self, path: &str) -> Result<Option<TaskXml>, ObjErr> {
        let found = self.get(path).map(|t| t.xml);
        if let Some(hook) = self.after_definition.borrow().as_ref() {
            hook(&mut self.tasks.borrow_mut());
        }
        Ok(found)
    }

    fn delete(&self, path: &str) -> Result<(), ObjErr> {
        event("delete");
        self.deletes.set(self.deletes.get() + 1);
        if self.delete_fails.get() {
            return Err(ObjErr::Api {
                code: Some(0x8007_0005),
                detail: "access denied".into(),
            });
        }
        self.tasks.borrow_mut().remove(&fold(path));
        Ok(())
    }

    fn register(&self, def: &TaskDef, mode: Register) -> Result<(), ObjErr> {
        event("register");
        // C-WIN: create only. The only mode there is; asserted so a second mode cannot slip in.
        assert_eq!(mode, Register::CreateOnly);
        self.registers.borrow_mut().push(mode);
        if self.get(&def.path).is_some() {
            return Err(ObjErr::AlreadyExists);
        }
        if def.stored_password {
            return Err(ObjErr::PasswordNeeded);
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
        if let Some(hook) = self.after_register.borrow().as_ref() {
            hook(&mut self.tasks.borrow_mut());
        }
        Ok(())
    }

    fn flush(&self, _path: &str) -> Result<(), ObjErr> {
        event("flush");
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------------
// The bench: a session, its journal and a gate context for op 1
// ---------------------------------------------------------------------------------------------------

const OP: OpId = OpId(1);

fn op(path: &str) -> ExecOp {
    ExecOp::DeleteTask { path: path.into() }
}

fn candidate(
    path: &str,
    identity: Option<&TaskIdentity>,
    reversibility: Reversibility,
) -> Candidate {
    let mut c = safe(
        "c-001",
        Target::Task { path: path.into() },
        Action::DeleteKey,
    );
    c.object_fp = identity.map(TaskIdentity::fp);
    c.reversibility = reversibility;
    c
}

struct Bench {
    journal: JournalWriter,
    ctx: GateCtx,
    session: SessionDir,
    _roots: StorageRoots,
    /// Last: removed after the journal and the session's handles are closed.
    _s: Scratch,
}

impl Bench {
    fn new(tag: &str) -> Bench {
        let s = Scratch::new(&format!("task-{tag}"));
        let roots = StorageRoots::install_relaxed(Path::new(&s.path("data"))).unwrap();
        let session = roots.create_session().unwrap();
        let header = Header {
            schema: JournalSchema,
            session: session.id().clone(),
            created: FileTime(134_078_121_020_000_000),
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
        let journal = JournalWriter::create(&session, header).unwrap();
        let deny = DenyList::compile(&live_env(roots.data_root().to_str().unwrap()));
        let scope = roots.store_scope(session.id(), &[] as &[&Path]).unwrap();
        let ctx = GateCtx::new(deny, &[op(PATH)], scope).unwrap();
        Bench {
            journal,
            ctx,
            session,
            _roots: roots,
            _s: s,
        }
    }

    /// Validates op 1 for `cand` and journals the `validated` record (and records it in the context).
    fn validate(&mut self, fake: &dyn TaskBackend, path: &str, cand: &Candidate) -> TaskValidate {
        let v = validate_task(fake, &self.ctx, &op(path), cand);
        let record = Validated {
            op: OP,
            item: cand.id.clone(),
            target: op(path).target(),
            facts: v.journal_facts(),
            exemptions: GateExemptions::default(),
        };
        self.journal.validated(record.clone()).unwrap();
        self.ctx.record(&op(path), &record, 0).unwrap();
        v
    }

    fn prepare(&self, fake: &dyn TaskBackend, planned: Reversibility) -> TaskPrepared {
        prepare_task(fake, &self.ctx, &self.session, OP, planned, &roots()).unwrap()
    }

    /// Validates, prepares, journals the intent, deletes and journals the `done`. Returns the result
    /// and the intent (when one was written).
    fn run(
        &mut self,
        fake: &Fake,
        cand: &Candidate,
        planned: Reversibility,
    ) -> (TypedResult, Option<Intent>) {
        match self.validate(fake, PATH, cand) {
            TaskValidate::Decided(d) => {
                self.journal
                    .done_without_intent(OP, d.result.outcome.clone())
                    .unwrap();
                return (d.result, None);
            }
            TaskValidate::Validated { .. } => {}
        }
        match self.prepare(fake, planned) {
            TaskPrepared::Decided(d) => {
                self.journal
                    .done_without_intent(OP, d.result.outcome.clone())
                    .unwrap();
                (d.result, None)
            }
            TaskPrepared::Ready(ready) => {
                let intent = ready.intent().clone();
                let token = self.journal.intent(intent.clone()).unwrap();
                let result = delete_task(fake, &self.ctx, &self.session, &intent, &token, &roots());
                self.journal.done(token, result.outcome.clone()).unwrap();
                (result, Some(intent))
            }
        }
    }

    fn prepare_undo(
        &self,
        fake: &dyn TaskBackend,
        intent: &Intent,
        done: Option<&ItemOutcome>,
        roots: &[String],
    ) -> TaskUndoPrepared {
        prepare_undo_task(fake, &self.ctx, &self.session, intent, done, roots, None).unwrap()
    }

    /// The whole undo of op 1, journalled as the undo driver does.
    fn undo(&mut self, fake: &dyn TaskBackend, intent: &Intent, roots: &[String]) -> TypedUndo {
        let done = journal::read(&self.session)
            .unwrap()
            .state
            .op(OP)
            .and_then(|o| o.outcome.clone());
        match self.prepare_undo(fake, intent, done.as_ref(), roots) {
            TaskUndoPrepared::Decided(undo) => undo,
            TaskUndoPrepared::Ready(ready) => {
                let token = self.journal.undo_intent(OP).unwrap();
                let undo = run_undo_task(fake, *ready, &token);
                match &undo {
                    TypedUndo::Done(outcome) => {
                        self.journal.undo_done(token, outcome.clone()).unwrap();
                    }
                    TypedUndo::Conflict { conflict, detail } => {
                        self.journal
                            .undo_conflict(token, conflict.clone(), detail.clone())
                            .unwrap();
                    }
                }
                undo
            }
        }
    }

    fn def_file(&self) -> PathBuf {
        self.session
            .path()
            .join(backup_rel(BackupKind::Definition, OP))
    }
}

fn roots() -> Vec<String> {
    vec![ROOT.to_owned()]
}

fn changed() -> ItemOutcome {
    ItemOutcome::Skipped {
        reason: SkipReason::ChangedSinceScan,
    }
}

fn gate_blocked(blocker: Blocker) -> ItemOutcome {
    ItemOutcome::Skipped {
        reason: SkipReason::GateBlocked { blocker },
    }
}

fn identity() -> TaskIdentity {
    vendor_task().live.identity
}

// ---------------------------------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------------------------------

#[test]
fn validate_absent_vanished() {
    let mut b = Bench::new("absent");
    let fake = Fake::with(vec![]);
    let v = b.validate(
        &fake,
        PATH,
        &candidate(PATH, Some(&identity()), Reversibility::Full),
    );
    let TaskValidate::Decided(d) = &v else {
        panic!("{v:?}");
    };
    assert_eq!(d.result.outcome, ItemOutcome::Vanished);
    assert_eq!(v.journal_facts(), ItemFacts::Absent);
    assert_eq!(fake.deletes.get(), 0);
}

#[test]
fn validate_digest_mismatch() {
    let mut b = Bench::new("digest");
    // The live task runs another program than the one the scan fingerprinted.
    let fake = Fake::with(vec![repointed(
        vendor_task(),
        r"C:\Program Files\Vendor\other.exe",
    )]);
    let v = b.validate(
        &fake,
        PATH,
        &candidate(PATH, Some(&identity()), Reversibility::Full),
    );
    let TaskValidate::Decided(d) = &v else {
        panic!("{v:?}");
    };
    assert_eq!(d.result.outcome, changed());
    assert!(matches!(v.journal_facts(), ItemFacts::Refused { .. }));

    // A candidate with no object fingerprint is refused the same way.
    let fake = Fake::with(vec![vendor_task()]);
    let v = validate_task(
        &fake,
        &b.ctx,
        &op(PATH),
        &candidate(PATH, None, Reversibility::Full),
    );
    let TaskValidate::Decided(d) = &v else {
        panic!("{v:?}");
    };
    assert_eq!(d.result.outcome, changed());
}

#[test]
fn validate_windows_task_blocked() {
    let b = Bench::new("windows");
    // A task under \Microsoft\Windows\, and a vendor-named task whose program is in the Windows folder.
    let windows = task(
        r"\Microsoft\Windows\Defrag\ScheduledDefrag",
        vec![exec(r"C:\Program Files\Vendor\update.exe")],
    );
    let system_program = task(
        r"\Vendor\Helper",
        vec![exec(r"%windir%\system32\defrag.exe")],
    );
    for t in [windows, system_program] {
        let path = t.live.identity.path.clone();
        let fake = Fake::with(vec![t.clone()]);
        let v = validate_task(
            &fake,
            &b.ctx,
            &op(&path),
            &candidate(&path, Some(&t.live.identity), Reversibility::Full),
        );
        let TaskValidate::Decided(d) = &v else {
            panic!("{path}: {v:?}");
        };
        assert_eq!(
            d.result.outcome,
            gate_blocked(Blocker::DenyListed {
                rule: "sys.task.windows".into()
            }),
            "{path}"
        );
    }
}

#[test]
fn validate_running_in_use() {
    let b = Bench::new("running");
    let mut t = vendor_task();
    t.live.running = true;
    let fake = Fake::with(vec![t]);
    let v = validate_task(
        &fake,
        &b.ctx,
        &op(PATH),
        &candidate(PATH, Some(&identity()), Reversibility::Full),
    );
    let TaskValidate::Decided(d) = &v else {
        panic!("{v:?}");
    };
    assert_eq!(d.result.outcome, gate_blocked(Blocker::InUse));
    assert_eq!(fake.deletes.get(), 0);
}

#[test]
fn validate_unreadable_cannot_back_up() {
    let b = Bench::new("unreadable");
    let fake = Fake::with(vec![vendor_task()]);
    fake.unreadable.set(true);
    let v = validate_task(
        &fake,
        &b.ctx,
        &op(PATH),
        &candidate(PATH, Some(&identity()), Reversibility::Full),
    );
    let TaskValidate::Decided(d) = &v else {
        panic!("{v:?}");
    };
    assert_eq!(d.result.outcome, gate_blocked(Blocker::CannotBackUp));
}

#[test]
fn validate_pass_binds_the_digest() {
    let mut b = Bench::new("pass");
    let fake = Fake::with(vec![vendor_task()]);
    let v = b.validate(
        &fake,
        PATH,
        &candidate(PATH, Some(&identity()), Reversibility::Full),
    );
    let sha256 = identity().fp().sha256;
    assert_eq!(
        v,
        TaskValidate::Validated {
            stamp: Stamp::Object {
                kind: ObjectKind::Task,
                sha256: sha256.clone()
            },
            facts: ItemFacts::Object {
                kind: ObjectKind::Task,
                sha256: sha256.clone(),
                running: false
            },
        }
    );
    assert_eq!(
        b.ctx.stamp(OP),
        Some(&Stamp::Object {
            kind: ObjectKind::Task,
            sha256
        })
    );
}

// ---------------------------------------------------------------------------------------------------
// Prepare
// ---------------------------------------------------------------------------------------------------

/// Hostile: after validation, the task's action is repointed to another program (and the XML with
/// it), before the backup, or between the XML read and the identity re-read. Nothing is backed up or
/// deleted.
#[test]
fn prepare_action_changed_after_validate_skips() {
    // Before the backup (the first read of prepare: read 2 overall).
    let mut b = Bench::new("repoint-1");
    let fake = Fake::with(vec![vendor_task()]);
    b.validate(
        &fake,
        PATH,
        &candidate(PATH, Some(&identity()), Reversibility::Full),
    );
    fake.on_read(2, |tasks| {
        let t = tasks.values().next().unwrap().clone();
        let evil = repointed(t, OTHER_EXE);
        tasks.insert(fold(PATH), evil);
    });
    let TaskPrepared::Decided(d) = b.prepare(&fake, Reversibility::Full) else {
        panic!("prepared");
    };
    assert_eq!(d.result.outcome, changed());
    assert!(!b.def_file().exists());

    // Between the XML read and the re-read of the identity: the XML is the old one, the task is new.
    let mut b = Bench::new("repoint-2");
    let fake = Fake::with(vec![vendor_task()]);
    b.validate(
        &fake,
        PATH,
        &candidate(PATH, Some(&identity()), Reversibility::Full),
    );
    *fake.after_definition.borrow_mut() = Some(Box::new(|tasks: &mut Tasks| {
        let t = tasks.values().next().unwrap().clone();
        tasks.insert(fold(PATH), repointed(t, OTHER_EXE));
    }));
    let TaskPrepared::Decided(d) = b.prepare(&fake, Reversibility::Full) else {
        panic!("prepared");
    };
    assert_eq!(d.result.outcome, changed());
    assert!(!b.def_file().exists());

    // The identity stays, but the XML names another program: the XML is not the identity's.
    let mut b = Bench::new("repoint-3");
    let mut t = vendor_task();
    t.xml.xml = xml_for(&[exec(OTHER_EXE)], "InteractiveToken", true, "");
    let fake = Fake::with(vec![t]);
    b.validate(
        &fake,
        PATH,
        &candidate(PATH, Some(&identity()), Reversibility::Full),
    );
    let TaskPrepared::Decided(d) = b.prepare(&fake, Reversibility::Full) else {
        panic!("prepared");
    };
    assert_eq!(d.result.outcome, changed());
    assert!(!b.def_file().exists());
    assert_eq!(fake.deletes.get(), 0);
}

#[test]
fn prepare_stored_password_planned_full_blocked() {
    let mut b = Bench::new("password-full");
    let fake = Fake::with(vec![password_task()]);
    b.validate(
        &fake,
        PATH,
        &candidate(PATH, Some(&identity()), Reversibility::Full),
    );
    let TaskPrepared::Decided(d) = b.prepare(&fake, Reversibility::Full) else {
        panic!("prepared");
    };
    assert_eq!(
        d.result.outcome,
        gate_blocked(Blocker::ReversibilityPartial)
    );
    assert!(!b.def_file().exists());

    // The logon type alone (the backend's flag clear) is enough.
    let mut b = Bench::new("password-logon");
    let mut t = vendor_task();
    t.live.logon_type = 6;
    let fake = Fake::with(vec![t]);
    b.validate(
        &fake,
        PATH,
        &candidate(PATH, Some(&identity()), Reversibility::Full),
    );
    let TaskPrepared::Decided(d) = b.prepare(&fake, Reversibility::Full) else {
        panic!("prepared");
    };
    assert_eq!(
        d.result.outcome,
        gate_blocked(Blocker::ReversibilityPartial)
    );

    // Planned partial: the delete may go ahead, and the definition records the password.
    let mut b = Bench::new("password-partial");
    let fake = Fake::with(vec![password_task()]);
    b.validate(
        &fake,
        PATH,
        &candidate(PATH, Some(&identity()), Reversibility::Partial),
    );
    let TaskPrepared::Ready(ready) = b.prepare(&fake, Reversibility::Partial) else {
        panic!("decided");
    };
    assert!(ready.definition().stored_password);
}

#[test]
fn prepare_oversized_xml_refused() {
    let mut b = Bench::new("oversized");
    let mut t = vendor_task();
    let pad = format!("<Description>{}</Description>", "x".repeat(1 << 20));
    t.xml.xml = t.xml.xml.replace(
        "<Author>Vendor</Author>",
        &format!("<Author>Vendor</Author>{pad}"),
    );
    let fake = Fake::with(vec![t]);
    b.validate(
        &fake,
        PATH,
        &candidate(PATH, Some(&identity()), Reversibility::Full),
    );
    let TaskPrepared::Decided(d) = b.prepare(&fake, Reversibility::Full) else {
        panic!("prepared");
    };
    assert_eq!(d.result.outcome, gate_blocked(Blocker::CannotBackUp));
    assert!(!b.def_file().exists());

    // A RegistrationTrigger would start the task when it is put back: not deleted either.
    let mut b = Bench::new("regtrigger");
    let mut t = vendor_task();
    t.xml.xml = xml_for(
        &t.live.identity.actions,
        "InteractiveToken",
        true,
        "<RegistrationTrigger><Enabled>true</Enabled></RegistrationTrigger>",
    );
    let fake = Fake::with(vec![t]);
    b.validate(
        &fake,
        PATH,
        &candidate(PATH, Some(&identity()), Reversibility::Full),
    );
    let TaskPrepared::Decided(d) = b.prepare(&fake, Reversibility::Full) else {
        panic!("prepared");
    };
    assert_eq!(d.result.outcome, gate_blocked(Blocker::CannotBackUp));
}

#[test]
fn prepare_writes_the_definition_and_a_consistent_intent() {
    let mut b = Bench::new("prepare");
    let fake = Fake::with(vec![vendor_task()]);
    b.validate(
        &fake,
        PATH,
        &candidate(PATH, Some(&identity()), Reversibility::Full),
    );
    let TaskPrepared::Ready(ready) = b.prepare(&fake, Reversibility::Full) else {
        panic!("decided");
    };
    let intent = ready.intent();
    assert!(intent.is_consistent());
    let Inverse::RecreateTask { definition } = &intent.inverse else {
        panic!("{:?}", intent.inverse);
    };
    assert_eq!(definition.path, backup_rel(BackupKind::Definition, OP));
    let def = ready.definition();
    assert_eq!(def.schema, TASKDEF_SCHEMA);
    assert_eq!(def.xml, vendor_task().xml.xml);
    assert_eq!(def.sddl, SDDL);
    assert_eq!(def.identity_sha256, identity().fp().sha256);
    assert!(def.enabled && !def.stored_password);
    let on_disk = std::fs::read(b.def_file()).unwrap();
    assert_eq!(sha256_bytes(&on_disk), definition.sha256);
    assert_eq!(fake.deletes.get(), 0);
}

// ---------------------------------------------------------------------------------------------------
// Act, complete, probe
// ---------------------------------------------------------------------------------------------------

/// Validated and prepared, intent journalled; returns the intent and its token's journal.
fn ready(b: &mut Bench, fake: &Fake) -> Intent {
    b.validate(
        fake,
        PATH,
        &candidate(PATH, Some(&identity()), Reversibility::Full),
    );
    let TaskPrepared::Ready(ready) = b.prepare(fake, Reversibility::Full) else {
        panic!("decided");
    };
    ready.intent().clone()
}

#[test]
fn act_rechecks_digest() {
    let mut b = Bench::new("act-digest");
    let fake = Fake::with(vec![vendor_task()]);
    let intent = ready(&mut b, &fake);
    let token = b.journal.intent(intent.clone()).unwrap();
    // The task is repointed after the intent is durable.
    fake.put(repointed(vendor_task(), OTHER_EXE));
    let result = act_task(&fake, &b.ctx, &b.session, &intent, &token, &roots()).unwrap_err();
    assert_eq!(result.outcome, changed());
    assert_eq!(fake.deletes.get(), 0);
    assert_eq!(fake.get(PATH).unwrap(), repointed(vendor_task(), OTHER_EXE));

    // Running now: InUse, nothing ended or deleted.
    let mut t = vendor_task();
    t.live.running = true;
    fake.put(t);
    let result = act_task(&fake, &b.ctx, &b.session, &intent, &token, &roots()).unwrap_err();
    assert_eq!(result.outcome, gate_blocked(Blocker::InUse));
    assert_eq!(fake.deletes.get(), 0);

    // Gone now: Vanished, no delete call.
    fake.tasks.borrow_mut().clear();
    let result = act_task(&fake, &b.ctx, &b.session, &intent, &token, &roots()).unwrap_err();
    assert_eq!(result.outcome, ItemOutcome::Vanished);
    assert_eq!(fake.deletes.get(), 0);
    b.journal.done(token, result.outcome).unwrap();
}

/// Review R2b S4: the act is bound to the backup, not only to the identity digest. A trigger added
/// after prepare (same actions, so the same digest), the task disabled, or the definition gone: nothing
/// is deleted.
#[test]
fn act_binds_to_the_backup() {
    let mut b = Bench::new("act-bind");
    let fake = Fake::with(vec![vendor_task()]);
    let intent = ready(&mut b, &fake);
    let token = b.journal.intent(intent.clone()).unwrap();
    let mut t = vendor_task();
    t.xml.xml = xml_for(
        &t.live.identity.actions,
        "InteractiveToken",
        true,
        "<BootTrigger><Enabled>true</Enabled></BootTrigger>",
    );
    fake.put(t);
    let result = act_task(&fake, &b.ctx, &b.session, &intent, &token, &roots()).unwrap_err();
    assert_eq!(result.outcome, changed(), "{}", result.detail);
    let mut t = vendor_task();
    t.live.enabled = false;
    fake.put(t);
    let result = act_task(&fake, &b.ctx, &b.session, &intent, &token, &roots()).unwrap_err();
    assert_eq!(result.outcome, changed(), "{}", result.detail);
    // Roots that do not hold the program (a resumed run's header): refused.
    fake.put(vendor_task());
    let result = act_task(&fake, &b.ctx, &b.session, &intent, &token, &[]).unwrap_err();
    assert_eq!(result.outcome, gate_blocked(Blocker::CannotBackUp));
    let Inverse::RecreateTask { definition } = &intent.inverse else {
        panic!();
    };
    b.session.delete_backup_file(&definition.path).unwrap();
    let result = act_task(&fake, &b.ctx, &b.session, &intent, &token, &roots()).unwrap_err();
    assert_eq!(
        result.outcome,
        ItemOutcome::Skipped {
            reason: SkipReason::NoVerifiedBackup
        },
        "{}",
        result.detail
    );
    assert_eq!(fake.deletes.get(), 0);
    b.journal.done(token, result.outcome).unwrap();
}

/// Review R2b B1: a task whose program is outside the run's roots is not deleted (undo would refuse to
/// register it), and nothing is written for it.
#[test]
fn prepare_refuses_a_program_outside_the_roots() {
    for roots in [vec![r"C:\Program Files\Other".to_owned()], Vec::new()] {
        let mut b = Bench::new("prep-roots");
        let fake = Fake::with(vec![vendor_task()]);
        b.validate(
            &fake,
            PATH,
            &candidate(PATH, Some(&identity()), Reversibility::Full),
        );
        let TaskPrepared::Decided(d) =
            prepare_task(&fake, &b.ctx, &b.session, OP, Reversibility::Full, &roots).unwrap()
        else {
            panic!("ready");
        };
        assert_eq!(d.result.outcome, gate_blocked(Blocker::CannotBackUp));
        let def_rel = backup_rel(BackupKind::Definition, OP);
        assert!(!b.session.path().join(&def_rel).exists());
        assert_eq!(fake.deletes.get(), 0);
    }
}

/// Review R3b S2: a task of COM handlers only has no program, so the per-program check passes it for
/// any roots; with no roots it is refused all the same, at prepare and at the act.
#[test]
fn no_roots_refuses_a_com_handler_task() {
    let com = task(
        PATH,
        vec![TaskAction::ComHandler {
            clsid: "{0B7AC2E8-3A6B-4C1D-9E58-7F7B2B1E7A10}".into(),
            data: None,
        }],
    );
    let ident = com.live.identity.clone();
    let mut b = Bench::new("noroots-com");
    let fake = Fake::with(vec![com.clone()]);
    b.validate(
        &fake,
        PATH,
        &candidate(PATH, Some(&ident), Reversibility::Full),
    );
    let TaskPrepared::Decided(d) =
        prepare_task(&fake, &b.ctx, &b.session, OP, Reversibility::Full, &[]).unwrap()
    else {
        panic!("ready");
    };
    assert_eq!(d.result.outcome, gate_blocked(Blocker::CannotBackUp));
    assert!(
        d.result.detail.contains("gate.no-program-roots"),
        "{}",
        d.result.detail
    );
    assert!(
        !b.session
            .path()
            .join(backup_rel(BackupKind::Definition, OP))
            .exists()
    );
    // Prepared with roots (the COM task passes them), acted with none: refused, nothing deleted.
    let TaskPrepared::Ready(ready) = b.prepare(&fake, Reversibility::Full) else {
        panic!("decided");
    };
    let intent = ready.intent().clone();
    let token = b.journal.intent(intent.clone()).unwrap();
    let result = act_task(&fake, &b.ctx, &b.session, &intent, &token, &[]).unwrap_err();
    assert_eq!(result.outcome, gate_blocked(Blocker::CannotBackUp));
    assert!(
        result.detail.contains("gate.no-program-roots"),
        "{}",
        result.detail
    );
    assert_eq!(fake.deletes.get(), 0);
    assert_eq!(fake.get(PATH), Some(com));
    b.journal.done(token, result.outcome).unwrap();
}

#[test]
fn act_done_and_flush_order() {
    let mut b = Bench::new("act-order");
    let fake = Fake::with(vec![vendor_task()]);
    let intent = ready(&mut b, &fake);
    let token = b.journal.intent(intent.clone()).unwrap();
    take_events();
    set_fault_observer(Some(fault_seen));
    let result = delete_task(&fake, &b.ctx, &b.session, &intent, &token, &roots());
    set_fault_observer(None);
    assert_eq!(result.outcome, ItemOutcome::Done);
    assert_eq!(
        take_events(),
        [
            "delete",
            "fault:objdelete.after",
            "flush",
            "fault:act.after"
        ]
    );
    assert!(fake.get(PATH).is_none());
    b.journal.done(token, result.outcome).unwrap();
    let read = journal::read(&b.session).unwrap();
    assert_eq!(read.state.op(OP).unwrap().outcome, Some(ItemOutcome::Done));

    // A delete call that fails and leaves the task: Failed{AccessDenied}, still there.
    let fake = Fake::with(vec![vendor_task()]);
    fake.delete_fails.set(true);
    let acted = Acted {
        delete_error: Some(ObjErr::Api {
            code: Some(0x8007_0005),
            detail: "access denied".into(),
        }),
        flush_error: None,
    };
    let result = complete_task(&fake, &intent, Some(&acted));
    assert!(
        matches!(
            result.outcome,
            ItemOutcome::Failed {
                code: FailCode::AccessDenied,
                ..
            }
        ),
        "{result:?}"
    );
    // Still there with no error reported: Failed{ObjectApi}.
    let result = complete_task(&fake, &intent, None);
    assert!(
        matches!(
            result.outcome,
            ItemOutcome::Failed {
                code: FailCode::ObjectApi,
                ..
            }
        ),
        "{result:?}"
    );
    // Still there after this process's delete call reported success: VerifyFailed, never "nothing
    // changed" (review R3b M4).
    let ok = Acted {
        delete_error: None,
        flush_error: None,
    };
    let result = complete_task(&fake, &intent, Some(&ok));
    assert!(
        matches!(
            result.outcome,
            ItemOutcome::Failed {
                code: FailCode::VerifyFailed,
                ..
            }
        ),
        "{result:?}"
    );
    // Gone, but the flush failed: VerifyFailed (the delete may not be durable).
    fake.tasks.borrow_mut().clear();
    let acted = Acted {
        delete_error: None,
        flush_error: Some(ObjErr::Api {
            code: Some(5),
            detail: "flush".into(),
        }),
    };
    let result = complete_task(&fake, &intent, Some(&acted));
    assert!(
        matches!(
            result.outcome,
            ItemOutcome::Failed {
                code: FailCode::VerifyFailed,
                ..
            }
        ),
        "{result:?}"
    );
}

#[test]
fn probe_three_states() {
    let mut b = Bench::new("probe");
    let fake = Fake::with(vec![vendor_task()]);
    let intent = ready(&mut b, &fake);
    assert_eq!(probe_task(&fake, &intent), Probe::NotDone);
    fake.put(repointed(vendor_task(), OTHER_EXE));
    assert!(matches!(
        probe_task(&fake, &intent),
        Probe::Attention { .. }
    ));
    fake.tasks.borrow_mut().clear();
    assert_eq!(probe_task(&fake, &intent), Probe::Done(ItemOutcome::Done));
    // A read that fails is Attention too.
    fake.put(vendor_task());
    fake.unreadable.set(true);
    assert!(matches!(
        probe_task(&fake, &intent),
        Probe::Attention { .. }
    ));
}

// ---------------------------------------------------------------------------------------------------
// Undo
// ---------------------------------------------------------------------------------------------------

/// A completed delete of the vendor task; returns the bench, the fake (task gone) and the intent.
fn deleted(tag: &str, t: FakeTask, planned: Reversibility) -> (Bench, Fake, Intent) {
    let mut b = Bench::new(tag);
    let fake = Fake::with(vec![t]);
    let (result, intent) = b.run(&fake, &candidate(PATH, Some(&identity()), planned), planned);
    assert_eq!(result.outcome, ItemOutcome::Done, "{result:?}");
    assert!(fake.get(PATH).is_none());
    (b, fake, intent.unwrap())
}

#[test]
fn undo_restores_exact() {
    let mut t = vendor_task();
    t.live.enabled = false;
    t.xml.xml = xml_for(&t.live.identity.actions, "InteractiveToken", false, "");
    let (mut b, fake, intent) = deleted("undo-exact", t.clone(), Reversibility::Full);
    let undo = b.undo(&fake, &intent, &roots());
    assert_eq!(undo, TypedUndo::Done(UndoOutcome::Restored));
    // XML, SDDL, the disabled setting and the identity are back; it was never run.
    assert_eq!(fake.get(PATH).unwrap(), t);
    assert_eq!(*fake.registers.borrow(), [Register::CreateOnly]);
    let read = journal::read(&b.session).unwrap();
    assert!(read.state.op(OP).unwrap().undo.is_settled());

    // A registration that does not read back exactly is ValueDiffers.
    let (mut b, fake, intent) = deleted("undo-differs", vendor_task(), Reversibility::Full);
    *fake.after_register.borrow_mut() = Some(Box::new(|tasks: &mut Tasks| {
        let t = tasks.get_mut(&fold(PATH)).unwrap();
        t.xml.sddl.push_str("(A;;FR;;;BU)");
    }));
    let undo = b.undo(&fake, &intent, &roots());
    assert!(
        matches!(
            undo,
            TypedUndo::Conflict {
                conflict: UndoConflict::ValueDiffers,
                ..
            }
        ),
        "{undo:?}"
    );
}

#[test]
fn undo_existing_equal_already_restored() {
    let (mut b, fake, intent) = deleted("undo-equal", vendor_task(), Reversibility::Full);
    fake.put(vendor_task());
    let undo = b.undo(&fake, &intent, &roots());
    assert_eq!(undo, TypedUndo::Done(UndoOutcome::AlreadyRestored));
    assert!(fake.registers.borrow().is_empty());
}

/// Hostile: another task now sits at the path (same path, another program). It is never overwritten.
#[test]
fn undo_existing_other_task_same_path_object_exists() {
    let (mut b, fake, intent) = deleted("undo-other", vendor_task(), Reversibility::Full);
    let other = repointed(vendor_task(), OTHER_EXE);
    fake.put(other.clone());
    let undo = b.undo(&fake, &intent, &roots());
    assert!(
        matches!(
            undo,
            TypedUndo::Conflict {
                conflict: UndoConflict::ObjectExists,
                ..
            }
        ),
        "{undo:?}"
    );
    assert!(fake.registers.borrow().is_empty());
    assert_eq!(fake.get(PATH).unwrap(), other);

    // Same actions, other security descriptor: still not the backed-up task.
    let mut sd = vendor_task();
    sd.xml.sddl = "O:BAG:BAD:(A;;FA;;;WD)".into();
    fake.put(sd.clone());
    let undo = b.undo(&fake, &intent, &roots());
    assert!(
        matches!(
            undo,
            TypedUndo::Conflict {
                conflict: UndoConflict::ObjectExists,
                ..
            }
        ),
        "{undo:?}"
    );
    assert_eq!(fake.get(PATH).unwrap(), sd);
}

/// Hostile: a definition (valid, hash-consistent, as a forged store would hold it) whose exec action
/// runs a program outside every root recorded for the session. Nothing is registered. Also: no roots
/// recorded at all refuses every re-registration.
#[test]
fn undo_action_outside_root_refused() {
    let b = Bench::new("undo-root");
    let evil = repointed(task(PATH, vec![]), OTHER_EXE);
    let forged = TaskDef {
        schema: TASKDEF_SCHEMA.into(),
        path: PATH.into(),
        identity_sha256: evil.live.identity.fp().sha256,
        actions: evil.live.identity.actions.clone(),
        xml: evil.xml.xml.clone(),
        sddl: SDDL.into(),
        enabled: true,
        logon_type: 3,
        stored_password: false,
    };
    let reference = write_def(&b.session, OP, &forged).unwrap();
    let intent = Intent {
        op: OP,
        item: purge_model::CandidateId("c-001".into()),
        exec_op: op(PATH),
        inverse: Inverse::RecreateTask {
            definition: reference,
        },
        definition: None,
        pre: ItemFacts::Object {
            kind: ObjectKind::Task,
            sha256: forged.identity_sha256.clone(),
            running: false,
        },
    };
    assert!(intent.is_consistent());
    let fake = Fake::with(vec![]);
    let TaskUndoPrepared::Decided(undo) =
        b.prepare_undo(&fake, &intent, Some(&ItemOutcome::Done), &roots())
    else {
        panic!("ready");
    };
    assert!(
        matches!(
            undo,
            TypedUndo::Conflict {
                conflict: UndoConflict::ProgramOutsideRoot,
                ..
            }
        ),
        "{undo:?}"
    );
    assert!(fake.registers.borrow().is_empty());

    // The genuine definition, but no root recorded in the header: refused as well.
    let (b, fake, intent) = deleted("undo-noroot", vendor_task(), Reversibility::Full);
    let TaskUndoPrepared::Decided(undo) =
        b.prepare_undo(&fake, &intent, Some(&ItemOutcome::Done), &[])
    else {
        panic!("ready");
    };
    assert!(
        matches!(
            undo,
            TypedUndo::Conflict {
                conflict: UndoConflict::ProgramOutsideRoot,
                ..
            }
        ),
        "{undo:?}"
    );
    assert!(fake.registers.borrow().is_empty());
}

#[test]
fn undo_stored_password_refused_xml_kept() {
    let (mut b, fake, intent) = deleted("undo-password", password_task(), Reversibility::Partial);
    let undo = b.undo(&fake, &intent, &roots());
    let TypedUndo::Conflict { conflict, detail } = &undo else {
        panic!("{undo:?}");
    };
    assert_eq!(*conflict, UndoConflict::PasswordNeeded);
    assert!(fake.registers.borrow().is_empty());
    // The XML stays in the store, and the report says where.
    let file = b.def_file();
    assert!(detail.contains(&file.display().to_string()), "{detail}");
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(doc["xml"], password_task().xml.xml);
    assert_eq!(doc["stored_password"], true);
}

/// The registration is create-only: a task that appears between the check and the registration is
/// never replaced (the fake asserts the mode and refuses over an existing task, as `TASK_CREATE` does).
#[test]
fn undo_never_overwrites() {
    let (b, fake, intent) = deleted("undo-race", vendor_task(), Reversibility::Full);
    let TaskUndoPrepared::Ready(recreate) =
        b.prepare_undo(&fake, &intent, Some(&ItemOutcome::Done), &roots())
    else {
        panic!("decided");
    };
    let squatter = repointed(vendor_task(), OTHER_EXE);
    fake.put(squatter.clone());
    let mut b = b;
    let token = b.journal.undo_intent(OP).unwrap();
    let undo = run_undo_task(&fake, *recreate, &token);
    assert!(
        matches!(
            undo,
            TypedUndo::Conflict {
                conflict: UndoConflict::ObjectExists,
                ..
            }
        ),
        "{undo:?}"
    );
    assert_eq!(*fake.registers.borrow(), [Register::CreateOnly]);
    assert_eq!(fake.get(PATH).unwrap(), squatter);
    if let TypedUndo::Conflict { conflict, detail } = undo {
        b.journal.undo_conflict(token, conflict, detail).unwrap();
    }
}

#[test]
fn undo_tampered_def_refused() {
    let (mut b, fake, intent) = deleted("undo-tamper", vendor_task(), Reversibility::Full);
    let file = b.def_file();
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, text.replace("update.exe", "evil00.exe")).unwrap();
    let undo = b.undo(&fake, &intent, &roots());
    assert!(
        matches!(
            undo,
            TypedUndo::Conflict {
                conflict: UndoConflict::BackupTampered,
                ..
            }
        ),
        "{undo:?}"
    );
    assert!(fake.registers.borrow().is_empty());

    // Missing: BackupMissing.
    std::fs::remove_file(&file).unwrap();
    let undo = b.undo(&fake, &intent, &roots());
    assert!(
        matches!(
            undo,
            TypedUndo::Conflict {
                conflict: UndoConflict::BackupMissing,
                ..
            }
        ),
        "{undo:?}"
    );

    // An inverse of another kind: BackupTampered, before anything is read.
    let mut wrong = intent.clone();
    wrong.inverse = Inverse::None;
    let TaskUndoPrepared::Decided(undo) =
        b.prepare_undo(&fake, &wrong, Some(&ItemOutcome::Done), &roots())
    else {
        panic!("ready");
    };
    assert!(
        matches!(
            undo,
            TypedUndo::Conflict {
                conflict: UndoConflict::BackupTampered,
                ..
            }
        ),
        "{undo:?}"
    );
    assert!(fake.registers.borrow().is_empty());
}

#[test]
fn undo_of_an_op_that_changed_nothing() {
    let (b, fake, intent) = deleted("undo-nothing", vendor_task(), Reversibility::Full);
    for done in [
        ItemOutcome::Vanished,
        changed(),
        ItemOutcome::Failed {
            code: FailCode::ObjectApi,
            os_error: None,
            detail: String::new(),
        },
    ] {
        let TaskUndoPrepared::Decided(undo) = b.prepare_undo(&fake, &intent, Some(&done), &roots())
        else {
            panic!("ready");
        };
        assert_eq!(
            undo,
            TypedUndo::Done(UndoOutcome::NothingToUndo),
            "{done:?}"
        );
    }
    // Intent only (the run stopped during the delete): undone from what is there.
    assert!(matches!(
        b.prepare_undo(&fake, &intent, None, &roots()),
        TaskUndoPrepared::Ready(_)
    ));
    assert!(fake.registers.borrow().is_empty());
}

#[test]
fn fault_points_reached() {
    let (mut b, fake, intent) = deleted("faults", vendor_task(), Reversibility::Full);
    take_events();
    set_fault_observer(Some(fault_seen));
    let undo = b.undo(&fake, &intent, &roots());
    set_fault_observer(None);
    assert_eq!(undo, TypedUndo::Done(UndoOutcome::Restored));
    assert_eq!(take_events(), ["register", "fault:undo.act.after", "flush"]);

    // The act's points, in order around the delete and the flush (also in act_done_and_flush_order).
    let mut b = Bench::new("faults-act");
    let fake = Fake::with(vec![vendor_task()]);
    let intent = ready(&mut b, &fake);
    let token = b.journal.intent(intent.clone()).unwrap();
    set_fault_observer(Some(fault_seen));
    let acted = act_task(&fake, &b.ctx, &b.session, &intent, &token, &roots()).unwrap();
    set_fault_observer(None);
    assert_eq!(acted.delete_error, None);
    assert_eq!(
        take_events(),
        [
            "delete",
            "fault:objdelete.after",
            "flush",
            "fault:act.after"
        ]
    );
    let result = complete_task(&fake, &intent, Some(&acted));
    b.journal.done(token, result.outcome).unwrap();
}

// ---------------------------------------------------------------------------------------------------
// The real backend: VM rig only
// ---------------------------------------------------------------------------------------------------

/// Deletes and re-registers a disposable task through Task Scheduler. Runs only in the VM rig
/// (`PURGE_TEST_TASK_RIG=1`, elevated): it changes the machine's scheduled tasks.
#[test]
#[ignore = "registers, deletes and re-registers a scheduled task; runs only in the VM rig with PURGE_TEST_TASK_RIG=1"]
fn rig_live_delete_and_undo() {
    use purge_exec::act_task::WinTasks;
    assert_eq!(
        std::env::var("PURGE_TEST_TASK_RIG").as_deref(),
        Ok("1"),
        "refusing to touch Task Scheduler outside the VM rig"
    );
    let path = format!(r"\PurgeTest-{}\XTask", common::unique("t"));
    let actions = vec![TaskAction::Exec {
        path: format!(r"{ROOT}\does-not-exist.exe"),
        arguments: Some("--never".into()),
        working_dir: None,
    }];
    let xml = format!(
        r#"<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType></Principal></Principals>
  <Settings><Enabled>false</Enabled><AllowStartOnDemand>false</AllowStartOnDemand></Settings>
  <Actions Context="Author"><Exec><Command>{ROOT}\does-not-exist.exe</Command><Arguments>--never</Arguments></Exec></Actions>
</Task>"#
    );
    purge_win::taskschd::register_xml(&path, &xml, "").unwrap();
    let windir = std::env::var("WINDIR").unwrap();
    let backend = WinTasks::new(&windir);
    let identity = TaskIdentity {
        path: path.clone(),
        actions,
    };
    let mut b = Bench::new("rig");
    // The bench's context was made for PATH; give the rig task its own.
    let deny = DenyList::compile(&live_env(b._roots.data_root().to_str().unwrap()));
    let scope = b
        ._roots
        .store_scope(b.session.id(), &[] as &[&Path])
        .unwrap();
    b.ctx = GateCtx::new(deny, &[op(&path)], scope).unwrap();
    let cand = candidate(&path, Some(&identity), Reversibility::Full);
    let v = b.validate(&backend, &path, &cand);
    assert!(matches!(v, TaskValidate::Validated { .. }), "{v:?}");
    let TaskPrepared::Ready(ready) = b.prepare(&backend, Reversibility::Full) else {
        panic!("decided");
    };
    let intent = ready.intent().clone();
    let token = b.journal.intent(intent.clone()).unwrap();
    let result = delete_task(&backend, &b.ctx, &b.session, &intent, &token, &roots());
    b.journal.done(token, result.outcome.clone()).unwrap();
    assert_eq!(result.outcome, ItemOutcome::Done, "{result:?}");
    assert!(backend.read(&path).unwrap().is_none());
    let undo = b.undo(&backend, &intent, &roots());
    assert_eq!(undo, TypedUndo::Done(UndoOutcome::Restored));
    let back = backend.definition(&path).unwrap().unwrap();
    assert_eq!(back.xml, ready.definition().xml);
    assert_eq!(back.sddl, ready.definition().sddl);
    purge_win::taskschd::delete(&path).unwrap();
}
