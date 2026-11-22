//! Library tests of `plan.execute` through the serving loop (M3-EXEC): the in-memory transport, the
//! scripted consent dialog, the fixture machine of the flow tests and a scripted [`ExecBackend`].
//!
//! The executor itself (`execute_bound` on real stores, the object binding at act time, the journal) is
//! tested in `purge-exec`; the live wiring (`LiveExec`) needs an elevated process and a real store and is
//! VM work. Here is every refusal of the broker's own rules, and that the run is the plan object the
//! dialog was drawn from.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use purge_engine::pipeline::Settings;
use purge_exec::execute::{ExecError, ExecOutput, Progress as ExecProgress};
use purge_exec::plan_in::{BoundPlan, ExecSettings};
use purge_exec::prepare::RestorePointSetting;
use purge_model::exec::op::ItemOutcome;
use purge_model::exec::session::{
    ExecReport, ExecReportSchema, Locker, RestorePointOutcome, SessionId, SessionState,
};
use purge_model::{
    Action, AppRef, Band, Candidate, CandidateId, Category, Decision, FileTime, Fingerprint, Harm,
    Origin, Reversibility, ScanMode, Target, Tool,
};
use purge_plan::emit::{ScanDoc, ScanSchema};
use purge_rpc::error::{ErrorObject, Outcome};
use purge_rpc::methods::{OutcomeResult, PendingSession, PipeCall, UndoResult};
use purge_win::taskdialog::{Outcome as Answer, Page};
use serde_json::{Value, json};

use crate::backend::{Backend, BackendError, PendingReport};
use crate::baseline::BuildHandle;
use crate::broker::BrokerHandler;
use crate::execute::{ExecBackend, ExecFailure, ExecJob};
use crate::flow_tests::{
    FixtureMachine, LONG, app_fixture, ask, broker_id, create_selected, created_id,
    first_selectable, medium_id, prepared, scan_session,
};
use crate::lifetime::{Exit, ExitReason};
use crate::plan::Plan;
use crate::purge::{ExpirySource, Listing, Purger};
use crate::serve::{Ctx, Handler, Wiring, run_timed};
use crate::session::ScanSlot;
use crate::testkit::{
    Client, FakeBuild, FakeClock, FakeHost, FakeParent, Gate, HELLO, ME, MemNet, SECS,
    ScriptedConsent, expected, kind, request, test_limits,
};
use crate::undo::UndoMethods;

// ---------------------------------------------------------------------------------------------------
// The scripted parts
// ---------------------------------------------------------------------------------------------------

/// The undo side: only `pending` matters to `plan.execute`.
struct FakeUndo {
    pending: Mutex<Result<PendingReport, BackendError>>,
}

impl FakeUndo {
    fn new() -> Arc<FakeUndo> {
        Arc::new(FakeUndo {
            pending: Mutex::new(Ok(PendingReport::default())),
        })
    }
}

impl Backend for Arc<FakeUndo> {
    fn pending(&self) -> Result<PendingReport, BackendError> {
        self.pending.lock().unwrap().clone()
    }

    fn history(&self, _: &SessionId) -> Result<purge_rpc::methods::HistoryDetail, BackendError> {
        Err(BackendError::Gone)
    }

    fn undo_preview(
        &self,
        _: &SessionId,
        _: Option<&[purge_model::exec::op::OpId]>,
    ) -> Result<purge_exec::undo::UndoPreview, BackendError> {
        Err(BackendError::Gone)
    }

    fn places_taken(
        &self,
        _: &BoundPlan,
        _: &[purge_model::exec::op::OpId],
    ) -> Vec<purge_model::exec::op::OpId> {
        Vec::new()
    }

    fn undo(&self, _: &purge_exec::undo::UndoPreview) -> Result<UndoResult, BackendError> {
        Err(BackendError::Gone)
    }

    fn recover_preview(
        &self,
        _: &SessionId,
        _: purge_exec::recover::Want,
    ) -> Result<purge_exec::recover::RecoverPreview, BackendError> {
        Err(BackendError::Gone)
    }

    fn recover(
        &self,
        _: &purge_exec::recover::RecoverPreview,
        _: purge_exec::recover::Want,
    ) -> Result<OutcomeResult, BackendError> {
        Err(BackendError::Gone)
    }
}

/// An expiry store with nothing due.
struct NoExpiry;

impl ExpirySource for NoExpiry {
    fn now(&self) -> FileTime {
        FileTime(133_800_000_000_000_000)
    }

    fn listing(&self, _: FileTime) -> Result<Listing, purge_exec::storage::StorageError> {
        Ok(Listing::default())
    }

    fn purge(
        &self,
        _: &[purge_exec::expiry::ExpiryId],
        _: &purge_exec::expiry::PurgeConsent,
        _: FileTime,
    ) -> Result<purge_exec::expiry::PurgeReport, purge_exec::expiry::PurgeError> {
        panic!("not scripted")
    }
}

fn refused(error: ExecError) -> ExecFailure {
    ExecFailure::Exec(Box::new(error))
}

fn session_id() -> SessionId {
    SessionId::new(FileTime(133_800_000_000_000_000), 9)
}

/// What the scripted executor was given.
struct Called {
    plan: Arc<BoundPlan>,
    settings: ExecSettings,
    fingerprint: Arc<Fingerprint>,
}

/// The executor: records what it was given, can be held in flight, and answers a scripted output (or
/// a report in which every item is done).
struct FakeExec {
    called: Mutex<Vec<Called>>,
    next: Mutex<Option<Result<ExecOutput, ExecFailure>>>,
    hold: Gate,
    holding: AtomicBool,
    started: Gate,
    completed: AtomicUsize,
}

impl FakeExec {
    fn new() -> Arc<FakeExec> {
        Arc::new(FakeExec {
            called: Mutex::new(Vec::new()),
            next: Mutex::new(None),
            hold: Gate::default(),
            holding: AtomicBool::new(false),
            started: Gate::default(),
            completed: AtomicUsize::new(0),
        })
    }

    fn script(&self, result: Result<ExecOutput, ExecFailure>) {
        *self.next.lock().unwrap() = Some(result);
    }

    fn hold_runs(&self) {
        self.holding.store(true, Ordering::SeqCst);
    }

    fn calls(&self) -> usize {
        self.called.lock().unwrap().len()
    }
}

fn output_of(plan: &BoundPlan) -> ExecOutput {
    let items: Vec<purge_model::exec::session::ItemReport> = plan
        .items()
        .iter()
        .map(|item| {
            let candidate = plan
                .candidate(item)
                .expect("a bound item has its candidate");
            purge_model::exec::session::ItemReport {
                item: candidate.id.clone(),
                op: item.op,
                target: candidate.target.clone(),
                exec_op: item.exec_op.clone(),
                outcome: ItemOutcome::Done,
                backup_bytes: 0,
                lockers: Vec::new(),
            }
        })
        .collect();
    output_with(plan, items)
}

fn output_with(plan: &BoundPlan, items: Vec<purge_model::exec::session::ItemReport>) -> ExecOutput {
    let mut counts = purge_model::exec::op::OutcomeCounts::default();
    for item in &items {
        counts.record(&item.outcome);
    }
    ExecOutput {
        session: session_id(),
        report: ExecReport {
            schema: ExecReportSchema,
            session: session_id(),
            app: plan.scan().app.clone(),
            plan_hash: plan.plan_hash(),
            selection_hash: plan.selection_hash(),
            state: SessionState::Committed,
            started: FileTime(1),
            finished: FileTime(2),
            items,
            counts,
            backup_bytes: 0,
            pending_reboot: false,
            restore_point: RestorePointOutcome::NotRequested,
            warnings: Vec::new(),
        },
        closed: true,
        report_written: true,
        index_updated: true,
    }
}

impl ExecBackend for FakeExec {
    fn now(&self) -> FileTime {
        // 2026-11-21 00:00 UTC.
        FileTime(134_080_000_000_000_000)
    }

    fn execute(
        &self,
        job: ExecJob,
        progress: &dyn Fn(&ExecProgress<'_>),
    ) -> Result<ExecOutput, ExecFailure> {
        self.called.lock().unwrap().push(Called {
            plan: job.plan.clone(),
            settings: job.settings.clone(),
            fingerprint: job.fingerprint.clone(),
        });
        self.started.open();
        let id = session_id();
        progress(&ExecProgress::SessionCreated {
            session: &id,
            path: Path::new("session"),
            items: u32::try_from(job.plan.items().len()).unwrap_or(u32::MAX),
        });
        if self.holding.load(Ordering::SeqCst) {
            assert!(self.hold.wait(SECS * 3), "the held run was never released");
        }
        let scripted = self.next.lock().unwrap().take();
        let result = scripted.unwrap_or_else(|| Ok(output_of(&job.plan)));
        if let Ok(output) = &result {
            for item in &output.report.items {
                progress(&ExecProgress::ItemFinished {
                    op: item.op,
                    outcome: &item.outcome,
                });
            }
            self.completed.fetch_add(1, Ordering::SeqCst);
        }
        result
    }
}

// ---------------------------------------------------------------------------------------------------
// The handler and the harness
// ---------------------------------------------------------------------------------------------------

/// A scan and its fingerprint a test puts in the tables through `journal.pending` (which the wrapper
/// answers instead of the broker): the broker's own scan is built from a harvest, and these cases
/// need documents a fixture machine does not make.
type Seed = (ScanDoc, Fingerprint);

/// The broker's handler, with the plans and scans it created kept for the test.
struct Wrapped {
    inner: BrokerHandler<Arc<FakeUndo>>,
    plans: Arc<Mutex<Vec<Arc<Plan>>>>,
    scans: Arc<Mutex<Vec<Arc<ScanSlot<crate::scan::Scan>>>>>,
    seeds: Arc<Mutex<Vec<Seed>>>,
    vanish: Arc<Mutex<Vec<String>>>,
}

impl Handler for Wrapped {
    type Session = crate::uninstall::Session;
    type Scan = crate::scan::Scan;
    type Plan = crate::plan::Plan;

    fn call(&self, ctx: &Ctx<'_, Self>, call: PipeCall) -> Result<Value, ErrorObject> {
        match call {
            // Uninstall sessions a test takes out of the table without a run (no method does that: a
            // run removes its session and spends the program's scans at once).
            PipeCall::JournalPending(_) if !self.vanish.lock().unwrap().is_empty() => {
                let ids: Vec<String> = self.vanish.lock().unwrap().drain(..).collect();
                let removed = ids
                    .iter()
                    .filter(|id| ctx.tables().sessions.remove(id.parse().unwrap()))
                    .count();
                Ok(json!({ "vanished": removed }))
            }
            PipeCall::JournalPending(_) if !self.seeds.lock().unwrap().is_empty() => {
                let (doc, fingerprint) = self.seeds.lock().unwrap().remove(0);
                let scan = crate::scan::Scan::for_test(doc, fingerprint, ME);
                let id = ctx.add_scan(scan)?;
                if let Ok(slot) = ctx.tables().scans.get(id) {
                    self.scans.lock().unwrap().push(slot);
                }
                Ok(json!({ "seeded_scan": id.to_string() }))
            }
            PipeCall::PlanCreate(params) => {
                let out = self.inner.dispatch(ctx, PipeCall::PlanCreate(params))?;
                let id = out["plan_id"].as_str().unwrap_or_default().parse().unwrap();
                if let Ok(plan) = ctx.tables().plans.get(id) {
                    self.plans.lock().unwrap().push(plan);
                }
                Ok(out)
            }
            PipeCall::LeftoversScan(params) => {
                let out = self.inner.dispatch(ctx, PipeCall::LeftoversScan(params))?;
                let id = out["scan_id"].as_str().unwrap_or_default().parse().unwrap();
                if let Ok(scan) = ctx.tables().scans.get(id) {
                    self.scans.lock().unwrap().push(scan);
                }
                Ok(out)
            }
            other => self.inner.dispatch(ctx, other),
        }
    }
}

struct Rig {
    net: MemNet,
    parent: Arc<FakeParent>,
    consent: Arc<ScriptedConsent>,
    exec: Arc<FakeExec>,
    undo: Arc<FakeUndo>,
    plans: Arc<Mutex<Vec<Arc<Plan>>>>,
    scans: Arc<Mutex<Vec<Arc<ScanSlot<crate::scan::Scan>>>>>,
    seeds: Arc<Mutex<Vec<Seed>>>,
    vanish: Arc<Mutex<Vec<String>>>,
    join: Option<JoinHandle<Exit>>,
}

impl Rig {
    fn start() -> Rig {
        Rig::start_timed(crate::timing::Timings::default())
    }

    fn start_timed(timings: crate::timing::Timings) -> Rig {
        let net = MemNet::default();
        let clock = Arc::new(FakeClock::default());
        let parent = Arc::new(FakeParent::default());
        let consent = Arc::new(ScriptedConsent::default());
        consent.announce_shown();
        let exec = FakeExec::new();
        let undo = FakeUndo::new();
        let plans = Arc::new(Mutex::new(Vec::new()));
        let scans = Arc::new(Mutex::new(Vec::new()));
        let seeds = Arc::new(Mutex::new(Vec::new()));
        let vanish = Arc::new(Mutex::new(Vec::new()));
        let machine = Arc::new(FixtureMachine::new(app_fixture()));
        let handler = Wrapped {
            inner: BrokerHandler::new(
                crate::uninstall::Flow::new(machine),
                Purger::new(Arc::new(NoExpiry)),
                UndoMethods::new(undo.clone()),
                exec.clone(),
            ),
            plans: plans.clone(),
            scans: scans.clone(),
            seeds: seeds.clone(),
            vanish: vanish.clone(),
        };
        let wiring = Wiring {
            link: net.link(),
            handler,
            expected: expected(),
            parent: parent.clone(),
            consent: Arc::new(consent.clone()),
            host: Arc::new(FakeHost),
            clock,
            build: Some(FakeBuild::new(purge_rpc::BaselineBuild::None {
                reason: "test".into(),
            }) as Arc<dyn BuildHandle>),
            settings: Settings::default(),
            limits: test_limits(),
        };
        let timings = Arc::new(timings);
        let join = std::thread::spawn(move || run_timed(wiring, timings));
        Rig {
            net,
            parent,
            consent,
            exec,
            undo,
            plans,
            scans,
            seeds,
            vanish,
            join: Some(join),
        }
    }

    fn client(&self) -> Client {
        let c = self.net.connect(Ok(()));
        c.send_line(HELLO);
        let hello = c.reply();
        assert_eq!(hello["id"], 1, "{hello}");
        c
    }

    fn exit(&mut self, timeout: Duration) -> Exit {
        let join = self.join.take().expect("the broker was running");
        let deadline = std::time::Instant::now() + timeout;
        while !join.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "the broker did not end"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        join.join().unwrap()
    }

    fn running(&self) -> bool {
        std::thread::sleep(Duration::from_millis(150));
        self.join.as_ref().is_some_and(|j| !j.is_finished())
    }

    fn plan(&self) -> Arc<Plan> {
        self.plans.lock().unwrap().last().cloned().expect("a plan")
    }

    fn scan(&self) -> Arc<ScanSlot<crate::scan::Scan>> {
        self.scans.lock().unwrap().last().cloned().expect("a scan")
    }

    fn dialog_opens(&self) -> bool {
        self.consent.wait_open(Duration::from_millis(300))
    }

    fn put_seed(&self, doc: ScanDoc, fingerprint: Fingerprint) {
        self.seeds.lock().unwrap().push((doc, fingerprint));
    }
}

/// The next line with an id, with the notifications before it.
fn answer_with_notes(c: &Client) -> (Value, Vec<Value>) {
    let mut notes = Vec::new();
    loop {
        let line = c.recv(LONG).expect("an answer");
        if line.get("id").is_some() {
            return (line, notes);
        }
        notes.push(line);
    }
}

fn answer_of(c: &Client) -> Value {
    answer_with_notes(c).0
}

fn execute_params(plan: &str, restore_point: &str) -> Value {
    json!({ "plan_id": plan, "restore_point": restore_point })
}

/// Sends `plan.execute`, waits for its dialog, answers it, and returns the reply and the notifications.
fn execute_answering(
    rig: &Rig,
    c: &Client,
    id: u64,
    plan: &str,
    restore_point: &str,
    answer: Answer,
) -> (Value, Vec<Value>) {
    c.send_line(&request(
        id,
        "plan.execute",
        &execute_params(plan, restore_point),
    ));
    assert!(rig.consent.wait_open(SECS), "the dialog did not open");
    rig.consent.answer(answer);
    answer_with_notes(c)
}

fn text_of(pages: &[Page]) -> String {
    format!("{pages:?}")
}

/// One session scanned (forced) and planned over its first selectable item, through the flow.
struct Planned {
    sessions: Vec<String>,
    scan: String,
    item: String,
    plan: String,
}

/// Prepares `programs`, scans the first as `forced` and plans its first selectable item. Request ids
/// 2 to 5 are used.
fn planned(rig: &Rig, c: &Client, programs: &[purge_model::ProgramId]) -> Planned {
    let prepare = prepared(c, 2, programs);
    let sessions: Vec<String> = prepare["result"]["programs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["session_id"].as_str().unwrap().to_owned())
        .collect();
    let scan = scan_session(c, 3, &sessions[0], true);
    let scan_id = scan["result"]["scan_id"].as_str().unwrap().to_owned();
    let item = first_selectable(&rig.scan().scan).id.0.clone();
    let reply = create_selected(c, 4, &scan_id, &[&item]);
    let plan = created_id(&reply);
    Planned {
        sessions,
        scan: scan_id,
        item,
        plan,
    }
}

// ---------------------------------------------------------------------------------------------------
// Seeded documents
// ---------------------------------------------------------------------------------------------------

fn cid(n: u64) -> CandidateId {
    CandidateId(format!("c-{n:016x}"))
}

fn candidate(n: u64, target: Target, action: Action) -> Candidate {
    Candidate {
        id: cid(n),
        target,
        action,
        owner: AppRef {
            program_id: "HKLM|64|VendorApp".parse().unwrap(),
            display_name: "Vendor App".into(),
        },
        origin: Origin::Scanner,
        scanner: "TEST".into(),
        category: Category::AppFiles,
        evidence: Vec::new(),
        blockers: Vec::new(),
        harm: Harm::Low,
        reversibility: Reversibility::Full,
        children: Vec::new(),
        size_bytes: None,
        child_count: None,
        item_fp: None,
        object_fp: None,
        display_name: None,
        owner_program: None,
        decision: Some(Decision {
            band: Band::Safe,
            preselected: true,
            score: 9,
            explanation: "test".into(),
        }),
    }
}

fn file(n: u64) -> Candidate {
    candidate(
        n,
        Target::Path {
            path: format!(r"C:\Vendor\file{n}.txt"),
        },
        Action::Quarantine,
    )
}

fn package(n: u64) -> Candidate {
    Candidate {
        category: Category::Package,
        reversibility: Reversibility::None,
        ..candidate(
            n,
            Target::AppxPackage {
                full_name: "Vendor.App_1.0.0.0_x64__abcdefghijklm".into(),
            },
            Action::RemovePackage,
        )
    }
}

fn task_identity() -> purge_model::TaskIdentity {
    purge_model::TaskIdentity {
        path: r"\Vendor\Update".into(),
        actions: Vec::new(),
    }
}

fn task(n: u64) -> Candidate {
    let identity = task_identity();
    Candidate {
        object_fp: Some(identity.fp()),
        ..candidate(
            n,
            Target::Task {
                path: identity.path.clone(),
            },
            Action::DeleteKey,
        )
    }
}

fn doc_of(items: Vec<Candidate>) -> ScanDoc {
    let mut doc = ScanDoc {
        schema: ScanSchema,
        app: "vendor-app".into(),
        tool: Tool::Purge,
        mode: ScanMode::Post,
        policy_version: "m1a.6".into(),
        plan_hash: String::new(),
        items,
        absorbed: Vec::new(),
    };
    doc.plan_hash = purge_plan::hash::plan_hash(&doc.items, &doc.policy_version, doc.mode);
    doc
}

fn fingerprint(program: &str, tasks: Vec<purge_model::SysTask>) -> Fingerprint {
    let mut fp: Fingerprint = serde_json::from_value(json!({
        "schema": "purge.fp/0",
        "app": {"program_id": program, "display_name": "Vendor App"},
        "identity": {"names": [], "vendors": [], "tokens": [], "mega_vendor": false},
        "os": {"edition": "Professional", "build": 26340, "ubr": 9882},
        "user_sid": ME
    }))
    .unwrap();
    fp.sys.tasks = tasks;
    fp
}

fn vouching_task() -> purge_model::SysTask {
    purge_model::SysTask {
        identity: task_identity(),
        program: None,
        why: purge_model::ObjectWhy::ProgramInRoot,
    }
}

/// Takes uninstall session `session` out of the broker's table without a run (through `journal.pending`,
/// which the wrapper answers instead of the broker).
fn vanish_session(rig: &Rig, c: &Client, id: u64, session: &str) {
    rig.vanish.lock().unwrap().push(session.to_owned());
    let reply = ask(c, id, "journal.pending", json!({}));
    assert_eq!(reply["result"]["vanished"], 1, "{reply}");
}

/// Seeds `doc` and returns the scan id the broker gave it.
fn seed(rig: &Rig, c: &Client, id: u64, doc: ScanDoc, fp: Fingerprint) -> String {
    rig.put_seed(doc, fp);
    let reply = ask(c, id, "journal.pending", json!({}));
    reply["result"]["seeded_scan"]
        .as_str()
        .unwrap_or_else(|| panic!("not seeded: {reply}"))
        .to_owned()
}

fn plan_selected(
    c: &Client,
    id: u64,
    scan: &str,
    selected: &[CandidateId],
    allow_irreversible: bool,
) -> Value {
    let ids: Vec<&str> = selected.iter().map(|c| c.0.as_str()).collect();
    ask(
        c,
        id,
        "plan.create",
        json!({ "scan_id": scan, "selected": ids, "allow_irreversible": allow_irreversible }),
    )
}

// ---------------------------------------------------------------------------------------------------
// Approve, decline, reuse (B3, B4; "a plan id is used once")
// ---------------------------------------------------------------------------------------------------

/// An approved plan runs the very object the dialog was drawn from, with the account and roots the
/// plan froze, the fingerprint of its scan and the restore-point setting of the request; progress
/// is sent; the answer is the run's outcome; and the completed change ends the broker.
#[test]
fn an_approved_plan_runs_the_plan_object_the_dialog_was_drawn_from() {
    let mut rig = Rig::start();
    let c = rig.client();
    let p = planned(&rig, &c, &[broker_id()]);
    let frozen = rig.plan();

    c.send_line(&request(
        5,
        "plan.execute",
        &execute_params(&p.plan, "always"),
    ));
    assert!(rig.consent.wait_open(SECS));
    // The dialog is drawn from the frozen plan: its code is the plan's, its text names the item.
    let pages = rig.consent.pages();
    let text = text_of(&pages);
    assert!(text.contains(&frozen.code.to_string()), "{text}");
    assert!(
        text.contains("restore point"),
        "an `always` request says a restore point is asked for: {text}"
    );
    assert_eq!(rig.exec.calls(), 0, "nothing runs before the answer");
    rig.consent.answer(Answer::Approved);
    let (reply, notes) = answer_with_notes(&c);

    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    assert_eq!(reply["result"]["session"], session_id().to_string());
    assert_eq!(reply["result"]["counts"]["done"], 1);
    assert_eq!(rig.exec.calls(), 1);
    let called = rig.exec.called.lock().unwrap();
    assert!(
        Arc::ptr_eq(&called[0].plan, &frozen.bound),
        "the executor got the object the dialog was drawn from"
    );
    assert!(Arc::ptr_eq(
        &called[0].fingerprint,
        &rig.scan().scan.fingerprint
    ));
    assert_eq!(
        called[0].settings.restore_point,
        RestorePointSetting::Always
    );
    assert_eq!(called[0].settings.user_sid.as_deref(), Some(ME));
    assert_eq!(
        called[0].settings.program_roots,
        frozen.settings.program_roots
    );
    drop(called);
    let methods: Vec<&str> = notes.iter().filter_map(|n| n["method"].as_str()).collect();
    assert!(methods.contains(&"consent.shown"), "{methods:?}");
    assert!(methods.contains(&"exec.progress"), "{methods:?}");
    assert_eq!(p.sessions.len(), 1);

    // A completed change with no session left ends the broker once the client closes.
    c.close();
    assert_eq!(rig.exit(SECS).reason, ExitReason::CompletedChange);
}

/// The marks of a result's `timings` (design 9.1): name and ms, after a check that they never go back.
fn timing_marks(reply: &Value) -> Vec<(String, u64)> {
    let marks: Vec<(String, u64)> = reply["result"]["timings"]["marks"]
        .as_array()
        .unwrap_or_else(|| panic!("no timings in {reply}"))
        .iter()
        .map(|m| {
            (
                m["mark"].as_str().unwrap().to_owned(),
                m["ms"].as_u64().unwrap(),
            )
        })
        .collect();
    assert!(
        marks.windows(2).all(|w| w[0].1 <= w[1].1),
        "the marks go back: {marks:?}"
    );
    marks
}

/// The names of the marks, `first_progress` checked against the progress lines and then left out (a
/// step may or may not send one): present exactly when a `*.progress` line of the request was sent,
/// and then right after the start mark and before the end mark.
fn timing_names(reply: &Value, notes: &[Value], start: &str) -> Vec<String> {
    let names: Vec<String> = timing_marks(reply).into_iter().map(|m| m.0).collect();
    let progressed = notes.iter().any(|n| {
        n["method"]
            .as_str()
            .is_some_and(|m| m.ends_with(".progress"))
            && n["params"]["request"] == reply["id"]
    });
    let first = names.iter().position(|n| n == "first_progress");
    assert_eq!(first.is_some(), progressed, "{names:?} {notes:?}");
    if let Some(at) = first {
        let started = names.iter().position(|n| n == start).unwrap();
        assert!(started < at && at + 1 < names.len(), "{names:?}");
    }
    names
        .into_iter()
        .filter(|n| n != "first_progress")
        .collect()
}

/// The flow's four timed results carry their marks (design 9.1, gate G12): the process mark, then the
/// request's own, in order and never going back.
#[test]
fn the_flow_results_carry_their_timing_marks_in_order() {
    let mut rig = Rig::start();
    let c = rig.client();
    let (prepare, notes) = {
        c.send_line(&request(
            2,
            "uninstall.prepare",
            &json!({ "program_ids": [broker_id()] }),
        ));
        answer_with_notes(&c)
    };
    assert_eq!(
        timing_names(&prepare, &notes, "harvest_start"),
        ["pipe_connected", "harvest_start", "harvest_complete"]
    );
    let session = prepare["result"]["programs"][0]["session_id"]
        .as_str()
        .unwrap()
        .to_owned();

    c.send_line(&request(
        3,
        "leftovers.scan",
        &json!({ "session_id": session, "forced": true }),
    ));
    let (scan, notes) = answer_with_notes(&c);
    assert_eq!(
        timing_names(&scan, &notes, "scan_start"),
        ["pipe_connected", "scan_start", "scan_complete"]
    );
    let scan_id = scan["result"]["scan_id"].as_str().unwrap().to_owned();
    let item = first_selectable(&rig.scan().scan).id.0.clone();
    let plan = create_selected(&c, 4, &scan_id, &[&item]);
    assert_eq!(
        timing_names(&plan, &[], "plan_ready"),
        ["pipe_connected", "plan_ready"]
    );
    // The process mark is the same in every result.
    assert_eq!(timing_marks(&prepare)[0], timing_marks(&plan)[0]);

    let (done, notes) = execute_answering(&rig, &c, 5, &created_id(&plan), "off", Answer::Approved);
    assert_eq!(done["result"]["outcome"], "complete", "{done}");
    assert_eq!(
        timing_names(&done, &notes, "execute_start"),
        [
            "pipe_connected",
            "consent_shown",
            "consent_answered",
            "execute_start",
            "execute_complete"
        ]
    );
    // Later requests count on from earlier ones: one clock for the whole process.
    let last = |reply: &Value| *timing_marks(reply).last().map(|(_, ms)| ms).unwrap();
    assert!(last(&prepare) <= last(&scan) && last(&scan) <= last(&plan));
    assert!(last(&plan) <= last(&done));
    c.close();
    assert_eq!(rig.exit(SECS).reason, ExitReason::CompletedChange);
}

/// A timer that cannot be read, or panics, leaves the `timings` member out and changes nothing else:
/// the same flow runs to the same end.
#[test]
fn a_failing_timer_changes_no_step_of_the_flow() {
    use std::sync::atomic::Ordering::SeqCst;
    for panics in [false, true] {
        let steps = Arc::new(crate::timing::tests::Steps::default());
        if panics {
            steps.panic.store(true, SeqCst);
        } else {
            steps.fail.store(true, SeqCst);
        }
        let mut rig = Rig::start_timed(crate::timing::Timings::new(steps, 7));
        let c = rig.client();
        let p = planned(&rig, &c, &[broker_id()]);
        let (done, _) = execute_answering(&rig, &c, 5, &p.plan, "off", Answer::Approved);
        assert_eq!(done["result"]["outcome"], "complete", "{done}");
        assert!(done["result"].get("timings").is_none(), "{done}");
        assert_eq!(rig.exec.calls(), 1);
        c.close();
        assert_eq!(rig.exit(SECS).reason, ExitReason::CompletedChange);
    }
}

/// The restore point follows the request's enum. The dialog says one is asked for only when it will be:
/// `always`, or `high_risk` over a high-risk plan (a forced-mode scan is one); never for `off`.
#[test]
fn the_restore_point_setting_is_the_requests_enum() {
    for (name, expected, line) in [
        ("off", RestorePointSetting::Off, false),
        ("high_risk", RestorePointSetting::HighRiskOnly, false),
        ("always", RestorePointSetting::Always, true),
    ] {
        let mut rig = Rig::start();
        let c = rig.client();
        let scan = seed(
            &rig,
            &c,
            2,
            doc_of(vec![file(1)]),
            fingerprint("HKLM|64|VendorApp", Vec::new()),
        );
        let reply = plan_selected(&c, 3, &scan, &[cid(1)], false);
        let plan = created_id(&reply);
        let (reply, _) = execute_answering(&rig, &c, 4, &plan, name, Answer::Approved);
        assert_eq!(reply["result"]["outcome"], "complete", "{name}: {reply}");
        assert_eq!(
            rig.exec.called.lock().unwrap()[0].settings.restore_point,
            expected
        );
        assert_eq!(
            text_of(&rig.consent.pages()).contains("restore point"),
            line,
            "{name}"
        );
        c.close();
        rig.exit(SECS);
    }

    // A forced-mode scan is high-risk: `high_risk` asks, and the dialog says so.
    let mut rig = Rig::start();
    let c = rig.client();
    let p = planned(&rig, &c, &[broker_id()]);
    let (reply, _) = execute_answering(&rig, &c, 5, &p.plan, "high_risk", Answer::Approved);
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    assert!(text_of(&rig.consent.pages()).contains("restore point"));
    c.close();
    rig.exit(SECS);
}
/// Decline does nothing and leaves no session; the plan id is spent, the scan can have a new plan, and
/// the broker keeps serving.
#[test]
fn a_declined_dialog_changes_nothing_and_the_scan_can_be_planned_again() {
    let mut rig = Rig::start();
    let c = rig.client();
    let p = planned(&rig, &c, &[broker_id(), medium_id()]);

    let (reply, _) = execute_answering(&rig, &c, 5, &p.plan, "off", Answer::Declined);
    assert_eq!(kind(&reply), "consent_declined", "{reply}");
    assert_eq!(rig.exec.calls(), 0);
    assert!(rig.running(), "a declined change does not end the broker");

    // The id was used: executing it again is `gone`, with no dialog.
    c.send_line(&request(6, "plan.execute", &execute_params(&p.plan, "off")));
    let again = answer_of(&c);
    assert_eq!(kind(&again), "gone", "{again}");
    assert!(!rig.dialog_opens());

    // Nothing ran, so the scan's claim was given back: it can have its next plan.
    let next = create_selected(&c, 7, &p.scan, &[&p.item]);
    assert!(next["result"]["plan_id"].is_string(), "{next}");
    assert_ne!(created_id(&next), p.plan);
    c.close();
    rig.exit(SECS);
}

/// A plan id is used once: after a run the same id is `gone`, no dialog opens and nothing runs again,
/// and the scan stays claimed (its machine has changed: it is scanned again, not planned again).
#[test]
fn a_plan_id_runs_once_and_its_scan_is_spent() {
    let mut rig = Rig::start();
    let c = rig.client();
    // Two sessions, so that the first run does not end the broker.
    let p = planned(&rig, &c, &[broker_id(), medium_id()]);
    let (reply, _) = execute_answering(&rig, &c, 5, &p.plan, "off", Answer::Approved);
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    assert_eq!(rig.exec.calls(), 1);

    c.send_line(&request(6, "plan.execute", &execute_params(&p.plan, "off")));
    let again = answer_of(&c);
    assert_eq!(kind(&again), "gone", "{again}");
    assert!(!rig.dialog_opens(), "a used plan opens no dialog");
    assert_eq!(rig.exec.calls(), 1);

    let second = create_selected(&c, 7, &p.scan, &[&p.item]);
    assert_eq!(kind(&second), "plan_refused", "{second}");

    // The spent uninstall session is gone; the other one is still there.
    let spent = scan_session(&c, 8, &p.sessions[0], true);
    assert_eq!(kind(&spent), "gone", "{spent}");
    let kept = scan_session(&c, 9, &p.sessions[1], true);
    assert!(kept["result"]["scan_id"].is_string(), "{kept}");
    c.close();
    rig.exit(SECS);
}

/// Ids the broker does not hold (a plan of another broker, a scan id or session id in the plan's
/// place, a path) never open a dialog and never reach the executor.
#[test]
fn ids_that_are_not_this_brokers_plans_never_open_a_dialog() {
    let mut rig = Rig::start();
    let c = rig.client();
    let p = planned(&rig, &c, &[broker_id(), medium_id()]);

    c.send_line(&request(
        5,
        "plan.execute",
        &execute_params("p-0123456789abcdef", "off"),
    ));
    let foreign = answer_of(&c);
    assert_eq!(kind(&foreign), "gone", "{foreign}");

    for (n, wrong) in [
        (6, p.scan.as_str()),
        (7, p.sessions[0].as_str()),
        (8, r"C:\Windows\System32"),
        (9, ""),
    ] {
        c.send_line(&request(n, "plan.execute", &execute_params(wrong, "off")));
        let reply = answer_of(&c);
        assert!(reply.get("error").is_some(), "{wrong}: {reply}");
        assert_ne!(
            reply["error"]["data"]["kind"], "runtime",
            "{wrong}: {reply}"
        );
    }
    // A field the request does not have is refused as well.
    c.send_line(&request(
        10,
        "plan.execute",
        &json!({ "plan_id": p.plan, "restore_point": "off", "path": r"C:\x" }),
    ));
    assert!(answer_of(&c).get("error").is_some());
    assert!(!rig.dialog_opens());
    assert_eq!(rig.exec.calls(), 0);

    // The real plan is untouched by all of it.
    let (reply, _) = execute_answering(&rig, &c, 11, &p.plan, "off", Answer::Approved);
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    c.close();
    rig.exit(SECS);
}

/// Two programs, two scans, two plans: each plan id runs the object frozen for it, and neither can run
/// the other's.
#[test]
fn a_plan_runs_its_own_scans_object_and_not_another() {
    let mut rig = Rig::start();
    let c = rig.client();
    let prepare = prepared(&c, 2, &[broker_id(), medium_id()]);
    let sessions: Vec<String> = prepare["result"]["programs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["session_id"].as_str().unwrap().to_owned())
        .collect();
    let scan_a = scan_session(&c, 3, &sessions[0], true);
    let scan_a = scan_a["result"]["scan_id"].as_str().unwrap().to_owned();
    let item_a = first_selectable(&rig.scan().scan).id.0.clone();
    let reply = create_selected(&c, 4, &scan_a, &[&item_a]);
    let plan_a = created_id(&reply);
    let first = rig.plan();

    let scan_b = scan_session(&c, 5, &sessions[1], true);
    let scan_b = scan_b["result"]["scan_id"].as_str().unwrap().to_owned();
    let item_b = first_selectable(&rig.scan().scan).id.0.clone();
    let reply = create_selected(&c, 6, &scan_b, &[&item_b]);
    let plan_b = created_id(&reply);
    let second = rig.plan();
    assert!(!Arc::ptr_eq(&first.bound, &second.bound));

    let (reply, _) = execute_answering(&rig, &c, 7, &plan_b, "off", Answer::Approved);
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    {
        let called = rig.exec.called.lock().unwrap();
        assert!(Arc::ptr_eq(&called[0].plan, &second.bound));
        assert!(!Arc::ptr_eq(&called[0].plan, &first.bound));
    }
    // The other program is another scan and another plan: still its own object, still unused.
    let (reply, _) = execute_answering(&rig, &c, 8, &plan_a, "off", Answer::Approved);
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    let called = rig.exec.called.lock().unwrap();
    assert!(Arc::ptr_eq(&called[1].plan, &first.bound));
    drop(called);
    c.close();
    rig.exit(SECS);
}

/// M3-R2 S2: a run spends every scan of its program, not only the plan's. A sibling scan made before
/// the run can be neither planned nor run afterwards; a fresh scan from the stored fingerprint
/// describes the machine now and can.
#[test]
fn a_run_spends_every_scan_of_the_program() {
    let mut rig = Rig::start();
    let c = rig.client();
    let p = planned(&rig, &c, &[broker_id(), medium_id()]);
    // A sibling scan of the same session, made and planned before the run.
    let sibling = scan_session(&c, 5, &p.sessions[0], true);
    let sibling_id = sibling["result"]["scan_id"].as_str().unwrap().to_owned();
    let sibling_plan = created_id(&create_selected(&c, 6, &sibling_id, &[&p.item]));

    let (reply, _) = execute_answering(&rig, &c, 7, &p.plan, "off", Answer::Approved);
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    assert_eq!(rig.exec.calls(), 1);

    // A plan already made from the sibling scan cannot run: its document is the machine before the run.
    c.send_line(&request(
        8,
        "plan.execute",
        &execute_params(&sibling_plan, "off"),
    ));
    let refused_plan = answer_of(&c);
    assert_eq!(kind(&refused_plan), "plan_refused", "{refused_plan}");
    assert!(!rig.dialog_opens(), "a spent scan opens no dialog");
    assert_eq!(rig.exec.calls(), 1);

    // A new plan from that scan is refused too.
    let refused_create = create_selected(&c, 9, &sibling_id, &[&p.item]);
    assert_eq!(kind(&refused_create), "plan_refused", "{refused_create}");

    // A fresh scan (from the stored fingerprint) is not spent and can be planned.
    let fresh = ask(
        &c,
        10,
        "leftovers.scan",
        json!({ "program_id": broker_id() }),
    );
    let fresh_id = fresh["result"]["scan_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{fresh}"))
        .to_owned();
    let fresh_item = first_selectable(&rig.scan().scan).id.0.clone();
    let planned_from_fresh = create_selected(&c, 11, &fresh_id, &[&fresh_item]);
    assert!(
        planned_from_fresh["result"]["plan_id"].is_string(),
        "{planned_from_fresh}"
    );
    c.close();
    rig.exit(SECS);
}

/// M3-R2 S2: a scan whose uninstall session is no longer in the table, and that no run has spent, is
/// refused by `plan.create` as `plan_refused` "scan again" (not `gone`: the scan id is valid), before
/// any dialog and with nothing run. A scan of another session that is still there is planned as usual.
#[test]
fn a_scan_whose_session_vanished_cannot_be_planned_until_scanned_again() {
    let mut rig = Rig::start();
    let c = rig.client();
    let prepare = prepared(&c, 2, &[broker_id(), medium_id()]);
    let sessions: Vec<String> = prepare["result"]["programs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["session_id"].as_str().unwrap().to_owned())
        .collect();
    let orphan = scan_session(&c, 3, &sessions[0], true);
    let orphan_id = orphan["result"]["scan_id"].as_str().unwrap().to_owned();
    let orphan_slot = rig.scan();
    let orphan_item = first_selectable(&orphan_slot.scan).id.0.clone();
    let kept = scan_session(&c, 4, &sessions[1], true);
    let kept_id = kept["result"]["scan_id"].as_str().unwrap().to_owned();
    let kept_item = first_selectable(&rig.scan().scan).id.0.clone();

    vanish_session(&rig, &c, 5, &sessions[0]);
    // Nothing ran: the scan is not spent, so the refusal below is the vanished session's own.
    assert!(!orphan_slot.scan.spent());
    let gone = scan_session(&c, 6, &sessions[0], true);
    assert_eq!(kind(&gone), "gone", "{gone}");

    let refused = create_selected(&c, 7, &orphan_id, &[&orphan_item]);
    assert_eq!(kind(&refused), "plan_refused", "{refused}");
    let reason = refused["error"]["data"]["refusals"][0]["reason"]
        .as_str()
        .unwrap_or_default();
    assert!(
        reason.contains("session") && reason.ends_with("scan again"),
        "{refused}"
    );
    assert!(!rig.dialog_opens(), "a refused plan opens no dialog");
    assert_eq!(rig.exec.calls(), 0);

    // The control: a scan of a session still in the table, not spent, is planned.
    let planned = create_selected(&c, 8, &kept_id, &[&kept_item]);
    assert!(planned["result"]["plan_id"].is_string(), "{planned}");
    assert_eq!(rig.exec.calls(), 0);
    c.close();
    rig.exit(SECS);
}

// ---------------------------------------------------------------------------------------------------
// Pending sessions, a dialog that cannot be drawn
// ---------------------------------------------------------------------------------------------------

#[test]
fn an_interrupted_session_blocks_execute_before_any_dialog() {
    let mut rig = Rig::start();
    let c = rig.client();
    let p = planned(&rig, &c, &[broker_id(), medium_id()]);
    *rig.undo.pending.lock().unwrap() = Ok(PendingReport {
        open: vec![PendingSession {
            session: session_id(),
            app: "Vendor App".into(),
            started: FileTime(133_800_000_000_000_000),
            done: 1,
            total: 3,
        }],
        damaged: Vec::new(),
    });
    c.send_line(&request(5, "plan.execute", &execute_params(&p.plan, "off")));
    let reply = answer_of(&c);
    assert_eq!(kind(&reply), "needs_recovery", "{reply}");
    assert!(!rig.dialog_opens());
    assert_eq!(rig.exec.calls(), 0);

    // A damaged journal is named first, and the scan is free for a new plan once recovery is done.
    *rig.undo.pending.lock().unwrap() = Ok(PendingReport {
        open: Vec::new(),
        damaged: vec![(session_id(), "hash chain broken".into())],
    });
    let again = create_selected(&c, 6, &p.scan, &[&p.item]);
    let plan = created_id(&again);
    c.send_line(&request(7, "plan.execute", &execute_params(&plan, "off")));
    assert_eq!(kind(&answer_of(&c)), "store_integrity");
    assert_eq!(rig.exec.calls(), 0);
    c.close();
    rig.exit(SECS);
}

/// A plan nothing of which can run (a package, no acknowledgement) is refused before a dialog: the
/// dialog would be a button over nothing.
#[test]
fn a_plan_that_cannot_run_anything_opens_no_dialog() {
    let mut rig = Rig::start();
    let c = rig.client();
    let scan = seed(
        &rig,
        &c,
        2,
        doc_of(vec![package(1)]),
        fingerprint("HKLM|64|VendorApp", Vec::new()),
    );
    let reply = plan_selected(&c, 3, &scan, &[cid(1)], false);
    // `plan.create` already says so: the view model has nothing that would run.
    assert_eq!(kind(&reply), "plan_refused", "{reply}");
    assert!(!rig.dialog_opens());
    assert_eq!(rig.exec.calls(), 0);
    c.close();
    rig.exit(SECS);
}

// ---------------------------------------------------------------------------------------------------
// The irreversible acknowledgement
// ---------------------------------------------------------------------------------------------------

/// Without `allow_irreversible` a package is "Leave alone" in the dialog and in the plan the executor
/// gets; with it the dialog names the package, warns that it cannot be put back and gates the button
/// behind the verification box, and the executor gets the acknowledgement.
#[test]
fn a_removal_without_undo_runs_only_after_a_dialog_that_names_it() {
    let mut rig = Rig::start();
    let c = rig.client();
    let fp = || fingerprint("HKLM|64|VendorApp", Vec::new());
    let scan = seed(&rig, &c, 2, doc_of(vec![file(1), package(2)]), fp());

    // Not offered: the package is left alone.
    let reply = plan_selected(&c, 3, &scan, &[cid(1), cid(2)], false);
    let plan = created_id(&reply);
    assert!(!rig.plan().bound().allow_irreversible());
    let (done, _) = execute_answering(&rig, &c, 4, &plan, "off", Answer::Declined);
    assert_eq!(kind(&done), "consent_declined");
    let text = text_of(&rig.consent.pages());
    assert!(text.contains("Leave alone"), "{text}");
    assert!(!text.contains("cannot be put back"), "{text}");

    // Offered: the dialog is the acknowledgement.
    let reply = plan_selected(&c, 5, &scan, &[cid(1), cid(2)], true);
    let plan = created_id(&reply);
    assert!(rig.plan().bound().allow_irreversible());
    assert!(
        reply["result"]["attention"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["reasons"]
                .as_array()
                .unwrap()
                .contains(&json!("no_undo"))),
        "the review page lists the package as one that cannot be put back: {reply}"
    );
    c.send_line(&request(6, "plan.execute", &execute_params(&plan, "off")));
    assert!(rig.consent.wait_open(SECS));
    let pages = rig.consent.pages();
    let last = pages.last().unwrap();
    assert!(last.verification.is_some(), "the box is there");
    assert_eq!(last.gated_button, Some(rig.consent.primary()));
    let text = text_of(&pages);
    assert!(text.contains("cannot be put back"), "{text}");
    assert!(text.contains("Vendor.App_1.0.0.0"), "{text}");
    assert_eq!(rig.exec.calls(), 0);
    rig.consent.answer(Answer::Approved);
    let reply = answer_of(&c);
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    let called = rig.exec.called.lock().unwrap();
    assert!(called[0].plan.allow_irreversible());
    assert_eq!(called[0].plan.items().len(), 2);
    drop(called);
    c.close();
    rig.exit(SECS);
}

// ---------------------------------------------------------------------------------------------------
// Object binding
// ---------------------------------------------------------------------------------------------------

/// A service, task or firewall rule must be one the scan's own fingerprint records with the digest the
/// scan saw: `plan.create` refuses it otherwise (a replaced object, another owner, no record), and a
/// vouched one reaches the executor with that very fingerprint.
#[test]
fn a_system_object_the_fingerprint_does_not_vouch_for_is_never_planned() {
    let mut rig = Rig::start();
    let c = rig.client();

    let none = seed(
        &rig,
        &c,
        2,
        doc_of(vec![file(1), task(2)]),
        fingerprint("HKLM|64|VendorApp", Vec::new()),
    );
    let reply = plan_selected(&c, 3, &none, &[cid(1), cid(2)], false);
    assert_eq!(kind(&reply), "plan_refused", "{reply}");
    assert_eq!(
        reply["error"]["data"]["refusals"][0]["candidate_id"],
        cid(2).0
    );

    let other_owner = seed(
        &rig,
        &c,
        4,
        doc_of(vec![task(2)]),
        fingerprint("HKLM|64|OtherApp", vec![vouching_task()]),
    );
    let reply = plan_selected(&c, 5, &other_owner, &[cid(2)], false);
    assert_eq!(kind(&reply), "plan_refused", "{reply}");

    // The same task path, replaced between harvest and scan: another digest.
    let mut replaced = vouching_task();
    replaced.identity.actions = vec![purge_model::TaskAction::Exec {
        path: r"C:\Evil\run.exe".into(),
        arguments: None,
        working_dir: None,
    }];
    let swapped = seed(
        &rig,
        &c,
        6,
        doc_of(vec![task(2)]),
        fingerprint("HKLM|64|VendorApp", vec![replaced]),
    );
    let reply = plan_selected(&c, 7, &swapped, &[cid(2)], false);
    assert_eq!(kind(&reply), "plan_refused", "{reply}");
    assert!(!rig.dialog_opens());

    let vouched = seed(
        &rig,
        &c,
        8,
        doc_of(vec![file(1), task(2)]),
        fingerprint("HKLM|64|VendorApp", vec![vouching_task()]),
    );
    let reply = plan_selected(&c, 9, &vouched, &[cid(1), cid(2)], false);
    let plan = created_id(&reply);
    let (done, _) = execute_answering(&rig, &c, 10, &plan, "off", Answer::Approved);
    assert_eq!(done["result"]["outcome"], "complete", "{done}");
    let called = rig.exec.called.lock().unwrap();
    assert!(Arc::ptr_eq(
        &called[0].fingerprint,
        &rig.scan().scan.fingerprint
    ));
    assert_eq!(called[0].plan.items().len(), 2);
    drop(called);
    c.close();
    rig.exit(SECS);
}

/// The executor refuses a plan whose objects are not vouched for (the binding it makes itself), or the
/// process is not elevated, or a cap or the store says no: each is the design's error, nothing ran, and
/// the scan can be planned again.
#[test]
fn an_executor_that_refuses_to_start_changes_nothing_and_says_why() {
    let mut rig = Rig::start();
    let c = rig.client();
    let p = planned(&rig, &c, &[broker_id(), medium_id()]);
    let mut next_plan = p.plan.clone();
    let cases: Vec<(ExecFailure, &str)> = vec![
        (
            refused(ExecError::ObjectsUnbound(vec![cid(7).0])),
            "plan_refused",
        ),
        (refused(ExecError::NeedsElevation(1)), "not_elevated"),
        (
            refused(ExecError::Store(
                purge_exec::storage::StorageError::IndexMalformed {
                    path: "x".into(),
                    detail: "bad".into(),
                },
            )),
            "store_integrity",
        ),
        (refused(ExecError::ScanCopy("disk".into())), "runtime"),
        (ExecFailure::Machine("no deny-list".into()), "runtime"),
    ];
    for (n, (failure, expected)) in cases.into_iter().enumerate() {
        rig.exec.script(Err(failure));
        let id = 10 + 10 * n as u64;
        let (reply, _) = execute_answering(&rig, &c, id, &next_plan, "off", Answer::Approved);
        assert_eq!(kind(&reply), expected, "{reply}");
        assert_eq!(rig.exec.completed.load(Ordering::SeqCst), 0);
        // Nothing ran: the scan has its next plan.
        let next = create_selected(&c, id + 1, &p.scan, &[&p.item]);
        next_plan = created_id(&next);
    }
    // The unbound objects are named as refusals.
    rig.exec
        .script(Err(refused(ExecError::ObjectsUnbound(vec![cid(7).0]))));
    let (reply, _) = execute_answering(&rig, &c, 100, &next_plan, "off", Answer::Approved);
    assert_eq!(
        reply["error"]["data"]["refusals"][0]["candidate_id"],
        cid(7).0,
        "{reply}"
    );
    c.close();
    rig.exit(SECS);
}

// ---------------------------------------------------------------------------------------------------
// Killing the UI at each step
// ---------------------------------------------------------------------------------------------------

/// The pipe lost while the dialog is open closes it as Cancel: nothing runs, no session exists, and the
/// broker ends.
#[test]
fn a_dialog_closed_by_the_loss_of_the_pipe_runs_nothing() {
    let mut rig = Rig::start();
    let c = rig.client();
    let p = planned(&rig, &c, &[broker_id()]);
    c.send_line(&request(5, "plan.execute", &execute_params(&p.plan, "off")));
    assert!(rig.consent.wait_open(SECS));
    c.close();
    let exit = rig.exit(SECS);
    assert_eq!(exit.reason, ExitReason::PipeLost);
    assert!(rig.consent.closed_by_broker());
    assert_eq!(rig.exec.calls(), 0);
}

#[test]
fn a_dialog_closed_by_the_loss_of_the_parent_runs_nothing() {
    let mut rig = Rig::start();
    let c = rig.client();
    let p = planned(&rig, &c, &[broker_id()]);
    c.send_line(&request(5, "plan.execute", &execute_params(&p.plan, "off")));
    assert!(rig.consent.wait_open(SECS));
    rig.parent.exit();
    let exit = rig.exit(SECS);
    assert_eq!(exit.reason, ExitReason::ParentLost);
    assert!(rig.consent.closed_by_broker());
    assert_eq!(rig.exec.calls(), 0);
}

/// After the approval the run is finished and recorded whatever happens to the pipe: the broker does
/// not end while it runs, the executor completes, and the answer is dropped.
#[test]
fn an_approved_run_finishes_when_the_ui_is_killed_during_it() {
    let mut rig = Rig::start();
    let c = rig.client();
    let p = planned(&rig, &c, &[broker_id(), medium_id()]);
    rig.exec.hold_runs();
    c.send_line(&request(5, "plan.execute", &execute_params(&p.plan, "off")));
    assert!(rig.consent.wait_open(SECS));
    rig.consent.answer(Answer::Approved);
    assert!(rig.exec.started.wait(SECS), "the run started");

    c.close();
    assert!(rig.running(), "the broker waits for the change it started");
    assert_eq!(rig.exec.completed.load(Ordering::SeqCst), 0);
    rig.exec.hold.open();
    let exit = rig.exit(SECS);
    assert_eq!(exit.reason, ExitReason::PipeLost);
    assert_eq!(rig.exec.completed.load(Ordering::SeqCst), 1);
}

#[test]
fn an_approved_run_finishes_when_the_parent_dies_during_it() {
    let mut rig = Rig::start();
    let c = rig.client();
    let p = planned(&rig, &c, &[broker_id()]);
    rig.exec.hold_runs();
    c.send_line(&request(5, "plan.execute", &execute_params(&p.plan, "off")));
    assert!(rig.consent.wait_open(SECS));
    rig.consent.answer(Answer::Approved);
    assert!(rig.exec.started.wait(SECS));
    rig.parent.exit();
    assert!(rig.running());
    rig.exec.hold.open();
    let exit = rig.exit(SECS);
    assert_eq!(exit.reason, ExitReason::ParentLost);
    assert_eq!(rig.exec.completed.load(Ordering::SeqCst), 1);
    drop(c);
}

/// A second `plan.execute` while the first one's dialog is open is `busy`; it never opens a second
/// dialog and never takes the second plan.
#[test]
fn a_second_execute_while_the_dialog_is_open_is_busy_and_keeps_its_plan() {
    let mut rig = Rig::start();
    let c = rig.client();
    let p = planned(&rig, &c, &[broker_id(), medium_id()]);
    let first = rig.plan();
    c.send_line(&request(5, "plan.execute", &execute_params(&p.plan, "off")));
    assert!(rig.consent.wait_open(SECS));
    c.send_line(&request(6, "plan.execute", &execute_params(&p.plan, "off")));
    let busy = answer_of(&c);
    assert_eq!(kind(&busy), "busy", "{busy}");
    rig.consent.answer(Answer::Approved);
    let reply = answer_of(&c);
    assert_eq!(reply["id"], 5);
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    let called = rig.exec.called.lock().unwrap();
    assert_eq!(called.len(), 1);
    assert!(Arc::ptr_eq(&called[0].plan, &first.bound));
    drop(called);
    c.close();
    rig.exit(SECS);
}

// ---------------------------------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------------------------------

fn item_report(
    plan: &BoundPlan,
    n: usize,
    outcome: ItemOutcome,
    lockers: Vec<Locker>,
) -> purge_model::exec::session::ItemReport {
    let item = &plan.items()[n];
    let candidate = plan.candidate(item).unwrap();
    purge_model::exec::session::ItemReport {
        item: candidate.id.clone(),
        op: item.op,
        target: candidate.target.clone(),
        exec_op: item.exec_op.clone(),
        outcome,
        backup_bytes: 0,
        lockers,
    }
}

/// Through the wire: `partial` names the held item with the processes that hold it and carries the
/// restore point's fate; `not_closed` is answered as a result, not an error; a plain run is `complete`.
#[test]
fn outcomes_travel_as_results_with_the_held_items_named() {
    let mut rig = Rig::start();
    let c = rig.client();
    let fp = || fingerprint("HKLM|64|VendorApp", Vec::new());
    // An open uninstall session keeps the broker up after a completed change.
    prepared(&c, 20, &[medium_id()]);
    let locker = Locker {
        pid: 4242,
        name: "vendor.exe".into(),
        service: None,
    };

    // Partial: the item is held by a process.
    let scan = seed(&rig, &c, 2, doc_of(vec![file(1)]), fp());
    let reply = plan_selected(&c, 3, &scan, &[cid(1)], false);
    let plan = created_id(&reply);
    let bound = rig.plan().bound.clone();
    let mut output = output_with(
        &bound,
        vec![item_report(&bound, 0, ItemOutcome::HeldRetry, vec![locker])],
    );
    output.report.restore_point = RestorePointOutcome::Created { sequence: 7 };
    rig.exec.script(Ok(output));
    let (reply, _) = execute_answering(&rig, &c, 4, &plan, "always", Answer::Approved);
    assert_eq!(reply["result"]["outcome"], "partial", "{reply}");
    assert_eq!(reply["result"]["counts"]["held_retry"], 1);
    assert_eq!(reply["result"]["held"][0]["op"], 1);
    assert_eq!(reply["result"]["held"][0]["lockers"][0]["pid"], 4242);
    assert_eq!(
        reply["result"]["held"][0]["lockers"][0]["name"],
        "vendor.exe"
    );
    assert_eq!(reply["result"]["restore_point"]["kind"], "Created");

    // Not closed: the run happened, the record is incomplete; it is a result, not an error.
    let scan = seed(&rig, &c, 5, doc_of(vec![file(1)]), fp());
    let reply = plan_selected(&c, 6, &scan, &[cid(1)], false);
    let plan = created_id(&reply);
    let bound = rig.plan().bound.clone();
    let mut output = output_of(&bound);
    output.index_updated = false;
    rig.exec.script(Ok(output));
    let (reply, _) = execute_answering(&rig, &c, 7, &plan, "off", Answer::Approved);
    assert_eq!(reply["result"]["outcome"], "not_closed", "{reply}");
    assert_eq!(reply["result"]["held"], json!([]));

    // Complete.
    let scan = seed(&rig, &c, 8, doc_of(vec![file(1)]), fp());
    let reply = plan_selected(&c, 9, &scan, &[cid(1)], false);
    let plan = created_id(&reply);
    let (reply, _) = execute_answering(&rig, &c, 10, &plan, "off", Answer::Approved);
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    c.close();
    rig.exit(SECS);
}
/// The outcome rules on their own: every combination of the three records and the item outcomes.
#[test]
fn the_outcome_of_a_run_follows_the_cli_exit_rules() {
    let rig = Rig::start();
    let c = rig.client();
    let p = planned(&rig, &c, &[broker_id()]);
    let _ = p;
    let plan = rig.plan();
    let bound = plan.bound();
    let base = || output_of(bound);
    assert_eq!(crate::execute::outcome_of(&base()), Outcome::Complete);

    let mut vanished = base();
    vanished.report.items[0].outcome = ItemOutcome::Vanished;
    assert_eq!(crate::execute::outcome_of(&vanished), Outcome::Complete);

    let mut failed = base();
    failed.report.items[0].outcome = ItemOutcome::Failed {
        code: purge_model::exec::op::FailCode::InUse,
        os_error: None,
        detail: "x".into(),
    };
    assert_eq!(crate::execute::outcome_of(&failed), Outcome::Partial);

    let mut skipped = base();
    skipped.report.items[0].outcome = ItemOutcome::Skipped {
        reason: purge_model::exec::op::SkipReason::ChangedSinceScan,
    };
    assert_eq!(crate::execute::outcome_of(&skipped), Outcome::Partial);

    let mut aborted = base();
    aborted.report.state = SessionState::Aborted;
    assert_eq!(crate::execute::outcome_of(&aborted), Outcome::Partial);

    for edit in [
        |o: &mut ExecOutput| o.closed = false,
        |o: &mut ExecOutput| o.report_written = false,
        |o: &mut ExecOutput| o.index_updated = false,
    ] {
        // Not closed wins over a complete run and over a partial one.
        let mut open = base();
        edit(&mut open);
        assert_eq!(crate::execute::outcome_of(&open), Outcome::NotClosed);
        let mut open = failed.clone();
        edit(&mut open);
        assert_eq!(crate::execute::outcome_of(&open), Outcome::NotClosed);
    }
    c.close();
}

// ---------------------------------------------------------------------------------------------------
// The one dispatch
// ---------------------------------------------------------------------------------------------------

/// Every package's methods are reachable through the broker's one handler: the purge listing
/// (M3-PURGE), history and pending (M3-UNDO), the flow, and `plan.execute`.
#[test]
fn every_packages_methods_are_wired_into_the_one_handler() {
    let mut rig = Rig::start();
    let c = rig.client();

    let expiring = ask(&c, 2, "quarantine.expiring", json!({}));
    assert_eq!(expiring["result"]["items"], json!([]), "{expiring}");

    let pending = ask(&c, 3, "journal.pending", json!({}));
    assert_eq!(pending["result"]["sessions"], json!([]), "{pending}");

    let history = ask(
        &c,
        4,
        "history.get",
        json!({ "session": session_id().to_string() }),
    );
    assert_eq!(kind(&history), "gone", "{history}");

    let stored = ask(
        &c,
        5,
        "leftovers.stored",
        json!({ "program_ids": [broker_id()] }),
    );
    assert_eq!(stored["result"]["stored"], json!([]), "{stored}");

    let execute = ask(
        &c,
        6,
        "plan.execute",
        execute_params("p-0123456789abcdef", "off"),
    );
    assert_eq!(kind(&execute), "gone", "{execute}");
    c.close();
    rig.exit(SECS);
}

/// The error each way a run can refuse to start is the design's kind.
#[test]
fn exec_errors_map_to_the_designs_kinds() {
    use crate::execute::exec_error;
    let kind_of = |e: ExecError| exec_error(e).data.map(|d| d.kind());
    assert_eq!(kind_of(ExecError::NeedsElevation(2)), Some("not_elevated"));
    assert_eq!(
        kind_of(ExecError::ObjectsUnbound(vec![cid(1).0])),
        Some("plan_refused")
    );
    assert_eq!(
        kind_of(ExecError::Plan(
            purge_exec::plan_in::PlanRefusal::EmptySelection
        )),
        Some("plan_refused")
    );
    assert_eq!(
        kind_of(ExecError::NotResumable("x".into())),
        Some("runtime")
    );
    // Another writer of the store (another broker's run, undo, recovery or purge) holds it.
    assert_eq!(
        kind_of(ExecError::Store(
            purge_exec::storage::StorageError::WriterBusy {
                path: r"C:\ProgramData\Purge\sessions\writer.lock".into()
            }
        )),
        Some("busy")
    );
    // An interrupted or damaged session the run found once it held the lock (after the dialog).
    let sessions = vec!["20251115T101502Z-9f3a6c1d2b7e4a50".parse().unwrap()];
    let reply = exec_error(ExecError::NeedsRecovery(sessions.clone()));
    assert_eq!(
        reply.data,
        Some(purge_rpc::error::ErrorData::NeedsRecovery { sessions })
    );
    assert_eq!(
        kind_of(ExecError::Damaged(vec!["s (cut)".into()])),
        Some("store_integrity")
    );
}
