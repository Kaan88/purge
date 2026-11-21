//! Tests of `history.get`, `undo.run` and the `journal.*` methods through the serving loop (M3-UNDO): the
//! in-memory transport, a scripted consent dialog and a scripted [`Backend`]. The journals themselves
//! (previews on real sessions, the guarded runs, the crash leftovers) are tested in `purge-exec`
//! (`execute::tests`); here is every refusal of the broker's own rules, and that the run is the one
//! the dialog was drawn from.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use purge_engine::pipeline::Settings;
use purge_exec::journal::sha256_bytes;
use purge_exec::plan_in::{
    BoundPlan, ExecRequest, ExecSettings, Selection, bind, confirm_hash, selection_hash,
};
use purge_exec::recover::{PendingKind, RecoverPreview, Want};
use purge_exec::undo::{UndoExpect, UndoPreview, UndoRequest, UndoSelection};
use purge_model::exec::journal::UndoConflict;
use purge_model::exec::op::{ItemOutcome, OpId};
use purge_model::exec::session::{JournalMark, SessionId, SessionState};
use purge_model::{
    Action, AppRef, Band, Candidate, CandidateId, Category, Decision, FileTime, Harm, Origin,
    Reversibility, ScanMode, Target, Tool,
};
use purge_plan::emit::{ScanDoc, ScanSchema};
use purge_rpc::error::Outcome;
use purge_rpc::methods::{
    ConflictRow, HistoryDetail, HistoryItem, ItemKind, OutcomeResult, PendingSession, PipeCall,
    UndoResult,
};
use purge_win::taskdialog::Outcome as Answer;
use serde_json::{Value, json};

use crate::backend::{Backend, BackendError, PendingReport};
use crate::lifetime::{Exit, ExitReason};
use crate::serve::{Ctx, Handler, Wiring, run};
use crate::testkit::{
    Client, FakeClock, FakeHost, FakeParent, Gate, MemNet, SECS, ScriptedConsent, expected, kind,
    request, test_limits,
};
use crate::undo::UndoMethods;

// ---------------------------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------------------------

fn session() -> SessionId {
    SessionId::new(FileTime(133_800_000_000_000_000), 7)
}

fn other_session() -> SessionId {
    SessionId::new(FileTime(133_800_000_000_000_000), 8)
}

fn candidate(id: &str, target: Target, action: Action) -> Candidate {
    Candidate {
        id: CandidateId(id.to_owned()),
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

fn file(id: &str, path: &str) -> Candidate {
    candidate(
        id,
        Target::Path {
            path: path.to_owned(),
        },
        Action::Quarantine,
    )
}

fn package(id: &str) -> Candidate {
    Candidate {
        category: Category::Package,
        ..candidate(
            id,
            Target::AppxPackage {
                full_name: "Vendor.App_1.0.0.0_x64__abcdefghijklm".into(),
            },
            Action::RemovePackage,
        )
    }
}

/// A bound plan over `items` (every one selected).
fn plan_of(items: Vec<Candidate>) -> BoundPlan {
    let ids: Vec<CandidateId> = items.iter().map(|c| c.id.clone()).collect();
    let mut scan = ScanDoc {
        schema: ScanSchema,
        app: "vendor-app".into(),
        tool: Tool::Purge,
        mode: ScanMode::Post,
        policy_version: "m1a.6".into(),
        plan_hash: String::new(),
        items,
        absorbed: Vec::new(),
    };
    scan.plan_hash = purge_plan::hash::plan_hash(&scan.items, &scan.policy_version, scan.mode);
    let confirm = confirm_hash(scan.plan_hash.parse().unwrap(), selection_hash(&ids)).to_string();
    bind(&ExecRequest {
        scan,
        confirm,
        selection: Selection::Ids(ids),
        allow_irreversible: true,
        settings: ExecSettings::default(),
    })
    .expect("the fixture plan binds")
}

/// Three files: ops 1 to 3.
fn files_plan() -> BoundPlan {
    plan_of(vec![
        file("c-a", r"C:\Vendor\a.txt"),
        file("c-b", r"C:\Vendor\b.txt"),
        file("c-c", r"C:\Vendor\c.txt"),
    ])
}

fn mark() -> JournalMark {
    JournalMark {
        records: 12,
        head: sha256_bytes(b"journal"),
    }
}

fn ops(ns: &[u32]) -> Vec<OpId> {
    ns.iter().map(|n| OpId(*n)).collect()
}

fn owner() -> Option<AppRef> {
    Some(AppRef {
        program_id: "HKLM|64|VendorApp".parse().unwrap(),
        display_name: "Vendor App".into(),
    })
}

fn undo_preview(plan: BoundPlan, put_back: &[u32]) -> UndoPreview {
    UndoPreview {
        request: UndoRequest {
            session: session(),
            selection: UndoSelection::All,
            plan_hash: Some(plan.plan_hash()),
        },
        app: "vendor-app".into(),
        owner: owner(),
        plan,
        put_back: ops(put_back),
        pulled_in: Vec::new(),
        already_undone: Vec::new(),
        expect: UndoExpect {
            ops: ops(put_back),
            mark: mark(),
        },
    }
}

fn recover_preview(plan: Option<BoundPlan>, effective: Want, op_ns: &[u32]) -> RecoverPreview {
    RecoverPreview {
        session: session(),
        kind: Some(PendingKind::Run),
        effective,
        app: "vendor-app".into(),
        owner: owner(),
        started: FileTime(133_800_000_000_000_000),
        done: 1,
        total: 3,
        plan,
        ops: ops(op_ns),
        mark: mark(),
    }
}

fn pending_session() -> PendingSession {
    PendingSession {
        session: session(),
        app: "Vendor App".into(),
        started: FileTime(133_800_000_000_000_000),
        done: 1,
        total: 3,
    }
}

// ---------------------------------------------------------------------------------------------------
// The scripted backend
// ---------------------------------------------------------------------------------------------------

type Scripted<T> = Mutex<Result<T, BackendError>>;

struct FakeBackend {
    pending: Scripted<PendingReport>,
    history: Scripted<HistoryDetail>,
    undo_preview: Scripted<UndoPreview>,
    taken: Mutex<Vec<OpId>>,
    undo: Scripted<UndoResult>,
    recover_preview: Scripted<RecoverPreview>,
    recover: Scripted<OutcomeResult>,
    /// Every call, with what the handler passed: `undo_preview(All)`, `undo_preview([1, 2])`, `undo`,
    /// `recover_preview(Resume)`, `recover(Resume)`.
    calls: Mutex<Vec<String>>,
    /// What `undo` was given.
    undone: Mutex<Vec<UndoPreview>>,
    /// What `recover` was given.
    recovered: Mutex<Vec<(RecoverPreview, Want)>>,
    /// `undo` and `recover` wait for this.
    hold: Gate,
    holding: Mutex<bool>,
    started: Gate,
}

impl FakeBackend {
    fn new() -> Arc<FakeBackend> {
        fn gone<T>() -> Result<T, BackendError> {
            Err(BackendError::Gone)
        }
        Arc::new(FakeBackend {
            pending: Mutex::new(Ok(PendingReport::default())),
            history: Mutex::new(gone()),
            undo_preview: Mutex::new(gone()),
            taken: Mutex::new(Vec::new()),
            undo: Mutex::new(Ok(UndoResult {
                outcome: Outcome::Complete,
                conflicts: Vec::new(),
            })),
            recover_preview: Mutex::new(gone()),
            recover: Mutex::new(Ok(OutcomeResult {
                outcome: Outcome::Complete,
            })),
            calls: Mutex::new(Vec::new()),
            undone: Mutex::new(Vec::new()),
            recovered: Mutex::new(Vec::new()),
            hold: Gate::default(),
            holding: Mutex::new(false),
            started: Gate::default(),
        })
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn log(&self, call: impl Into<String>) {
        self.calls.lock().unwrap().push(call.into());
    }

    fn hold_runs(&self) {
        *self.holding.lock().unwrap() = true;
    }

    fn wait_if_held(&self) {
        self.started.open();
        if *self.holding.lock().unwrap() {
            self.hold.wait(SECS);
        }
    }
}

impl Backend for Arc<FakeBackend> {
    fn pending(&self) -> Result<PendingReport, BackendError> {
        self.log("pending");
        self.pending.lock().unwrap().clone()
    }

    fn history(&self, session: &SessionId) -> Result<HistoryDetail, BackendError> {
        self.log(format!("history({session})"));
        self.history.lock().unwrap().clone()
    }

    fn undo_preview(
        &self,
        session: &SessionId,
        ops: Option<&[OpId]>,
    ) -> Result<UndoPreview, BackendError> {
        self.log(format!(
            "undo_preview({session}, {})",
            ops.map_or("All".to_owned(), |o| format!("{o:?}"))
        ));
        self.undo_preview.lock().unwrap().clone()
    }

    fn places_taken(&self, _plan: &BoundPlan, ops: &[OpId]) -> Vec<OpId> {
        self.taken
            .lock()
            .unwrap()
            .iter()
            .filter(|op| ops.contains(op))
            .copied()
            .collect()
    }

    fn undo(&self, preview: &UndoPreview) -> Result<UndoResult, BackendError> {
        self.log("undo");
        self.undone.lock().unwrap().push(preview.clone());
        self.wait_if_held();
        self.undo.lock().unwrap().clone()
    }

    fn recover_preview(
        &self,
        session: &SessionId,
        want: Want,
    ) -> Result<RecoverPreview, BackendError> {
        self.log(format!("recover_preview({session}, {want:?})"));
        self.recover_preview.lock().unwrap().clone()
    }

    fn recover(&self, preview: &RecoverPreview, want: Want) -> Result<OutcomeResult, BackendError> {
        self.log(format!("recover({want:?})"));
        self.recovered.lock().unwrap().push((preview.clone(), want));
        self.wait_if_held();
        self.recover.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------------------------------------------
// The handler and the harness
// ---------------------------------------------------------------------------------------------------

/// The broker's handler as BROKER-FLOW wires it: this package's methods, and `plan.execute` stood in by
/// the check it must make first.
struct TestHandler {
    methods: Arc<UndoMethods<Arc<FakeBackend>>>,
    /// The request thread still held the restore privilege or an impersonation token after a call.
    leaked: Arc<AtomicBool>,
}

impl Handler for TestHandler {
    type Session = ();
    type Scan = ();
    type Plan = ();

    fn call(
        &self,
        ctx: &Ctx<'_, Self>,
        call: PipeCall,
    ) -> Result<Value, purge_rpc::error::ErrorObject> {
        if UndoMethods::<Arc<FakeBackend>>::handles(&call) {
            let result = self.methods.call(ctx, call);
            if purge_win::privilege::restore_privilege_enabled().unwrap_or(true)
                || purge_win::privilege::thread_impersonates().unwrap_or(true)
            {
                self.leaked.store(true, Ordering::SeqCst);
            }
            return result;
        }
        if let PipeCall::PlanExecute(_) = call {
            self.methods.check_nothing_pending()?;
            return Err(purge_rpc::error::ErrorObject::runtime("would execute"));
        }
        Err(purge_rpc::error::ErrorObject::runtime("not scripted"))
    }
}

struct Rig {
    net: MemNet,
    parent: Arc<FakeParent>,
    consent: Arc<ScriptedConsent>,
    leaked: Arc<AtomicBool>,
    join: Option<JoinHandle<Exit>>,
}

impl Rig {
    fn start(backend: Arc<FakeBackend>) -> Rig {
        let net = MemNet::default();
        let clock = Arc::new(FakeClock::default());
        let parent = Arc::new(FakeParent::default());
        let consent = Arc::new(ScriptedConsent::default());
        let methods = Arc::new(UndoMethods::new(backend.clone()));
        let leaked = Arc::new(AtomicBool::new(false));
        let wiring = Wiring {
            link: net.link(),
            handler: TestHandler {
                methods,
                leaked: leaked.clone(),
            },
            expected: expected(),
            parent: parent.clone(),
            consent: Arc::new(consent.clone()),
            host: Arc::new(FakeHost),
            clock,
            build: None,
            settings: Settings::default(),
            limits: test_limits(),
        };
        let join = std::thread::spawn(move || run(wiring));
        Rig {
            net,
            parent,
            consent,
            leaked,
            join: Some(join),
        }
    }

    fn client(&self) -> Client {
        let c = self.net.connect(Ok(()));
        c.send_line(crate::testkit::HELLO);
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
        std::thread::sleep(Duration::from_millis(100));
        self.join.as_ref().is_some_and(|j| !j.is_finished())
    }

    /// Whether a dialog was opened within a short while.
    fn dialog_opens(&self) -> bool {
        self.consent.wait_open(Duration::from_millis(300))
    }
}

/// The next answer (a line with an id), past the notifications before it.
fn answer_of(c: &Client) -> Value {
    loop {
        let line = c.reply();
        if line.get("id").is_some() {
            return line;
        }
    }
}

fn undo_params(item_ids: Option<&[u32]>) -> Value {
    match item_ids {
        Some(ids) => json!({ "session": session().to_string(), "item_ids": ids }),
        None => json!({ "session": session().to_string() }),
    }
}

fn session_params() -> Value {
    json!({ "session": session().to_string() })
}

/// Sends `method`, waits for its dialog and answers it; returns the reply.
fn ask(rig: &Rig, c: &Client, id: u64, method: &str, params: &Value, answer: Answer) -> Value {
    c.send_line(&request(id, method, params));
    assert!(rig.consent.wait_open(SECS), "the dialog did not open");
    rig.consent.answer(answer);
    answer_of(c)
}

fn restore_rig(plan: BoundPlan, put_back: &[u32]) -> (Rig, Arc<FakeBackend>) {
    let backend = FakeBackend::new();
    *backend.undo_preview.lock().unwrap() = Ok(undo_preview(plan, put_back));
    (Rig::start(backend.clone()), backend)
}

// ---------------------------------------------------------------------------------------------------
// history.get and journal.pending
// ---------------------------------------------------------------------------------------------------

#[test]
fn history_get_answers_from_the_backend_and_an_unknown_session_is_gone() {
    let backend = FakeBackend::new();
    *backend.history.lock().unwrap() = Ok(HistoryDetail {
        session: session(),
        state: SessionState::Committed,
        items: vec![HistoryItem {
            op: OpId(1),
            display_name: r"C:\Vendor\a.txt".into(),
            kind: ItemKind::File,
            outcome: ItemOutcome::Done,
            undone: false,
        }],
    });
    let rig = Rig::start(backend.clone());
    let c = rig.client();
    c.send_line(&request(2, "history.get", &session_params()));
    let reply = c.reply();
    assert_eq!(reply["result"]["state"], "Committed", "{reply}");
    assert_eq!(reply["result"]["items"][0]["op"], 1);
    assert_eq!(reply["result"]["items"][0]["kind"], "file");

    *backend.history.lock().unwrap() = Err(BackendError::Gone);
    c.send_line(&request(3, "history.get", &session_params()));
    let reply = c.reply();
    assert_eq!(kind(&reply), "gone");
    assert_eq!(reply["error"]["data"]["id"], "session");
    // A read opens no dialog and ends nothing.
    assert!(!rig.dialog_opens());
    assert!(rig.running());
}

#[test]
fn a_session_that_is_not_an_executor_id_never_reaches_the_backend() {
    let backend = FakeBackend::new();
    let rig = Rig::start(backend.clone());
    let c = rig.client();
    for bad in [
        json!({ "session": r"C:\ProgramData\Purge\sessions\x" }),
        json!({ "session": "..\\..\\evil" }),
        json!({ "session": "" }),
        json!({ "session": session().to_string(), "path": r"C:\x" }),
        json!({}),
    ] {
        c.send_line(&request(2, "history.get", &bad));
        let reply = c.reply();
        assert_eq!(reply["error"]["code"], -32602, "{bad}: {reply}");
        c.send_line(&request(3, "undo.run", &bad));
        assert_eq!(c.reply()["error"]["code"], -32602, "{bad}");
    }
    assert_eq!(backend.calls(), Vec::<String>::new());
}

#[test]
fn journal_pending_lists_the_interrupted_sessions() {
    let backend = FakeBackend::new();
    *backend.pending.lock().unwrap() = Ok(PendingReport {
        open: vec![pending_session()],
        damaged: vec![(other_session(), "chain".into())],
    });
    let rig = Rig::start(backend);
    let c = rig.client();
    c.send_line(&request(2, "journal.pending", &json!({})));
    let reply = c.reply();
    let sessions = reply["result"]["sessions"].as_array().unwrap();
    assert_eq!(
        sessions.len(),
        1,
        "a damaged journal cannot be recovered: {reply}"
    );
    assert_eq!(sessions[0]["done"], 1);
    assert_eq!(sessions[0]["total"], 3);
    assert_eq!(sessions[0]["session"], session().to_string());
}

#[test]
fn an_interrupted_session_blocks_execute_and_a_damaged_one_is_store_integrity() {
    let backend = FakeBackend::new();
    let rig = Rig::start(backend.clone());
    let c = rig.client();
    let execute = json!({ "plan_id": "p-0000000000000001", "restore_point": "off" });

    c.send_line(&request(2, "plan.execute", &execute));
    let reply = c.reply();
    assert_eq!(kind(&reply), "runtime", "{reply}");
    assert_eq!(reply["error"]["message"], "runtime");
    assert_eq!(
        reply["error"]["data"]["message"], "would execute",
        "nothing is pending"
    );

    *backend.pending.lock().unwrap() = Ok(PendingReport {
        open: vec![pending_session()],
        damaged: Vec::new(),
    });
    c.send_line(&request(3, "plan.execute", &execute));
    let reply = c.reply();
    assert_eq!(kind(&reply), "needs_recovery", "{reply}");
    assert_eq!(
        reply["error"]["data"]["sessions"],
        json!([session().to_string()])
    );

    *backend.pending.lock().unwrap() = Ok(PendingReport {
        open: vec![pending_session()],
        damaged: vec![(other_session(), "the hash chain does not match".into())],
    });
    c.send_line(&request(4, "plan.execute", &execute));
    let reply = c.reply();
    assert_eq!(
        kind(&reply),
        "store_integrity",
        "a damaged journal comes first: {reply}"
    );
    assert!(
        reply["error"]["data"]["message"]
            .as_str()
            .unwrap()
            .contains("hash chain")
    );
    assert!(!rig.dialog_opens());
}

// ---------------------------------------------------------------------------------------------------
// undo.run
// ---------------------------------------------------------------------------------------------------

#[test]
fn undo_all_asks_first_and_runs_the_preview_the_dialog_was_drawn_from() {
    let (mut rig, backend) = restore_rig(files_plan(), &[3, 2, 1]);
    rig.consent.announce_shown();
    let c = rig.client();
    c.send_line(&request(2, "undo.run", &undo_params(None)));
    assert!(rig.consent.wait_open(SECS));
    // Nothing runs before the answer.
    assert_eq!(
        backend.calls(),
        [format!("undo_preview({}, All)", session())]
    );

    let pages = rig.consent.pages();
    let last = pages.last().unwrap();
    assert_eq!(last.instruction, "Restore 3 items of \"Vendor App\"?");
    assert_eq!(last.buttons[0].label, "Restore 3 items");
    assert_eq!(rig.consent.primary(), 100);
    assert!(
        last.verification.is_none(),
        "no conflict, nothing to verify"
    );
    let shown = c.reply();
    assert_eq!(shown["method"], "consent.shown", "{shown}");
    assert_eq!(shown["params"]["request"], 2);
    let code = shown["params"]["code"].as_str().unwrap().to_owned();
    assert!(pages[0].footer.as_deref().unwrap().contains(&code));

    rig.consent.answer(Answer::Approved);
    let reply = answer_of(&c);
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    assert_eq!(reply["result"]["conflicts"], json!([]));

    // The backend ran what it had previewed, once, unchanged.
    let undone = backend.undone.lock().unwrap();
    assert_eq!(undone.len(), 1);
    assert_eq!(undone[0].put_back, ops(&[3, 2, 1]));
    assert_eq!(
        undone[0].expect,
        undo_preview(files_plan(), &[3, 2, 1]).expect
    );
    assert_eq!(undone[0].request.session, session());
    drop(undone);
    // A completed change with no session left ends the broker.
    c.close();
    assert_eq!(rig.exit(SECS).reason, ExitReason::CompletedChange);
}

#[test]
fn a_cancelled_undo_changes_nothing_and_leaves_the_broker_serving() {
    let (rig, backend) = restore_rig(files_plan(), &[3, 2, 1]);
    let c = rig.client();
    let reply = ask(
        &rig,
        &c,
        2,
        "undo.run",
        &undo_params(None),
        Answer::Declined,
    );
    assert_eq!(kind(&reply), "consent_declined", "{reply}");
    assert!(!backend.calls().contains(&"undo".to_owned()));
    assert!(rig.running(), "a declined change does not end the broker");
    // Asking again asks again: the decline left no state.
    let reply = ask(
        &rig,
        &c,
        3,
        "undo.run",
        &undo_params(None),
        Answer::Approved,
    );
    assert_eq!(reply["result"]["outcome"], "complete");
    assert_eq!(backend.calls().iter().filter(|c| *c == "undo").count(), 1);
}

#[test]
fn a_partial_undo_names_its_ops_to_the_backend_and_shows_what_it_pulled_in() {
    let (rig, backend) = restore_rig(files_plan(), &[3, 1]);
    // The selection is op 1; the backend says the run also goes through op 3.
    backend
        .undo_preview
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .pulled_in = ops(&[3]);
    let c = rig.client();
    let reply = ask(
        &rig,
        &c,
        2,
        "undo.run",
        &undo_params(Some(&[1])),
        Answer::Approved,
    );
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    assert_eq!(
        backend.calls()[0],
        format!("undo_preview({}, [OpId(1)])", session())
    );
    let pages = rig.consent.pages();
    assert_eq!(
        pages.last().unwrap().instruction,
        "Restore 2 items of \"Vendor App\"?",
        "the dialog counts the pulled-in op"
    );
    let text: String = pages.iter().map(|p| p.content.clone()).collect();
    assert!(
        !text.contains("b.txt"),
        "op 2 is not part of the run: {text}"
    );
}

#[test]
fn an_op_that_is_not_in_the_session_is_gone_and_nothing_is_asked() {
    let backend = FakeBackend::new();
    *backend.undo_preview.lock().unwrap() = Err(BackendError::UnknownOp("op 99".into()));
    let rig = Rig::start(backend.clone());
    let c = rig.client();
    c.send_line(&request(2, "undo.run", &undo_params(Some(&[99]))));
    let reply = c.reply();
    assert_eq!(kind(&reply), "gone", "{reply}");
    assert_eq!(reply["error"]["data"]["id"], "candidate");
    assert!(!rig.dialog_opens());
    assert!(!backend.calls().contains(&"undo".to_owned()));
}

#[test]
fn an_undo_over_a_taken_place_lists_it_as_attention_and_needs_the_box() {
    let (rig, backend) = restore_rig(files_plan(), &[3, 2, 1]);
    *backend.taken.lock().unwrap() = ops(&[2]);
    *backend.undo.lock().unwrap() = Ok(UndoResult {
        outcome: Outcome::UndoConflicts,
        conflicts: vec![ConflictRow {
            op: OpId(2),
            display_name: r"C:\Vendor\b.txt".into(),
            conflict: UndoConflict::DestinationExists,
        }],
    });
    let c = rig.client();
    c.send_line(&request(2, "undo.run", &undo_params(None)));
    assert!(rig.consent.wait_open(SECS));
    let pages = rig.consent.pages();
    let last = pages.last().unwrap();
    let text: String = pages.iter().map(|p| p.content.clone()).collect();
    assert!(text.contains(r"C:\Vendor\b.txt"), "{text}");
    assert!(text.contains("something is there now"), "{text}");
    assert!(
        last.verification.is_some(),
        "a conflict is gated by the box"
    );
    assert_eq!(last.gated_button, Some(100));
    assert!(
        !text.contains("a.txt\""),
        "only the conflict is an attention entry: {text}"
    );
    rig.consent.answer(Answer::Approved);
    let reply = answer_of(&c);
    assert_eq!(reply["result"]["outcome"], "undo_conflicts", "{reply}");
    assert_eq!(reply["result"]["conflicts"][0]["op"], 2);
    assert_eq!(
        reply["result"]["conflicts"][0]["conflict"]["kind"],
        "DestinationExists"
    );
    // A conflict outcome is a completed change.
    c.close();
    assert!(!rig.running());
}

#[test]
fn a_taken_place_that_is_not_part_of_the_run_is_not_shown() {
    let (rig, backend) = restore_rig(files_plan(), &[1]);
    *backend.taken.lock().unwrap() = ops(&[2, 3]);
    let c = rig.client();
    c.send_line(&request(2, "undo.run", &undo_params(Some(&[1]))));
    assert!(rig.consent.wait_open(SECS));
    let pages = rig.consent.pages();
    assert!(pages.last().unwrap().verification.is_none());
    rig.consent.answer(Answer::Declined);
    assert_eq!(kind(&answer_of(&c)), "consent_declined");
}

#[test]
fn nothing_to_put_back_is_an_error_not_a_dialog() {
    let (rig, backend) = restore_rig(files_plan(), &[]);
    let c = rig.client();
    c.send_line(&request(2, "undo.run", &undo_params(None)));
    let reply = c.reply();
    assert_eq!(kind(&reply), "runtime", "{reply}");
    assert!(!rig.dialog_opens());
    assert!(!backend.calls().contains(&"undo".to_owned()));
}

#[test]
fn a_preview_the_dialog_cannot_describe_is_never_run() {
    // An op the plan does not hold.
    let (rig, backend) = restore_rig(files_plan(), &[9]);
    let c = rig.client();
    c.send_line(&request(2, "undo.run", &undo_params(None)));
    assert_eq!(kind(&c.reply()), "runtime");
    assert!(!rig.dialog_opens());
    assert!(!backend.calls().contains(&"undo".to_owned()));

    // An op that cannot be put back is not offered as something that will be.
    let plan = plan_of(vec![file("c-a", r"C:\Vendor\a.txt"), package("c-pkg")]);
    *backend.undo_preview.lock().unwrap() = Ok(undo_preview(plan, &[2, 1]));
    c.send_line(&request(3, "undo.run", &undo_params(None)));
    let reply = c.reply();
    assert_eq!(kind(&reply), "runtime", "{reply}");
    assert!(!rig.dialog_opens());
    assert!(!backend.calls().contains(&"undo".to_owned()));
}

#[test]
fn a_session_that_changed_after_the_dialog_is_not_undone() {
    let (rig, backend) = restore_rig(files_plan(), &[3, 2, 1]);
    *backend.undo.lock().unwrap() = Err(BackendError::NotAsShown);
    let c = rig.client();
    let reply = ask(
        &rig,
        &c,
        2,
        "undo.run",
        &undo_params(None),
        Answer::Approved,
    );
    assert_eq!(kind(&reply), "runtime", "{reply}");
    assert!(
        reply["error"]["data"]["message"]
            .as_str()
            .unwrap()
            .contains("nothing was done")
    );
    // The failed change is not a completed one.
    assert!(rig.running());
}

#[test]
fn the_errors_of_the_store_are_the_errors_the_client_is_told() {
    let (rig, backend) = restore_rig(files_plan(), &[1]);
    let c = rig.client();
    for (error, expected) in [
        (BackendError::Gone, "gone"),
        (BackendError::Integrity("bad".into()), "store_integrity"),
        (
            BackendError::NeedsRecovery(vec![session()]),
            "needs_recovery",
        ),
        (BackendError::Failed("x".into()), "runtime"),
    ] {
        *backend.undo_preview.lock().unwrap() = Err(error);
        c.send_line(&request(2, "undo.run", &undo_params(None)));
        assert_eq!(kind(&c.reply()), expected);
    }
    assert!(!rig.dialog_opens());
}

#[test]
fn a_dialog_closed_by_the_loss_of_the_pipe_runs_nothing() {
    let (mut rig, backend) = restore_rig(files_plan(), &[3, 2, 1]);
    let c = rig.client();
    c.send_line(&request(2, "undo.run", &undo_params(None)));
    assert!(rig.consent.wait_open(SECS));
    c.close();
    assert_eq!(rig.exit(SECS).reason, ExitReason::PipeLost);
    assert!(rig.consent.closed_by_broker());
    assert!(!backend.calls().contains(&"undo".to_owned()));
}

#[test]
fn a_dialog_closed_by_the_loss_of_the_parent_runs_nothing() {
    let (mut rig, backend) = restore_rig(files_plan(), &[3, 2, 1]);
    let c = rig.client();
    c.send_line(&request(2, "undo.run", &undo_params(None)));
    assert!(rig.consent.wait_open(SECS));
    rig.parent.exit();
    assert_eq!(rig.exit(SECS).reason, ExitReason::ParentLost);
    assert!(rig.consent.closed_by_broker());
    assert!(!backend.calls().contains(&"undo".to_owned()));
}

#[test]
fn an_approved_undo_finishes_when_the_ui_is_killed_during_the_run() {
    let (mut rig, backend) = restore_rig(files_plan(), &[3, 2, 1]);
    backend.hold_runs();
    let c = rig.client();
    c.send_line(&request(2, "undo.run", &undo_params(None)));
    assert!(rig.consent.wait_open(SECS));
    rig.consent.answer(Answer::Approved);
    assert!(backend.started.wait(SECS), "the run began");
    c.close();
    // The broker waits for the run; it is not cut short.
    assert!(rig.running(), "a mutating request is finished first");
    assert_eq!(backend.undone.lock().unwrap().len(), 1);
    backend.hold.open();
    assert_eq!(rig.exit(SECS).reason, ExitReason::PipeLost);
}

#[test]
fn a_second_mutating_request_while_the_dialog_is_open_is_busy() {
    let (rig, backend) = restore_rig(files_plan(), &[3, 2, 1]);
    let c = rig.client();
    c.send_line(&request(2, "undo.run", &undo_params(None)));
    assert!(rig.consent.wait_open(SECS));
    c.send_line(&request(3, "journal.resume", &session_params()));
    let reply = c.reply();
    assert_eq!(kind(&reply), "busy", "{reply}");
    rig.consent.answer(Answer::Declined);
    assert_eq!(kind(&c.reply()), "consent_declined");
    assert_eq!(
        backend
            .calls()
            .iter()
            .filter(|c| c.starts_with("recover"))
            .count(),
        0
    );
}

#[test]
fn hostile_names_are_escaped_in_the_restore_dialog() {
    let plan = plan_of(vec![
        file("c-a", "C:\\Vendor\\a\u{202e}txt.exe"),
        file("c-b", "C:\\Vendor\\M\u{43e}zilla"),
    ]);
    let (rig, _backend) = restore_rig(plan, &[2, 1]);
    let c = rig.client();
    c.send_line(&request(2, "undo.run", &undo_params(None)));
    assert!(rig.consent.wait_open(SECS));
    let pages = rig.consent.pages();
    let text: String = pages.iter().map(|p| p.content.clone()).collect();
    assert!(
        !text.contains('\u{202e}'),
        "the bidi control is shown escaped"
    );
    assert!(text.contains(r"\u{202e}"), "{text}");
    assert!(text.contains(r"M\u{43e}zilla"), "{text}");
    assert!(
        pages.last().unwrap().verification.is_some(),
        "an escaped name is gated"
    );
    rig.consent.answer(Answer::Declined);
    let _ = c.reply();
}

// ---------------------------------------------------------------------------------------------------
// journal.resume, journal.rollback, journal.retry_held
// ---------------------------------------------------------------------------------------------------

fn recover_rig(preview: RecoverPreview) -> (Rig, Arc<FakeBackend>) {
    let backend = FakeBackend::new();
    *backend.recover_preview.lock().unwrap() = Ok(preview);
    (Rig::start(backend.clone()), backend)
}

#[test]
fn a_resume_asks_first_and_runs_the_preview_with_the_method_asked() {
    let (rig, backend) = recover_rig(recover_preview(Some(files_plan()), Want::Resume, &[2, 3]));
    let c = rig.client();
    c.send_line(&request(2, "journal.resume", &session_params()));
    assert!(rig.consent.wait_open(SECS));
    assert_eq!(
        backend.calls(),
        [format!("recover_preview({}, Resume)", session())],
        "nothing runs before the answer"
    );
    let pages = rig.consent.pages();
    let last = pages.last().unwrap();
    assert_eq!(last.instruction, "Finish the cleanup of \"Vendor App\"?");
    assert_eq!(last.buttons[0].label, "Finish the cleanup");
    let text: String = pages.iter().map(|p| p.content.clone()).collect();
    assert!(text.contains("1 of 3 items are done"), "{text}");
    assert!(text.contains("started 2024-12-30 02:40 UTC"), "{text}");
    rig.consent.answer(Answer::Approved);
    let reply = c.reply();
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    let recovered = backend.recovered.lock().unwrap();
    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].1, Want::Resume);
    assert_eq!(recovered[0].0.ops, ops(&[2, 3]));
    assert_eq!(recovered[0].0.mark, mark());
}

#[test]
fn a_rollback_and_a_retry_have_their_own_dialogs() {
    let (rig, backend) = recover_rig(recover_preview(Some(files_plan()), Want::Rollback, &[1]));
    let c = rig.client();
    let reply = ask(
        &rig,
        &c,
        2,
        "journal.rollback",
        &session_params(),
        Answer::Approved,
    );
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    let last = rig.consent.pages().pop().unwrap();
    assert_eq!(last.instruction, "Roll the cleanup of \"Vendor App\" back?");
    assert_eq!(last.buttons[0].label, "Roll the cleanup back");
    assert_eq!(backend.recovered.lock().unwrap()[0].1, Want::Rollback);

    *backend.recover_preview.lock().unwrap() =
        Ok(recover_preview(Some(files_plan()), Want::RetryHeld, &[2]));
    // The broker ended after a completed change in the test above; use a new one.
    let (rig, backend) = recover_rig(recover_preview(Some(files_plan()), Want::RetryHeld, &[2]));
    let c = rig.client();
    let reply = ask(
        &rig,
        &c,
        2,
        "journal.retry_held",
        &session_params(),
        Answer::Approved,
    );
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    let last = rig.consent.pages().pop().unwrap();
    assert_eq!(
        last.instruction,
        "Try the held items of \"Vendor App\" again?"
    );
    assert_eq!(last.buttons[0].label, "Try the held items again");
    assert_eq!(backend.recovered.lock().unwrap()[0].1, Want::RetryHeld);
}

#[test]
fn what_recovery_will_do_is_what_the_dialog_says_not_the_method_name() {
    // A `journal.resume` of a run that was being rolled back puts items back, and the dialog says so.
    let (rig, backend) = recover_rig(recover_preview(Some(files_plan()), Want::Rollback, &[1]));
    let c = rig.client();
    let reply = ask(
        &rig,
        &c,
        2,
        "journal.resume",
        &session_params(),
        Answer::Approved,
    );
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    let last = rig.consent.pages().pop().unwrap();
    assert_eq!(last.instruction, "Roll the cleanup of \"Vendor App\" back?");
    // The run is still the method that was asked (the library decides the same from the journal).
    assert_eq!(backend.recovered.lock().unwrap()[0].1, Want::Resume);
}

#[test]
fn a_cancelled_recovery_changes_nothing() {
    let (rig, backend) = recover_rig(recover_preview(Some(files_plan()), Want::Resume, &[1, 2]));
    let c = rig.client();
    let reply = ask(
        &rig,
        &c,
        2,
        "journal.resume",
        &session_params(),
        Answer::Declined,
    );
    assert_eq!(kind(&reply), "consent_declined", "{reply}");
    assert!(backend.recovered.lock().unwrap().is_empty());
    assert!(rig.running());
}

#[test]
fn a_recovery_that_changes_nothing_on_the_machine_runs_without_a_dialog() {
    // Every op is done: only Purge's own records are missing.
    let (mut rig, backend) = recover_rig(recover_preview(None, Want::Resume, &[]));
    let c = rig.client();
    c.send_line(&request(2, "journal.resume", &session_params()));
    let reply = c.reply();
    assert_eq!(reply["result"]["outcome"], "complete", "{reply}");
    assert!(!rig.dialog_opens());
    assert_eq!(backend.recovered.lock().unwrap().len(), 1);
    c.close();
    assert_eq!(rig.exit(SECS).reason, ExitReason::CompletedChange);

    // Ops that the run only leaves alone change nothing either; the plan names no op for them.
    let plan = plan_of(vec![Candidate {
        category: Category::System,
        ..candidate(
            "c-svc",
            Target::Service {
                name: "VendorSvc".into(),
            },
            Action::DeleteKey,
        )
    }]);
    let (rig, backend) = recover_rig(recover_preview(Some(plan), Want::Resume, &[1]));
    let c = rig.client();
    c.send_line(&request(2, "journal.resume", &session_params()));
    assert_eq!(c.reply()["result"]["outcome"], "complete");
    assert!(!rig.dialog_opens());
    assert_eq!(backend.recovered.lock().unwrap().len(), 1);
}

#[test]
fn a_recovery_with_ops_but_no_plan_is_refused() {
    let (rig, backend) = recover_rig(recover_preview(None, Want::Resume, &[1]));
    let c = rig.client();
    c.send_line(&request(2, "journal.resume", &session_params()));
    assert_eq!(kind(&c.reply()), "runtime");
    assert!(!rig.dialog_opens());
    assert!(backend.recovered.lock().unwrap().is_empty());
}

#[test]
fn a_recovery_the_dialog_cannot_describe_is_never_run() {
    // An op the plan does not hold.
    let (rig, backend) = recover_rig(recover_preview(Some(files_plan()), Want::Resume, &[7]));
    let c = rig.client();
    c.send_line(&request(2, "journal.resume", &session_params()));
    assert_eq!(kind(&c.reply()), "runtime");
    // A rollback of an op that cannot be put back.
    let plan = plan_of(vec![package("c-pkg")]);
    *backend.recover_preview.lock().unwrap() =
        Ok(recover_preview(Some(plan), Want::Rollback, &[1]));
    c.send_line(&request(3, "journal.rollback", &session_params()));
    assert_eq!(kind(&c.reply()), "runtime");
    assert!(!rig.dialog_opens());
    assert!(backend.recovered.lock().unwrap().is_empty());
}

#[test]
fn a_session_that_changed_after_the_recovery_dialog_is_not_recovered() {
    let (rig, backend) = recover_rig(recover_preview(Some(files_plan()), Want::Resume, &[1, 2]));
    *backend.recover.lock().unwrap() = Err(BackendError::NotAsShown);
    let c = rig.client();
    let reply = ask(
        &rig,
        &c,
        2,
        "journal.resume",
        &session_params(),
        Answer::Approved,
    );
    assert_eq!(kind(&reply), "runtime", "{reply}");
    assert!(rig.running());
}

#[test]
fn recovery_refusals_are_the_errors_the_client_is_told() {
    let backend = FakeBackend::new();
    let rig = Rig::start(backend.clone());
    let c = rig.client();
    for (error, method, expected) in [
        (BackendError::Gone, "journal.resume", "gone"),
        (
            BackendError::Refused("needs no recovery".into()),
            "journal.rollback",
            "runtime",
        ),
        (
            BackendError::NeedsRecovery(vec![session()]),
            "journal.retry_held",
            "needs_recovery",
        ),
        (
            BackendError::Integrity("damaged".into()),
            "journal.resume",
            "store_integrity",
        ),
    ] {
        *backend.recover_preview.lock().unwrap() = Err(error);
        c.send_line(&request(2, method, &session_params()));
        assert_eq!(kind(&c.reply()), expected, "{method}");
    }
    assert!(!rig.dialog_opens());
    assert!(backend.recovered.lock().unwrap().is_empty());
}

#[test]
fn the_outcome_of_a_recovery_reaches_the_client() {
    let (rig, backend) = recover_rig(recover_preview(Some(files_plan()), Want::Resume, &[1]));
    *backend.recover.lock().unwrap() = Ok(OutcomeResult {
        outcome: Outcome::NotClosed,
    });
    let c = rig.client();
    let reply = ask(
        &rig,
        &c,
        2,
        "journal.resume",
        &session_params(),
        Answer::Approved,
    );
    assert_eq!(reply["result"]["outcome"], "not_closed", "{reply}");
}

#[test]
fn the_ui_killed_at_every_step_of_a_recovery_leaves_no_half_state() {
    // Before the dialog: a closed pipe ends the broker; the preview changed nothing.
    let (mut rig, backend) =
        recover_rig(recover_preview(Some(files_plan()), Want::Resume, &[1, 2]));
    let c = rig.client();
    c.send_line(&request(2, "journal.resume", &session_params()));
    assert!(rig.consent.wait_open(SECS));
    // With the dialog open: it closes as Cancel and nothing runs.
    c.close();
    assert_eq!(rig.exit(SECS).reason, ExitReason::PipeLost);
    assert!(rig.consent.closed_by_broker());
    assert!(backend.recovered.lock().unwrap().is_empty());

    // After the approval, during the run: the run is finished and recorded, the answer dropped.
    let (mut rig, backend) =
        recover_rig(recover_preview(Some(files_plan()), Want::Resume, &[1, 2]));
    backend.hold_runs();
    let c = rig.client();
    c.send_line(&request(2, "journal.resume", &session_params()));
    assert!(rig.consent.wait_open(SECS));
    rig.consent.answer(Answer::Approved);
    assert!(backend.started.wait(SECS));
    c.close();
    assert!(rig.running());
    backend.hold.open();
    assert_eq!(rig.exit(SECS).reason, ExitReason::PipeLost);
    assert_eq!(backend.recovered.lock().unwrap().len(), 1);
    assert_eq!(backend.undone.lock().unwrap().len(), 0);
}

#[test]
fn no_privilege_or_impersonation_outlives_a_request() {
    let (rig, backend) = restore_rig(files_plan(), &[3, 2, 1]);
    let c = rig.client();
    let reply = ask(
        &rig,
        &c,
        2,
        "undo.run",
        &undo_params(None),
        Answer::Approved,
    );
    assert_eq!(reply["result"]["outcome"], "complete");
    assert_eq!(backend.undone.lock().unwrap().len(), 1);
    // The handler thread holds neither the restore privilege nor a token it set: the methods of this
    // package enable nothing, and the executor enables it only inside purge-win's closure.
    assert!(!rig.leaked.load(Ordering::SeqCst));
}
