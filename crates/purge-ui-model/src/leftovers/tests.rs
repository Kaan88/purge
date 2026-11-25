//! The ports of `LeftoversPageTests` and the model parts of `LeftoversBrokerTests`: paging, the
//! tick rules, re-ticking by candidate id after a re-scan, `plan_refused`, the waiting state
//! (`consent.shown`), the result outcomes, a broker that dies mid-execute, "delete after", "Put back
//! all" over an ended link, and the params each call carries. The real broker and UAC are VM tests.

use std::collections::{HashSet, VecDeque};

use purge_model::exec::journal::UndoConflict;
use purge_model::exec::op::{OpId, OutcomeCounts};
use purge_model::exec::session::{Locker, RestorePointOutcome, SessionId};
use purge_model::{Band, Category, ProgramId, ScanMode};
use purge_rpc::error::{ErrorData, Outcome, Refusal};
use purge_rpc::frame::RequestId;
use purge_rpc::methods::{
    AttentionItem, AttentionReason, BaselineChanged, CandidateRef, CandidateRow, CandidatesPage,
    ConfirmCode, ConflictRow, ConsentShown, DeleteAfter, DeleteAfterOutcome, ExecResult,
    Explanation, HeldItem, ItemKind, LeftoversScanParams, OutcomeResult, PlanCreateParams,
    PlanCreated, Progress, RestorePoint, ScanId, ScanResult, UndoResult, UninstallSessionId,
};

use super::*;
use crate::broker_link::{BrokerLaunch, CallError};

const SESSION: &str = "20251115T101502Z-9f3a6c1d2b7e4a50";

fn session() -> SessionId {
    SESSION.parse().expect("a session id")
}

fn id(n: u64) -> CandidateRef {
    CandidateRef::from_bits(n)
}

fn code(text: &str) -> ConfirmCode {
    text.parse().expect("a code")
}

fn program(id: &str) -> ProgramId {
    serde_json::from_value(serde_json::json!(id)).expect("a program id")
}

fn row(n: u64, band: Band, category: Category, kind: ItemKind, pre: bool) -> CandidateRow {
    CandidateRow {
        candidate_id: id(n),
        band,
        kind,
        category,
        display_name: format!(r"C:\Users\tester\AppData\Local\Leftover\{n}"),
        owner_program: None,
        size_bytes: Some(1024),
        warnings: Vec::new(),
        preselected: pre,
    }
}

fn safe(n: u64, pre: bool) -> CandidateRow {
    row(n, Band::Safe, Category::AppFiles, ItemKind::File, pre)
}

fn plan(code_text: &str, attention: Vec<AttentionItem>) -> PlanCreated {
    let mut plan: PlanCreated = serde_json::from_str(include_str!(
        "../../../purge-rpc/fixtures/pipe.plan.create.result.json"
    ))
    .expect("the plan fixture");
    plan.code = code(code_text);
    plan.attention = attention;
    plan
}

fn complete(done: u32, vanished: u32) -> ExecResult {
    ExecResult {
        outcome: Outcome::Complete,
        session: session(),
        counts: OutcomeCounts {
            done,
            vanished,
            ..OutcomeCounts::default()
        },
        held: Vec::new(),
        restore_point: RestorePointOutcome::NotRequested,
        timings: None,
        delete_after: None,
    }
}

fn deleted(outcome: DeleteAfterOutcome, purged: u32, kept: u32) -> ExecResult {
    let mut result = complete(1, 0);
    result.delete_after = Some(DeleteAfter {
        outcome,
        purged,
        kept,
    });
    result
}

fn undo_complete() -> UndoResult {
    UndoResult {
        outcome: Outcome::Complete,
        conflicts: Vec::new(),
        alerts: Vec::new(),
    }
}

fn rpc(data: ErrorData, message: &str) -> CallError {
    CallError::rpc(data, message)
}

fn declined() -> CallError {
    rpc(ErrorData::ConsentDeclined, "cancelled")
}

type Answer<T> = Box<dyn FnMut() -> Result<T, CallError>>;

/// A broker played by the test: rows, plans and outcomes, one scripted answer per method. It answers
/// every call the model sends, in order, until the model sends none.
struct Broker {
    rows: Vec<CandidateRow>,
    page_calls: Vec<(u32, u16)>,
    scan_calls: usize,
    scans: Vec<LeftoversScanParams>,
    create_plan_calls: usize,
    create_plan: Answer<PlanCreated>,
    execute: Answer<ExecResult>,
    execute_calls: usize,
    delete_calls: usize,
    last_restore_point: Option<RestorePoint>,
    /// `undo.run` per broker generation: 0 the first, 1 the one a relaunch started.
    undo_calls: [usize; 2],
    undo: [Answer<UndoResult>; 2],
    foreground: [usize; 2],
    relaunch: Box<dyn FnMut() -> BrokerLaunch>,
    launches: usize,
    generation: usize,
}

impl Broker {
    fn new() -> Self {
        Self {
            rows: Vec::new(),
            page_calls: Vec::new(),
            scan_calls: 0,
            scans: Vec::new(),
            create_plan_calls: 0,
            create_plan: Box::new(|| Ok(plan("A1B2-C3D4", Vec::new()))),
            execute: Box::new(|| Ok(complete(1, 0))),
            execute_calls: 0,
            delete_calls: 0,
            last_restore_point: None,
            undo_calls: [0; 2],
            undo: [
                Box::new(|| Ok(undo_complete())),
                Box::new(|| Ok(undo_complete())),
            ],
            foreground: [0; 2],
            relaunch: Box::new(BrokerLaunch::started),
            launches: 0,
            generation: 0,
        }
    }

    fn with_rows(rows: Vec<CandidateRow>) -> Self {
        let mut broker = Self::new();
        broker.rows = rows;
        broker
    }

    /// Answers `calls` and every call they lead to.
    fn run(&mut self, model: &mut LeftoversModel, calls: Vec<LeftoversCall>) {
        let mut queue: VecDeque<LeftoversCall> = calls.into();
        while let Some(call) = queue.pop_front() {
            let next = self.answer(model, call);
            queue.extend(next);
        }
    }

    fn answer(&mut self, model: &mut LeftoversModel, call: LeftoversCall) -> Vec<LeftoversCall> {
        match call {
            LeftoversCall::Scan(params) => {
                self.scan_calls += 1;
                let forced = match &params {
                    LeftoversScanParams::Session(p) => p.forced,
                    LeftoversScanParams::Stored(_) => true,
                };
                self.scans.push(params);
                model.on_scan(Ok(scan_result(forced)))
            }
            LeftoversCall::Candidates(params) => {
                self.page_calls.push((params.offset, params.limit.get()));
                let items = self
                    .rows
                    .iter()
                    .skip(params.offset as usize)
                    .take(usize::from(params.limit.get()))
                    .cloned()
                    .collect();
                model.on_candidates(Ok(CandidatesPage {
                    total: self.rows.len() as u32,
                    offset: params.offset,
                    items,
                }))
            }
            LeftoversCall::Explain(params) => {
                model.on_explain(
                    &params.candidate_id,
                    Ok(Explanation {
                        candidate_id: params.candidate_id,
                        evidence: vec![
                            "Inside Mozilla's install folder".into(),
                            "Not on clean Windows 11".into(),
                        ],
                        blockers: Vec::new(),
                    }),
                );
                Vec::new()
            }
            LeftoversCall::CreatePlan(PlanCreateParams::Selected(_)) => {
                self.create_plan_calls += 1;
                let answer = (self.create_plan)();
                model.on_plan_created(answer)
            }
            LeftoversCall::CreatePlan(PlanCreateParams::Preselected(_)) => {
                panic!("the page always sends its selection")
            }
            LeftoversCall::Execute(params) => {
                if params.delete_after {
                    self.delete_calls += 1;
                } else {
                    self.execute_calls += 1;
                }
                self.last_restore_point = Some(params.restore_point);
                let answer = (self.execute)();
                model.on_executed(answer);
                Vec::new()
            }
            LeftoversCall::Undo(params) => {
                assert_eq!(params.session, session());
                assert!(params.item_ids.is_none(), "Put back all names no item");
                self.undo_calls[self.generation] += 1;
                let answer = (self.undo[self.generation])();
                model.on_undone(answer)
            }
            LeftoversCall::RetryHeld(_) => {
                model.on_retried(Ok(OutcomeResult {
                    outcome: Outcome::Complete,
                    alerts: Vec::new(),
                }));
                Vec::new()
            }
            LeftoversCall::AllowForeground => {
                self.foreground[self.generation] += 1;
                Vec::new()
            }
            LeftoversCall::Relaunch => {
                self.launches += 1;
                let launch = (self.relaunch)();
                if launch.started {
                    self.generation = 1;
                }
                model.on_relaunch(launch)
            }
            LeftoversCall::OpenHistory => Vec::new(),
        }
    }
}

fn scan_result(forced: bool) -> ScanResult {
    let mut scan: ScanResult = serde_json::from_str(
        r#"{"scan_id":"s-0000000000000001","mode":"post","counts":{"safe":1,"likely":0,"weak":0,"blocked":0,"preselected":1},"baseline_trust":"Exact","warnings":[]}"#,
    )
    .expect("a scan result");
    if forced {
        scan.mode = ScanMode::Forced;
    }
    scan
}

fn uninstall_session() -> UninstallSessionId {
    "u-0000000000000001".parse().expect("an uninstall session")
}

/// A page that scanned `broker`'s rows (a post scan unless `forced`).
fn scanned(broker: &mut Broker, options: LeftoversOptions, forced: bool) -> LeftoversModel {
    let mut model = LeftoversModel::new(options);
    let calls = model.scan_target(ScanTarget::Session(uninstall_session()), forced);
    broker.run(&mut model, calls);
    model
}

fn scanned_default(broker: &mut Broker) -> LeftoversModel {
    scanned(broker, LeftoversOptions::default(), false)
}

fn checked(model: &LeftoversModel, n: u64) -> bool {
    model.item(&id(n)).expect("the item").checked
}

fn moved(broker: &mut Broker, model: &mut LeftoversModel) {
    let calls = model.move_items(RestorePoint::HighRisk);
    broker.run(model, calls);
}

fn shown(model: &mut LeftoversModel, n: u32) {
    model.on_consent_shown(&ConsentShown {
        request: RequestId(1),
        code: code(match n {
            1 => "A1B2-C3D4",
            2 => "E5F6-A7B8",
            _ => "ABCD-EF01",
        }),
    });
}

#[test]
fn paging_reads_every_page_in_order() {
    let mut broker = Broker::with_rows((0..2_000).map(|i| safe(i, true)).collect());
    let model = scanned_default(&mut broker);

    assert_eq!(model.phase(), LeftoversPhase::Review);
    assert_eq!(model.items().len(), 2_000);
    assert_eq!(broker.page_calls.len(), 4);
    assert!(broker.page_calls.iter().all(|c| c.1 == CANDIDATE_PAGE_SIZE));
    assert_eq!(
        broker.page_calls.iter().map(|c| c.0).collect::<Vec<_>>(),
        [0, 500, 1000, 1500]
    );
    assert!(model.can_move());
}

/// A stand-in for the Programs model's `RegistryLabel::describe`: only the wiring is tested here
/// (the path, kind and SID reach it; its title and location are what the row shows).
fn describe(path: &str, kind: ItemKind, sid: Option<&str>) -> Option<ItemLabel> {
    if kind != ItemKind::RegistryKey {
        return None;
    }
    let rest = path.strip_prefix(r"HKU\")?;
    let (owner, _) = rest.split_once('\\')?;
    let scope = if Some(owner) == sid {
        "Your account"
    } else {
        "Another account"
    };
    Some(ItemLabel {
        title: "Settings of Mozilla Firefox".into(),
        location: format!("{scope} › Software"),
    })
}

#[test]
fn registry_rows_get_a_readable_label_and_keep_the_raw_path() {
    const SID: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";
    let raw = format!(r"HKU\{SID}\Software\Mozilla\Firefox");
    let mut key = row(
        1,
        Band::Safe,
        Category::Registration,
        ItemKind::RegistryKey,
        true,
    );
    key.display_name = raw.clone();
    let mut broker = Broker::with_rows(vec![key, safe(2, true)]);
    let options = LeftoversOptions {
        current_user_sid: Some(SID.into()),
        describe_label: Some(describe),
        ..LeftoversOptions::default()
    };
    let model = scanned(&mut broker, options.clone(), false);

    let key = model.item(&id(1)).expect("the key");
    assert_eq!(key.display_name, raw);
    assert_eq!(key.title(), "Settings of Mozilla Firefox");
    assert_eq!(key.location(), "Your account › Software");

    // A file row has no label: the raw path stays its main line.
    let file = model.item(&id(2)).expect("the file");
    assert!(file.label.is_none());
    assert_eq!(file.title(), file.display_name);
    assert_eq!(file.location(), "");

    // Without the user's SID the same key belongs to "another account".
    let other = scanned(
        &mut broker,
        LeftoversOptions {
            current_user_sid: None,
            ..options
        },
        false,
    );
    assert_eq!(
        other.item(&id(1)).expect("the key").location(),
        "Another account › Software"
    );
    // The row shows the label and keeps the raw path as its tooltip.
    let index = other
        .items()
        .iter()
        .position(|i| i.candidate_id == id(1))
        .expect("index");
    let drawn = other.item_row(index).expect("the row");
    assert!(drawn.labelled);
    assert_eq!(drawn.raw_tip.as_deref(), Some(raw.as_str()));
}

#[test]
fn the_bench_fixture_has_the_asked_count_unique_ids_and_every_group_of_the_sample() {
    let mut model = LeftoversModel::offline(LeftoversOptions::default());
    model.load_sample("Mozilla Firefox", 2_000);

    assert_eq!(model.phase(), LeftoversPhase::Review);
    assert_eq!(model.items().len(), 2_000);
    let ids: HashSet<_> = model.items().iter().map(|i| i.candidate_id).collect();
    assert_eq!(ids.len(), 2_000);
    let names: HashSet<_> = model
        .items()
        .iter()
        .map(|i| i.display_name.clone())
        .collect();
    assert_eq!(names.len(), 2_000);

    let mut sample = LeftoversModel::offline(LeftoversOptions::default());
    sample.load_sample("Mozilla Firefox", 0);
    let group_names = |m: &LeftoversModel| {
        m.groups()
            .iter()
            .map(|g| g.name.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(group_names(&sample), group_names(&model));
    // The sample's one Protected item in ten stays one in ten.
    assert_eq!(
        model.items().iter().filter(|i| i.is_protected()).count(),
        200
    );
    // count 0 is the 10-item sample.
    assert_eq!(sample.items().len(), 10);
    // Nothing can be moved from the sample, and the page says so.
    assert!(!sample.footer().move_enabled);
    assert_eq!(sample.footer().hint, text::SAMPLE_HINT);
    assert!(
        sample
            .bars(None, None)
            .iter()
            .any(|b| b.title == text::BAR_SAMPLE_TITLE)
    );
}

#[test]
fn a_forced_scan_preselects_nothing() {
    let mut broker = Broker::with_rows(vec![safe(1, true), safe(2, true)]);
    let model = scanned(&mut broker, LeftoversOptions::default(), true);

    assert!(model.items().iter().all(|i| !i.checked));
    assert!(!model.can_move());
    assert_eq!(model.scan().expect("a scan").mode, ScanMode::Forced);
    assert!(
        model
            .bars(None, None)
            .iter()
            .any(|b| b.title == text::BAR_FORCED_TITLE)
    );
    // The scan asked for the forced mode.
    assert!(matches!(&broker.scans[0], LeftoversScanParams::Session(p) if p.forced));
}

#[test]
fn group_box_ticks_safe_only_and_each_row_needs_its_own_tick() {
    let mut broker = Broker::with_rows(vec![
        row(1, Band::Safe, Category::AppFiles, ItemKind::File, true),
        row(2, Band::Likely, Category::AppFiles, ItemKind::File, false),
        row(3, Band::Likely, Category::UserData, ItemKind::File, false),
        row(4, Band::Blocked, Category::AppFiles, ItemKind::File, false),
    ]);
    let mut model = scanned_default(&mut broker);
    assert!(checked(&model, 1));
    assert!(!checked(&model, 2));
    assert!(!checked(&model, 3));
    assert!(!checked(&model, 4));

    // A Likely or user-data row needs its own tick; a Protected row can never be ticked.
    model.set_checked(&id(2), true);
    model.set_checked(&id(3), true);
    model.set_checked(&id(4), true);
    assert!(checked(&model, 2));
    assert!(checked(&model, 3));
    assert!(!checked(&model, 4));
    assert!(!model.item(&id(4)).expect("blocked").selectable());

    // Start over with no tick; the group box fills the Safe items and nothing else.
    model.set_checked(&id(2), false);
    model.set_checked(&id(3), false);
    model.set_checked(&id(1), false);
    let group = model
        .groups()
        .iter()
        .position(|g| g.name == "Files & folders")
        .expect("the group");
    model.toggle_group(group);
    assert!(checked(&model, 1));
    assert!(!checked(&model, 2));
    assert!(!checked(&model, 3));
    assert!(!checked(&model, 4));
    assert_eq!(model.group_header(group, 0).expect("header").checked, None);

    // With every selectable row ticked, a second group click unticks the group.
    model.set_checked(&id(2), true);
    model.set_checked(&id(3), true);
    assert_eq!(
        model.group_header(group, 0).expect("header").checked,
        Some(true)
    );
    model.toggle_group(group);
    assert!(!checked(&model, 1));
    assert!(!checked(&model, 2));
    assert!(!checked(&model, 3));
}

#[test]
fn rescan_reapplies_ticks_by_candidate_id() {
    let mut broker = Broker::with_rows(vec![
        safe(1, false),
        safe(2, true),
        safe(3, false),
        safe(5, false),
    ]);
    let mut model = scanned_default(&mut broker);
    assert!(checked(&model, 2));
    model.set_checked(&id(2), false);
    model.set_checked(&id(3), true);
    model.set_checked(&id(5), true);

    broker.rows = vec![safe(1, true), safe(3, false), safe(4, true)];
    let calls = model.rescan();
    broker.run(&mut model, calls);

    assert!(checked(&model, 3));
    assert!(
        !checked(&model, 1),
        "a new scan's preselection does not override the old ticks"
    );
    assert!(!checked(&model, 4));
    let message = model.rescan_message().expect("a message");
    assert!(message.contains("1 new item"), "{message}");
    assert!(message.contains("2 gone (1 of them ticked)"), "{message}");
    assert_eq!(model.phase(), LeftoversPhase::Review);
    assert_eq!(broker.scan_calls, 2);
}

#[test]
fn plan_refused_renders_the_items_unticked() {
    let mut broker = Broker::with_rows(vec![safe(1, true), safe(2, true)]);
    broker.create_plan = Box::new(|| {
        Err(rpc(
            ErrorData::PlanRefused {
                refusals: vec![Refusal {
                    candidate_id: Some(id(2)),
                    reason: "it cannot be backed up".into(),
                }],
            },
            "bind refused the plan",
        ))
    });
    let mut model = scanned_default(&mut broker);

    moved(&mut broker, &mut model);

    assert_eq!(model.phase(), LeftoversPhase::Review);
    assert!(model.plan().is_none());
    let refused = model.item(&id(2)).expect("refused");
    assert!(refused.refused);
    assert!(!refused.checked);
    assert!(refused.refusal_reason.contains("cannot be backed up"));
    assert!(checked(&model, 1));
    assert_eq!(model.refusal_lines().len(), 1);
    assert!(
        model
            .error()
            .expect("an error")
            .contains("cannot be quarantined")
    );
    assert!(
        model.can_move(),
        "the item that was not refused keeps its tick"
    );
    assert_eq!(broker.execute_calls, 0);
    assert!(
        model
            .bars(None, None)
            .iter()
            .any(|b| b.title == text::BAR_SOME_REFUSED)
    );
}

#[test]
fn waiting_state_shows_the_code_when_the_broker_dialog_is_up() {
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    let mut model = scanned_default(&mut broker);

    let calls = model.move_items(RestorePoint::HighRisk);
    assert!(matches!(calls[..], [LeftoversCall::CreatePlan(_)]));
    assert_eq!(model.waiting_title(), "Preparing the plan…");
    let calls = model.on_plan_created(Ok(plan("A1B2-C3D4", Vec::new())));
    assert_eq!(calls[0], LeftoversCall::AllowForeground);
    assert!(matches!(calls[1], LeftoversCall::Execute(_)));
    shown(&mut model, 1);

    assert_eq!(model.phase(), LeftoversPhase::Waiting);
    assert!(model.prompt_up());
    assert_eq!(model.waiting_code_text(), "A1B2-C3D4");
    assert!(model.waiting_detail().contains("Nothing has been moved"));
    assert!(
        model
            .waiting_title()
            .contains("Confirm in the Purge security prompt")
    );
    // The shell must not hand this page another broker link now (LeftoversNavigator.TryShow).
    assert!(model.is_changing());

    model.on_executed(Ok(complete(1, 0)));
    assert_eq!(model.phase(), LeftoversPhase::Result);
    assert!(!model.is_changing());
}

#[test]
fn quarantine_is_the_default_and_the_move_asks_for_no_delete() {
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    let mut model = scanned_default(&mut broker);

    assert!(!model.delete_after());
    assert_eq!(model.move_text(), "Move 1 item to quarantine…");
    assert_eq!(
        text::DELETE_AFTER_TEXT,
        "Delete instead of keeping in quarantine"
    );
    moved(&mut broker, &mut model);

    assert_eq!(broker.execute_calls, 1);
    assert_eq!(broker.delete_calls, 0);
    assert!(model.delete_after_result().is_none());
    assert_eq!(model.result_title(), Some("Moved 1 item to quarantine"));
}

#[test]
fn the_tick_asks_the_broker_for_the_delete_step_and_the_result_says_what_it_did() {
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    broker.execute = Box::new(|| Ok(deleted(DeleteAfterOutcome::Deleted, 1, 0)));
    let mut model = scanned_default(&mut broker);

    let version = model.list_version();
    model.set_delete_after(true);
    assert_eq!(model.move_text(), "Move 1 item, then delete it…");
    // The tick changes the button's words and nothing else (no list rebuild).
    assert_eq!(model.list_version(), version);
    assert_eq!(model.footer().hint, text::TWO_PROMPTS_HINT);

    let calls = model.move_items(RestorePoint::Off);
    broker.run(&mut model, calls);

    // One request, the one with the delete step; the plain execute is not also sent.
    assert_eq!(broker.delete_calls, 1);
    assert_eq!(broker.execute_calls, 0);
    assert_eq!(broker.last_restore_point, Some(RestorePoint::Off));
    assert_eq!(model.phase(), LeftoversPhase::Result);
    assert_eq!(model.result_title(), Some("Moved 1 item to quarantine"));
    let said = model.delete_after_result().expect("the delete line");
    assert!(said.starts_with(
        "Then deleted for good, as you asked: 1 quarantined item. That cannot be undone."
    ));
    assert!(said.contains("Registry and other changes of this cleanup can still be undone"));
    // Off again for the next move.
    assert!(!model.delete_after());
    assert!(broker.foreground[0] >= 1);
}

#[test]
fn a_declined_or_failed_delete_step_leaves_the_items_in_quarantine_and_says_so() {
    for (outcome, purged, kept, starts) in [
        (
            DeleteAfterOutcome::Declined,
            0,
            2,
            "Nothing was deleted: the delete prompt was cancelled. What was moved is in quarantine and can be put back for 30 days",
        ),
        (
            DeleteAfterOutcome::Failed,
            0,
            2,
            "The delete did not go through. What was moved is safe in quarantine and can be put back for 30 days",
        ),
        (
            DeleteAfterOutcome::Nothing,
            0,
            0,
            "Nothing was deleted: this cleanup left nothing in quarantine that can be deleted now.",
        ),
        (
            DeleteAfterOutcome::Partial,
            1,
            1,
            "Then deleted for good: 1. Still in quarantine: 1 (declined, or not deletable now); it can be put back for 30 days",
        ),
    ] {
        let mut broker = Broker::with_rows(vec![safe(1, true)]);
        broker.execute = Box::new(move || Ok(deleted(outcome, purged, kept)));
        let mut model = scanned_default(&mut broker);
        model.set_delete_after(true);

        moved(&mut broker, &mut model);

        // The move's own result is unchanged; the delete line never claims a delete that did not happen.
        assert_eq!(model.phase(), LeftoversPhase::Result);
        assert_eq!(model.result_title(), Some("Moved 1 item to quarantine"));
        let said = model.delete_after_result().expect("the delete line");
        assert!(said.starts_with(starts), "{said}");
        assert!(model.can_undo());
    }

    // An answer without the step at all (a broker that does not know the request) claims nothing.
    let none = text::describe_delete_after(None);
    assert!(none.starts_with("The delete step did not run. What was moved is in quarantine"));
    assert!(!none.contains("deleted for good"));
}

/// Review M1: after a delete step that deleted something, the result page never offers "Put back
/// all". Nothing left to undo: no button. Registry changes left: "Undo registry changes…". Items
/// still in quarantine: "Put back what is still in quarantine…". Each opens History & undo.
#[test]
fn after_a_delete_step_the_undo_button_never_promises_what_was_deleted() {
    fn after(done: u32, step: Option<DeleteAfter>) -> (LeftoversModel, Broker) {
        let mut broker = Broker::with_rows(vec![safe(1, true)]);
        broker.execute = Box::new(move || {
            let mut result = complete(done, 0);
            result.delete_after = step;
            Ok(result)
        });
        let mut model = scanned_default(&mut broker);
        model.set_delete_after(true);
        moved(&mut broker, &mut model);
        (model, broker)
    }
    let step = |outcome, purged, kept| {
        Some(DeleteAfter {
            outcome,
            purged,
            kept,
        })
    };

    // Two files moved, both deleted, nothing else changed: nothing to undo, no button.
    let (all, _) = after(2, step(DeleteAfterOutcome::Deleted, 2, 0));
    assert!(!all.can_undo());

    // Two files deleted and a registry change besides: the registry change can still be undone.
    let (mut registry, mut registry_broker) = after(3, step(DeleteAfterOutcome::Deleted, 2, 0));
    assert!(registry.can_undo());
    assert_eq!(registry.undo_text(), "Undo registry changes…");
    assert!(registry.undo_opens_history());
    assert_eq!(registry.click_undo_all(), [LeftoversCall::OpenHistory]);
    let calls = registry.undo_all();
    registry_broker.run(&mut registry, calls);
    assert_eq!(registry_broker.undo_calls, [0, 0]);
    assert_eq!(registry.phase(), LeftoversPhase::Result);
    assert!(registry.error().is_none());
    assert_eq!(
        registry.info(),
        Some("Open History & undo to put back what this cleanup still holds.")
    );

    // One deleted, one declined: what is still in quarantine can be put back, from History.
    let (mut partial, mut partial_broker) = after(2, step(DeleteAfterOutcome::Partial, 1, 1));
    assert!(partial.can_undo());
    assert_eq!(partial.undo_text(), "Put back what is still in quarantine…");
    assert!(partial.undo_opens_history());
    let calls = partial.undo_all();
    partial_broker.run(&mut partial, calls);
    assert_eq!(partial_broker.undo_calls, [0, 0]);

    // Nothing deleted (declined): everything is in quarantine, the button is the usual one.
    let (mut declined_page, mut declined_broker) =
        after(2, step(DeleteAfterOutcome::Declined, 0, 2));
    assert!(declined_page.can_undo());
    assert_eq!(declined_page.undo_text(), "Put back all");
    assert!(!declined_page.undo_opens_history());

    // A link that has ended never gets an undo sent into it, and no "ended while putting things back".
    declined_page.set_broker_live(false);
    assert!(declined_page.undo_opens_history());
    let calls = declined_page.undo_all();
    declined_broker.run(&mut declined_page, calls);
    assert_eq!(declined_broker.undo_calls, [0, 0]);
    assert_eq!(declined_page.phase(), LeftoversPhase::Result);
    assert!(declined_page.error().is_none());
}

fn with_launcher() -> LeftoversOptions {
    LeftoversOptions {
        can_relaunch: true,
        ..LeftoversOptions::default()
    }
}

/// A page that moved one item over `broker` and can start a new broker.
fn moved_with_launcher(broker: &mut Broker) -> LeftoversModel {
    broker.rows = vec![safe(1, true)];
    let mut model = scanned(broker, with_launcher(), false);
    moved(broker, &mut model);
    assert_eq!(model.phase(), LeftoversPhase::Result);
    model
}

/// DECISIONS 2026-11-24 (A): a completed move ends the broker, so "Put back all" over the dead link
/// starts a new broker in place, then sends `undo.run` over the new one, and the "Put back" result
/// shows on the same page. Nothing goes into the dead link, and History is not opened.
#[test]
fn put_back_all_over_an_ended_link_starts_a_new_broker_and_undoes_on_the_page() {
    let mut broker = Broker::new();
    let mut model = moved_with_launcher(&mut broker);
    model.set_broker_live(false);
    assert!(!model.undo_opens_history());
    assert!(model.can_undo());

    let calls = model.click_undo_all();
    assert_eq!(calls, [LeftoversCall::Relaunch]);
    assert_eq!(model.waiting_title(), text::UNDO_STARTING_TITLE);
    broker.generation = 1;
    let calls = model.on_relaunch(BrokerLaunch::started());
    assert_eq!(model.waiting_title(), text::UNDO_WAITING_TITLE);
    broker.run(&mut model, calls);

    assert_eq!(broker.undo_calls, [0, 1]);
    assert_eq!(broker.foreground[1], 1);
    assert_eq!(model.phase(), LeftoversPhase::Undone);
    assert_eq!(model.undo_title(), Some("Put back"));
    assert!(model.error().is_none());
    assert!(model.broker_is_live());
    // The new broker's prompt reports to the page.
    shown(&mut model, 3);
    assert_eq!(model.code(), Some(code("ABCD-EF01")));
}

/// The broker refuses because it is closing after the move, or the request could not be written:
/// nothing was done, so the page starts a new broker and puts back over it.
#[test]
fn put_back_all_while_the_broker_is_closing_starts_a_new_broker() {
    for refusal in [
        rpc(
            ErrorData::Runtime {
                message: "the broker is closing".into(),
            },
            "the broker is closing",
        ),
        CallError::link("The administrator part is not running.", true),
    ] {
        let mut broker = Broker::new();
        broker.undo[0] = Box::new(move || Err(refusal.clone()));
        let mut model = moved_with_launcher(&mut broker);
        let calls = model.undo_all();
        broker.run(&mut model, calls);
        assert_eq!(broker.undo_calls, [1, 1]);
        assert_eq!(broker.launches, 1);
        assert_eq!(model.phase(), LeftoversPhase::Undone);
        assert!(model.error().is_none());
    }

    // Without a launcher, the same refusal says that nothing was put back: no "Interrupted".
    let mut lone = Broker::with_rows(vec![safe(1, true)]);
    lone.undo[0] = Box::new(|| Err(CallError::link("gone", true)));
    let mut page = scanned_default(&mut lone);
    moved(&mut lone, &mut page);
    let calls = page.undo_all();
    lone.run(&mut page, calls);
    assert_eq!(page.phase(), LeftoversPhase::Result);
    let error = page.error().expect("an error");
    assert!(error.starts_with("Nothing was put back"));
    assert!(!error.contains("cannot tell"));
}

/// The admin explanation declined ("Not now") or UAC cancelled: nothing is sent, the page stays on
/// its result and says "Not put back: administrator permission was not given."
#[test]
fn put_back_all_without_admin_permission_says_nothing_was_put_back() {
    for launch in [
        BrokerLaunch::declined(),
        BrokerLaunch::cancelled("The Windows prompt was cancelled."),
    ] {
        let mut broker = Broker::new();
        broker.relaunch = Box::new(move || launch.clone());
        let mut model = moved_with_launcher(&mut broker);
        model.set_broker_live(false);
        let calls = model.undo_all();
        broker.run(&mut model, calls);
        assert_eq!(broker.undo_calls, [0, 0]);
        assert_eq!(model.phase(), LeftoversPhase::Result);
        assert_eq!(
            model.info(),
            Some("Not put back: administrator permission was not given.")
        );
        assert!(model.error().is_none());
        assert!(model.can_undo(), "the button is offered again");
    }

    // A launch that failed names its reason, still on the result page.
    let mut failed = Broker::new();
    failed.relaunch = Box::new(|| BrokerLaunch::failed("broker missing"));
    let mut page = moved_with_launcher(&mut failed);
    page.set_broker_live(false);
    let calls = page.undo_all();
    failed.run(&mut page, calls);
    assert_eq!(page.phase(), LeftoversPhase::Result);
    assert_eq!(
        page.error(),
        Some("Not put back: the administrator part could not be started. broker missing")
    );
}

/// After a delete step that deleted something, "Put back…" still routes to History, launcher or not.
#[test]
fn after_a_delete_step_the_undo_button_still_routes_to_history_with_a_launcher() {
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    broker.execute = Box::new(|| {
        let mut result = complete(3, 0);
        result.delete_after = Some(DeleteAfter {
            outcome: DeleteAfterOutcome::Deleted,
            purged: 2,
            kept: 0,
        });
        Ok(result)
    });
    let mut model = scanned(&mut broker, with_launcher(), false);
    model.set_delete_after(true);
    moved(&mut broker, &mut model);
    for live in [true, false] {
        model.set_broker_live(live);
        assert!(model.undo_opens_history());
        let calls = model.undo_all();
        broker.run(&mut model, calls);
        assert_eq!(broker.undo_calls, [0, 0]);
        assert_eq!(broker.launches, 0);
        assert_eq!(
            model.info(),
            Some("Open History & undo to put back what this cleanup still holds.")
        );
    }
}

#[test]
fn the_waiting_state_says_when_the_second_prompt_is_the_one_to_confirm() {
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    let mut model = scanned_default(&mut broker);
    model.set_delete_after(true);

    let _ = model.move_items(RestorePoint::HighRisk);
    let calls = model.on_plan_created(Ok(plan("A1B2-C3D4", Vec::new())));
    let Some(LeftoversCall::Execute(params)) = calls.get(1) else {
        panic!("plan.execute: {calls:?}");
    };
    assert!(params.delete_after);
    shown(&mut model, 1);
    assert_eq!(model.code(), Some(code("A1B2-C3D4")));
    assert!(
        model
            .waiting_title()
            .contains("Confirm in the Purge security prompt")
    );
    assert!(
        model
            .waiting_detail()
            .contains("It approves the move only; a second prompt then asks about deleting")
    );

    let calls = model.on_progress(&Progress {
        request: RequestId(1),
        program_id: None,
        phase: DELETE_AFTER_PHASE.into(),
        done: 1,
        total: Some(1),
    });
    assert_eq!(calls, [LeftoversCall::AllowForeground]);
    assert!(
        model
            .waiting_title()
            .contains("second Purge security prompt")
    );
    assert_eq!(
        model.waiting_detail(),
        "The items are in quarantine. Nothing has been deleted yet."
    );
    // The first prompt's code is not shown for the second prompt; the broker announces its own.
    assert!(model.code().is_none());
    assert!(!model.prompt_up());
    shown(&mut model, 2);
    assert_eq!(model.code(), Some(code("E5F6-A7B8")));
    assert!(model.prompt_up());
    assert!(model.is_changing());

    model.on_executed(Ok(deleted(DeleteAfterOutcome::Declined, 0, 1)));
    assert_eq!(model.phase(), LeftoversPhase::Result);
    assert!(
        model
            .delete_after_result()
            .expect("the line")
            .starts_with("Nothing was deleted: the delete prompt was cancelled.")
    );
}

#[test]
fn a_cancelled_move_prompt_with_the_tick_moves_and_deletes_nothing() {
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    broker.execute = Box::new(|| Err(declined()));
    let mut model = scanned_default(&mut broker);
    model.set_delete_after(true);

    moved(&mut broker, &mut model);

    assert_eq!(model.phase(), LeftoversPhase::Review);
    assert_eq!(
        model.info(),
        Some("Nothing was moved: the prompt was cancelled.")
    );
    assert!(model.result().is_none());
    assert!(model.delete_after_result().is_none());
    // The choice is the user's and stays as it was for the next try.
    assert!(model.delete_after());
}

#[test]
fn attention_rows_come_from_plan_create_including_absorbed_ids() {
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    let absorbed: CandidateRef = "c-00000000abad1dea".parse().expect("an id");
    let mut model = scanned_default(&mut broker);
    let _ = model.move_items(RestorePoint::HighRisk);
    let _ = model.on_plan_created(Ok(plan(
        "A1B2-C3D4",
        vec![AttentionItem {
            candidate_id: absorbed,
            display_name: r"C:\Users\tester\AppData\Local\Mozilla\cache".into(),
            kind: ItemKind::Folder,
            band: Band::Likely,
            size_bytes: None,
            reasons: vec![AttentionReason::Inside, AttentionReason::UserData],
        }],
    )));

    assert_eq!(model.attention().len(), 1);
    let attention = &model.attention()[0];
    assert_eq!(attention.candidate_id, absorbed);
    assert!(attention.reasons_text().contains("inside another item"));
    assert!(attention.reasons_text().contains("holds your data"));
    assert!(model.item(&absorbed).is_none());
    assert_eq!(
        model.attention_header().as_deref(),
        Some("Items that need attention (1)")
    );
}

#[test]
fn complete_result_names_moved_and_already_gone() {
    let mut broker = Broker::with_rows(vec![safe(1, true), safe(2, true), safe(3, true)]);
    broker.execute = Box::new(|| {
        let mut result = complete(2, 1);
        result.restore_point = RestorePointOutcome::Created { sequence: 42 };
        Ok(result)
    });
    let mut model = scanned_default(&mut broker);

    moved(&mut broker, &mut model);

    assert_eq!(model.phase(), LeftoversPhase::Result);
    assert!(
        model
            .result_title()
            .expect("a title")
            .contains("Moved 3 items")
    );
    let detail = model.result_detail().expect("a detail");
    assert!(detail.contains("2 moved"));
    assert!(detail.contains("1 already gone"));
    assert!(
        model
            .restore_point_text()
            .expect("a restore point")
            .contains("42")
    );
    assert!(model.can_undo());
    assert!(!model.can_retry_held());
    assert!(model.result_complete());
}

#[test]
fn partial_result_shows_held_lockers_and_failures() {
    let mut broker = Broker::with_rows(vec![safe(1, true), safe(2, true), safe(3, true)]);
    broker.execute = Box::new(|| {
        Ok(ExecResult {
            outcome: Outcome::Partial,
            session: session(),
            counts: OutcomeCounts {
                done: 1,
                held_retry: 1,
                failed: 1,
                ..OutcomeCounts::default()
            },
            held: vec![HeldItem {
                op: OpId(2),
                display_name: r"C:\Program Files\Mozilla\firefox.exe".into(),
                lockers: vec![Locker {
                    pid: 4242,
                    name: "firefox.exe".into(),
                    service: None,
                }],
            }],
            restore_point: RestorePointOutcome::NotRequested,
            timings: None,
            delete_after: None,
        })
    });
    let mut model = scanned_default(&mut broker);

    moved(&mut broker, &mut model);

    assert_eq!(model.phase(), LeftoversPhase::Result);
    assert!(
        model
            .result_title()
            .expect("a title")
            .contains("Moved 1 of 3 items")
    );
    assert_eq!(model.held_lines().len(), 1);
    assert!(model.held_lines()[0].contains("firefox.exe"));
    assert!(model.held_lines()[0].contains("4242"));
    assert_eq!(model.failed_lines().len(), 1);
    assert!(model.failed_lines()[0].contains("1 could not be moved"));
    assert!(model.can_retry_held());
    assert!(model.restore_point_text().is_none());
    assert!(!model.result_complete());

    // The retry goes out for the result's session through the broker's prompt.
    let calls = model.retry_held();
    assert_eq!(model.waiting_title(), text::CONFIRM_RETRY);
    broker.run(&mut model, calls);
    assert_eq!(model.phase(), LeftoversPhase::Result);
    assert_eq!(model.info(), Some(text::RETRY_MOVED));
}

#[test]
fn a_result_that_was_not_closed_says_history_offers_recovery() {
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    broker.execute = Box::new(|| {
        let mut result = complete(1, 0);
        result.outcome = Outcome::NotClosed;
        Ok(result)
    });
    let mut model = scanned_default(&mut broker);

    moved(&mut broker, &mut model);

    assert_eq!(
        model.result_title(),
        Some("The session was not recorded completely")
    );
    assert!(
        model
            .result_detail()
            .expect("a detail")
            .contains("History & undo offers recovery")
    );
}

#[test]
fn broker_death_mid_execute_never_claims_a_result() {
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    broker.execute = Box::new(|| Err(CallError::link("The administrator part ended.", false)));
    let mut model = scanned_default(&mut broker);

    moved(&mut broker, &mut model);

    assert_eq!(model.phase(), LeftoversPhase::Interrupted);
    assert!(model.result().is_none());
    assert!(model.result_title().is_none());
    let error = model.error().expect("an error").to_owned();
    assert!(error.contains("cannot tell"));
    assert!(error.contains("History & undo"));
    assert!(!model.can_undo());
    let (title, text) = model.empty_panel().expect("the interrupted panel");
    assert_eq!(title, "A change was interrupted");
    assert_eq!(text, error);
}

#[test]
fn a_move_never_sent_says_nothing_was_moved() {
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    broker.execute = Box::new(|| {
        Err(CallError::link(
            "The administrator part is not running.",
            true,
        ))
    });
    let mut model = scanned_default(&mut broker);

    moved(&mut broker, &mut model);

    assert_eq!(model.phase(), LeftoversPhase::Review);
    assert!(model.result().is_none());
    let error = model.error().expect("an error").to_owned();
    assert!(error.contains("Nothing was moved"), "{error}");
    assert!(!error.contains("cannot tell"));
    assert!(checked(&model, 1), "the review is kept as it was");
}

#[test]
fn consent_declined_does_nothing() {
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    broker.execute = Box::new(|| Err(declined()));
    let mut model = scanned_default(&mut broker);

    moved(&mut broker, &mut model);

    assert_eq!(model.phase(), LeftoversPhase::Review);
    assert!(model.result().is_none());
    assert!(model.info().expect("a note").contains("Nothing was moved"));
    assert!(checked(&model, 1));
}

/// The S3 half of `S2CompletesHandsTheScanToS3AndThePlanRunsToTheResult` (the S2 half is the
/// pipeline's, package UI-MODEL-A): the request S2 builds, candidate paging for the scan it was
/// handed (no second scan), then plan.create and plan.execute with the confirm dialog's choice.
#[test]
fn the_hand_off_shows_the_scan_it_was_given_and_the_plan_runs_to_the_result() {
    let scan_id: ScanId = "s-00000000005c5c52".parse().expect("a scan id");
    let request = LeftoversRequest {
        program_id: program("HKLM|64|prog-1"),
        program_name: "Mozilla Firefox".into(),
        session_id: Some(uninstall_session()),
        scan_id,
        mode: ScanMode::Post,
        restore_point: RestorePoint::Always,
        quiet: false,
        broker: Some("the S2 link"),
    };
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    let mut model = LeftoversModel::new(LeftoversOptions::default());
    let shown = model.try_show(request).expect("taken");
    assert_eq!(shown.broker, Some("the S2 link"));
    broker.run(&mut model, shown.calls);

    assert_eq!(broker.scan_calls, 0);
    assert_eq!(model.scan().expect("a scan").scan_id, scan_id);
    assert_eq!(model.program_name(), "Mozilla Firefox");
    assert_eq!(model.title(), "Leftovers of Mozilla Firefox");
    assert_eq!(model.subtitle(), "Post-uninstall scan · 1 items");
    assert_eq!(model.app_initial().as_deref(), Some("M"));
    assert!(checked(&model, 1));
    assert_eq!(model.waiting_for_review(), 1);

    let calls = model.click_move();
    broker.run(&mut model, calls);

    assert_eq!(broker.create_plan_calls, 1);
    assert_eq!(broker.execute_calls, 1);
    assert_eq!(broker.last_restore_point, Some(RestorePoint::Always));
    assert_eq!(model.phase(), LeftoversPhase::Result);
    assert!(
        model
            .result_title()
            .expect("a title")
            .contains("Moved 1 item")
    );
    assert!(model.can_undo());
}

/// `LeftoversNavigator.TryShow`: while a change is on its way the page takes no new request (its
/// link would end the running change), and a request without a link says so.
#[test]
fn a_request_is_refused_while_a_change_runs_and_one_without_a_link_says_it_ended() {
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    let mut model = scanned_default(&mut broker);
    let _ = model.move_items(RestorePoint::HighRisk);
    assert!(model.is_changing());
    let request = LeftoversRequest {
        program_id: program("HKLM|64|x"),
        program_name: "Other".into(),
        session_id: None,
        scan_id: ScanId::from_bits(9),
        mode: ScanMode::External,
        restore_point: RestorePoint::HighRisk,
        quiet: true,
        broker: Some(7_u8),
    };
    let refused = model.try_show(request.clone()).expect_err("refused");
    assert_eq!(refused.broker, Some(7));
    assert!(model.is_changing());

    let mut fresh = LeftoversModel::new(LeftoversOptions::default());
    let shown = fresh
        .try_show(LeftoversRequest {
            broker: None,
            ..request
        })
        .expect("taken");
    assert!(shown.calls.is_empty());
    assert_eq!(fresh.phase(), LeftoversPhase::Empty);
    assert_eq!(
        fresh.empty_panel().map(|p| p.0),
        Some("The administrator part ended")
    );
    assert!(!fresh.broker_is_live());
}

#[test]
fn the_detail_pane_asks_explain_once_and_shows_the_evidence() {
    let mut broker = Broker::with_rows(vec![
        safe(1, true),
        row(2, Band::Weak, Category::Cache, ItemKind::Folder, false),
    ]);
    let mut model = scanned_default(&mut broker);

    let calls = model.select(id(1));
    assert!(matches!(calls[..], [LeftoversCall::Explain(_)]));
    // A second selection while explain is on its way sends nothing more.
    assert!(model.select(id(1)).is_empty());
    broker.run(&mut model, calls);
    let detail = model.detail().expect("the pane");
    assert_eq!(detail.preselect, "Ticked");
    assert_eq!(detail.evidence.len(), 2);
    assert!(
        detail
            .evidence
            .iter()
            .all(|l| l.glyph == EvidenceGlyph::Explicit)
    );
    assert_eq!(
        detail.if_removed,
        "Moved to quarantine, restorable from History & undo"
    );
    assert_eq!(detail.found_by, "File · the program's files");

    // A weak item with nothing says it matches by name only; a failed explain is its blocker.
    let calls = model.select(id(2));
    assert_eq!(calls.len(), 1);
    assert!(
        model.detail().expect("pane").evidence[0]
            .text
            .contains("Name matches only")
    );
    model.on_explain(&id(2), Err(CallError::link("pipe closed", false)));
    let detail = model.detail().expect("pane");
    assert_eq!(detail.evidence[0].glyph, EvidenceGlyph::Warning);
    assert_eq!(detail.evidence[0].text, "pipe closed");
}

#[test]
fn weak_matches_are_hidden_counted_and_unticked_when_hidden_again() {
    let mut broker = Broker::with_rows(vec![
        safe(1, true),
        row(2, Band::Weak, Category::AppFiles, ItemKind::File, false),
    ]);
    let mut model = scanned_default(&mut broker);
    let rows = model.rows();
    // The header, then the one visible row: the weak match is hidden and counted.
    assert_eq!(rows.len(), 2);
    assert_eq!(model.row_name(rows[0]), "Files & folders, 1 (1 hidden)");
    assert_eq!(
        model.row_name(rows[1]),
        r"C:\Users\tester\AppData\Local\Leftover\1, Safe, ticked"
    );
    assert_eq!(model.weak_button_text(), "Show weak matches (1)");

    model.toggle_weak();
    assert_eq!(model.rows().len(), 3);
    model.set_checked(&id(2), true);
    model.toggle_weak();
    assert!(!checked(&model, 2), "hiding weak matches unticks them");

    let footer = model.footer();
    assert_eq!(footer.count, "1 of 2 selected");
    assert_eq!(footer.verdict, "1 item · 1.0 KB");
    assert_eq!(footer.detail, " · 1.0 KB, 1 file item");
    let bands = model.band_summary();
    assert_eq!(bands.safe_text, "Safe 1 · 1.0 KB");
    assert_eq!(bands.likely_text, "Likely 1 · 1.0 KB");
    assert_eq!(bands.protected_text, "Protected 0");

    model.toggle_expanded(0);
    assert_eq!(model.rows().len(), 1);
    assert_eq!(model.expand_all_text(), "Expand all");
    model.expand_all();
    assert_eq!(model.expand_all_text(), "Collapse all");
}

#[test]
fn a_baseline_build_offers_a_rescan_of_the_scan_shown() {
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    let mut model = scanned_default(&mut broker);
    let scan_id = model.scan().expect("a scan").scan_id;
    let mut changed: BaselineChanged = serde_json::from_str(include_str!(
        "../../../purge-rpc/fixtures/notification.baseline.changed.json"
    ))
    .expect("the fixture");
    model.on_baseline_changed(&changed);
    assert!(!model.rescan_offered(), "another scan is offered");
    changed.rescan_offered = vec![scan_id];
    model.on_baseline_changed(&changed);
    assert!(model.rescan_offered());
    assert!(
        model
            .bars(None, None)
            .iter()
            .any(|b| b.action == Some(LeftoversAction::ScanAgain))
    );
}

#[test]
fn a_held_scan_bar_waits_for_the_change_and_otherwise_offers_the_scan() {
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    let mut model = scanned_default(&mut broker);
    let bars = model.bars(Some("Git"), Some("7-Zip"));
    assert_eq!(bars[0].title, "A scan of Git is waiting for this page.");
    assert_eq!(bars[0].action, Some(LeftoversAction::ShowHeldScan));
    assert!(
        !bars
            .iter()
            .any(|b| b.action == Some(LeftoversAction::GoToUninstall))
    );
    let _ = model.move_items(RestorePoint::HighRisk);
    let bars = model.bars(Some("Git"), None);
    assert_eq!(bars[0].action, None);
    assert_eq!(bars[0].message, text::BAR_HELD_CHANGING);
    let idle = LeftoversModel::new(LeftoversOptions::default());
    assert_eq!(
        idle.bars(None, Some("7-Zip"))[0].title,
        "Next to uninstall: 7-Zip."
    );
}

#[test]
fn errors_say_what_the_broker_refused() {
    let mut broker = Broker::with_rows(vec![safe(1, true)]);
    broker.create_plan = Box::new(|| {
        Err(rpc(
            ErrorData::CapExceeded {
                volume: r"C:\".into(),
                used: 10,
                needed: 20,
                cap: 25,
            },
            "cap",
        ))
    });
    let mut model = scanned_default(&mut broker);
    moved(&mut broker, &mut model);
    assert_eq!(
        model.error(),
        Some(
            r"The quarantine would pass its cap on C:\: 20 bytes are needed, 10 of 25 are in use."
        )
    );

    // A scan whose link ended says so on the empty page.
    let mut model = LeftoversModel::new(LeftoversOptions::default());
    let _ = model.scan_target(ScanTarget::Session(uninstall_session()), false);
    let _ = model.on_scan(Err(CallError::link("pipe closed", false)));
    assert_eq!(model.phase(), LeftoversPhase::Empty);
    assert_eq!(
        model.error(),
        Some("The administrator part ended before the scan finished. pipe closed")
    );
    let _ = model.scan_target(ScanTarget::Session(uninstall_session()), false);
    let _ = model.on_scan(Err(CallError::Cancelled));
    assert_eq!(model.info(), Some("The scan was cancelled."));
}

// ---- LeftoversBrokerTests (model parts): the params of each call ----------------------------

fn json(call: &LeftoversCall) -> String {
    match call {
        LeftoversCall::Scan(p) => serde_json::to_string(p),
        LeftoversCall::Candidates(p) => serde_json::to_string(p),
        LeftoversCall::CreatePlan(p) => serde_json::to_string(p),
        LeftoversCall::Execute(p) => serde_json::to_string(p),
        LeftoversCall::Undo(p) => serde_json::to_string(p),
        LeftoversCall::RetryHeld(p) => serde_json::to_string(p),
        LeftoversCall::Explain(p) => serde_json::to_string(p),
        other => Ok(format!("{other:?}")),
    }
    .expect("json")
}

/// A page with one scanned, ticked candidate, ready to move.
fn ready(delete_after: bool) -> LeftoversModel {
    let mut model = LeftoversModel::new(LeftoversOptions::default());
    let _ = model.scan_target(ScanTarget::Session(uninstall_session()), false);
    let _ = model.on_scan(Ok(scan_result(false)));
    let _ = model.on_candidates(Ok(CandidatesPage {
        total: 1,
        offset: 0,
        items: vec![safe(1, true)],
    }));
    model.set_delete_after(delete_after);
    model
}

#[test]
fn the_calls_carry_the_design_params() {
    let mut model = LeftoversModel::new(LeftoversOptions::default());
    let scan = model.scan_target(ScanTarget::Session(uninstall_session()), true);
    let scan = json(&scan[0]);
    assert!(
        scan.contains(r#""session_id":"u-0000000000000001""#),
        "{scan}"
    );
    assert!(scan.contains(r#""forced":true"#), "{scan}");
    let stored = LeftoversModel::new(LeftoversOptions::default())
        .scan_target(ScanTarget::Stored(program("HKLM|64|Git_is1")), false);
    assert_eq!(json(&stored[0]), r#"{"program_id":"HKLM|64|Git_is1"}"#);

    let mut model = ready(false);
    let create = model.move_items(RestorePoint::HighRisk);
    let create = json(&create[0]);
    assert!(
        create.contains(r#""scan_id":"s-0000000000000001""#),
        "{create}"
    );
    assert!(
        create.contains(r#""selected":["c-0000000000000001"]"#),
        "{create}"
    );
    assert!(!create.contains("allow_irreversible"), "{create}");
    let execute = model.on_plan_created(Ok(plan("A1B2-C3D4", Vec::new())));
    assert_eq!(
        json(&execute[1]),
        r#"{"plan_id":"p-feed000000000001","restore_point":"high_risk","delete_after":false}"#
    );
    model.on_executed(Ok(complete(1, 0)));

    let undo = model.undo_all();
    assert_eq!(json(&undo[1]), format!(r#"{{"session":"{SESSION}"}}"#));
    let _ = model.on_undone(Ok(UndoResult {
        outcome: Outcome::UndoConflicts,
        conflicts: vec![ConflictRow {
            op: OpId(3),
            display_name: r"C:\Program Files\Git\etc".into(),
            conflict: UndoConflict::DestinationExists,
        }],
        alerts: Vec::new(),
    }));
    assert_eq!(model.undo_title(), Some("Put back, with conflicts"));
    assert_eq!(
        model.undo_conflict_lines(),
        [r"C:\Program Files\Git\etc: DestinationExists"]
    );

    // The delete-after flag is the one thing a move with the tick adds.
    let mut model = ready(true);
    let _ = model.move_items(RestorePoint::HighRisk);
    let execute = model.on_plan_created(Ok(plan("A1B2-C3D4", Vec::new())));
    assert_eq!(
        json(&execute[1]),
        r#"{"plan_id":"p-feed000000000001","restore_point":"high_risk","delete_after":true}"#
    );
}

#[test]
fn sizes_read_as_the_winui_app_shows_them() {
    assert_eq!(format_size(0), "0 B");
    assert_eq!(format_size(1023), "1023 B");
    assert_eq!(format_size(1024), "1.0 KB");
    assert_eq!(format_size(2_726_297), "2.6 MB");
    assert_eq!(format_size(345_000_000), "329 MB");
    assert_eq!(format_size(10_737_418_240), "10.0 GB");
}
