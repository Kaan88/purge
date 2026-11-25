//! The port of `HistoryPageTests`: the list from `history.index` (medium engine, no broker), the
//! empty and error states, "Show items" through the broker with the reconcile alert mark per item
//! (review M3-R2 S5), the alerts of `undo.run` and `journal.resume`, and `journal.pending`. The real
//! broker and UAC are VM tests; `TheMediumEngineAnswersHistoryIndex` is a client test (the wire
//! shape is covered by purge-rpc's fixture tests).

use std::collections::VecDeque;

use purge_model::FileTime;
use purge_model::exec::journal::UndoConflict;
use purge_model::exec::op::{ItemOutcome, OpId};
use purge_model::exec::session::{SessionId, SessionState};
use purge_rpc::error::{ErrorData, Outcome};
use purge_rpc::frame::RequestId;
use purge_rpc::methods::{
    Alert, ConflictRow, Deleted, HistoryDetail, HistoryIndex, HistoryItem, ItemKind, OutcomeResult,
    PendingList, PendingSession, Progress, UndoResult,
};

use super::*;
use crate::broker_link::{BrokerLaunch, CallError};
use crate::info_bar::Severity;

const GIT_SESSION: &str = "20251115T101502Z-9f3a6c1d2b7e4a50";
const CUT: &str = "20251116T090000Z-00000000000000aa";

fn sid(text: &str) -> SessionId {
    text.parse().expect("a session id")
}

/// A day and a bit after the Git session started (15 Nov 2025 10:15 UTC).
fn clock() -> Clock {
    Clock::utc(FileTime(134_077_700_000_000_000))
}

fn git_index() -> HistoryIndex {
    serde_json::from_str(include_str!(
        "../../../purge-rpc/fixtures/stdio.history.index.result.json"
    ))
    .expect("the index fixture")
}

fn git_detail() -> HistoryDetail {
    serde_json::from_str(include_str!(
        "../../../purge-rpc/fixtures/pipe.history.get.result.json"
    ))
    .expect("the detail fixture")
}

fn empty_index() -> HistoryIndex {
    HistoryIndex {
        sessions: Vec::new(),
        volumes: Vec::new(),
    }
}

fn pending(session: &str, app: &str, started: u64, done: u32, total: u32) -> PendingSession {
    PendingSession {
        session: sid(session),
        app: app.into(),
        started: FileTime(started),
        done,
        total,
    }
}

fn rpc(data: ErrorData, message: &str) -> CallError {
    CallError::rpc(data, message)
}

type Answer<T> = Box<dyn FnMut() -> Result<T, CallError>>;

/// The engine and a broker played by the test. It answers every call the model sends, in order,
/// until the model sends none.
struct Rig {
    index: Answer<HistoryIndex>,
    reads: usize,
    launch: Box<dyn FnMut() -> BrokerLaunch>,
    launches: usize,
    drops: usize,
    foreground: usize,
    detail: Answer<HistoryDetail>,
    get_calls: Vec<SessionId>,
    undo: Answer<UndoResult>,
    undo_calls: Vec<(SessionId, Option<Vec<OpId>>)>,
    recover: Answer<OutcomeResult>,
    recover_calls: Vec<(SessionId, bool)>,
    pending: Answer<PendingList>,
    pending_calls: usize,
}

impl Rig {
    fn new(index: HistoryIndex) -> Self {
        Self {
            index: Box::new(move || Ok(index.clone())),
            reads: 0,
            launch: Box::new(BrokerLaunch::started),
            launches: 0,
            drops: 0,
            foreground: 0,
            detail: Box::new(|| Ok(git_detail())),
            get_calls: Vec::new(),
            undo: Box::new(|| {
                Ok(UndoResult {
                    outcome: Outcome::Complete,
                    conflicts: Vec::new(),
                    alerts: Vec::new(),
                })
            }),
            undo_calls: Vec::new(),
            recover: Box::new(|| {
                Ok(OutcomeResult {
                    outcome: Outcome::Complete,
                    alerts: Vec::new(),
                })
            }),
            recover_calls: Vec::new(),
            pending: Box::new(|| {
                Ok(PendingList {
                    sessions: Vec::new(),
                })
            }),
            pending_calls: 0,
        }
    }

    fn git() -> Self {
        Self::new(git_index())
    }

    fn run(&mut self, model: &mut HistoryModel, calls: Vec<HistoryCall>) {
        let mut queue: VecDeque<HistoryCall> = calls.into();
        while let Some(call) = queue.pop_front() {
            let next = match call {
                HistoryCall::ReadIndex => {
                    self.reads += 1;
                    let answer = (self.index)();
                    model.on_index(answer, &clock())
                }
                HistoryCall::Launch { .. } => {
                    self.launches += 1;
                    let launch = (self.launch)();
                    model.on_launch(launch)
                }
                HistoryCall::DropBroker => {
                    self.drops += 1;
                    Vec::new()
                }
                HistoryCall::AllowForeground => {
                    self.foreground += 1;
                    Vec::new()
                }
                HistoryCall::Get(p) => {
                    self.get_calls.push(p.session);
                    let answer = (self.detail)();
                    if matches!(answer, Err(CallError::Link { .. })) {
                        model.on_broker_ended();
                    }
                    model.on_items(answer)
                }
                HistoryCall::Undo(p) => {
                    self.undo_calls
                        .push((p.session, p.item_ids.map(|ops| ops.into_vec())));
                    let answer = (self.undo)();
                    model.on_undone(answer)
                }
                HistoryCall::Resume(p) => {
                    self.recover_calls.push((p.session, false));
                    let answer = (self.recover)();
                    model.on_recovered(answer)
                }
                HistoryCall::Rollback(p) => {
                    self.recover_calls.push((p.session, true));
                    let answer = (self.recover)();
                    model.on_recovered(answer)
                }
                HistoryCall::Pending => {
                    self.pending_calls += 1;
                    let answer = (self.pending)();
                    model.on_pending(answer)
                }
            };
            queue.extend(next);
        }
    }

    /// A page that read its index.
    fn loaded(&mut self) -> HistoryModel {
        let mut model = HistoryModel::new();
        let calls = model.load();
        self.run(&mut model, calls);
        model
    }

    fn act(
        &mut self,
        model: &mut HistoryModel,
        act: impl FnOnce(&mut HistoryModel) -> Vec<HistoryCall>,
    ) {
        let calls = act(model);
        self.run(model, calls);
    }
}

fn ids(model: &HistoryModel) -> Vec<String> {
    model.sessions().iter().map(|s| s.id.to_string()).collect()
}

#[test]
fn loads_entries_newest_first_without_starting_the_broker() {
    let mut index = git_index();
    let mut newer = index.sessions[0].clone();
    newer.id = sid("20251116T080000Z-0000000000000001");
    newer.started = FileTime(newer.started.0 + 864_000_000_000);
    newer.owner = Some(
        serde_json::from_value(
            serde_json::json!({"program_id": "HKLM|64|Git_is1", "display_name": "Git"}),
        )
        .expect("an app ref"),
    );
    newer.state = SessionState::Undone;
    index.sessions.push(newer);
    let mut rig = Rig::new(index);

    let model = rig.loaded();

    assert_eq!(model.phase(), HistoryPhase::Ready);
    assert_eq!(rig.launches, 0);
    assert_eq!(
        ids(&model),
        ["20251116T080000Z-0000000000000001", GIT_SESSION]
    );
    let restored = &model.sessions()[0];
    assert_eq!(restored.name, "Git");
    assert_eq!(restored.state, "Put back");
    assert!(!restored.held);
    let git = &model.sessions()[1];
    assert_eq!(git.name, "HKLM|64|Git_is1");
    assert_eq!(git.state, "Undoable");
    assert_eq!(git.chip, HistoryChip::Undoable);
    assert!(git.held);
    assert!(
        git.detail.starts_with("21 items moved · "),
        "{}",
        git.detail
    );
    assert!(git.detail.contains("1 held, in use"));
    assert!(!git.has_alert);
    assert_eq!(model.selected().map(|s| &s.id), Some(&restored.id));
    assert!(model.items().is_none());
}

#[test]
fn an_empty_index_shows_the_empty_state() {
    let mut rig = Rig::new(empty_index());
    let model = rig.loaded();

    assert_eq!(model.phase(), HistoryPhase::Empty);
    assert!(model.sessions().is_empty());
    assert!(model.selected().is_none());
    assert!(!model.can_restore());
    assert_eq!(
        model.state_panel(),
        Some((text::NO_CLEANUPS, text::NO_CLEANUPS_TEXT.to_owned(), false))
    );
}

#[test]
fn an_index_that_cannot_be_read_shows_the_error() {
    let mut rig = Rig::git();
    rig.index = Box::new(|| Err(CallError::Other("index.json is over the limit".into())));
    let model = rig.loaded();

    assert_eq!(model.phase(), HistoryPhase::Error);
    assert_eq!(model.error(), Some("index.json is over the limit"));
    assert!(model.sessions().is_empty());
    assert_eq!(
        model.state_panel(),
        Some((
            text::COULD_NOT_READ_HISTORY,
            "index.json is over the limit".to_owned(),
            true
        ))
    );
}

#[test]
fn show_items_starts_the_broker_and_marks_the_reconcile_alert() {
    let mut rig = Rig::git();
    let mut model = rig.loaded();

    rig.act(&mut model, HistoryModel::show_items);
    rig.act(&mut model, HistoryModel::show_items);

    assert_eq!(rig.launches, 1);
    assert_eq!(rig.get_calls, [sid(GIT_SESSION), sid(GIT_SESSION)]);
    let items = model.items().expect("items");
    assert_eq!(items.len(), 1);
    let item = &items[0];
    assert!(item.has_alert());
    assert_eq!(
        item.alert_text.as_deref(),
        Some(r"Purge found another file in quarantine and put it back at C:\Program Files\Git.")
    );
    assert_eq!(item.kind_text, "Folder");
    assert_eq!(item.outcome_text, "Moved to quarantine");
    assert!(model.selected().expect("selected").has_alert);

    // The session's mark stays after the list is read again.
    rig.act(&mut model, HistoryModel::load);
    assert!(model.sessions()[0].has_alert);
    assert!(model.items().is_some());
}

#[test]
fn an_item_without_an_alert_has_no_mark() {
    let mut rig = Rig::git();
    rig.detail = Box::new(|| {
        let mut detail = git_detail();
        detail.items[0].alert = None;
        Ok(detail)
    });
    let mut model = rig.loaded();

    rig.act(&mut model, HistoryModel::show_items);

    assert!(!model.items().expect("items")[0].has_alert());
    assert!(!model.selected().expect("selected").has_alert);
}

#[test]
fn restore_shows_the_undo_alerts_and_reads_the_list_again() {
    let mut rig = Rig::git();
    rig.undo = Box::new(|| {
        Ok(UndoResult {
            outcome: Outcome::Complete,
            conflicts: Vec::new(),
            alerts: vec![Alert {
                op: OpId(1),
                original_path: r"C:\Program Files\Git".into(),
                moved_back: false,
            }],
        })
    });
    let mut model = rig.loaded();
    rig.act(&mut model, HistoryModel::show_items);
    model.set_checked(OpId(1), true);

    rig.act(&mut model, |m| m.restore(false));

    assert_eq!(rig.undo_calls, [(sid(GIT_SESSION), Some(vec![OpId(1)]))]);
    assert_eq!(rig.foreground, 1);
    assert_eq!(model.restore_title(), Some("Put back"));
    assert_eq!(
        model.restore_lines(),
        [r"Purge found another file in quarantine and kept it there: C:\Program Files\Git."]
    );
    assert!(model.selected().expect("selected").has_alert);
    assert_eq!(rig.reads, 2);
    assert_eq!(rig.get_calls.len(), 2);
    assert!(!model.busy());
}

/// An item whose kept data was deleted (after its retention, or before it with the vault's "Delete
/// now") says so, cannot be ticked for a restore, and its undo conflict is said in words.
#[test]
fn a_deleted_item_is_shown_as_deleted_and_cannot_be_chosen_for_a_restore() {
    let mut detail: HistoryDetail = serde_json::from_str(include_str!(
        "../../../purge-rpc/fixtures/pipe.history.get.result.deleted.json"
    ))
    .expect("the fixture");
    assert_eq!(
        detail.items.iter().map(|i| i.deleted).collect::<Vec<_>>(),
        [Some(Deleted::Early), Some(Deleted::Expired)]
    );
    detail.items.push(HistoryItem {
        op: OpId(3),
        display_name: r"C:\Program Files\Git".into(),
        kind: ItemKind::Folder,
        outcome: ItemOutcome::Done,
        undone: false,
        alert: None,
        deleted: None,
    });
    let mut rig = Rig::git();
    rig.detail = Box::new(move || Ok(detail.clone()));
    rig.undo = Box::new(|| {
        Ok(UndoResult {
            outcome: Outcome::UndoConflicts,
            conflicts: vec![
                ConflictRow {
                    op: OpId(1),
                    display_name: r"C:\ProgramData\Git\cache1".into(),
                    conflict: UndoConflict::Expired,
                },
                ConflictRow {
                    op: OpId(3),
                    display_name: r"C:\Program Files\Git".into(),
                    conflict: UndoConflict::DestinationExists,
                },
            ],
            alerts: Vec::new(),
        })
    });
    let mut model = rig.loaded();
    rig.act(&mut model, HistoryModel::show_items);

    let items = model.items().expect("items");
    assert_eq!(
        items[0].outcome_text,
        "Deleted from quarantine at your request · cannot be put back"
    );
    assert_eq!(
        items[1].outcome_text,
        "Deleted after its retention ended · cannot be put back"
    );
    assert_eq!(items[2].outcome_text, "Moved to quarantine");
    assert_eq!(
        items.iter().map(|i| i.is_deleted).collect::<Vec<_>>(),
        [true, true, false]
    );
    assert_eq!(
        items.iter().map(|i| i.selectable).collect::<Vec<_>>(),
        [false, false, true]
    );

    // Ticking a deleted item selects nothing: only the item that is still kept is sent.
    for op in [1, 2, 3] {
        model.set_checked(OpId(op), true);
    }
    assert_eq!(model.checked_count(), 1);
    rig.act(&mut model, |m| m.restore(false));

    assert_eq!(rig.undo_calls[0].1, Some(vec![OpId(3)]));
    assert_eq!(model.restore_title(), Some("Put back, with conflicts"));
    assert_eq!(
        model.restore_lines(),
        [
            r"C:\ProgramData\Git\cache1: what Purge kept of it was deleted, so it cannot be put back",
            r"C:\Program Files\Git: DestinationExists",
        ]
    );
}

#[test]
fn restore_all_sends_no_item_ids_and_a_declined_prompt_puts_nothing_back() {
    let mut rig = Rig::git();
    rig.undo = Box::new(|| Err(rpc(ErrorData::ConsentDeclined, "declined")));
    let mut model = rig.loaded();

    rig.act(&mut model, |m| m.restore(true));

    assert_eq!(rig.undo_calls, [(sid(GIT_SESSION), None)]);
    assert_eq!(
        model.action_info(),
        Some("Nothing was put back: the prompt was cancelled.")
    );
    assert!(model.restore_title().is_none());
}

#[test]
fn a_cancelled_admin_prompt_starts_nothing() {
    let mut rig = Rig::git();
    rig.launch = Box::new(|| BrokerLaunch::cancelled(""));
    let mut model = rig.loaded();

    rig.act(&mut model, HistoryModel::show_items);

    assert!(model.prompt_cancelled());
    assert!(!model.prompt_declined());
    assert!(model.items().is_none());
    assert!(model.action_error().is_none());
    assert_eq!(model.action_info(), Some(text::NOT_STARTED));
    assert!(!model.busy());
}

#[test]
fn not_now_at_the_explanation_is_a_declined_prompt() {
    let mut rig = Rig::git();
    rig.launch = Box::new(BrokerLaunch::declined);
    let mut model = rig.loaded();

    let calls = model.show_items();
    assert_eq!(calls, [HistoryCall::Launch { read_only: true }]);
    assert!(model.launch_is_read_only());
    rig.run(&mut model, calls);

    assert!(model.prompt_cancelled());
    assert!(model.prompt_declined());
    assert!(model.items().is_none());
}

#[test]
fn a_broker_that_dies_is_started_again_on_the_next_click() {
    let mut rig = Rig::git();
    let mut first = true;
    rig.detail = Box::new(move || {
        if std::mem::take(&mut first) {
            Err(CallError::link("pipe closed", false))
        } else {
            Ok(git_detail())
        }
    });
    let mut model = rig.loaded();

    rig.act(&mut model, HistoryModel::show_items);
    assert_eq!(model.action_error(), Some(text::ENDED_BEFORE_ANSWER));
    assert_eq!(rig.drops, 1, "the dead broker is ended");

    rig.act(&mut model, HistoryModel::show_items);
    assert!(model.action_error().is_none());
    assert_eq!(model.items().expect("items").len(), 1);
    assert_eq!(rig.launches, 2);
}

#[test]
fn an_interrupted_session_offers_recovery_and_shows_its_alerts() {
    let mut index = git_index();
    index.sessions[0].state = SessionState::Open;
    let mut rig = Rig::new(index);
    rig.recover = Box::new(|| {
        Ok(OutcomeResult {
            outcome: Outcome::Complete,
            alerts: vec![Alert {
                op: OpId(1),
                original_path: r"C:\Program Files\Git".into(),
                moved_back: true,
            }],
        })
    });
    let mut model = rig.loaded();
    let selected = model.selected().expect("selected");
    assert!(selected.interrupted);
    assert_eq!(selected.state, "Interrupted");
    assert!(!model.can_restore());
    let bars = model.bars();
    assert_eq!(bars[0].title, text::RECOVERY_TITLE);
    assert_eq!(bars[0].action, Some(HistoryBarAction::Recover));

    rig.act(&mut model, |m| m.recover(true));

    assert_eq!(rig.recover_calls, [(sid(GIT_SESSION), true)]);
    assert_eq!(model.restore_title(), Some("Rolled back"));
    assert_eq!(
        model.restore_lines(),
        [r"Purge found another file in quarantine and put it back at C:\Program Files\Git."]
    );
}

#[test]
fn opening_the_page_never_asks_for_interrupted_sessions() {
    let mut rig = Rig::git();
    let model = rig.loaded();

    assert_eq!(rig.launches, 0);
    assert_eq!(rig.pending_calls, 0);
    assert!(!model.selected().expect("selected").interrupted);
}

#[test]
fn check_for_interrupted_lists_a_session_the_index_does_not_have_and_offers_its_recovery() {
    let mut rig = Rig::git();
    rig.pending = Box::new(|| {
        Ok(PendingList {
            sessions: vec![pending(
                CUT,
                "Mozilla Firefox",
                134_077_617_020_000_000,
                37,
                52,
            )],
        })
    });
    let mut model = rig.loaded();

    rig.act(&mut model, HistoryModel::check_interrupted);

    assert_eq!(rig.launches, 1);
    assert_eq!(rig.pending_calls, 1);
    assert_eq!(ids(&model), [CUT, GIT_SESSION]);
    let found = model.selected().expect("selected");
    assert_eq!(found.id, sid(CUT));
    assert!(found.interrupted);
    assert!(found.from_journal);
    assert_eq!(found.name, "Mozilla Firefox");
    assert_eq!(found.state, "Interrupted");
    assert_eq!(found.detail, "37 of 52 items done · found in the journals");
    assert!(!found.held);
    assert!(!model.can_restore());
    assert!(model.action_info().is_none());

    rig.act(&mut model, |m| m.recover(false));

    assert_eq!(rig.recover_calls, [(sid(CUT), false)]);
    assert_eq!(model.restore_title(), Some("Finished"));
    // Recovered: it is no longer listed from the journal (the index lists it once recovery wrote
    // its entry).
    assert!(!ids(&model).contains(&CUT.to_owned()));
    assert_eq!(rig.launches, 1);
}

#[test]
fn check_for_interrupted_marks_an_indexed_session_whose_report_was_never_written() {
    // The index lists the session as committed; journal.pending lists it (Unindexed: no report).
    let mut rig = Rig::git();
    rig.pending = Box::new(|| {
        Ok(serde_json::from_str(include_str!(
            "../../../purge-rpc/fixtures/pipe.journal.pending.result.json"
        ))
        .expect("the fixture"))
    });
    let mut model = rig.loaded();
    assert!(!model.selected().expect("selected").interrupted);

    rig.act(&mut model, HistoryModel::check_interrupted);

    assert_eq!(model.sessions().len(), 1);
    let git = &model.sessions()[0];
    assert!(git.interrupted);
    assert!(!git.from_journal);
    assert_eq!(git.state, "Interrupted");
    assert_eq!(git.chip, HistoryChip::Caution);
}

#[test]
fn the_next_refresh_drops_the_marks_of_an_earlier_check() {
    let mut rig = Rig::git();
    rig.pending = Box::new(|| {
        Ok(PendingList {
            sessions: vec![
                pending(CUT, "Firefox", 134_077_617_020_000_000, 0, 0),
                pending(GIT_SESSION, "Git", 134_076_753_020_000_000, 0, 0),
            ],
        })
    });
    let mut model = rig.loaded();
    rig.act(&mut model, HistoryModel::check_interrupted);
    assert_eq!(model.sessions().iter().filter(|s| s.interrupted).count(), 2);

    // The run in the other window committed meanwhile; the page is shown again.
    rig.act(&mut model, HistoryModel::load);

    assert_eq!(model.sessions().len(), 1);
    let git = &model.sessions()[0];
    assert!(!git.interrupted);
    assert_eq!(git.state, "Undoable");
}

#[test]
fn another_window_at_work_lists_no_interrupted_session() {
    let mut rig = Rig::git();
    rig.pending = Box::new(|| Err(rpc(ErrorData::Busy, "another writer holds the store")));
    let mut model = rig.loaded();

    rig.act(&mut model, HistoryModel::check_interrupted);

    assert_eq!(rig.pending_calls, 1);
    assert!(
        model
            .action_error()
            .expect("an error")
            .starts_with("Another Purge window is working on the quarantine.")
    );
    assert!(!model.sessions().iter().any(|s| s.interrupted));
    assert!(!model.busy());
}

#[test]
fn check_for_interrupted_says_so_when_nothing_was_interrupted() {
    let mut rig = Rig::new(empty_index());
    let mut model = rig.loaded();

    rig.act(&mut model, HistoryModel::check_interrupted);

    assert_eq!(model.phase(), HistoryPhase::Empty);
    assert_eq!(model.action_info(), Some("No cleanup was interrupted."));
    assert!(!model.busy());
    // On the empty page the answer still shows as a bar.
    assert_eq!(model.bars()[0].title, "No cleanup was interrupted.");
}

#[test]
fn check_for_interrupted_without_admin_permission_says_it_did_not_check() {
    let mut rig = Rig::git();
    rig.launch = Box::new(BrokerLaunch::declined);
    let mut model = rig.loaded();

    rig.act(&mut model, HistoryModel::check_interrupted);

    assert_eq!(rig.pending_calls, 0);
    assert_eq!(model.action_info(), Some(text::NOT_CHECKED));
    assert_eq!(rig.reads, 1);
}

#[test]
fn a_restore_refused_for_recovery_lists_the_interrupted_sessions_without_another_prompt() {
    let mut rig = Rig::git();
    rig.undo = Box::new(|| {
        Err(rpc(
            ErrorData::NeedsRecovery {
                sessions: vec![sid(CUT)],
            },
            "an interrupted session comes first",
        ))
    });
    rig.pending = Box::new(|| {
        Ok(PendingList {
            sessions: vec![pending(CUT, "Firefox", 1, 0, 0)],
        })
    });
    let mut model = rig.loaded();

    rig.act(&mut model, |m| m.restore(true));

    assert_eq!(rig.launches, 1);
    assert_eq!(rig.pending_calls, 1);
    assert!(
        model
            .action_error()
            .expect("an error")
            .contains("interrupted cleanup comes first")
    );
    let selected = model.selected().expect("selected");
    assert_eq!(selected.id, sid(CUT));
    assert!(selected.interrupted);
}

#[test]
fn another_writer_of_the_store_is_busy_not_a_failure() {
    let mut rig = Rig::git();
    rig.undo = Box::new(|| Err(rpc(ErrorData::Busy, "a mutating request is running")));
    let mut model = rig.loaded();

    rig.act(&mut model, |m| m.restore(true));

    assert_eq!(
        model.action_error(),
        Some(
            "Another Purge window is changing the quarantine. Wait for it to finish, then try again."
        )
    );
    assert!(!model.busy());
    assert_eq!(
        rig.reads, 1,
        "nothing changed, so the list is not read again"
    );
}

// ---- the view's logic (HistoryView.xaml.cs) -----------------------------------------------------

#[test]
fn the_list_groups_by_day_and_the_timeline_runs_oldest_first() {
    let mut index = git_index();
    let base = index.sessions[0].clone();
    let at = |id: &str, ticks: u64| {
        let mut s = base.clone();
        s.id = sid(id);
        s.started = FileTime(ticks);
        s
    };
    // 15 Nov 2025 10:15 is the fixture; 16 Nov 08:00 and 16 Nov 09:00; and one in 2024.
    index.sessions.push(at(
        "20251116T080000Z-0000000000000001",
        134_077_536_000_000_000,
    ));
    index.sessions.push(at(
        "20251116T090000Z-0000000000000002",
        134_077_572_000_000_000,
    ));
    index.sessions.push(at(
        "20240301T090000Z-0000000000000003",
        133_537_572_000_000_000,
    ));
    let mut rig = Rig::new(index);
    let model = rig.loaded();
    let clock = clock();

    let rows = model.rows(&clock);
    let names: Vec<String> = rows.iter().map(|r| model.row_name(r)).collect();
    assert_eq!(
        names,
        [
            "Today",
            "HKLM|64|Git_is1, 09:00, Undoable",
            "HKLM|64|Git_is1, 08:00, Undoable",
            "Yesterday",
            "HKLM|64|Git_is1, 10:15, Undoable",
            "1 March 2024",
            "HKLM|64|Git_is1, 09:00, Undoable",
        ]
    );

    let timeline = model.timeline(&clock);
    let order: Vec<String> = timeline.iter().map(|r| model.row_name(r)).collect();
    assert_eq!(
        order,
        [
            "1 March 2024",
            "HKLM|64|Git_is1, 09:00, Undoable",
            "Yesterday",
            "HKLM|64|Git_is1, 10:15, Undoable",
            "Today",
            "HKLM|64|Git_is1, 08:00, Undoable",
            "HKLM|64|Git_is1, 09:00, Undoable",
        ]
    );
    // A day marker jumps to that day's first cleanup.
    let today = timeline
        .iter()
        .position(|r| r == &HistoryRow::Day("Today".into()));
    assert_eq!(
        model.timeline_target(&timeline, today.expect("today")),
        Some(1)
    );

    let row = model.session_row(0).expect("a row");
    assert_eq!(row.initial, "H");
    assert_eq!(row.mark_restorable, "Files 29 d · registry 179 d");
    assert_eq!(
        row.mark_name,
        "HKLM|64|Git_is1 09:00, Files 29 d · registry 179 d"
    );
}

#[test]
fn the_detail_pane_and_bars_say_what_the_page_does() {
    let mut rig = Rig::git();
    rig.undo = Box::new(|| {
        Ok(UndoResult {
            outcome: Outcome::Complete,
            conflicts: Vec::new(),
            alerts: Vec::new(),
        })
    });
    let mut model = rig.loaded();
    let clock = clock();

    let pane = model.detail(&clock).expect("the pane");
    assert_eq!(pane.title, "HKLM|64|Git_is1 · 15 Nov 2025 10:15");
    assert_eq!(
        pane.expiry,
        "Files restorable until 15 Dec 2025 (29 days), registry and task backups until 14 May 2026"
    );
    assert!(pane.show_items_visible);
    assert_eq!(pane.restore_selected_text, "Put back 0 selected");
    assert!(!pane.restore_selected_enabled);
    assert!(pane.restore_all_enabled);

    // While the prompt is up the waiting bar shows and nothing else can start.
    assert_eq!(
        model.restore(true),
        [HistoryCall::Launch { read_only: false }]
    );
    let calls = model.on_launch(BrokerLaunch::started());
    assert!(model.busy());
    assert!(!model.can_check_interrupted());
    model.on_progress(&Progress {
        request: RequestId(1),
        program_id: None,
        phase: "Putting back 1 of 21".into(),
        done: 1,
        total: Some(21),
    });
    assert_eq!(model.waiting(), Some("Putting back 1 of 21"));
    assert_eq!(model.bars()[0].severity, Severity::Informational);
    assert!(model.check_interrupted().is_empty());
    rig.run(&mut model, calls);

    let bars = model.bars();
    assert_eq!(bars.len(), 1);
    assert_eq!(bars[0].severity, Severity::Success);
    assert_eq!(bars[0].title, "Put back");
    assert_eq!(bars[0].message, "What you chose is back where it was.");
}

#[test]
fn closing_the_page_ends_the_broker_it_started() {
    let mut rig = Rig::git();
    let mut model = rig.loaded();
    assert!(model.close().is_empty());
    rig.act(&mut model, HistoryModel::show_items);
    assert!(model.broker_is_live());
    assert_eq!(model.close(), [HistoryCall::DropBroker]);
    assert!(!model.broker_is_live());
}
