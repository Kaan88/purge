//! The History page (S4) as a plain state machine: the port of `HistoryModel.cs` and the logic of
//! `HistoryView.xaml.cs`.
//!
//! The list is `history.index` from the medium engine, so opening the page never starts the broker
//! or a UAC prompt; "Show items" (`history.get`), Restore (`undo.run`), the recovery banner
//! (`journal.resume` / `journal.rollback`) and "Check for interrupted cleanups" (`journal.pending`)
//! start it on the click (design 6.3). The model never holds the broker: it asks for one with
//! [`HistoryCall::Launch`], sends calls the UI forwards, and reads each answer through an `on_*`
//! method. Reconcile alerts (review M3-R2 S5) show per item and in the restore result.

mod rows;
mod session;
pub mod text;

#[cfg(test)]
mod tests;

use purge_model::exec::op::OpId;
use purge_model::exec::session::SessionId;
use purge_rpc::error::Outcome;
use purge_rpc::methods::{
    HistoryDetail, HistoryIndex, NonEmpty, OutcomeResult, PendingList, PendingSession, Progress,
    SessionParams, UndoParams, UndoResult,
};

pub use rows::{HistoryBarAction, HistoryDetailPane, HistoryRow, SessionRowView};
pub use session::{HistoryChip, HistoryEntry, HistorySession};

use crate::broker_link::{self, BrokerLaunch, CallError};
use crate::local_time::Clock;

/// The History page's states (design 6.3 page table, "History & undo").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoryPhase {
    /// `history.index` is being read.
    Loading,
    /// The index has no session.
    Empty,
    /// The index could not be read; [`HistoryModel::error`] says why.
    Error,
    /// The list is shown.
    Ready,
}

/// What the page asks of the UI: an engine read, a broker launch, or a broker call. Each is
/// answered through the `on_*` method named on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryCall {
    /// `history.index` on the medium engine; answer with [`HistoryModel::on_index`].
    ReadIndex,
    /// Start the broker (the first-elevation explanation, then the Windows prompt); `read_only`
    /// words the explanation for a read. Answer with [`HistoryModel::on_launch`].
    Launch {
        /// The action only reads (the check for interrupted cleanups, "Show items").
        read_only: bool,
    },
    /// End the broker this page started (its link ended, or the page closes). No answer.
    DropBroker,
    /// Let the broker's consent dialog come to the foreground. No answer.
    AllowForeground,
    /// `history.get`; answer with [`HistoryModel::on_items`].
    Get(SessionParams),
    /// `undo.run`; answer with [`HistoryModel::on_undone`], progress with [`HistoryModel::on_progress`].
    Undo(UndoParams),
    /// `journal.resume`; answer with [`HistoryModel::on_recovered`].
    Resume(SessionParams),
    /// `journal.rollback`; answer with [`HistoryModel::on_recovered`].
    Rollback(SessionParams),
    /// `journal.pending`; answer with [`HistoryModel::on_pending`].
    Pending,
}

/// What a broker call waits for, so an answer that does not match is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pending {
    /// A launch, then this.
    Launch(Next),
    /// `history.get` for this session.
    Get(SessionId),
    /// `undo.run` for this session.
    Undo(SessionId),
    /// A recovery of this session.
    Recover { session: SessionId, rollback: bool },
    /// `journal.pending`, then this.
    Journal(AfterPending),
}

/// What runs once the broker is there.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Next {
    Get(SessionId),
    Undo {
        session: SessionId,
        ops: Option<NonEmpty<OpId>>,
    },
    Recover {
        session: SessionId,
        rollback: bool,
    },
    CheckPending,
}

/// Who asked for `journal.pending`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AfterPending {
    /// "Check for interrupted cleanups".
    Check,
    /// A restore that was refused with `needs_recovery`.
    Undo(SessionId),
}

/// The History page's view model.
#[derive(Debug, Clone)]
pub struct HistoryModel {
    phase: HistoryPhase,
    error: Option<String>,
    sessions: Vec<HistorySession>,
    selected: Option<SessionId>,
    items: Option<Vec<HistoryEntry>>,
    pending: Option<Pending>,
    waiting: Option<String>,
    waiting_detail: String,
    action_error: Option<String>,
    action_info: Option<String>,
    prompt_cancelled: bool,
    prompt_declined: bool,
    restore_title: Option<&'static str>,
    restore_lines: Vec<String>,
    launch_is_read_only: bool,
    /// What the last `journal.pending` found, shown by the next index read only.
    found: Vec<PendingSession>,
    select_after_load: Option<SessionId>,
    /// After the next index read: read this session's items again (a restore of a session whose
    /// items were shown).
    reread_items: Option<SessionId>,
    has_broker: bool,
    broker_live: bool,
}

impl Default for HistoryModel {
    fn default() -> Self {
        Self::new()
    }
}

impl HistoryModel {
    /// A page that has read nothing yet: call [`load`](Self::load) when it is shown.
    pub fn new() -> Self {
        Self {
            phase: HistoryPhase::Loading,
            error: None,
            sessions: Vec::new(),
            selected: None,
            items: None,
            pending: None,
            waiting: None,
            waiting_detail: String::new(),
            action_error: None,
            action_info: None,
            prompt_cancelled: false,
            prompt_declined: false,
            restore_title: None,
            restore_lines: Vec::new(),
            launch_is_read_only: false,
            found: Vec::new(),
            select_after_load: None,
            reread_items: None,
            has_broker: false,
            broker_live: false,
        }
    }

    // ---- state ---------------------------------------------------------------------------------

    /// The page's state.
    pub fn phase(&self) -> HistoryPhase {
        self.phase
    }

    /// Why the index could not be read ([`HistoryPhase::Error`]).
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Newest first.
    pub fn sessions(&self) -> &[HistorySession] {
        &self.sessions
    }

    /// The session shown in the detail pane.
    pub fn selected(&self) -> Option<&HistorySession> {
        let id = self.selected.as_ref()?;
        self.sessions.iter().find(|s| &s.id == id)
    }

    /// The items of the selected session once "Show items" has read them.
    pub fn items(&self) -> Option<&[HistoryEntry]> {
        self.items.as_deref()
    }

    /// A broker call is running or its dialog is open.
    pub fn busy(&self) -> bool {
        self.pending.is_some()
    }

    /// The waiting line while the broker works or its dialog is open.
    pub fn waiting(&self) -> Option<&str> {
        self.waiting.as_deref()
    }

    /// The waiting bar's second line.
    pub fn waiting_detail(&self) -> &str {
        &self.waiting_detail
    }

    /// The last action's error.
    pub fn action_error(&self) -> Option<&str> {
        self.action_error.as_deref()
    }

    /// The last action's note (a cancelled dialog, a restore's result).
    pub fn action_info(&self) -> Option<&str> {
        self.action_info.as_deref()
    }

    /// The admin prompt was declined or cancelled.
    pub fn prompt_cancelled(&self) -> bool {
        self.prompt_cancelled
    }

    /// With [`prompt_cancelled`](Self::prompt_cancelled): it was "Not now", so no Windows prompt
    /// was shown.
    pub fn prompt_declined(&self) -> bool {
        self.prompt_declined
    }

    /// The last restore's or recovery's outcome title.
    pub fn restore_title(&self) -> Option<&'static str> {
        self.restore_title
    }

    /// The last restore's conflict and alert lines.
    pub fn restore_lines(&self) -> &[String] {
        &self.restore_lines
    }

    /// The broker is being started for an action that only reads: the first-elevation explanation
    /// is then worded for a read.
    pub fn launch_is_read_only(&self) -> bool {
        self.launch_is_read_only
    }

    /// Whether "Put back" can run for the selected session.
    pub fn can_restore(&self) -> bool {
        !self.busy() && self.selected().is_some_and(|s| s.held)
    }

    /// The ticked items that can be put back.
    pub fn checked_count(&self) -> usize {
        self.items.as_ref().map_or(0, |i| {
            i.iter().filter(|e| e.checked && e.selectable).count()
        })
    }

    /// The broker link this page started is live.
    pub fn broker_is_live(&self) -> bool {
        self.has_broker && self.broker_live
    }

    /// The UI's word that the broker link ended (it stays to be dropped on the next click).
    pub fn on_broker_ended(&mut self) {
        self.broker_live = false;
    }

    // ---- the list ------------------------------------------------------------------------------

    /// Reads `history.index`: each time the page is shown (the store changes under it), and from
    /// the error state's Retry.
    pub fn load(&mut self) -> Vec<HistoryCall> {
        if self.sessions.is_empty() {
            self.phase = HistoryPhase::Loading;
        }
        vec![HistoryCall::ReadIndex]
    }

    /// The answer to [`HistoryCall::ReadIndex`]. Keeps the selection when the session is still
    /// listed. May ask to read the selected session's items again (after a restore).
    pub fn on_index(
        &mut self,
        answer: Result<HistoryIndex, CallError>,
        clock: &Clock,
    ) -> Vec<HistoryCall> {
        let reread = self.reread_items.take();
        let index = match answer {
            Ok(index) => index,
            Err(e) => {
                self.sessions.clear();
                self.selected = None;
                self.items = None;
                self.error = Some(e.message().to_owned());
                self.phase = HistoryPhase::Error;
                return Vec::new();
            }
        };
        let keep = self.selected.clone();
        let alerts: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|s| s.has_alert)
            .map(|s| s.id.clone())
            .collect();
        let mut listed: Vec<HistorySession> = index
            .sessions
            .iter()
            .map(|s| HistorySession::from_summary(s, clock))
            .collect();
        // What the journal.pending just read found is interrupted whatever the index says, and is
        // listed from the journal when the index has no entry for it.
        for s in listed.iter_mut() {
            if self.found.iter().any(|p| p.session == s.id) {
                s.mark_interrupted();
            }
        }
        for p in &self.found {
            if !listed.iter().any(|s| s.id == p.session) {
                listed.push(HistorySession::from_pending(p, clock));
            }
        }
        listed.sort_by_key(|s| std::cmp::Reverse(s.started));
        for s in listed.iter_mut() {
            s.has_alert = alerts.contains(&s.id);
        }
        self.sessions = listed;
        // A journal.pending answer is shown once: the next refresh drops its marks, so a session
        // that ended since is never left marked Interrupted.
        self.found.clear();
        self.error = None;
        self.phase = if self.sessions.is_empty() {
            HistoryPhase::Empty
        } else {
            HistoryPhase::Ready
        };
        let keep = self.select_after_load.take().or(keep);
        let next = keep
            .as_ref()
            .and_then(|k| self.sessions.iter().find(|s| &s.id == k))
            .or(self.sessions.first())
            .map(|s| s.id.clone());
        if next.is_none() || next != self.selected {
            self.items = None;
        }
        self.selected = next;
        match reread {
            Some(session)
                if self.items.is_some()
                    && self.selected.as_ref() == Some(&session)
                    && self.broker_is_live() =>
            {
                self.read_items(false)
            }
            _ => Vec::new(),
        }
    }

    /// Shows this session in the detail pane.
    pub fn select(&mut self, id: &SessionId) {
        if self.selected.as_ref() == Some(id) || !self.sessions.iter().any(|s| &s.id == id) {
            return;
        }
        self.selected = Some(id.clone());
        self.items = None;
        self.action_error = None;
        self.action_info = None;
        self.restore_title = None;
        self.restore_lines.clear();
        self.prompt_cancelled = false;
    }

    /// Ticks or unticks an item for "Put back N selected"; an item that cannot be put back stays
    /// unticked.
    pub fn set_checked(&mut self, op: OpId, checked: bool) {
        if let Some(item) = self
            .items
            .as_mut()
            .and_then(|items| items.iter_mut().find(|i| i.op == op))
        {
            item.checked = checked && item.selectable;
        }
    }

    // ---- "Show items" --------------------------------------------------------------------------

    /// "Show items": `history.get` through the broker, which starts on this click.
    pub fn show_items(&mut self) -> Vec<HistoryCall> {
        self.read_items(true)
    }

    fn read_items(&mut self, clear: bool) -> Vec<HistoryCall> {
        let Some(session) = self.idle_selection() else {
            return Vec::new();
        };
        self.begin(text::READING_ITEMS, "", clear);
        self.with_broker(true, Next::Get(session))
    }

    /// The answer to [`HistoryCall::Get`].
    pub fn on_items(&mut self, answer: Result<HistoryDetail, CallError>) -> Vec<HistoryCall> {
        let Some(Pending::Get(session)) = self.pending.clone() else {
            return Vec::new();
        };
        let mut calls = Vec::new();
        match answer {
            Ok(detail) => {
                if self.selected.as_ref() == Some(&session) {
                    let items: Vec<HistoryEntry> =
                        detail.items.into_iter().map(HistoryEntry::new).collect();
                    let alert = items.iter().any(HistoryEntry::has_alert);
                    self.items = Some(items);
                    if let Some(s) = self.session_mut(&session) {
                        s.has_alert = alert;
                    }
                }
            }
            Err(e) if e.kind() == Some("gone") => self.action_error = Some(text::GONE.into()),
            Err(e) if e.is_link() => {
                calls.extend(self.drop_broker());
                self.action_error = Some(text::ENDED_BEFORE_ANSWER.into());
            }
            Err(CallError::Cancelled) => {}
            Err(e) => {
                self.action_error = Some(format!("{}{}", text::COULD_NOT_READ_ITEMS, e.message()))
            }
        }
        self.end();
        calls
    }

    // ---- Restore -------------------------------------------------------------------------------

    /// Restore: `undo.run` for the ticked items (`all` false) or the whole session.
    pub fn restore(&mut self, all: bool) -> Vec<HistoryCall> {
        if !self.can_restore() {
            return Vec::new();
        }
        let Some(session) = self.selected.clone() else {
            return Vec::new();
        };
        let ops = if all {
            None
        } else {
            let ops: Vec<OpId> = self
                .items
                .iter()
                .flatten()
                .filter(|i| i.checked && i.selectable)
                .map(|i| i.op)
                .collect();
            match NonEmpty::new(ops) {
                Some(ops) => Some(ops),
                None => return Vec::new(),
            }
        };
        self.begin(text::CONFIRM_RESTORE, text::NOTHING_PUT_BACK_YET, true);
        self.with_broker(false, Next::Undo { session, ops })
    }

    /// A `progress` notification of the running undo: its phase is the waiting line.
    pub fn on_progress(&mut self, progress: &Progress) {
        if matches!(self.pending, Some(Pending::Undo(_))) {
            self.waiting = Some(progress.phase.clone());
        }
    }

    /// The answer to [`HistoryCall::Undo`]. A change reads the list again (and the items, when they
    /// were shown).
    pub fn on_undone(&mut self, answer: Result<UndoResult, CallError>) -> Vec<HistoryCall> {
        let Some(Pending::Undo(session)) = self.pending.clone() else {
            return Vec::new();
        };
        let mut calls = Vec::new();
        let mut changed = false;
        match answer {
            Ok(undo) => {
                changed = true;
                self.restore_lines
                    .extend(undo.conflicts.iter().map(broker_link::conflict_text));
                self.restore_lines
                    .extend(undo.alerts.iter().map(broker_link::alert_text));
                self.restore_title = Some(match undo.outcome {
                    Outcome::UndoConflicts => text::PUT_BACK_WITH_CONFLICTS,
                    Outcome::NotClosed => text::NOT_RECORDED,
                    Outcome::Partial => text::PARTLY_PUT_BACK,
                    _ => text::PUT_BACK,
                });
                self.action_info = Some(if undo.conflicts.is_empty() {
                    text::WHAT_YOU_CHOSE_IS_BACK.into()
                } else {
                    text::could_not_put_back(undo.conflicts.len())
                });
                if !undo.alerts.is_empty()
                    && let Some(s) = self.session_mut(&session)
                {
                    s.has_alert = true;
                }
            }
            Err(e) if e.kind() == Some("consent_declined") => {
                self.action_info = Some(text::RESTORE_DECLINED.into());
            }
            Err(e) if e.kind() == Some("needs_recovery") => {
                self.action_error = Some(text::NEEDS_RECOVERY.into());
                // The broker is up already: list the interrupted sessions now, without another
                // prompt.
                if self.broker_is_live() {
                    self.pending = Some(Pending::Journal(AfterPending::Undo(session)));
                    return vec![HistoryCall::Pending];
                }
            }
            Err(e) if e.kind() == Some("busy") => self.action_error = Some(text::BUSY.into()),
            Err(e) if e.is_link() => {
                calls.extend(self.drop_broker());
                changed = true;
                self.action_error = Some(text::ENDED_WHILE_PUTTING_BACK.into());
            }
            Err(CallError::Cancelled) => {}
            Err(e) => {
                self.action_error = Some(format!("{}{}", text::COULD_NOT_PUT_BACK, e.message()))
            }
        }
        self.end();
        if changed {
            calls.extend(self.reload_after(Some(session)));
        }
        calls
    }

    // ---- Recovery ------------------------------------------------------------------------------

    /// The recovery banner of an interrupted session: `journal.resume` (`rollback` false) or
    /// `journal.rollback`, each through the broker's own dialog.
    pub fn recover(&mut self, rollback: bool) -> Vec<HistoryCall> {
        if self.busy() || !self.selected().is_some_and(|s| s.interrupted) {
            return Vec::new();
        }
        let Some(session) = self.selected.clone() else {
            return Vec::new();
        };
        let waiting = if rollback {
            text::CONFIRM_ROLLBACK
        } else {
            text::CONFIRM_RESUME
        };
        self.begin(waiting, text::NOTHING_CHANGED_YET, true);
        self.with_broker(false, Next::Recover { session, rollback })
    }

    /// The answer to [`HistoryCall::Resume`] or [`HistoryCall::Rollback`].
    pub fn on_recovered(&mut self, answer: Result<OutcomeResult, CallError>) -> Vec<HistoryCall> {
        let Some(Pending::Recover { session, rollback }) = self.pending.clone() else {
            return Vec::new();
        };
        let mut calls = Vec::new();
        let mut changed = false;
        match answer {
            Ok(result) => {
                changed = true;
                self.found.retain(|p| p.session != session);
                self.restore_lines
                    .extend(result.alerts.iter().map(broker_link::alert_text));
                self.restore_title = Some(match (result.outcome, rollback) {
                    (Outcome::Complete, true) => text::ROLLED_BACK,
                    (Outcome::Complete, false) => text::FINISHED,
                    (Outcome::NotClosed, _) => text::NOT_RECORDED,
                    (_, true) => text::PARTLY_ROLLED_BACK,
                    (_, false) => text::PARTLY_FINISHED,
                });
                self.action_info =
                    (result.outcome != Outcome::Complete).then(|| text::SOME_STILL_HELD.to_owned());
                if !result.alerts.is_empty()
                    && let Some(s) = self.session_mut(&session)
                {
                    s.has_alert = true;
                }
            }
            Err(e) if e.kind() == Some("consent_declined") => {
                self.action_info = Some(text::RECOVER_DECLINED.into());
            }
            Err(e) if e.kind() == Some("busy") => self.action_error = Some(text::BUSY.into()),
            Err(e) if e.is_link() => {
                calls.extend(self.drop_broker());
                changed = true;
                self.action_error = Some(text::ENDED_DURING_RECOVERY.into());
            }
            Err(CallError::Cancelled) => {}
            Err(e) => {
                self.action_error = Some(format!("{}{}", text::COULD_NOT_RECOVER, e.message()))
            }
        }
        self.end();
        if changed {
            calls.extend(self.reload_after(None));
        }
        calls
    }

    // ---- "Check for interrupted cleanups" ------------------------------------------------------

    /// "Check for interrupted cleanups": `journal.pending` through the broker, which starts on this
    /// click, never on page open (design 6.3). The index gets a run's entry only when the run ends,
    /// so a run cut short before that, and one whose report or entry was never written
    /// (`Unindexed`), are found only here; each is then listed with Resume and Roll back.
    pub fn check_interrupted(&mut self) -> Vec<HistoryCall> {
        if self.busy() {
            return Vec::new();
        }
        self.begin(text::LOOKING, "", true);
        self.with_broker(true, Next::CheckPending)
    }

    /// Whether "Check for interrupted cleanups" can be clicked.
    pub fn can_check_interrupted(&self) -> bool {
        !self.busy()
    }

    /// The answer to [`HistoryCall::Pending`].
    pub fn on_pending(&mut self, answer: Result<PendingList, CallError>) -> Vec<HistoryCall> {
        let Some(Pending::Journal(after)) = self.pending.clone() else {
            return Vec::new();
        };
        let mut calls = Vec::new();
        let mut read = false;
        let mut cancelled = false;
        match answer {
            Ok(list) => {
                // Show the first one found unless an interrupted session is selected already.
                if !self.selected().is_some_and(|s| s.interrupted)
                    && let Some(first) = list.sessions.first()
                {
                    self.select_after_load = Some(first.session.clone());
                }
                self.found = list.sessions;
                read = true;
            }
            Err(e) if e.kind() == Some("busy") => {
                // Another broker is changing the store: its live run would read as interrupted,
                // so the broker lists nothing until it has finished.
                self.found.clear();
                self.action_error = Some(text::PENDING_BUSY.into());
            }
            Err(e) if e.is_link() => {
                calls.extend(self.drop_broker());
                self.action_error = Some(text::ENDED_BEFORE_ANSWER.into());
            }
            Err(CallError::Cancelled) => cancelled = true,
            Err(e) => self.action_error = Some(format!("{}{}", text::COULD_NOT_LOOK, e.message())),
        }
        self.end();
        if !read || cancelled {
            return calls;
        }
        match after {
            AfterPending::Check => {
                if self.found.is_empty() {
                    self.action_info = Some(text::NOTHING_INTERRUPTED.into());
                }
                calls.extend(self.reload_after(None));
            }
            AfterPending::Undo(session) => calls.extend(self.reload_after(Some(session))),
        }
        calls
    }

    // ---- the broker ----------------------------------------------------------------------------

    /// The answer to [`HistoryCall::Launch`].
    pub fn on_launch(&mut self, launch: BrokerLaunch) -> Vec<HistoryCall> {
        let Some(Pending::Launch(next)) = self.pending.clone() else {
            return Vec::new();
        };
        if launch.started {
            self.has_broker = true;
            self.broker_live = true;
            return self.run(next);
        }
        if launch.cancelled {
            self.prompt_cancelled = true;
            self.prompt_declined = launch.declined_explanation;
            // The page's own answer to the click (the window's bar is not used here).
            self.action_info = Some(
                if next == Next::CheckPending {
                    text::NOT_CHECKED
                } else {
                    text::NOT_STARTED
                }
                .into(),
            );
        } else {
            self.action_error = Some(launch.message);
        }
        self.end();
        Vec::new()
    }

    /// The page is closing: end the broker it started.
    pub fn close(&mut self) -> Vec<HistoryCall> {
        self.drop_broker()
    }

    fn with_broker(&mut self, read_only: bool, next: Next) -> Vec<HistoryCall> {
        if self.broker_is_live() {
            return self.run(next);
        }
        let mut calls = self.drop_broker();
        self.launch_is_read_only = read_only;
        self.pending = Some(Pending::Launch(next));
        calls.push(HistoryCall::Launch { read_only });
        calls
    }

    fn run(&mut self, next: Next) -> Vec<HistoryCall> {
        match next {
            Next::Get(session) => {
                let params = SessionParams {
                    session: session.clone(),
                };
                self.pending = Some(Pending::Get(session));
                vec![HistoryCall::Get(params)]
            }
            Next::Undo { session, ops } => {
                let params = UndoParams {
                    session: session.clone(),
                    item_ids: ops,
                };
                self.pending = Some(Pending::Undo(session));
                vec![HistoryCall::AllowForeground, HistoryCall::Undo(params)]
            }
            Next::Recover { session, rollback } => {
                let params = SessionParams {
                    session: session.clone(),
                };
                self.pending = Some(Pending::Recover { session, rollback });
                let call = if rollback {
                    HistoryCall::Rollback(params)
                } else {
                    HistoryCall::Resume(params)
                };
                vec![HistoryCall::AllowForeground, call]
            }
            Next::CheckPending => {
                self.pending = Some(Pending::Journal(AfterPending::Check));
                vec![HistoryCall::Pending]
            }
        }
    }

    fn drop_broker(&mut self) -> Vec<HistoryCall> {
        let had = self.has_broker;
        self.has_broker = false;
        self.broker_live = false;
        if had {
            vec![HistoryCall::DropBroker]
        } else {
            Vec::new()
        }
    }

    /// After a change: read the index again, then the items of `session` when they were shown.
    fn reload_after(&mut self, session: Option<SessionId>) -> Vec<HistoryCall> {
        self.reread_items = session.filter(|_| self.items.is_some());
        self.load()
    }

    fn idle_selection(&self) -> Option<SessionId> {
        if self.busy() {
            None
        } else {
            self.selected.clone()
        }
    }

    fn session_mut(&mut self, id: &SessionId) -> Option<&mut HistorySession> {
        self.sessions.iter_mut().find(|s| &s.id == id)
    }

    fn begin(&mut self, waiting: &str, detail: &str, clear: bool) {
        self.waiting = Some(waiting.to_owned());
        self.waiting_detail = detail.to_owned();
        if clear {
            self.action_error = None;
            self.action_info = None;
            self.restore_title = None;
            self.restore_lines.clear();
        }
        self.prompt_cancelled = false;
    }

    fn end(&mut self) {
        self.pending = None;
        self.waiting = None;
    }
}
