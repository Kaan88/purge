//! The Quarantine vault (board 16, design 7a page table) as a plain state machine: the port of
//! `VaultModel.cs`, `VaultRows.cs` and the logic of `VaultView.xaml.cs`.
//!
//! The list and the per-volume use and cap are `history.index` from the medium engine, so opening
//! the page starts no broker and no prompt. "Put back…" (`undo.run` for the whole session) and
//! "Review and delete…" (`quarantine.expiring`, then `quarantine.purge` with the broker's own
//! dialogs) start the broker on the click. Expiry only proposes: nothing is deleted without the
//! broker's prompt.
//!
//! "Delete now" (DECISIONS 2026-11-23) is the same two calls for one cleanup or one item of it
//! before the retention ends: the page asks the broker for the cleanup's quarantined items
//! (`include_not_due`) and sends back only the broker's ids; the broker's prompt is the
//! confirmation. With "Also delete its registry backups" ticked (DECISIONS 2026-11-24) the page also
//! asks for the cleanup's backups and sends their ids along; the broker asks for them in a prompt
//! of their own.

mod batch;
mod rows;
pub mod text;

#[cfg(test)]
mod tests;

use purge_model::exec::session::{RetentionClass, SessionId, SessionState};
use purge_rpc::error::Outcome;
use purge_rpc::methods::{
    ExpiringItem, ExpiringList, ExpiringParams, ExpiryId, HistoryIndex, NonEmpty, Progress,
    PurgeParams, PurgeResult, UndoParams, UndoResult,
};

pub use batch::{VaultBatch, VaultChip, VaultItem, VaultVolume, WARN_DAYS};
pub use rows::{BatchRowView, DeleteNowChoice, ReviewButton, VaultBarAction};

use crate::broker_link::{self, BrokerLaunch, CallError};
use crate::leftovers::format_size;
use crate::local_time::Clock;

/// The vault's states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaultPhase {
    /// `history.index` is being read.
    Loading,
    /// Nothing is held in quarantine or in a backup.
    Empty,
    /// The index could not be read; [`VaultModel::error`] says why.
    Error,
    /// The list is shown.
    Ready,
}

/// What the page asks of the UI: an engine read, a broker launch, or a broker call. Each is
/// answered through the `on_*` method named on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultCall {
    /// `history.index` on the medium engine; answer with [`VaultModel::on_index`].
    ReadIndex,
    /// Start the broker (the first-elevation explanation, then the Windows prompt); answer with
    /// [`VaultModel::on_launch`].
    Launch,
    /// End the broker this page started. No answer.
    DropBroker,
    /// Let the broker's consent dialog come to the foreground. No answer.
    AllowForeground,
    /// `undo.run`; answer with [`VaultModel::on_undone`], progress with [`VaultModel::on_progress`].
    Undo(UndoParams),
    /// `quarantine.expiring`; answer with [`VaultModel::on_expiring`].
    Expiring(ExpiringParams),
    /// `quarantine.purge`; answer with [`VaultModel::on_purged`].
    Purge(PurgeParams),
}

/// The cleanup an action is for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    session: SessionId,
    name: String,
}

/// What runs once the broker is there.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Next {
    Restore(Target),
    Review,
    ShowItems(Target),
    DeleteNow {
        target: Target,
        only: Option<ExpiryId>,
        also_backups: bool,
    },
}

/// What a `quarantine.expiring` was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Listing {
    Review,
    ShowItems(Target),
    DeleteNow { target: Target, also_backups: bool },
}

/// What a `quarantine.purge` was sent for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Deleting {
    Review,
    DeleteNow {
        target: Target,
        only: Option<ExpiryId>,
    },
}

/// What a broker call waits for, so an answer that does not match is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pending {
    Launch(Next),
    Undo(Target),
    Expiring(Listing),
    Purge(Deleting),
}

/// The Quarantine vault's view model.
#[derive(Debug, Clone)]
pub struct VaultModel {
    phase: VaultPhase,
    error: Option<String>,
    batches: Vec<VaultBatch>,
    volumes: Vec<VaultVolume>,
    interrupted: usize,
    items_for: Option<SessionId>,
    items_name: String,
    items: Vec<VaultItem>,
    totals: String,
    pending: Option<Pending>,
    waiting: Option<String>,
    action_error: Option<String>,
    action_info: Option<String>,
    result_title: Option<String>,
    prompt_cancelled: bool,
    prompt_declined: bool,
    has_broker: bool,
    broker_live: bool,
}

impl Default for VaultModel {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultModel {
    /// A page that has read nothing yet: call [`load`](Self::load) when it is shown.
    pub fn new() -> Self {
        Self {
            phase: VaultPhase::Loading,
            error: None,
            batches: Vec::new(),
            volumes: Vec::new(),
            interrupted: 0,
            items_for: None,
            items_name: String::new(),
            items: Vec::new(),
            totals: String::new(),
            pending: None,
            waiting: None,
            action_error: None,
            action_info: None,
            result_title: None,
            prompt_cancelled: false,
            prompt_declined: false,
            has_broker: false,
            broker_live: false,
        }
    }

    // ---- state ---------------------------------------------------------------------------------

    /// The page's state.
    pub fn phase(&self) -> VaultPhase {
        self.phase
    }

    /// Why the index could not be read.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// The cleanups that hold something, newest first.
    pub fn batches(&self) -> &[VaultBatch] {
        &self.batches
    }

    /// A cleanup by its session.
    pub fn batch(&self, session: &SessionId) -> Option<&VaultBatch> {
        self.batches.iter().find(|b| &b.id == session)
    }

    /// Use and cap per volume.
    pub fn volumes(&self) -> &[VaultVolume] {
        &self.volumes
    }

    /// Sessions the index lists as interrupted; History offers their recovery.
    pub fn interrupted(&self) -> usize {
        self.interrupted
    }

    /// The held cleanups past a retention date: "Review and delete…" offers them.
    pub fn expired_batches(&self) -> impl Iterator<Item = &VaultBatch> {
        self.batches.iter().filter(|b| b.expired)
    }

    /// The cleanup whose quarantined items are listed for "Delete now".
    pub fn items_for(&self) -> Option<&SessionId> {
        self.items_for.as_ref()
    }

    /// The name of that cleanup.
    pub fn items_name(&self) -> &str {
        &self.items_name
    }

    /// Its quarantined items, as the broker listed them.
    pub fn items(&self) -> &[VaultItem] {
        &self.items
    }

    /// The totals line (shown while the list is).
    pub fn totals(&self) -> &str {
        if self.phase == VaultPhase::Ready {
            &self.totals
        } else {
            ""
        }
    }

    /// A broker call is running or its dialog is open: every row action is disabled.
    pub fn busy(&self) -> bool {
        self.pending.is_some()
    }

    /// The waiting line while the broker works or its dialog is open.
    pub fn waiting(&self) -> Option<&str> {
        self.waiting.as_deref()
    }

    /// The last action's error.
    pub fn action_error(&self) -> Option<&str> {
        self.action_error.as_deref()
    }

    /// The last action's note (a cancelled prompt, a result).
    pub fn action_info(&self) -> Option<&str> {
        self.action_info.as_deref()
    }

    /// The last action's result title.
    pub fn result_title(&self) -> Option<&str> {
        self.result_title.as_deref()
    }

    /// The admin prompt was declined or cancelled.
    pub fn prompt_cancelled(&self) -> bool {
        self.prompt_cancelled
    }

    /// With [`prompt_cancelled`](Self::prompt_cancelled): it was "Not now".
    pub fn prompt_declined(&self) -> bool {
        self.prompt_declined
    }

    /// The broker link this page started is live.
    pub fn broker_is_live(&self) -> bool {
        self.has_broker && self.broker_live
    }

    /// The UI's word that the broker link ended (it is dropped on the next click).
    pub fn on_broker_ended(&mut self) {
        self.broker_live = false;
    }

    // ---- the list ------------------------------------------------------------------------------

    /// Reads `history.index`: each time the page is shown (the store changes under it).
    pub fn load(&mut self) -> Vec<VaultCall> {
        if self.batches.is_empty() {
            self.phase = VaultPhase::Loading;
        }
        vec![VaultCall::ReadIndex]
    }

    /// The answer to [`VaultCall::ReadIndex`].
    pub fn on_index(&mut self, answer: Result<HistoryIndex, CallError>, clock: &Clock) {
        let index = match answer {
            Ok(index) => index,
            Err(e) => {
                self.batches.clear();
                self.volumes.clear();
                self.error = Some(e.message().to_owned());
                self.phase = VaultPhase::Error;
                return;
            }
        };
        let mut batches: Vec<VaultBatch> = index
            .sessions
            .iter()
            .filter(|s| VaultBatch::holds(s))
            .map(|s| VaultBatch::new(s, clock))
            .collect();
        batches.sort_by_key(|b| std::cmp::Reverse(b.created));
        self.batches = batches;
        self.volumes = index
            .volumes
            .iter()
            .map(|v| {
                let soon = self
                    .batches
                    .iter()
                    .filter(|b| b.expired || b.expiring)
                    .flat_map(|b| b.usage.iter().filter(|u| u.serial == v.serial))
                    .fold(0u64, |sum, u| sum.saturating_add(u.bytes));
                VaultVolume::new(v, soon)
            })
            .collect();
        self.interrupted = index
            .sessions
            .iter()
            .filter(|s| s.state == SessionState::Open)
            .count();
        let bytes = self
            .batches
            .iter()
            .fold(0u64, |sum, b| sum.saturating_add(b.bytes));
        let n = self.batches.len();
        self.totals = format!(
            "{n} {} {} · files 30 days, registry backups 180 days",
            if n == 1 {
                "cleanup holds"
            } else {
                "cleanups hold"
            },
            format_size(bytes)
        );
        self.error = None;
        self.phase = if self.batches.is_empty() {
            VaultPhase::Empty
        } else {
            VaultPhase::Ready
        };
    }

    // ---- actions -------------------------------------------------------------------------------

    /// "Put back…": `undo.run` for the whole session, through the broker's own dialog.
    pub fn restore(&mut self, session: &SessionId) -> Vec<VaultCall> {
        let Some(target) = self.idle_target(session) else {
            return Vec::new();
        };
        self.begin(text::CONFIRM_RESTORE);
        self.with_broker(Next::Restore(target))
    }

    /// "Review and delete…": `quarantine.expiring` says what is past retention now, and
    /// `quarantine.purge` asks for it in the broker's own dialogs. Nothing past retention is a
    /// note, not a dialog.
    pub fn review_expired(&mut self) -> Vec<VaultCall> {
        if self.busy() {
            return Vec::new();
        }
        self.begin(text::READING_EXPIRED);
        self.with_broker(Next::Review)
    }

    /// "Choose items…": asks the broker which quarantined items the cleanup still holds and lists
    /// them, each with its "Delete now". Reading changes nothing and shows no security prompt.
    pub fn show_items(&mut self, session: &SessionId) -> Vec<VaultCall> {
        let Some(target) = self.idle_target(session) else {
            return Vec::new();
        };
        self.begin(text::READING_HELD);
        self.with_broker(Next::ShowItems(target))
    }

    /// Closes the item list of "Choose items…".
    pub fn close_items(&mut self) {
        self.items_for = None;
        self.items_name.clear();
        self.items.clear();
    }

    /// "Delete now" for a whole cleanup: every quarantined item the broker lists for it, and with
    /// `also_backups` its registry backups too. The broker names each one in its prompt; only what
    /// is approved there is deleted.
    pub fn delete_now(&mut self, session: &SessionId, also_backups: bool) -> Vec<VaultCall> {
        self.start_delete(session, None, also_backups)
    }

    /// "Delete now" for one item of the list [`show_items`](Self::show_items) read, by the
    /// broker's id. An id that is not of that list starts nothing.
    pub fn delete_item_now(&mut self, expiry_id: ExpiryId) -> Vec<VaultCall> {
        match self.items_for.clone() {
            Some(session) if self.items.iter().any(|i| i.expiry_id == expiry_id) => {
                self.start_delete(&session, Some(expiry_id), false)
            }
            _ => Vec::new(),
        }
    }

    /// The page is closing (or done with its broker): end the broker it started.
    pub fn close(&mut self) -> Vec<VaultCall> {
        self.drop_broker()
    }

    fn start_delete(
        &mut self,
        session: &SessionId,
        only: Option<ExpiryId>,
        also_backups: bool,
    ) -> Vec<VaultCall> {
        let Some(target) = self.idle_target(session) else {
            return Vec::new();
        };
        self.begin(if only.is_none() {
            text::READING_HELD
        } else {
            text::CONFIRM_DELETE
        });
        self.with_broker(Next::DeleteNow {
            target,
            only,
            also_backups,
        })
    }

    // ---- answers -------------------------------------------------------------------------------

    /// The answer to [`VaultCall::Launch`].
    pub fn on_launch(&mut self, launch: BrokerLaunch) -> Vec<VaultCall> {
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
            self.action_info = Some(text::NOT_STARTED.into());
        } else {
            self.action_error = Some(launch.message);
        }
        self.end();
        Vec::new()
    }

    /// A `progress` notification of the running undo: its phase is the waiting line.
    pub fn on_progress(&mut self, progress: &Progress) {
        if matches!(self.pending, Some(Pending::Undo(_))) {
            self.waiting = Some(progress.phase.clone());
        }
    }

    /// The answer to [`VaultCall::Undo`].
    pub fn on_undone(&mut self, answer: Result<UndoResult, CallError>) -> Vec<VaultCall> {
        let Some(Pending::Undo(target)) = self.pending.clone() else {
            return Vec::new();
        };
        let mut calls = Vec::new();
        let mut changed = false;
        match answer {
            Ok(undo) => {
                changed = true;
                let name = &target.name;
                self.result_title = Some(match undo.outcome {
                    Outcome::UndoConflicts => format!("{name} is partly back, with conflicts"),
                    Outcome::NotClosed => text::NOT_RECORDED.into(),
                    Outcome::Partial => format!("{name} is partly back"),
                    _ => format!("{name} is back"),
                });
                let lines: Vec<String> = undo
                    .conflicts
                    .iter()
                    .map(broker_link::conflict_text)
                    .chain(undo.alerts.iter().map(broker_link::alert_text))
                    .collect();
                self.action_info = (!lines.is_empty()).then(|| lines.join(" "));
            }
            Err(e @ CallError::Rpc(_)) => self.describe(&e, text::RESTORE_DECLINED),
            Err(CallError::Link { .. }) => {
                calls.extend(self.drop_broker());
                changed = true;
                self.action_error = Some(text::ENDED_WHILE_PUTTING_BACK.into());
            }
            Err(CallError::Cancelled) => {}
            Err(e @ CallError::Other(_)) => {
                self.action_error = Some(format!("{}{}", text::COULD_NOT_PUT_BACK, e.message()))
            }
        }
        self.end();
        if changed {
            calls.extend(self.load());
        }
        calls
    }

    /// The answer to [`VaultCall::Expiring`]. `clock` dates the items of "Choose items…".
    pub fn on_expiring(
        &mut self,
        answer: Result<ExpiringList, CallError>,
        clock: &Clock,
    ) -> Vec<VaultCall> {
        let Some(Pending::Expiring(listing)) = self.pending.clone() else {
            return Vec::new();
        };
        match (listing, answer) {
            (Listing::Review, Ok(list)) => {
                let ids: Vec<ExpiryId> = list.items.iter().map(|i| i.expiry_id).collect();
                match NonEmpty::new(ids) {
                    None => {
                        self.action_info = Some(text::NOTHING_EXPIRED.into());
                        self.end();
                        Vec::new()
                    }
                    Some(ids) => self.purge(Deleting::Review, ids),
                }
            }
            (Listing::Review, Err(e)) => self.review_failed(e),
            (Listing::ShowItems(target), Ok(list)) => {
                let held = quarantined(&list, &target.session);
                if held.is_empty() {
                    self.close_items();
                    self.action_info = Some(text::NOTHING_TO_DELETE.into());
                } else {
                    self.items = held.iter().map(|i| VaultItem::new(i, clock)).collect();
                    self.items_for = Some(target.session);
                    self.items_name = target.name;
                }
                self.end();
                Vec::new()
            }
            (Listing::ShowItems(_), Err(e)) => {
                let mut calls = Vec::new();
                match &e {
                    CallError::Rpc(_) => self.describe(&e, ""),
                    CallError::Link { .. } => {
                        calls.extend(self.drop_broker());
                        self.action_error = Some(text::ENDED_WHILE_READING.into());
                    }
                    CallError::Cancelled => {}
                    CallError::Other(_) => {
                        self.action_error =
                            Some(format!("{}{}", text::COULD_NOT_READ_ITEMS, e.message()))
                    }
                }
                self.end();
                calls
            }
            (
                Listing::DeleteNow {
                    target,
                    also_backups,
                },
                Ok(list),
            ) => {
                // The ids are the broker's own, from a listing made now: the page never names a
                // path.
                let mut ids: Vec<ExpiryId> = quarantined(&list, &target.session)
                    .iter()
                    .map(|i| i.expiry_id)
                    .collect();
                // With the tick, the cleanup's backups too (due or not; the broker tells which and
                // asks accordingly).
                if also_backups {
                    ids.extend(
                        list.items
                            .iter()
                            .filter(|i| {
                                i.session == target.session && i.class == RetentionClass::Backup
                            })
                            .map(|i| i.expiry_id),
                    );
                }
                match NonEmpty::new(ids) {
                    None => {
                        self.action_info = Some(
                            if also_backups {
                                text::NOTHING_TO_DELETE_AT_ALL
                            } else {
                                text::NOTHING_TO_DELETE
                            }
                            .into(),
                        );
                        self.end();
                        Vec::new()
                    }
                    Some(ids) => self.purge(Deleting::DeleteNow { target, only: None }, ids),
                }
            }
            (Listing::DeleteNow { .. }, Err(e)) => self.delete_failed(e),
        }
    }

    /// The answer to [`VaultCall::Purge`].
    pub fn on_purged(&mut self, answer: Result<PurgeResult, CallError>) -> Vec<VaultCall> {
        let Some(Pending::Purge(deleting)) = self.pending.clone() else {
            return Vec::new();
        };
        let result = match answer {
            Ok(result) => result,
            Err(e) => {
                return match deleting {
                    Deleting::Review => self.review_failed(e),
                    Deleting::DeleteNow { .. } => self.delete_failed(e),
                };
            }
        };
        let mut calls = Vec::new();
        match deleting {
            Deleting::Review => {
                self.result_title = Some(if result.purged == 0 {
                    text::NOTHING_DELETED.into()
                } else {
                    format!("{} deleted for good", text::items(result.purged))
                });
                self.action_info = (result.kept > 0).then(|| text::kept(result.kept));
            }
            Deleting::DeleteNow { target, only } => {
                // The backups are counted apart: a deleted registry backup is not "an item
                // deleted", it is an undo given up.
                let backups = result.purged_backups.min(result.purged);
                let files = result.purged - backups;
                let name = &target.name;
                self.result_title = Some(if result.purged == 0 {
                    text::NOTHING_DELETED.into()
                } else if files == 0 {
                    format!("The registry backups of {name} were deleted for good")
                } else {
                    let also = if backups > 0 {
                        ", and its registry backups"
                    } else {
                        ""
                    };
                    format!("{} of {name} deleted for good{also}", text::items(files))
                });
                let mut notes = Vec::new();
                if backups > 0 {
                    notes.push(text::BACKUPS_GIVEN_UP.to_owned());
                }
                if result.kept > 0 {
                    notes.push(text::kept(result.kept));
                }
                self.action_info = (!notes.is_empty()).then(|| notes.join(" "));
                // What was deleted leaves the item list; a list that may be stale is closed
                // instead of guessed.
                let listed_here = self.items_for.as_ref() == Some(&target.session);
                match only {
                    Some(id) if result.purged > 0 && listed_here => {
                        self.items.retain(|i| i.expiry_id != id);
                        if self.items.is_empty() {
                            self.close_items();
                        }
                    }
                    None if listed_here => self.close_items(),
                    _ => {}
                }
                // A completed delete ends the broker; the next click starts a new one.
                calls.extend(self.drop_broker());
            }
        }
        self.end();
        calls.extend(self.load());
        calls
    }

    // ---- helpers -------------------------------------------------------------------------------

    fn purge(&mut self, deleting: Deleting, ids: NonEmpty<ExpiryId>) -> Vec<VaultCall> {
        self.waiting = Some(text::CONFIRM_DELETE.into());
        self.pending = Some(Pending::Purge(deleting));
        vec![
            VaultCall::AllowForeground,
            VaultCall::Purge(PurgeParams { expiry_ids: ids }),
        ]
    }

    fn review_failed(&mut self, e: CallError) -> Vec<VaultCall> {
        let mut calls = Vec::new();
        let mut changed = false;
        match &e {
            CallError::Rpc(_) if e.kind() == Some("busy") => {
                self.action_error = Some(text::DELETE_BUSY.into())
            }
            CallError::Rpc(_) => self.describe(&e, text::DELETE_DECLINED),
            CallError::Link { .. } => {
                calls.extend(self.drop_broker());
                changed = true;
                self.action_error = Some(text::ENDED_DURING_DELETE.into());
            }
            CallError::Cancelled => {}
            CallError::Other(_) => {
                self.action_error =
                    Some(format!("{}{}", text::COULD_NOT_DELETE_EXPIRED, e.message()))
            }
        }
        self.end();
        if changed {
            calls.extend(self.load());
        }
        calls
    }

    fn delete_failed(&mut self, e: CallError) -> Vec<VaultCall> {
        let mut calls = Vec::new();
        let mut changed = false;
        match &e {
            CallError::Rpc(_) if e.kind() == Some("busy") => {
                self.action_error = Some(text::DELETE_BUSY.into())
            }
            CallError::Rpc(_) if e.kind() == Some("gone") => {
                // The id no longer names anything in the broker's listing: put back, deleted, or
                // in use meanwhile.
                self.close_items();
                changed = true;
                self.action_info = Some(text::NO_LONGER_LISTED.into());
            }
            CallError::Rpc(_) => self.describe(&e, text::DELETE_DECLINED),
            CallError::Link { .. } => {
                calls.extend(self.drop_broker());
                self.close_items();
                changed = true;
                self.action_error = Some(text::ENDED_DURING_DELETE.into());
            }
            CallError::Cancelled => {}
            CallError::Other(_) => {
                self.action_error = Some(format!("{}{}", text::COULD_NOT_DELETE, e.message()))
            }
        }
        self.end();
        if changed {
            calls.extend(self.load());
        }
        calls
    }

    /// An error answer in words (`VaultViewModel.Describe`).
    fn describe(&mut self, e: &CallError, declined: &str) {
        match e.kind() {
            Some("consent_declined") => self.action_info = Some(declined.to_owned()),
            Some("busy") => self.action_error = Some(text::BUSY.into()),
            Some("needs_recovery") => self.action_error = Some(text::NEEDS_RECOVERY.into()),
            Some("store_integrity") => {
                self.action_error = Some(format!("{}{}", text::STORE_INTEGRITY, e.message()))
            }
            _ => self.action_error = Some(e.message().to_owned()),
        }
    }

    fn with_broker(&mut self, next: Next) -> Vec<VaultCall> {
        if self.broker_is_live() {
            return self.run(next);
        }
        let mut calls = self.drop_broker();
        self.pending = Some(Pending::Launch(next));
        calls.push(VaultCall::Launch);
        calls
    }

    fn run(&mut self, next: Next) -> Vec<VaultCall> {
        match next {
            Next::Restore(target) => {
                let params = UndoParams {
                    session: target.session.clone(),
                    item_ids: None,
                };
                self.pending = Some(Pending::Undo(target));
                vec![VaultCall::AllowForeground, VaultCall::Undo(params)]
            }
            Next::Review => {
                self.pending = Some(Pending::Expiring(Listing::Review));
                vec![VaultCall::Expiring(ExpiringParams::default())]
            }
            Next::ShowItems(target) => {
                self.pending = Some(Pending::Expiring(Listing::ShowItems(target)));
                vec![VaultCall::Expiring(ExpiringParams {
                    include_not_due: true,
                    include_backups_not_due: false,
                })]
            }
            Next::DeleteNow {
                target,
                only: Some(id),
                ..
            } => match NonEmpty::new(vec![id]) {
                Some(ids) => self.purge(
                    Deleting::DeleteNow {
                        target,
                        only: Some(id),
                    },
                    ids,
                ),
                None => {
                    self.end();
                    Vec::new()
                }
            },
            Next::DeleteNow {
                target,
                only: None,
                also_backups,
            } => {
                self.pending = Some(Pending::Expiring(Listing::DeleteNow {
                    target,
                    also_backups,
                }));
                vec![VaultCall::Expiring(ExpiringParams {
                    include_not_due: true,
                    include_backups_not_due: also_backups,
                })]
            }
        }
    }

    fn drop_broker(&mut self) -> Vec<VaultCall> {
        let had = self.has_broker;
        self.has_broker = false;
        self.broker_live = false;
        if had {
            vec![VaultCall::DropBroker]
        } else {
            Vec::new()
        }
    }

    fn idle_target(&self, session: &SessionId) -> Option<Target> {
        if self.busy() {
            return None;
        }
        self.batch(session).map(|b| Target {
            session: b.id.clone(),
            name: b.name.clone(),
        })
    }

    fn begin(&mut self, waiting: &str) {
        self.waiting = Some(waiting.to_owned());
        self.action_error = None;
        self.action_info = None;
        self.result_title = None;
        self.prompt_cancelled = false;
    }

    fn end(&mut self) {
        self.pending = None;
        self.waiting = None;
    }
}

/// The quarantined items (never the backups) the broker lists for one cleanup.
fn quarantined<'a>(list: &'a ExpiringList, session: &SessionId) -> Vec<&'a ExpiringItem> {
    list.items
        .iter()
        .filter(|i| &i.session == session && i.class == RetentionClass::Quarantine)
        .collect()
}
