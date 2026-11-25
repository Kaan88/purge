//! The Leftovers page (S3): the port of `Views/Leftovers/LeftoversModel.cs`, `LeftoversRow.cs`,
//! the logic of `LeftoversView.xaml.cs`, `Shell/LeftoversRequest.cs` and `LeftoversNavigator.cs`.
//!
//! [`LeftoversModel`] is the page's state machine and rules: candidate paging, the tick rules,
//! re-ticking after a re-scan, `plan.create` refusals, the waiting state, the result page and the
//! undo and retry flows (design 6.4, 7a S3, 8.1). It never claims an item was moved before
//! `plan.execute` returned.
//!
//! It does no I/O. Each action returns the [`LeftoversCall`]s the UI sends through purge-client,
//! and the UI hands each answer back with the matching `on_*` method (`on_scan`, `on_candidates`,
//! `on_plan_created`, `on_executed`, ...), plus the broker's notifications (`on_progress`,
//! `on_consent_shown`, `on_baseline_changed`). Only one change runs at a time; an answer the model
//! is not waiting for is ignored.

mod item;
mod rows;
pub mod text;

#[cfg(test)]
mod tests;

use std::collections::HashSet;

use purge_model::{ProgramId, ScanMode};
use purge_rpc::error::{ErrorData, Outcome};
use purge_rpc::methods::{
    BaselineChanged, CandidateRef, CandidatesPage, CandidatesParams, ConfirmCode, ConsentShown,
    ExecResult, ExplainParams, Explanation, LeftoversScanParams, NonEmpty, OutcomeResult,
    PageLimit, PlanCreateParams, PlanCreated, PlanExecuteParams, PlanSelectedParams, Progress,
    RestorePoint, ScanId, ScanResult, ScanSessionParams, ScanStoredParams, SessionParams,
    UndoParams, UndoResult, UninstallSessionId,
};

use crate::broker_link::{self, BrokerLaunch, CallError};

pub use item::{
    AttentionRow, DescribeLabel, ItemLabel, LeftoverGroup, LeftoverItem, Look, format_size,
    group_name_of, sample_fixture, sample_items,
};
pub use rows::{
    BandSummary, DetailPane, EvidenceGlyph, EvidenceLine, Footer, GroupHeader, ItemRow,
    LeftoversAction, LeftoversRow,
};

/// The broker's largest `scan.candidates` page.
pub const CANDIDATE_PAGE_SIZE: u16 = 500;

/// The `exec.progress` phase the broker sends when the move is recorded and its delete step begins.
pub const DELETE_AFTER_PHASE: &str = "delete_after";

/// The page's states; the list is only interactive in [`LeftoversPhase::Review`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeftoversPhase {
    /// Nothing scanned yet (or the page was opened from the rail).
    Empty,
    /// `leftovers.scan` or the candidate paging is running.
    Scanning,
    /// The list is shown.
    Review,
    /// `plan.create` or `plan.execute` is running, or the broker's dialog is open.
    Waiting,
    /// The move's result.
    Result,
    /// "Put back all" finished.
    Undone,
    /// The broker link ended during a change: what happened is unknown, so no result is claimed.
    Interrupted,
}

/// What the page asks the UI to do: a broker call (params are `purge_rpc`'s), or one of the UI's
/// own steps. Answers come back through the model's `on_*` methods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeftoversCall {
    /// `leftovers.scan`; answer with [`LeftoversModel::on_scan`].
    Scan(LeftoversScanParams),
    /// `scan.candidates`; answer with [`LeftoversModel::on_candidates`].
    Candidates(CandidatesParams),
    /// `candidate.explain`; answer with [`LeftoversModel::on_explain`].
    Explain(ExplainParams),
    /// `plan.create`; answer with [`LeftoversModel::on_plan_created`].
    CreatePlan(PlanCreateParams),
    /// `plan.execute` (with `delete_after` as the page asked); answer with
    /// [`LeftoversModel::on_executed`].
    Execute(PlanExecuteParams),
    /// `undo.run` for the result's session; answer with [`LeftoversModel::on_undone`].
    Undo(UndoParams),
    /// `journal.retry_held`; answer with [`LeftoversModel::on_retried`].
    RetryHeld(SessionParams),
    /// Let the broker's dialog come to the foreground (`AllowSetForegroundWindow` for the broker).
    AllowForeground,
    /// Start a new broker for "Put back all" (the first-elevation explanation, then UAC); the page
    /// owns it. Answer with [`LeftoversModel::on_relaunch`].
    Relaunch,
    /// Open History & undo (the undo button after a delete step, or over a link that has ended).
    OpenHistory,
}

/// What a scan is made of: an uninstall session of this broker, or a stored fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ScanTarget {
    /// After an uninstall in this broker.
    Session(UninstallSessionId),
    /// A program removed outside Purge, from its stored fingerprint.
    Stored(ProgramId),
}

/// The scan the page shows: its id and the mode the broker scanned in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScanInfo {
    /// The scan.
    pub scan_id: ScanId,
    /// The mode.
    pub mode: ScanMode,
}

/// The Uninstall pipeline's hand-off to the Leftovers page (M3-UI-S2 → S3): the uninstaller has
/// finished, the broker has scanned the session, and the page takes the live broker link `B` for
/// `scan.candidates`, `plan.create` and `plan.execute`. The page owns the link once it is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftoversRequest<B = ()> {
    /// The program the session recorded.
    pub program_id: ProgramId,
    /// The name the page titles itself with.
    pub program_name: String,
    /// The broker session of the uninstall; `None` for a stored-fingerprint scan.
    pub session_id: Option<UninstallSessionId>,
    /// The scan made over that session (`leftovers.scan`).
    pub scan_id: ScanId,
    /// post, external or forced; forced means nothing is pre-selected.
    pub mode: ScanMode,
    /// The restore-point choice the confirm dialog carried, passed on to `plan.execute` unchanged.
    pub restore_point: RestorePoint,
    /// Whether the uninstaller ran in quiet mode.
    pub quiet: bool,
    /// The live broker link; `None` when the pipeline ended without one.
    pub broker: Option<B>,
}

impl<B> LeftoversRequest<B> {
    /// True for the forced scan after a failed or unverified uninstall: nothing starts ticked.
    pub fn forced(&self) -> bool {
        self.mode == ScanMode::Forced
    }
}

/// A request the page took: the broker link it now owns and the calls to send.
#[derive(Debug)]
pub struct Shown<B> {
    /// The link, which the page (the UI's leftovers view) owns from now on.
    pub broker: Option<B>,
    /// The calls to send (the first candidate page).
    pub calls: Vec<LeftoversCall>,
}

/// How the page is made.
#[derive(Debug, Clone, Default)]
pub struct LeftoversOptions {
    /// The signed-in user's SID, so registry rows under it read "Your account".
    pub current_user_sid: Option<String>,
    /// Whether the page can start a new broker for "Put back all" ([`LeftoversCall::Relaunch`]).
    pub can_relaunch: bool,
    /// Turns a registry path into words (the Programs model's `RegistryLabel`).
    pub describe_label: Option<DescribeLabel>,
}

/// Why the empty page is empty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmptyReason {
    NoScan,
    LinkGone,
    /// The link ended (ended for another page, or the broker died) during a review or a scan.
    Ended,
}

/// The change the page waits for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pending {
    Scan {
        rescan: bool,
    },
    Page {
        show: bool,
        rescan: bool,
        offset: u32,
    },
    CreatePlan {
        delete_after: bool,
        restore_point: RestorePoint,
    },
    Execute {
        delete_after: bool,
    },
    /// A new broker is being started; the call it is for goes out over it next.
    Relaunch(After),
    Undo {
        relaunched: bool,
    },
    RetryHeld {
        relaunched: bool,
    },
}

/// What a new broker is started for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum After {
    Undo,
    Retry,
}

/// The Leftovers page's state machine (see the module docs).
#[derive(Debug, Clone)]
pub struct LeftoversModel {
    options: LeftoversOptions,
    broker_live: bool,
    pending: Option<Pending>,
    empty_reason: EmptyReason,
    target: Option<ScanTarget>,
    forced: bool,
    rescan_ticks: Option<HashSet<CandidateRef>>,
    rescan_ids: Option<HashSet<CandidateRef>>,
    asked: usize,
    restore_point: RestorePoint,
    selected: Option<CandidateRef>,
    explaining: bool,
    list_version: u64,

    phase: LeftoversPhase,
    scan: Option<ScanInfo>,
    plan: Option<PlanCreated>,
    result: Option<ExecResult>,
    undo: Option<UndoResult>,
    program_name: String,
    /// The empty panel's text after [`EmptyReason::Ended`]: it names the program.
    ended_text: String,
    is_sample: bool,
    code: Option<ConfirmCode>,
    prompt_up: bool,
    waiting_title: String,
    waiting_detail: String,
    scan_progress: String,
    error: Option<String>,
    info: Option<String>,
    result_title: Option<String>,
    result_detail: Option<String>,
    restore_point_text: Option<String>,
    undo_title: Option<String>,
    undo_detail: Option<String>,
    rescan_message: Option<String>,
    rescan_offered: bool,
    show_weak: bool,
    delete_after: bool,
    delete_after_result: Option<String>,

    items: Vec<LeftoverItem>,
    groups: Vec<LeftoverGroup>,
    attention: Vec<AttentionRow>,
    refusal_lines: Vec<String>,
    held_lines: Vec<String>,
    failed_lines: Vec<String>,
    undo_conflict_lines: Vec<String>,
}

impl LeftoversModel {
    /// A page over a live broker link.
    pub fn new(options: LeftoversOptions) -> Self {
        Self {
            options,
            broker_live: true,
            pending: None,
            empty_reason: EmptyReason::NoScan,
            target: None,
            forced: false,
            rescan_ticks: None,
            rescan_ids: None,
            asked: 0,
            restore_point: RestorePoint::HighRisk,
            selected: None,
            explaining: false,
            list_version: 0,
            phase: LeftoversPhase::Empty,
            scan: None,
            plan: None,
            result: None,
            undo: None,
            program_name: String::new(),
            ended_text: String::new(),
            is_sample: false,
            code: None,
            prompt_up: false,
            waiting_title: String::new(),
            waiting_detail: text::NOTHING_MOVED_YET.into(),
            scan_progress: String::new(),
            error: None,
            info: None,
            result_title: None,
            result_detail: None,
            restore_point_text: None,
            undo_title: None,
            undo_detail: None,
            rescan_message: None,
            rescan_offered: false,
            show_weak: false,
            delete_after: false,
            delete_after_result: None,
            items: Vec::new(),
            groups: Vec::new(),
            attention: Vec::new(),
            refusal_lines: Vec::new(),
            held_lines: Vec::new(),
            failed_lines: Vec::new(),
            undo_conflict_lines: Vec::new(),
        }
    }

    /// A page without a broker (the sample view, or no engine): every call it could send would be
    /// refused, so its link reads as ended.
    pub fn offline(options: LeftoversOptions) -> Self {
        let mut model = Self::new(options);
        model.broker_live = false;
        model
    }

    // ---- State --------------------------------------------------------------------------------

    /// The page's state.
    pub fn phase(&self) -> LeftoversPhase {
        self.phase
    }

    /// The scan the page shows.
    pub fn scan(&self) -> Option<&ScanInfo> {
        self.scan.as_ref()
    }

    /// The plan of the running or last move.
    pub fn plan(&self) -> Option<&PlanCreated> {
        self.plan.as_ref()
    }

    /// The last move's result.
    pub fn result(&self) -> Option<&ExecResult> {
        self.result.as_ref()
    }

    /// The last "Put back all"'s result.
    pub fn undo(&self) -> Option<&UndoResult> {
        self.undo.as_ref()
    }

    /// The program the page is about.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// True for the sample rows of `--sample`: there is no broker, so nothing can be moved.
    pub fn is_sample(&self) -> bool {
        self.is_sample
    }

    /// True when the scan is a forced one (the broker ticks nothing for you then).
    pub fn is_forced(&self) -> bool {
        self.scan.is_some_and(|s| s.mode == ScanMode::Forced)
    }

    /// The code the broker's dialog shows in its footer; `None` until the plan exists.
    pub fn code(&self) -> Option<ConfirmCode> {
        self.code
    }

    /// Whether `consent.shown` has arrived: the broker's dialog is up.
    pub fn prompt_up(&self) -> bool {
        self.prompt_up
    }

    /// The waiting panel's title (AutomationId `WaitingTitleText`).
    pub fn waiting_title(&self) -> &str {
        &self.waiting_title
    }

    /// The waiting panel's detail line.
    pub fn waiting_detail(&self) -> &str {
        &self.waiting_detail
    }

    /// The waiting panel's code (AutomationId `WaitingCodeText`): the code, or "—".
    pub fn waiting_code_text(&self) -> String {
        self.code
            .map_or_else(|| text::NO_CODE.to_owned(), |c| c.to_string())
    }

    /// What the scan is doing now.
    pub fn scan_progress(&self) -> &str {
        &self.scan_progress
    }

    /// The last error, for the error bar.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// The last note, for the info bar.
    pub fn info(&self) -> Option<&str> {
        self.info.as_deref()
    }

    /// The result title as computed (`None` before a result).
    pub fn result_title(&self) -> Option<&str> {
        self.result_title.as_deref()
    }

    /// The result title the panel shows (AutomationId `ResultTitleText`).
    pub fn result_title_text(&self) -> &str {
        self.result_title.as_deref().unwrap_or(text::MOVE_FINISHED)
    }

    /// The result detail line (AutomationId `ResultDetailText`).
    pub fn result_detail(&self) -> Option<&str> {
        self.result_detail.as_deref()
    }

    /// Whether the result's icon is the check mark (complete) rather than the warning.
    pub fn result_complete(&self) -> bool {
        self.result
            .as_ref()
            .is_some_and(|r| r.outcome == Outcome::Complete)
    }

    /// The restore-point line of the result.
    pub fn restore_point_text(&self) -> Option<&str> {
        self.restore_point_text.as_deref()
    }

    /// The "Put back" panel's title (AutomationId `UndoTitleText`).
    pub fn undo_title(&self) -> Option<&str> {
        self.undo_title.as_deref()
    }

    /// The "Put back" panel's title as shown.
    pub fn undo_title_text(&self) -> &str {
        self.undo_title.as_deref().unwrap_or(text::PUT_BACK)
    }

    /// The "Put back" panel's detail (AutomationId `UndoDetailText`).
    pub fn undo_detail(&self) -> Option<&str> {
        self.undo_detail.as_deref()
    }

    /// The re-scan's summary line.
    pub fn rescan_message(&self) -> Option<&str> {
        self.rescan_message.as_deref()
    }

    /// Whether `baseline.changed` offered a re-scan of this scan.
    pub fn rescan_offered(&self) -> bool {
        self.rescan_offered
    }

    /// The candidates, in the broker's order.
    pub fn items(&self) -> &[LeftoverItem] {
        &self.items
    }

    /// One candidate.
    pub fn item(&self, id: &CandidateRef) -> Option<&LeftoverItem> {
        self.items.iter().find(|i| &i.candidate_id == id)
    }

    /// The groups: the eight list groups, then the sections.
    pub fn groups(&self) -> &[LeftoverGroup] {
        &self.groups
    }

    /// The plan's attention list.
    pub fn attention(&self) -> &[AttentionRow] {
        &self.attention
    }

    /// The items `plan.create` refused, one line each.
    pub fn refusal_lines(&self) -> &[String] {
        &self.refusal_lines
    }

    /// The result's held items and what holds them.
    pub fn held_lines(&self) -> &[String] {
        &self.held_lines
    }

    /// The result's failed, pending and skipped counts in words.
    pub fn failed_lines(&self) -> &[String] {
        &self.failed_lines
    }

    /// The undo's conflicts and reconcile alerts.
    pub fn undo_conflict_lines(&self) -> &[String] {
        &self.undo_conflict_lines
    }

    /// Bumped whenever the list's rows must be rebuilt; a tick or the delete-after box does not.
    pub fn list_version(&self) -> u64 {
        self.list_version
    }

    /// The items of a scan that wait for review here (the rail's badge); 0 outside the review.
    pub fn waiting_for_review(&self) -> usize {
        if self.phase == LeftoversPhase::Review {
            self.items.len()
        } else {
            0
        }
    }

    /// The restore-point choice of the request, for `plan.execute`.
    pub fn restore_point(&self) -> RestorePoint {
        self.restore_point
    }

    /// Weak matches are hidden by default; the toggle shows them and never ticks them.
    pub fn show_weak(&self) -> bool {
        self.show_weak
    }

    /// Sets whether weak matches show.
    pub fn set_show_weak(&mut self, value: bool) {
        if self.show_weak != value {
            self.show_weak = value;
            self.list_version += 1;
        }
    }

    /// The view's weak-match button: shows or hides them, and unticks them when it hides them.
    pub fn toggle_weak(&mut self) {
        self.set_show_weak(!self.show_weak);
        if !self.show_weak {
            for item in self.items.iter_mut().filter(|i| i.is_weak() && i.checked) {
                item.checked = false;
            }
        }
    }

    /// Weak matches in the scan.
    pub fn weak_count(&self) -> usize {
        self.items.iter().filter(|i| i.is_weak()).count()
    }

    /// Items the user may tick.
    pub fn selectable_count(&self) -> usize {
        self.items.iter().filter(|i| i.selectable()).count()
    }

    /// Ticked items.
    pub fn selected_count(&self) -> usize {
        self.chosen().count()
    }

    /// Bytes of the ticked items.
    pub fn selected_bytes(&self) -> u64 {
        self.chosen().map(|i| i.size_bytes.unwrap_or(0)).sum()
    }

    fn chosen(&self) -> impl Iterator<Item = &LeftoverItem> {
        self.items.iter().filter(|i| i.checked && i.selectable())
    }

    /// The Move button's words (AutomationId `MoveText`).
    pub fn move_text(&self) -> String {
        text::move_text(self.delete_after, self.selected_count())
    }

    /// "Delete instead of keeping in quarantine" (DECISIONS 2026-11-24), off by default and after
    /// every move. A request to the broker (`plan.execute {delete_after}`), never a consent.
    pub fn delete_after(&self) -> bool {
        self.delete_after
    }

    /// Ticks or unticks "delete after"; the button's words change, the list does not.
    pub fn set_delete_after(&mut self, value: bool) {
        self.delete_after = value;
    }

    /// What became of the delete step of the last move, in words; `None` when the move did not ask
    /// for one.
    pub fn delete_after_result(&self) -> Option<&str> {
        self.delete_after_result.as_deref()
    }

    /// Whether the Move button works.
    pub fn can_move(&self) -> bool {
        self.phase == LeftoversPhase::Review && self.selected_count() > 0 && self.pending.is_none()
    }

    /// True while a change is on its way (`plan.create`, `plan.execute`, undo or the retry of held
    /// items, or the broker's dialog for one): the page's broker link must not be replaced then.
    pub fn is_changing(&self) -> bool {
        self.phase == LeftoversPhase::Waiting
    }

    /// Whether the broker link is live, as the UI last said.
    pub fn broker_is_live(&self) -> bool {
        self.broker_live
    }

    /// The UI's word on the link: it ended (a completed `plan.execute` ends the broker) or a new one
    /// is up.
    pub fn set_broker_live(&mut self, live: bool) {
        self.broker_live = live;
    }

    /// The page's link ended without a change on its way: "End it" for another page, or the broker
    /// died. A review or scan cannot go on over it (Move and Scan again would only be refused), so
    /// the page empties to a panel that names the program and says how to scan it again. Nothing
    /// was moved. A result keeps showing: undo and retry start a new broker.
    pub fn on_link_ended(&mut self) {
        self.broker_live = false;
        if !matches!(
            self.phase,
            LeftoversPhase::Review | LeftoversPhase::Scanning
        ) {
            return;
        }
        self.end_on_dead_link();
    }

    /// Empties the page to the ended panel: nothing of the scan stays, so nothing (a later
    /// `baseline.changed`, a re-scan's summary, a refusal) can offer it again over the dead link.
    fn end_on_dead_link(&mut self) {
        let stored = matches!(self.target, Some(ScanTarget::Stored(_)));
        self.pending = None;
        self.phase = LeftoversPhase::Empty;
        self.empty_reason = EmptyReason::Ended;
        self.ended_text = text::review_ended(&self.program_name, stored);
        self.error = None;
        self.info = None;
        self.scan = None;
        self.plan = None;
        self.code = None;
        self.prompt_up = false;
        self.rescan_message = None;
        self.rescan_ticks = None;
        self.rescan_ids = None;
        self.items.clear();
        self.groups.clear();
        self.attention.clear();
        self.refusal_lines.clear();
        self.selected = None;
        self.explaining = false;
        self.rescan_offered = false;
        self.list_version += 1;
    }

    /// Whether the result page offers the undo button.
    pub fn can_undo(&self) -> bool {
        self.phase == LeftoversPhase::Result
            && self.result.as_ref().is_some_and(|r| {
                (r.counts.done > 0 || r.counts.vanished > 0)
                    // Everything the run changed was a file that is now deleted for good.
                    && !(deleted_after(r) && !changed_more_than_it_deleted(r))
            })
    }

    /// The undo button (AutomationId `UndoAllButton`). After a delete step that deleted something
    /// it never reads "Put back all" (review M1): it names what still can come back.
    pub fn undo_text(&self) -> &'static str {
        match self.result.as_ref().and_then(|r| r.delete_after) {
            Some(step) if step.purged > 0 && step.kept > 0 => text::UNDO_KEPT,
            Some(step) if step.purged > 0 => text::UNDO_REGISTRY,
            _ => text::UNDO_ALL,
        }
    }

    /// The undo button opens History & undo instead of running `undo.run` here: after a delete step
    /// that deleted something, and whenever the link has ended and the page cannot start a new one.
    pub fn undo_opens_history(&self) -> bool {
        self.result
            .as_ref()
            .is_some_and(|r| deleted_after(r) || (!self.broker_live && !self.options.can_relaunch))
    }

    /// Whether the result offers "Try the held items again".
    pub fn can_retry_held(&self) -> bool {
        self.phase == LeftoversPhase::Result
            && self.result.as_ref().is_some_and(|r| !r.held.is_empty())
    }

    // ---- Groups -------------------------------------------------------------------------------

    /// The rows of a group the list shows (weak matches only while they are shown).
    pub fn visible_items(&self, group: usize) -> Vec<usize> {
        self.groups.get(group).map_or_else(Vec::new, |g| {
            g.items
                .iter()
                .copied()
                .filter(|&i| self.show_weak || !self.items[i].is_weak())
                .collect()
        })
    }

    /// The weak matches of a group that the list hides while weak matches are hidden.
    pub fn hidden_count(&self, group: usize) -> usize {
        if self.show_weak {
            return 0;
        }
        self.groups.get(group).map_or(0, |g| {
            g.items.iter().filter(|&&i| self.items[i].is_weak()).count()
        })
    }

    /// The groups with at least one visible row.
    pub fn visible_groups(&self) -> Vec<usize> {
        (0..self.groups.len())
            .filter(|&g| !self.visible_items(g).is_empty())
            .collect()
    }

    /// Group boxes tick Safe items only (design 9.4); sections have no box.
    pub fn group_can_tick(&self, group: usize) -> bool {
        self.groups.get(group).is_some_and(|g| {
            !g.is_section
                && g.items.iter().any(|&i| {
                    let item = &self.items[i];
                    item.selectable() && item.look == Look::Safe
                })
        })
    }

    /// Bytes of a group's items.
    pub fn group_bytes(&self, group: usize) -> u64 {
        self.groups.get(group).map_or(0, |g| {
            g.items
                .iter()
                .map(|&i| self.items[i].size_bytes.unwrap_or(0))
                .sum()
        })
    }

    /// The group named `name` (the UI resolves a click on a group by the name it showed).
    pub fn group_named(&self, name: &str) -> Option<usize> {
        self.groups.iter().position(|g| g.name == name)
    }

    /// Shows or hides a group's rows.
    pub fn toggle_expanded(&mut self, group: usize) {
        if let Some(g) = self.groups.get_mut(group) {
            g.expanded = !g.expanded;
            self.list_version += 1;
        }
    }

    /// "Expand all" / "Collapse all": expands every group when any is collapsed, else collapses all.
    pub fn expand_all(&mut self) {
        let expand = self.groups.iter().any(|g| !g.expanded);
        for g in &mut self.groups {
            g.expanded = expand;
        }
        self.list_version += 1;
    }

    /// The words of the expand button.
    pub fn expand_all_text(&self) -> &'static str {
        if self.groups.iter().any(|g| !g.expanded) {
            text::EXPAND_ALL
        } else {
            text::COLLAPSE_ALL
        }
    }

    /// The words of the weak-match button (shown when the scan has weak matches).
    pub fn weak_button_text(&self) -> String {
        text::weak_button(self.show_weak, self.weak_count())
    }

    // ---- Ticks --------------------------------------------------------------------------------

    /// Ticks or unticks one row; Likely and user-data rows need their own tick (design 9.4).
    pub fn set_checked(&mut self, id: &CandidateRef, value: bool) {
        if let Some(item) = self.items.iter_mut().find(|i| &i.candidate_id == id)
            && item.selectable()
        {
            item.checked = value;
        }
    }

    /// A group box ticks the group's Safe items only; a second click unticks the group.
    pub fn toggle_group(&mut self, group: usize) {
        if !self.group_can_tick(group) {
            return;
        }
        let members = self.groups[group].items.clone();
        let all = members
            .iter()
            .filter(|&&i| self.items[i].selectable())
            .all(|&i| self.items[i].checked);
        for i in members {
            let item = &mut self.items[i];
            if all {
                item.checked = false;
            } else if item.selectable() && item.look == Look::Safe {
                item.checked = true;
            }
        }
    }

    // ---- Showing a scan -----------------------------------------------------------------------

    /// The shell's hand-off (`LeftoversNavigator.TryShow` and the view's `Show`). Refused, with the
    /// request handed back untouched, while a change is on its way: the caller keeps or ends its
    /// link and says why. Taken, the page starts over for the request and owns its link; without a
    /// link it says the administrator part ended.
    pub fn try_show<B>(
        &mut self,
        request: LeftoversRequest<B>,
    ) -> Result<Shown<B>, LeftoversRequest<B>> {
        if self.is_changing() {
            return Err(request);
        }
        let options = self.options.clone();
        let LeftoversRequest {
            program_id,
            program_name,
            session_id,
            scan_id,
            mode,
            restore_point,
            broker,
            ..
        } = request;
        if broker.is_none() {
            *self = Self::offline(options);
            self.empty_reason = EmptyReason::LinkGone;
            self.program_name = program_name;
            return Ok(Shown {
                broker,
                calls: Vec::new(),
            });
        }
        *self = Self::new(options);
        self.restore_point = restore_point;
        let target = Some(match session_id {
            Some(session) => ScanTarget::Session(session),
            None => ScanTarget::Stored(program_id),
        });
        let calls = self.show_scan(scan_id, mode, program_name, target);
        Ok(Shown { broker, calls })
    }

    /// Shows a scan the broker already made: pages `scan.candidates` for its id without asking
    /// `leftovers.scan` again. The target is kept so a re-scan can ask again later.
    pub fn show_scan(
        &mut self,
        scan_id: ScanId,
        mode: ScanMode,
        program_name: impl Into<String>,
        target: Option<ScanTarget>,
    ) -> Vec<LeftoversCall> {
        if self.pending.is_some() {
            return Vec::new();
        }
        self.program_name = program_name.into();
        self.target = target;
        self.forced = mode == ScanMode::Forced;
        self.rescan_ticks = None;
        self.rescan_ids = None;
        self.start_loading(text::READING_SCAN);
        self.scan = Some(ScanInfo { scan_id, mode });
        self.items.clear();
        self.pending = Some(Pending::Page {
            show: true,
            rescan: false,
            offset: 0,
        });
        vec![page_call(scan_id, 0)]
    }

    /// Scans an uninstall session (or a stored fingerprint).
    pub fn scan_target(&mut self, target: ScanTarget, forced: bool) -> Vec<LeftoversCall> {
        self.load(target, forced, false)
    }

    /// Scans again and re-applies the ticks by candidate id (design 3.6).
    pub fn rescan(&mut self) -> Vec<LeftoversCall> {
        match (&self.scan, self.target.clone()) {
            (Some(_), Some(target)) => self.load(target, self.forced, true),
            _ => Vec::new(),
        }
    }

    fn load(&mut self, target: ScanTarget, forced: bool, rescan: bool) -> Vec<LeftoversCall> {
        if self.pending.is_some() {
            return Vec::new();
        }
        self.forced = forced;
        if rescan {
            self.rescan_ticks = Some(self.chosen().map(|i| i.candidate_id).collect());
            self.rescan_ids = Some(self.items.iter().map(|i| i.candidate_id).collect());
        } else {
            self.rescan_ticks = None;
            self.rescan_ids = None;
        }
        self.start_loading(text::STARTING_SCAN);
        let params = match &target {
            ScanTarget::Session(session_id) => LeftoversScanParams::Session(ScanSessionParams {
                session_id: *session_id,
                forced,
            }),
            ScanTarget::Stored(program_id) => LeftoversScanParams::Stored(ScanStoredParams {
                program_id: program_id.clone(),
            }),
        };
        self.target = Some(target);
        self.pending = Some(Pending::Scan { rescan });
        vec![LeftoversCall::Scan(params)]
    }

    fn start_loading(&mut self, progress: &str) {
        self.rescan_offered = false;
        self.rescan_message = None;
        self.error = None;
        self.info = None;
        self.attention.clear();
        self.refusal_lines.clear();
        self.phase = LeftoversPhase::Scanning;
        self.scan_progress = progress.into();
    }

    /// The answer to [`LeftoversCall::Scan`].
    pub fn on_scan(&mut self, answer: Result<ScanResult, CallError>) -> Vec<LeftoversCall> {
        let Some(Pending::Scan { rescan }) = self.pending else {
            return Vec::new();
        };
        match answer {
            Ok(scan) => {
                self.scan = Some(ScanInfo {
                    scan_id: scan.scan_id,
                    mode: scan.mode,
                });
                self.items.clear();
                self.pending = Some(Pending::Page {
                    show: false,
                    rescan,
                    offset: 0,
                });
                vec![page_call(scan.scan_id, 0)]
            }
            Err(e) => {
                self.fail_loading(false, &e);
                Vec::new()
            }
        }
    }

    /// The answer to [`LeftoversCall::Candidates`].
    pub fn on_candidates(
        &mut self,
        answer: Result<CandidatesPage, CallError>,
    ) -> Vec<LeftoversCall> {
        let Some(Pending::Page {
            show,
            rescan,
            offset,
        }) = self.pending
        else {
            return Vec::new();
        };
        let page = match answer {
            Ok(page) => page,
            Err(e) => {
                self.fail_loading(show, &e);
                return Vec::new();
            }
        };
        let read = u32::try_from(page.items.len()).unwrap_or(u32::MAX);
        let (label, sid) = (
            self.options.describe_label,
            self.options.current_user_sid.clone(),
        );
        self.items.extend(
            page.items
                .into_iter()
                .map(|row| LeftoverItem::from_row(row, label, sid.as_deref())),
        );
        let next = offset.saturating_add(read);
        if read > 0
            && next < page.total
            && let Some(scan) = self.scan
        {
            self.pending = Some(Pending::Page {
                show,
                rescan,
                offset: next,
            });
            return vec![page_call(scan.scan_id, next)];
        }
        self.pending = None;
        self.build_groups();
        let ticks = self.rescan_ticks.take();
        self.apply_ticks(ticks.as_ref());
        if rescan {
            self.describe_rescan(ticks.as_ref());
        }
        self.rescan_ids = None;
        self.phase = LeftoversPhase::Review;
        self.scan_progress.clear();
        Vec::new()
    }

    fn fail_loading(&mut self, show: bool, e: &CallError) {
        if !self.broker_live {
            // The link ended (`on_link_ended` came while nothing could end the scan): the
            // scan cannot go on over it, so the page says so the way `on_link_ended` does.
            self.end_on_dead_link();
            return;
        }
        self.pending = None;
        self.phase = LeftoversPhase::Empty;
        match e {
            CallError::Cancelled => {
                self.info = Some(
                    if show {
                        text::SCAN_NOT_LOADED
                    } else {
                        text::SCAN_CANCELLED
                    }
                    .into(),
                );
            }
            CallError::Link { message, .. } => {
                let prefix = if show {
                    text::SHOW_LINK_ENDED
                } else {
                    text::SCAN_LINK_ENDED
                };
                self.error = Some(format!("{prefix}{message}"));
            }
            other => self.error = Some(describe_error(other)),
        }
    }

    fn build_groups(&mut self) {
        self.groups.clear();
        for name in text::GROUP_ORDER {
            let items: Vec<usize> = (0..self.items.len())
                .filter(|&i| {
                    let item = &self.items[i];
                    item.group_name == name && !item.is_protected() && !item.is_report_only()
                })
                .collect();
            if !items.is_empty() {
                self.groups.push(group(name, false, items));
            }
        }
        let protected: Vec<usize> = (0..self.items.len())
            .filter(|&i| self.items[i].is_protected())
            .collect();
        if !protected.is_empty() {
            self.groups
                .push(group(text::GROUP_PROTECTED, true, protected));
        }
        let report_only: Vec<usize> = (0..self.items.len())
            .filter(|&i| !self.items[i].is_protected() && self.items[i].is_report_only())
            .collect();
        if !report_only.is_empty() {
            self.groups
                .push(group(text::GROUP_REPORT_ONLY, true, report_only));
        }
        self.list_version += 1;
    }

    fn apply_ticks(&mut self, ticks: Option<&HashSet<CandidateRef>>) {
        // The broker never preselects in a forced scan; do not invent ticks if a server ever did.
        let preselects = !self.is_forced();
        for item in &mut self.items {
            item.refused = false;
            item.refusal_reason.clear();
            item.checked = match ticks {
                None => preselects && item.preselected && item.selectable(),
                Some(ticks) => ticks.contains(&item.candidate_id) && item.selectable(),
            };
        }
    }

    fn describe_rescan(&mut self, ticks: Option<&HashSet<CandidateRef>>) {
        let (Some(ticks), Some(before)) = (ticks, self.rescan_ids.as_ref()) else {
            return;
        };
        let ids: HashSet<CandidateRef> = self.items.iter().map(|i| i.candidate_id).collect();
        let new_items = self
            .items
            .iter()
            .filter(|i| !before.contains(&i.candidate_id))
            .count();
        let gone = before.iter().filter(|id| !ids.contains(id)).count();
        let gone_ticked = ticks.iter().filter(|id| !ids.contains(id)).count();
        self.rescan_message = Some(if new_items == 0 && gone == 0 {
            text::RESCAN_UNCHANGED.into()
        } else {
            text::rescan_changed(new_items, gone, gone_ticked)
        });
    }

    // ---- The detail pane ----------------------------------------------------------------------

    /// The list's selection changed: the detail pane shows the item, and `candidate.explain` is
    /// asked for unless one is on its way.
    pub fn select(&mut self, id: CandidateRef) -> Vec<LeftoversCall> {
        if self.item(&id).is_none() {
            return Vec::new();
        }
        self.selected = Some(id);
        match self.scan {
            Some(scan) if !self.explaining && !self.is_sample => {
                self.explaining = true;
                vec![LeftoversCall::Explain(ExplainParams {
                    scan_id: scan.scan_id,
                    candidate_id: id,
                })]
            }
            _ => Vec::new(),
        }
    }

    /// The selected candidate.
    pub fn selected(&self) -> Option<&CandidateRef> {
        self.selected.as_ref()
    }

    /// The answer to [`LeftoversCall::Explain`] for `id`.
    pub fn on_explain(&mut self, id: &CandidateRef, answer: Result<Explanation, CallError>) {
        self.explaining = false;
        let Some(item) = self.items.iter_mut().find(|i| &i.candidate_id == id) else {
            return;
        };
        match answer {
            Ok(explanation) => {
                item.evidence = explanation.evidence;
                item.blockers = explanation.blockers;
            }
            Err(CallError::Cancelled) => {}
            Err(e) => item.blockers = vec![e.message().to_owned()],
        }
    }

    // ---- The move -----------------------------------------------------------------------------

    /// `plan.create` then `plan.execute`. The waiting state names the code from `plan.create` and
    /// switches when `consent.shown` says the dialog is up; nothing is said to be moved until the
    /// result arrives.
    pub fn move_items(&mut self, restore_point: RestorePoint) -> Vec<LeftoversCall> {
        if !self.can_move() {
            return Vec::new();
        }
        let Some(scan) = self.scan else {
            return Vec::new();
        };
        let chosen: Vec<CandidateRef> = self.chosen().map(|i| i.candidate_id).collect();
        let Some(selected) = NonEmpty::new(chosen) else {
            return Vec::new();
        };
        // Read once: the request the broker gets is the one the page showed when the button was pressed.
        let delete_after = self.delete_after;
        self.asked = selected.as_slice().len();
        self.delete_after_result = None;
        self.error = None;
        self.info = None;
        self.refusal_lines.clear();
        self.attention.clear();
        self.prompt_up = false;
        self.code = None;
        self.plan = None;
        self.phase = LeftoversPhase::Waiting;
        self.waiting_title = text::PREPARING_PLAN.into();
        self.waiting_detail = text::NOTHING_MOVED_YET.into();
        self.pending = Some(Pending::CreatePlan {
            delete_after,
            restore_point,
        });
        vec![LeftoversCall::CreatePlan(PlanCreateParams::Selected(
            PlanSelectedParams {
                scan_id: scan.scan_id,
                selected,
                allow_irreversible: false,
            },
        ))]
    }

    /// The Move button: [`Self::move_items`] with the request's restore-point choice.
    pub fn click_move(&mut self) -> Vec<LeftoversCall> {
        self.move_items(self.restore_point)
    }

    /// The answer to [`LeftoversCall::CreatePlan`].
    pub fn on_plan_created(
        &mut self,
        answer: Result<PlanCreated, CallError>,
    ) -> Vec<LeftoversCall> {
        let Some(Pending::CreatePlan {
            delete_after,
            restore_point,
        }) = self.pending
        else {
            return Vec::new();
        };
        let plan = match answer {
            Ok(plan) => plan,
            Err(e) => {
                if let Some(ErrorData::PlanRefused { refusals }) = e.data() {
                    let refusals = refusals.clone();
                    self.apply_refusals(&refusals);
                    self.phase = LeftoversPhase::Review;
                    self.pending = None;
                } else {
                    self.fail_move(&e);
                }
                return Vec::new();
            }
        };
        self.code = Some(plan.code);
        self.apply_attention(&plan);
        self.waiting_title = text::CONFIRM_MOVE.into();
        self.waiting_detail = if delete_after {
            text::CONFIRM_MOVE_DETAIL_DELETE
        } else {
            text::CONFIRM_MOVE_DETAIL
        }
        .into();
        let plan_id = plan.plan_id;
        self.plan = Some(plan);
        self.pending = Some(Pending::Execute { delete_after });
        vec![
            LeftoversCall::AllowForeground,
            LeftoversCall::Execute(PlanExecuteParams {
                plan_id,
                restore_point,
                delete_after,
            }),
        ]
    }

    /// The answer to [`LeftoversCall::Execute`].
    pub fn on_executed(&mut self, answer: Result<ExecResult, CallError>) {
        let Some(Pending::Execute { delete_after }) = self.pending else {
            return;
        };
        match answer {
            Ok(result) => {
                self.pending = None;
                self.build_result(&result);
                if delete_after {
                    self.delete_after_result =
                        Some(text::describe_delete_after(result.delete_after.as_ref()));
                }
                self.result = Some(result);
                // Off again: the next move keeps its items unless the box is ticked again.
                self.delete_after = false;
                self.phase = LeftoversPhase::Result;
                self.waiting_title.clear();
            }
            Err(e) => self.fail_move(&e),
        }
    }

    fn fail_move(&mut self, e: &CallError) {
        self.pending = None;
        match e {
            _ if e.kind() == Some("consent_declined") => {
                self.phase = LeftoversPhase::Review;
                self.info = Some(text::MOVE_DECLINED.into());
            }
            // Never sent (the session had ended, or the broker was closing): nothing was moved,
            // so the review stays as it was. Never "cannot tell".
            // The link is dead too (it ended while the move waited, so `on_link_ended` left the
            // page alone): a review over it would only be refused again. End it as
            // `on_link_ended` does; nothing was moved.
            _ if never_reached_a_broker(e) && !self.broker_live => self.end_on_dead_link(),
            _ if never_reached_a_broker(e) => {
                self.phase = LeftoversPhase::Review;
                self.error = Some(text::MOVE_NEVER_SENT.into());
            }
            CallError::Link { .. } => {
                self.phase = LeftoversPhase::Interrupted;
                self.error = Some(text::MOVE_INTERRUPTED.into());
            }
            CallError::Cancelled => {
                self.phase = LeftoversPhase::Review;
                self.info = Some(text::MOVE_NOT_STARTED.into());
            }
            other => {
                self.phase = LeftoversPhase::Review;
                self.error = Some(describe_error(other));
            }
        }
    }

    fn apply_refusals(&mut self, refusals: &[purge_rpc::error::Refusal]) {
        for refusal in refusals {
            let item = refusal
                .candidate_id
                .and_then(|id| self.items.iter_mut().find(|i| i.candidate_id == id));
            match (item, refusal.candidate_id) {
                (Some(item), _) => {
                    item.refused = true;
                    item.checked = false;
                    item.refusal_reason = refusal.reason.clone();
                    self.refusal_lines
                        .push(format!("{}: {}", item.display_name, refusal.reason));
                }
                (None, Some(id)) => self.refusal_lines.push(format!("{id}: {}", refusal.reason)),
                (None, None) => self.refusal_lines.push(refusal.reason.clone()),
            }
        }
        self.error = Some(if refusals.is_empty() {
            text::PLAN_REFUSED.into()
        } else {
            text::refused_some(refusals.len(), self.asked)
        });
    }

    fn apply_attention(&mut self, plan: &PlanCreated) {
        self.attention.clear();
        for attention in &plan.attention {
            self.attention.push(AttentionRow {
                candidate_id: attention.candidate_id,
                display_name: attention.display_name.clone(),
                look: Look::of(attention.band),
                kind: attention.kind,
                size_bytes: attention.size_bytes,
                reasons: attention.reasons.clone(),
            });
            if let Some(item) = self
                .items
                .iter_mut()
                .find(|i| i.candidate_id == attention.candidate_id)
            {
                item.attention = true;
            }
        }
    }

    fn build_result(&mut self, result: &ExecResult) {
        let counts = result.counts;
        let moved = counts.done + counts.vanished;
        self.held_lines = result
            .held
            .iter()
            .map(|held| {
                let lockers = if held.lockers.is_empty() {
                    text::STILL_IN_USE.to_owned()
                } else {
                    held.lockers
                        .iter()
                        .map(|locker| match &locker.service {
                            Some(service) if !service.is_empty() => {
                                format!("{} (service {service})", locker.name)
                            }
                            _ => format!("{} ({})", locker.name, locker.pid),
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                text::held_line(&held.display_name, &lockers)
            })
            .collect();
        self.failed_lines.clear();
        if counts.failed > 0 {
            self.failed_lines.push(text::failed_line(counts.failed));
        }
        if counts.pending_reboot > 0 {
            self.failed_lines
                .push(text::reboot_line(counts.pending_reboot));
        }
        if counts.skipped > 0 {
            self.failed_lines.push(text::skipped_line(counts.skipped));
        }
        self.result_title = Some(match result.outcome {
            Outcome::NotClosed => text::NOT_CLOSED.into(),
            Outcome::Complete => text::moved_title(moved),
            _ => text::moved_of_title(moved, self.asked),
        });
        let mut parts = Vec::new();
        if counts.done > 0 {
            parts.push(format!("{} moved", counts.done));
        }
        if counts.vanished > 0 {
            parts.push(format!("{} already gone", counts.vanished));
        }
        if counts.held_retry > 0 {
            parts.push(format!("{} held for a later try", counts.held_retry));
        }
        if counts.failed > 0 {
            parts.push(format!("{} failed", counts.failed));
        }
        let mut detail = parts.join(" · ");
        if result.outcome == Outcome::NotClosed {
            detail.push_str(text::NOT_CLOSED_DETAIL);
        }
        self.result_detail = Some(detail);
        self.restore_point_text = match result.restore_point {
            purge_model::exec::session::RestorePointOutcome::Created { sequence } => {
                Some(text::restore_point(sequence))
            }
            _ => None,
        };
    }

    // ---- Put back all -------------------------------------------------------------------------

    /// The undo button of the result page (the view's handler): opens History & undo when
    /// [`Self::undo_opens_history`], else [`Self::undo_all`].
    pub fn click_undo_all(&mut self) -> Vec<LeftoversCall> {
        if self.result.is_some() && self.undo_opens_history() {
            return vec![LeftoversCall::OpenHistory];
        }
        self.undo_all()
    }

    /// `undo.run` for everything the result's session moved. When the link has ended (a completed
    /// `plan.execute` ends the broker), or the broker refuses because it is closing, a new broker is
    /// started first (the admin explanation, UAC), then the broker's restore prompt is asked for, all
    /// on this page. A request that never reached a broker is never reported as "ended while putting
    /// things back".
    pub fn undo_all(&mut self) -> Vec<LeftoversCall> {
        if !self.can_undo() || self.pending.is_some() {
            return Vec::new();
        }
        if self.undo_opens_history() {
            // Nothing is sent over a link that has ended, and nothing deleted is promised back.
            self.error = None;
            self.info = Some(text::OPEN_HISTORY.into());
            return Vec::new();
        }
        self.error = None;
        self.info = None;
        self.prompt_up = false;
        self.code = None;
        self.attention.clear();
        self.phase = LeftoversPhase::Waiting;
        self.waiting_title = text::UNDO_WAITING_TITLE.into();
        self.waiting_detail = text::NOTHING_PUT_BACK_YET.into();
        if !self.broker_live {
            return self.relaunch_for_undo();
        }
        self.send_undo(false)
    }

    fn send_undo(&mut self, relaunched: bool) -> Vec<LeftoversCall> {
        let Some(session) = self.result.as_ref().map(|r| r.session.clone()) else {
            self.phase = LeftoversPhase::Result;
            self.pending = None;
            return Vec::new();
        };
        self.pending = Some(Pending::Undo { relaunched });
        vec![
            LeftoversCall::AllowForeground,
            LeftoversCall::Undo(UndoParams {
                session,
                item_ids: None,
            }),
        ]
    }

    fn relaunch_for_undo(&mut self) -> Vec<LeftoversCall> {
        if !self.options.can_relaunch {
            self.phase = LeftoversPhase::Result;
            self.info = Some(text::OPEN_HISTORY.into());
            self.pending = None;
            return Vec::new();
        }
        self.waiting_title = text::UNDO_STARTING_TITLE.into();
        self.waiting_detail = text::ASKS_PERMISSION_FIRST.into();
        self.pending = Some(Pending::Relaunch(After::Undo));
        vec![LeftoversCall::Relaunch]
    }

    /// The answer to [`LeftoversCall::Relaunch`]: a new broker is the page's link now, or none was
    /// started and nothing was sent.
    pub fn on_relaunch(&mut self, launch: BrokerLaunch) -> Vec<LeftoversCall> {
        let Some(Pending::Relaunch(after)) = self.pending else {
            return Vec::new();
        };
        if !launch.started {
            self.pending = None;
            self.phase = LeftoversPhase::Result;
            let (not_permitted, not_started) = match after {
                After::Undo => (text::UNDO_NOT_PERMITTED, text::UNDO_NOT_STARTED),
                After::Retry => (text::RETRY_NOT_PERMITTED, text::RETRY_NOT_STARTED),
            };
            if launch.cancelled {
                self.info = Some(not_permitted.into());
            } else {
                self.error = Some(format!("{not_started}{}", launch.message));
            }
            return Vec::new();
        }
        self.broker_live = true;
        match after {
            After::Undo => {
                self.waiting_title = text::UNDO_WAITING_TITLE.into();
                self.waiting_detail = text::NOTHING_PUT_BACK_YET.into();
                self.send_undo(true)
            }
            After::Retry => {
                self.waiting_title = text::CONFIRM_RETRY.into();
                self.waiting_detail = text::NOTHING_MOVED_YET.into();
                self.send_retry(true)
            }
        }
    }

    /// The answer to [`LeftoversCall::Undo`].
    pub fn on_undone(&mut self, answer: Result<UndoResult, CallError>) -> Vec<LeftoversCall> {
        let Some(Pending::Undo { relaunched }) = self.pending else {
            return Vec::new();
        };
        self.pending = None;
        match answer {
            Ok(undo) => {
                self.undo_conflict_lines = undo
                    .conflicts
                    .iter()
                    .map(broker_link::conflict_text)
                    .chain(undo.alerts.iter().map(broker_link::alert_text))
                    .collect();
                self.undo_title = Some(
                    if undo.outcome == Outcome::UndoConflicts {
                        text::PUT_BACK_CONFLICTS
                    } else {
                        text::PUT_BACK
                    }
                    .into(),
                );
                self.undo_detail = Some(if undo.conflicts.is_empty() {
                    text::ALL_BACK.into()
                } else {
                    text::conflicts_detail(undo.conflicts.len())
                });
                self.undo = Some(undo);
                self.phase = LeftoversPhase::Undone;
            }
            Err(e) if !relaunched && self.options.can_relaunch && never_reached_a_broker(&e) => {
                // The broker was closing after the move, or had just ended: nothing was done.
                self.broker_live = false;
                return self.relaunch_for_undo();
            }
            Err(e) if e.kind() == Some("consent_declined") => {
                self.phase = LeftoversPhase::Result;
                self.info = Some(text::UNDO_DECLINED.into());
            }
            Err(e) if never_reached_a_broker(&e) => {
                // Nothing reached a broker that could act on it: say so, never "cannot tell".
                self.phase = LeftoversPhase::Result;
                self.error = Some(text::UNDO_NEVER_SENT.into());
            }
            Err(CallError::Link { .. }) => {
                self.phase = LeftoversPhase::Interrupted;
                self.error = Some(text::UNDO_INTERRUPTED.into());
            }
            // A cancelled call leaves nothing sent: back to the result.
            Err(CallError::Cancelled) => self.phase = LeftoversPhase::Result,
            Err(e) => {
                self.phase = LeftoversPhase::Result;
                self.error = Some(describe_error(&e));
            }
        }
        Vec::new()
    }

    // ---- Retry the held items -----------------------------------------------------------------

    /// `journal.retry_held`: tries the items a partial run left locked. Over a link that has ended
    /// (a run ends the broker), a new broker is started first, as for "Put back all".
    pub fn retry_held(&mut self) -> Vec<LeftoversCall> {
        if !self.can_retry_held() || self.pending.is_some() {
            return Vec::new();
        }
        self.error = None;
        self.info = None;
        self.prompt_up = false;
        self.code = None;
        self.attention.clear();
        self.phase = LeftoversPhase::Waiting;
        self.waiting_title = text::CONFIRM_RETRY.into();
        self.waiting_detail = text::NOTHING_MOVED_YET.into();
        if !self.broker_live {
            return self.relaunch_for_retry();
        }
        self.send_retry(false)
    }

    fn send_retry(&mut self, relaunched: bool) -> Vec<LeftoversCall> {
        let Some(session) = self.result.as_ref().map(|r| r.session.clone()) else {
            self.phase = LeftoversPhase::Result;
            self.pending = None;
            return Vec::new();
        };
        self.pending = Some(Pending::RetryHeld { relaunched });
        vec![
            LeftoversCall::AllowForeground,
            LeftoversCall::RetryHeld(SessionParams { session }),
        ]
    }

    fn relaunch_for_retry(&mut self) -> Vec<LeftoversCall> {
        if !self.options.can_relaunch {
            // Nothing can reach a broker: nothing was tried, and the result stays.
            self.phase = LeftoversPhase::Result;
            self.error = Some(text::RETRY_NEVER_SENT.into());
            self.pending = None;
            return Vec::new();
        }
        self.waiting_title = text::RETRY_STARTING_TITLE.into();
        self.waiting_detail = text::RETRY_ASKS_PERMISSION_FIRST.into();
        self.pending = Some(Pending::Relaunch(After::Retry));
        vec![LeftoversCall::Relaunch]
    }

    /// The answer to [`LeftoversCall::RetryHeld`].
    pub fn on_retried(&mut self, answer: Result<OutcomeResult, CallError>) -> Vec<LeftoversCall> {
        let Some(Pending::RetryHeld { relaunched }) = self.pending else {
            return Vec::new();
        };
        self.pending = None;
        match answer {
            Ok(retried) => {
                self.phase = LeftoversPhase::Result;
                // The broker asks before it tries anything; a retry that ran without its prompt
                // found nothing held any more (design 8.2: a recovery that changes nothing has no
                // dialog), so it moved nothing.
                let first = if !self.prompt_up {
                    text::RETRY_NOTHING_HELD
                } else if retried.outcome == Outcome::Complete {
                    text::RETRY_MOVED
                } else {
                    text::RETRY_STILL_HELD
                };
                self.info = Some(
                    std::iter::once(first.to_owned())
                        .chain(retried.alerts.iter().map(broker_link::alert_text))
                        .collect::<Vec<_>>()
                        .join(" "),
                );
            }
            Err(e) if !relaunched && self.options.can_relaunch && never_reached_a_broker(&e) => {
                // The broker was closing after the run, or had just ended: nothing was tried.
                self.broker_live = false;
                return self.relaunch_for_retry();
            }
            Err(e) if e.kind() == Some("consent_declined") => {
                self.phase = LeftoversPhase::Result;
                self.info = Some(text::RETRY_DECLINED.into());
            }
            Err(e) if never_reached_a_broker(&e) => {
                // Nothing reached a broker that could act on it: say so, never "cannot tell".
                self.phase = LeftoversPhase::Result;
                self.error = Some(text::RETRY_NEVER_SENT.into());
            }
            Err(CallError::Link { .. }) => {
                self.phase = LeftoversPhase::Interrupted;
                self.error = Some(text::RETRY_INTERRUPTED.into());
            }
            Err(CallError::Cancelled) => self.phase = LeftoversPhase::Result,
            Err(e) => {
                self.phase = LeftoversPhase::Result;
                self.error = Some(describe_error(&e));
            }
        }
        Vec::new()
    }

    // ---- Notifications ------------------------------------------------------------------------

    /// A `*.progress` notification of the running call.
    pub fn on_progress(&mut self, progress: &Progress) -> Vec<LeftoversCall> {
        match self.pending {
            Some(Pending::Scan { .. }) => self.scan_progress = progress.phase.clone(),
            Some(Pending::Execute { delete_after }) => {
                if delete_after && progress.phase == DELETE_AFTER_PHASE {
                    // The move is done and recorded; the broker now asks its second question, with
                    // a code of its own.
                    self.prompt_up = false;
                    self.code = None;
                    self.waiting_title = text::CONFIRM_DELETE.into();
                    self.waiting_detail = text::CONFIRM_DELETE_DETAIL.into();
                    return vec![LeftoversCall::AllowForeground];
                }
                self.waiting_detail = progress.phase.clone();
            }
            Some(Pending::Undo { .. }) => self.waiting_detail = progress.phase.clone(),
            _ => {}
        }
        Vec::new()
    }

    /// `consent.shown`: the dialog's footer is the truth, the code the user sees in the prompt.
    pub fn on_consent_shown(&mut self, shown: &ConsentShown) {
        self.prompt_up = true;
        self.code = Some(shown.code);
    }

    /// `baseline.changed`: the scan shown is one worth making again.
    pub fn on_baseline_changed(&mut self, changed: &BaselineChanged) {
        if let Some(scan) = self.scan
            && changed.rescan_offered.contains(&scan.scan_id)
        {
            self.rescan_offered = true;
        }
    }

    // ---- Sample -------------------------------------------------------------------------------

    /// Sample rows for `--sample` and the Settings preview; `count` above zero loads the bench's
    /// fixture of that many items instead (the launch bench's S3 timer).
    pub fn load_sample(&mut self, name: &str, count: usize) {
        self.program_name = name.into();
        self.is_sample = true;
        let label = self.options.describe_label;
        self.items = if count > 0 {
            sample_fixture(count, label)
        } else {
            sample_items(label)
        };
        self.scan = Some(ScanInfo {
            scan_id: ScanId::from_bits(0),
            mode: ScanMode::Forced,
        });
        self.build_groups();
        self.apply_ticks(None);
        self.phase = LeftoversPhase::Review;
    }

    // ---- The page around the list -------------------------------------------------------------

    /// The page title.
    pub fn title(&self) -> String {
        if self.program_name.is_empty() {
            text::TITLE.into()
        } else {
            text::title_of(&self.program_name)
        }
    }

    /// The program's tile letter, when the tile shows (a program, and not the empty page).
    pub fn app_initial(&self) -> Option<String> {
        if self.program_name.is_empty() || self.phase == LeftoversPhase::Empty {
            return None;
        }
        self.program_name
            .chars()
            .next()
            .map(|c| c.to_uppercase().collect())
    }

    /// The line under the title.
    pub fn subtitle(&self) -> String {
        match self.phase {
            LeftoversPhase::Scanning if self.scan_progress.is_empty() => text::SUB_SCANNING.into(),
            LeftoversPhase::Scanning => {
                format!("{}{}", text::SUB_SCANNING_PREFIX, self.scan_progress)
            }
            LeftoversPhase::Waiting => text::SUB_WAITING.into(),
            LeftoversPhase::Result => text::SUB_RESULT.into(),
            LeftoversPhase::Undone => text::SUB_UNDONE.into(),
            LeftoversPhase::Interrupted => text::SUB_INTERRUPTED.into(),
            LeftoversPhase::Review => match self.scan {
                Some(scan) => {
                    let mode = match scan.mode {
                        ScanMode::Post => text::MODE_POST,
                        ScanMode::Forced => text::MODE_FORCED,
                        ScanMode::External => text::MODE_STORED,
                    };
                    text::review_subtitle(mode, self.items.len())
                }
                None => text::SUB_REVIEW.into(),
            },
            LeftoversPhase::Empty => text::SUB_EMPTY.into(),
        }
    }

    /// The empty panel's title and text (AutomationId `EmptyTitle`), when it shows.
    pub fn empty_panel(&self) -> Option<(&str, &str)> {
        match self.phase {
            LeftoversPhase::Interrupted => Some((
                text::INTERRUPTED_TITLE,
                self.error.as_deref().unwrap_or(text::INTERRUPTED_FALLBACK),
            )),
            LeftoversPhase::Empty if self.empty_reason == EmptyReason::LinkGone => {
                Some((text::LINK_GONE_TITLE, text::LINK_GONE_TEXT))
            }
            LeftoversPhase::Empty if self.empty_reason == EmptyReason::Ended => {
                Some((text::LINK_GONE_TITLE, &self.ended_text))
            }
            LeftoversPhase::Empty => Some((text::NO_SCAN_TITLE, text::NO_SCAN_TEXT)),
            _ => None,
        }
    }

    /// The waiting panel's attention header; `None` when the plan lists nothing.
    pub fn attention_header(&self) -> Option<String> {
        (!self.attention.is_empty()).then(|| text::attention_header(self.attention.len()))
    }
}

fn group(name: &str, is_section: bool, items: Vec<usize>) -> LeftoverGroup {
    LeftoverGroup {
        name: name.into(),
        is_section,
        expanded: true,
        items,
    }
}

fn page_call(scan_id: ScanId, offset: u32) -> LeftoversCall {
    LeftoversCall::Candidates(CandidatesParams {
        scan_id,
        offset,
        limit: PAGE_LIMIT,
    })
}

/// The page size of `scan.candidates`.
const PAGE_LIMIT: PageLimit = match PageLimit::new(CANDIDATE_PAGE_SIZE) {
    Some(limit) => limit,
    None => panic!("500 is a page limit"),
};

/// The delete step of the result deleted something for good ("deleted" or "partial").
fn deleted_after(result: &ExecResult) -> bool {
    result.delete_after.is_some_and(|step| step.purged > 0)
}

/// The run did more than move the items that were then deleted: registry, service or task changes,
/// or moved items that are still in quarantine. Those can still be undone.
fn changed_more_than_it_deleted(result: &ExecResult) -> bool {
    result
        .delete_after
        .is_some_and(|step| step.kept > 0 || result.counts.done > step.purged)
}

/// The request never reached a broker that could act on it: the link had ended before it was
/// written, or the broker refused it because it is closing after a completed change.
fn never_reached_a_broker(e: &CallError) -> bool {
    match e {
        CallError::Link { not_sent, .. } => *not_sent,
        _ => e.kind() == Some("runtime") && e.message().to_ascii_lowercase().contains("is closing"),
    }
}

/// A broker refusal in words.
fn describe_error(e: &CallError) -> String {
    match e.data() {
        Some(ErrorData::CapExceeded {
            volume,
            used,
            needed,
            cap,
        }) => text::cap_exceeded(volume, *needed, *used, *cap),
        Some(ErrorData::NeedsRecovery { .. }) => text::NEEDS_RECOVERY.into(),
        Some(ErrorData::Gone { .. }) => text::GONE.into(),
        Some(ErrorData::Busy) => text::BUSY.into(),
        Some(ErrorData::StoreIntegrity { .. }) => {
            format!("{}{}", text::STORE_INTEGRITY, e.message())
        }
        Some(ErrorData::PlanRefused { .. }) => {
            format!("{}{}", text::PLAN_REFUSED_PREFIX, e.message())
        }
        _ => e.message().to_owned(),
    }
}
