//! One session and one item of the History page (`HistorySessionModel`, `HistoryEntryModel`):
//! plain data the list, the timeline and the detail pane draw.

use purge_model::FileTime;
use purge_model::exec::op::{ItemOutcome, OpId};
use purge_model::exec::session::{RetentionClass, SessionId, SessionState, SessionSummary};
use purge_rpc::methods::{Deleted, HistoryItem, ItemKind, PendingSession};

use super::text;
use crate::broker_link;
use crate::leftovers::format_size;
use crate::local_time::{Clock, LocalTime};

/// The chip a session shows; each has its own glyph in the view, so the state never rests on colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoryChip {
    /// Something can be put back.
    Undoable,
    /// Interrupted, or only partly put back.
    Caution,
    /// Nothing to do.
    Neutral,
}

/// One session of `history.index` as the page lists it: time, app, count, size, days left, state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistorySession {
    /// The executor session.
    pub id: SessionId,
    /// The app's name, or its id when the index names no owner.
    pub name: String,
    /// When it started.
    pub started: FileTime,
    /// `started` in local time.
    pub local: LocalTime,
    /// `HH:mm`.
    pub time: String,
    /// The count line ("21 items moved · 1.2 MB · 1 held, in use").
    pub detail: String,
    /// Listed from `journal.pending` (broker), not from the index.
    pub from_journal: bool,
    /// The state in words.
    pub state: &'static str,
    /// The chip.
    pub chip: HistoryChip,
    /// When the quarantined files expire.
    pub file_expiry: FileTime,
    /// When the registry and task backups expire.
    pub backup_expiry: FileTime,
    /// Days until `file_expiry`, 0 once past.
    pub file_days: i32,
    /// Days until `backup_expiry`, 0 once past.
    pub backup_days: i32,
    /// Something is still in quarantine or in a backup to put back.
    pub held: bool,
    /// The session was not recorded completely (`Open` in the index, or listed by
    /// `journal.pending`); recovery comes first.
    pub interrupted: bool,
    /// A reconcile alert was found among the items read with "Show items" (review M3-R2 S5).
    pub has_alert: bool,
    /// `file_expiry` as `d MMM yyyy` (local).
    file_until: String,
    /// `backup_expiry` as `d MMM yyyy` (local).
    backup_until: String,
}

impl HistorySession {
    /// A session of the index.
    pub fn from_summary(s: &SessionSummary, clock: &Clock) -> Self {
        let name = match &s.owner {
            Some(owner) if !owner.display_name.is_empty() => owner.display_name.clone(),
            _ => s.app.clone(),
        };
        let counts = s.counts;
        let mut parts = vec![count(counts.done, "item moved", "items moved")];
        if s.backup_bytes > 0 {
            parts.push(format_size(s.backup_bytes));
        }
        if counts.held_retry > 0 {
            parts.push(format!("{} held, in use", counts.held_retry));
        }
        if counts.pending_reboot > 0 {
            parts.push(format!("{} at the next restart", counts.pending_reboot));
        }
        if counts.failed > 0 {
            parts.push(format!("{} failed", counts.failed));
        }
        if s.undone > 0 {
            parts.push(format!("{} put back", s.undone));
        }
        let purged_all = s.purged.contains(&RetentionClass::Quarantine)
            && s.purged.contains(&RetentionClass::Backup);
        let held = matches!(
            s.state,
            SessionState::Committed | SessionState::PartiallyUndone
        ) && s.backup_bytes > 0
            && !purged_all;
        let (state, chip) = match s.state {
            SessionState::Open => (text::INTERRUPTED, HistoryChip::Caution),
            SessionState::PartiallyUndone => (text::STATE_PARTLY_PUT_BACK, HistoryChip::Caution),
            SessionState::Undone => (text::PUT_BACK, HistoryChip::Neutral),
            SessionState::Aborted => (text::STATE_ROLLED_BACK, HistoryChip::Neutral),
            _ if !held => (text::NOTHING_TO_PUT_BACK, HistoryChip::Neutral),
            _ => (text::UNDOABLE, HistoryChip::Undoable),
        };
        let started = valid(s.started);
        let local = clock.local(started);
        let file_expiry = valid(s.expires.quarantine);
        let backup_expiry = valid(s.expires.backups);
        Self {
            id: s.id.clone(),
            name,
            started,
            local,
            time: local.hh_mm(),
            detail: parts.join(" · "),
            from_journal: false,
            state,
            chip,
            file_expiry,
            backup_expiry,
            file_days: clock.days_left(file_expiry),
            backup_days: clock.days_left(backup_expiry),
            held,
            interrupted: s.state == SessionState::Open,
            has_alert: false,
            file_until: clock.local(file_expiry).d_mmm_yyyy(),
            backup_until: clock.local(backup_expiry).d_mmm_yyyy(),
        }
    }

    /// A session `journal.pending` found interrupted that the index does not list (an `Unindexed`
    /// one, or a run that never reached its index entry): listed from the journal's facts, with
    /// recovery offered.
    pub fn from_pending(p: &PendingSession, clock: &Clock) -> Self {
        let started = valid(p.started);
        let local = clock.local(started);
        let never = clock.local(FileTime(0)).d_mmm_yyyy();
        Self {
            id: p.session.clone(),
            name: p.app.clone(),
            started,
            local,
            time: local.hh_mm(),
            detail: text::from_journal(p.done, p.total),
            from_journal: true,
            state: text::INTERRUPTED,
            chip: HistoryChip::Caution,
            file_expiry: FileTime(0),
            backup_expiry: FileTime(0),
            file_days: 0,
            backup_days: 0,
            held: false,
            interrupted: true,
            has_alert: false,
            file_until: never.clone(),
            backup_until: never,
        }
    }

    /// `journal.pending` lists a session the index shows as finished (its report was never written).
    pub(crate) fn mark_interrupted(&mut self) {
        self.interrupted = true;
        self.state = text::INTERRUPTED;
        self.chip = HistoryChip::Caution;
    }

    /// The timeline marker's second line.
    pub fn restorable(&self) -> String {
        if !self.held {
            text::NOTHING_TO_RESTORE.to_owned()
        } else if self.file_days > 0 {
            format!(
                "Files {} d · registry {} d",
                self.file_days, self.backup_days
            )
        } else {
            format!("Files expired · registry {} d", self.backup_days)
        }
    }

    /// The detail pane's expiry line.
    pub fn expiry(&self) -> String {
        if self.interrupted {
            text::NOT_RECORDED_COMPLETELY.to_owned()
        } else if !self.held {
            self.state.to_owned()
        } else {
            format!(
                "Files restorable until {} ({} days), registry and task backups until {}",
                self.file_until, self.file_days, self.backup_until
            )
        }
    }
}

/// The C# `FromFileTime`: 0, or a time past what a `DateTimeOffset` holds, is "never" (0 here).
fn valid(t: FileTime) -> FileTime {
    if t.0 > i64::MAX as u64 {
        FileTime(0)
    } else {
        t
    }
}

fn count(n: u32, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// One item of `history.get`, with its reconcile alert when there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// The wire item.
    pub source: HistoryItem,
    /// Its op.
    pub op: OpId,
    /// The name shown.
    pub display_name: String,
    /// What it is, in words.
    pub kind_text: &'static str,
    /// How it ended, in words.
    pub outcome_text: &'static str,
    /// The S5 mark: what reconcile found in quarantine in this item's place.
    pub alert_text: Option<String>,
    /// What Purge kept of the item was deleted for good (after its retention, or earlier at the
    /// user's request).
    pub is_deleted: bool,
    /// Only an item that changed something, is not back yet and still has its kept data can be
    /// ticked for "Restore selected": a deleted one cannot be put back.
    pub selectable: bool,
    /// Ticked for "Put back N selected".
    pub checked: bool,
}

impl HistoryEntry {
    /// The entry of one wire item.
    pub fn new(item: HistoryItem) -> Self {
        let outcome_text = if item.undone {
            text::PUT_BACK
        } else {
            match item.deleted {
                Some(Deleted::Early) => text::OUTCOME_DELETED_EARLY,
                Some(Deleted::Expired) => text::OUTCOME_DELETED_EXPIRED,
                None => outcome_words(&item.outcome),
            }
        };
        let selectable = !item.undone
            && item.deleted.is_none()
            && matches!(
                item.outcome,
                ItemOutcome::Done | ItemOutcome::PendingReboot { .. }
            );
        Self {
            op: item.op,
            display_name: item.display_name.clone(),
            kind_text: kind_words(item.kind),
            outcome_text,
            alert_text: item.alert.as_ref().map(broker_link::alert_text),
            is_deleted: item.deleted.is_some(),
            selectable,
            checked: false,
            source: item,
        }
    }

    /// Whether it carries a reconcile alert.
    pub fn has_alert(&self) -> bool {
        self.alert_text.is_some()
    }
}

fn kind_words(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Folder => "Folder",
        ItemKind::RegistryKey => "Registry key",
        ItemKind::RegistryValue => "Registry value",
        ItemKind::RegistryData => "Registry data",
        ItemKind::Service => "Service",
        ItemKind::Task => "Task",
        ItemKind::FirewallRule => "Firewall rule",
        ItemKind::Package => "Package",
        ItemKind::File => "File",
    }
}

fn outcome_words(outcome: &ItemOutcome) -> &'static str {
    match outcome {
        ItemOutcome::Done => "Moved to quarantine",
        ItemOutcome::Vanished => "Already gone",
        ItemOutcome::Skipped { .. } => "Skipped",
        ItemOutcome::HeldRetry => "Held, in use",
        ItemOutcome::PendingReboot { .. } => "Moved at the next restart",
        ItemOutcome::PendingDelete => "Removed at the next restart",
        ItemOutcome::Failed { .. } => "Failed",
    }
}
