//! What the History view draws (the logic of `HistoryView.xaml.cs`): the list and timeline rows
//! with their day headers, the detail pane, the state panel and the bars.

use super::{HistoryChip, HistoryModel, HistoryPhase, text};
use crate::info_bar::{InfoBar, Severity};
use crate::local_time::{Clock, LocalTime};

/// One row of the S4 list or the timeline strip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryRow {
    /// A day header ("Today", "Yesterday", "14 November", "14 November 2024").
    Day(String),
    /// The session at this index of [`HistoryModel::sessions`].
    Session(usize),
}

/// One session row as the list and the timeline marker draw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRowView {
    /// The app's name.
    pub title: String,
    /// `HH:mm`.
    pub time: String,
    /// The tile's letter: the name's first letter or digit, upper case, else `?`.
    pub initial: String,
    /// The count line.
    pub detail: String,
    /// The state in words.
    pub state: &'static str,
    /// The chip.
    pub chip: HistoryChip,
    /// Whether the alert mark shows (its tooltip is [`text::ALERT_TIP`]).
    pub alert: bool,
    /// The timeline marker's second line.
    pub mark_restorable: String,
    /// What a screen reader says for the timeline marker.
    pub mark_name: String,
}

/// The action a History bar carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HistoryBarAction {
    /// The recovery banner: two buttons, [`text::RESUME`] (`HistoryModel::recover(false)`) and
    /// [`text::ROLL_BACK`] (`HistoryModel::recover(true)`).
    Recover,
}

/// The detail pane of the selected session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryDetailPane {
    /// "Git · 15 Nov 2025 10:15".
    pub title: String,
    /// The count line.
    pub summary: String,
    /// The expiry line.
    pub expiry: String,
    /// "Show items" shows until the items are read.
    pub show_items_visible: bool,
    /// And can be clicked while no broker call runs.
    pub show_items_enabled: bool,
    /// "Put back N selected".
    pub restore_selected_text: String,
    /// Whether it can be clicked.
    pub restore_selected_enabled: bool,
    /// Whether "Put back all" can be clicked.
    pub restore_all_enabled: bool,
}

impl HistoryModel {
    /// The list rows: a header per local day (in the order the days first appear, newest first),
    /// then that day's sessions.
    pub fn rows(&self, clock: &Clock) -> Vec<HistoryRow> {
        let today = clock.today();
        let mut days: Vec<(i128, Vec<usize>)> = Vec::new();
        for (i, s) in self.sessions.iter().enumerate() {
            match days.iter_mut().find(|d| d.0 == s.local.day_number) {
                Some(day) => day.1.push(i),
                None => days.push((s.local.day_number, vec![i])),
            }
        }
        let mut rows = Vec::new();
        for (_, members) in days {
            let local = self.sessions[members[0]].local;
            rows.push(HistoryRow::Day(day_title(&local, &today)));
            rows.extend(members.into_iter().map(HistoryRow::Session));
        }
        rows
    }

    /// The timeline strip's rows: left to right, oldest day first and, within a day, oldest first.
    pub fn timeline(&self, clock: &Clock) -> Vec<HistoryRow> {
        let mut days: Vec<Vec<HistoryRow>> = Vec::new();
        for row in self.rows(clock) {
            match (&row, days.last_mut()) {
                (HistoryRow::Session(_), Some(day)) => day.push(row),
                _ => days.push(vec![row]),
            }
        }
        days.reverse();
        let started = |r: &HistoryRow| match r {
            HistoryRow::Session(i) => self.sessions[*i].started,
            HistoryRow::Day(_) => purge_model::FileTime(0),
        };
        days.into_iter()
            .flat_map(|mut day| {
                let mut rest = day.split_off(1.min(day.len()));
                rest.sort_by_key(|r| started(r));
                day.into_iter().chain(rest)
            })
            .collect()
    }

    /// A timeline day marker jumps to that day's first cleanup: the session a click on `row` of
    /// `timeline` selects.
    pub fn timeline_target(&self, timeline: &[HistoryRow], row: usize) -> Option<usize> {
        match timeline.get(row)? {
            HistoryRow::Session(i) => Some(*i),
            HistoryRow::Day(_) => timeline[row + 1..].iter().find_map(|r| match r {
                HistoryRow::Session(i) => Some(*i),
                HistoryRow::Day(_) => None,
            }),
        }
    }

    /// The session row at this index.
    pub fn session_row(&self, index: usize) -> Option<SessionRowView> {
        let s = self.sessions.get(index)?;
        let restorable = s.restorable();
        Some(SessionRowView {
            title: s.name.clone(),
            time: s.time.clone(),
            initial: initial(&s.name),
            detail: s.detail.clone(),
            state: s.state,
            chip: s.chip,
            alert: s.has_alert,
            mark_name: format!("{} {}, {}", s.name, s.time, restorable),
            mark_restorable: restorable,
        })
    }

    /// What a screen reader says for a list row.
    pub fn row_name(&self, row: &HistoryRow) -> String {
        match row {
            HistoryRow::Day(title) => title.clone(),
            HistoryRow::Session(i) => self
                .sessions
                .get(*i)
                .map(|s| format!("{}, {}, {}", s.name, s.time, s.state))
                .unwrap_or_default(),
        }
    }

    /// The state panel (shown unless the list is): title, text, and whether Retry shows.
    pub fn state_panel(&self) -> Option<(&'static str, String, bool)> {
        match self.phase {
            HistoryPhase::Loading => Some((text::READING_HISTORY, String::new(), false)),
            HistoryPhase::Empty => Some((text::NO_CLEANUPS, text::NO_CLEANUPS_TEXT.into(), false)),
            HistoryPhase::Error => Some((
                text::COULD_NOT_READ_HISTORY,
                self.error.clone().unwrap_or_default(),
                true,
            )),
            HistoryPhase::Ready => None,
        }
    }

    /// The detail pane of the selected session.
    pub fn detail(&self, clock: &Clock) -> Option<HistoryDetailPane> {
        let s = self.selected()?;
        let n = self.checked_count();
        Some(HistoryDetailPane {
            title: format!("{} · {}", s.name, clock.local(s.started).d_mmm_yyyy_hh_mm()),
            summary: s.detail.clone(),
            expiry: s.expiry(),
            show_items_visible: self.items.is_none(),
            show_items_enabled: !self.busy(),
            restore_selected_text: text::put_back_selected(n),
            restore_selected_enabled: n > 0 && self.can_restore(),
            restore_all_enabled: self.can_restore(),
        })
    }

    /// The bars above the page, in order. A declined or cancelled admin prompt is said by the
    /// page's own line (the action note), not the window's bar.
    pub fn bars(&self) -> Vec<InfoBar<HistoryBarAction>> {
        let mut bars = Vec::new();
        let selected = match self.phase {
            HistoryPhase::Ready => self.selected(),
            _ => None,
        };
        let Some(s) = selected else {
            // No cleanup chosen (or no list): the page's action still gets its answer.
            self.push_waiting(&mut bars);
            if let Some(info) = &self.action_info {
                bars.push(InfoBar::new(Severity::Informational, info, "", true));
            }
            self.push_error(&mut bars);
            return bars;
        };
        if s.interrupted && !self.busy() {
            bars.push(
                InfoBar::new(
                    Severity::Warning,
                    text::RECOVERY_TITLE,
                    text::RECOVERY_TEXT,
                    false,
                )
                .with_action(HistoryBarAction::Recover),
            );
        }
        self.push_waiting(&mut bars);
        if let Some(title) = self.restore_title {
            let severity = if self.restore_lines.is_empty() {
                Severity::Success
            } else {
                Severity::Warning
            };
            let mut parts = vec![self.action_info.clone().unwrap_or_default()];
            parts.extend(self.restore_lines.iter().cloned());
            bars.push(InfoBar::new(severity, title, parts.join(" ").trim(), true));
        } else if let Some(info) = &self.action_info {
            bars.push(InfoBar::new(Severity::Informational, info, "", true));
        }
        self.push_error(&mut bars);
        bars
    }

    fn push_waiting(&self, bars: &mut Vec<InfoBar<HistoryBarAction>>) {
        if let Some(waiting) = &self.waiting {
            bars.push(InfoBar::new(
                Severity::Informational,
                waiting,
                &self.waiting_detail,
                false,
            ));
        }
    }

    fn push_error(&self, bars: &mut Vec<InfoBar<HistoryBarAction>>) {
        if let Some(error) = &self.action_error {
            bars.push(InfoBar::new(
                Severity::Error,
                text::COULD_NOT_FINISH,
                error,
                true,
            ));
        }
    }
}

fn day_title(day: &LocalTime, today: &LocalTime) -> String {
    if day.day_number == today.day_number {
        text::TODAY.into()
    } else if day.day_number == today.day_number - 1 {
        text::YESTERDAY.into()
    } else if day.year == today.year {
        day.d_mmmm()
    } else {
        day.d_mmmm_yyyy()
    }
}

fn initial(name: &str) -> String {
    match name.chars().next() {
        Some(c) if c.is_alphanumeric() => c.to_uppercase().collect(),
        _ => "?".into(),
    }
}
