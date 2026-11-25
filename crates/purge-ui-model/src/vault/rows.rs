//! What the vault view draws (`VaultRows.cs` and the logic of `VaultView.xaml.cs`): the cleanup
//! rows, the item panel, the "Delete now" choice, the "Review and delete…" button and the bars.

use purge_model::exec::session::SessionId;

use super::{VaultChip, VaultModel, VaultPhase, text};
use crate::info_bar::{InfoBar, Severity};

/// One cleanup row as the list draws it.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchRowView {
    /// The app's name.
    pub name: String,
    /// The tile's letter: the name's first letter or digit, upper case, else `?`.
    pub initial: String,
    /// "Today 10:15" or "15 Nov 10:15".
    pub when: String,
    /// "21 items · 1.2 MB on C:\".
    pub summary: String,
    /// The retention line.
    pub detail: String,
    /// The state in words.
    pub state: &'static str,
    /// The chip.
    pub chip: VaultChip,
    /// The ring's fill, 0 to 100.
    pub ring: f64,
    /// The days in the ring.
    pub days_text: String,
    /// "day" or "days".
    pub days_caption: &'static str,
    /// "Put back…", or "Undo registry changes…" once only registry backups are left.
    pub restore_text: &'static str,
    /// "Delete now" is offered while the cleanup still has files in quarantine, or registry
    /// backups (those only with the tick of its choice).
    pub delete_visible: bool,
    /// "Choose items" lists quarantined files only: a backup belongs to a registry change.
    pub choose_visible: bool,
    /// False while a broker action runs: the row's actions are disabled, not just ignored.
    pub can_act: bool,
    /// What a screen reader says for the row.
    pub accessible_name: String,
}

/// The "Delete now" flyout of one cleanup. The page asks one thing of its own, whether the
/// registry backups go too (off each time it opens); the broker's prompts are the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteNowChoice {
    /// The text above the tick box.
    pub intro: &'static str,
    /// Whether the tick box shows ([`text::ALSO_BACKUPS_TEXT`]).
    pub offers_backups: bool,
    /// Whether "Continue to the security prompt…" can be clicked with the box unticked.
    pub can_continue_unticked: bool,
    /// And with it ticked.
    pub can_continue_ticked: bool,
}

/// "Review and delete…" on the page header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewButton {
    /// Whether it can be clicked.
    pub enabled: bool,
    /// Why it is off (on its host: a disabled button shows no tooltip).
    pub tooltip: Option<&'static str>,
}

/// The action a vault bar carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaultBarAction {
    /// "Open History & undo".
    OpenHistory,
    /// "Review and delete…" ([`VaultModel::review_expired`]).
    Review,
}

impl VaultBarAction {
    /// The button's text.
    pub fn text(self) -> &'static str {
        match self {
            VaultBarAction::OpenHistory => text::OPEN_HISTORY,
            VaultBarAction::Review => text::REVIEW_AND_DELETE,
        }
    }
}

impl VaultModel {
    /// The row of the cleanup at this index.
    pub fn batch_row(&self, index: usize) -> Option<BatchRowView> {
        let b = self.batches.get(index)?;
        Some(BatchRowView {
            name: b.name.clone(),
            initial: match b.name.chars().next() {
                Some(c) if c.is_alphanumeric() => c.to_uppercase().collect(),
                _ => "?".into(),
            },
            when: b.when.clone(),
            summary: b.summary.clone(),
            detail: b.detail.clone(),
            state: b.state,
            chip: b.chip(),
            ring: b.ring_percent,
            days_text: b.days_left_shown.to_string(),
            days_caption: if b.days_left_shown == 1 {
                "day"
            } else {
                "days"
            },
            restore_text: if b.registry_only {
                text::UNDO_REGISTRY
            } else {
                text::PUT_BACK
            },
            delete_visible: b.can_delete_now(true),
            choose_visible: !b.files_purged,
            can_act: !self.busy(),
            accessible_name: format!("{}, {}, {}", b.name, b.when, b.state),
        })
    }

    /// The "Delete now" choice of a cleanup.
    pub fn delete_now_choice(&self, session: &SessionId) -> Option<DeleteNowChoice> {
        let b = self.batch(session)?;
        Some(DeleteNowChoice {
            intro: b.delete_now_intro(),
            offers_backups: b.can_delete_backups(),
            can_continue_unticked: b.can_delete_now(false),
            can_continue_ticked: b.can_delete_now(true),
        })
    }

    /// The item panel's title, while "Choose items…" lists a cleanup.
    pub fn items_title(&self) -> Option<String> {
        self.items_for
            .as_ref()
            .map(|_| format!("In quarantine from {}", self.items_name))
    }

    /// Whether an item row's "Delete now" can be clicked (not while a broker action runs).
    pub fn items_can_act(&self) -> bool {
        !self.busy()
    }

    /// "Review and delete…".
    pub fn review_button(&self) -> ReviewButton {
        let enabled = !self.busy() && self.expired_batches().next().is_some();
        ReviewButton {
            enabled,
            tooltip: if enabled {
                None
            } else if self.busy() {
                Some(text::REVIEW_WAIT)
            } else {
                Some(text::REVIEW_NOTHING)
            },
        }
    }

    /// Whether the empty card shows.
    pub fn shows_empty_card(&self) -> bool {
        self.phase == VaultPhase::Empty
    }

    /// The bars above the page, in order. None can be closed. A declined or cancelled admin prompt
    /// is said by the page's own line (the action note), not the window's bar.
    pub fn bars(&self) -> Vec<InfoBar<VaultBarAction>> {
        let mut bars = Vec::new();
        match self.phase {
            VaultPhase::Loading => bars.push(InfoBar::new(
                Severity::Informational,
                text::READING_QUARANTINE,
                "",
                false,
            )),
            VaultPhase::Error => bars.push(InfoBar::new(
                Severity::Error,
                text::COULD_NOT_READ_QUARANTINE,
                self.error.clone().unwrap_or_default(),
                false,
            )),
            _ => {}
        }
        if self.interrupted > 0 {
            bars.push(
                InfoBar::new(
                    Severity::Warning,
                    text::INTERRUPTED_TITLE,
                    text::INTERRUPTED_TEXT,
                    false,
                )
                .with_action(VaultBarAction::OpenHistory),
            );
        }
        let expired = self.expired_batches().count();
        if expired > 0 && !self.busy() {
            bars.push(
                InfoBar::new(
                    Severity::Warning,
                    text::expired_title(expired),
                    text::EXPIRED_TEXT,
                    false,
                )
                .with_action(VaultBarAction::Review),
            );
        }
        if let Some(waiting) = &self.waiting {
            bars.push(InfoBar::new(
                Severity::Informational,
                waiting,
                text::NOTHING_CHANGED_YET,
                false,
            ));
        }
        if let Some(title) = &self.result_title {
            let severity = if self.action_info.is_none() {
                Severity::Success
            } else {
                Severity::Warning
            };
            bars.push(InfoBar::new(
                severity,
                title,
                self.action_info.clone().unwrap_or_default(),
                false,
            ));
        } else if let Some(info) = &self.action_info {
            bars.push(InfoBar::new(Severity::Informational, info, "", false));
        }
        if let Some(error) = &self.action_error {
            bars.push(InfoBar::new(
                Severity::Error,
                text::COULD_NOT_FINISH,
                error,
                false,
            ));
        }
        bars
    }
}
