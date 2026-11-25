//! What the Leftovers view draws, computed from the model: the flattened list (the port of
//! `LeftoversRow.cs`), the detail pane, the band chips and bar, the footer and the bars
//! (`LeftoversView.xaml.cs`). Plain values; the view only lays them out.

use purge_rpc::methods::{CandidateRef, ItemKind};

use super::item::{LeftoverItem, Look, format_size};
use super::{LeftoversModel, LeftoversPhase, text};
use crate::info_bar::{InfoBar, Severity};

/// One row of the flattened, virtualized list (design 9.4): a group header or a candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftoversRow {
    /// A group header; `hidden` is how many of its rows the list hides (weak matches).
    Group {
        /// The group's index in [`LeftoversModel::groups`].
        group: usize,
        /// Its rows the list hides.
        hidden: usize,
    },
    /// A candidate: its index in [`LeftoversModel::items`].
    Item(usize),
}

/// A group header as drawn.
#[derive(Debug, Clone, PartialEq)]
pub struct GroupHeader {
    /// Its name.
    pub name: String,
    /// The rows the list shows under it, and how many it hides ("4" never heads 3 rows).
    pub count_text: String,
    /// The box: ticked, unticked, or `None` for some ticked.
    pub checked: Option<bool>,
    /// The share of its items that are ticked, 0 to 1 (the WinUI bar is 120 px at 1).
    pub bar_fraction: f64,
    /// "n of m selected".
    pub bar_tip: String,
    /// Its bytes, or "n of m" when it has none.
    pub size_text: String,
    /// Whether its rows are shown (the chevron).
    pub expanded: bool,
    /// Every list group with something tickable has a box, so the headers look alike.
    pub tick_visible: bool,
    /// The box works only where the group holds Safe items: a group box ticks Safe items only.
    pub tick_enabled: bool,
    /// Why a box is disabled; `None` when it is enabled.
    pub tick_tip: Option<&'static str>,
    /// A section (Protected, report only).
    pub is_section: bool,
}

/// A candidate row as drawn.
#[derive(Debug, Clone, PartialEq)]
pub struct ItemRow {
    /// The candidate.
    pub candidate_id: CandidateRef,
    /// The main line: a registry item in words, else the raw name.
    pub title: String,
    /// The location line of a labelled row; empty otherwise.
    pub location: String,
    /// A registry item with a label: title, location, and the raw path as tooltip.
    pub labelled: bool,
    /// The exact path on hover; `None` for rows that already show it.
    pub raw_tip: Option<String>,
    /// The reason line.
    pub why: String,
    /// Its size, or empty.
    pub size_text: String,
    /// "Shared with …", or empty.
    pub owner_text: String,
    /// 0.6 for a Protected row, else 1.
    pub path_opacity: f64,
    /// Its tick.
    pub checked: bool,
    /// Whether it has a box (selectable rows only).
    pub check_visible: bool,
    /// Its band chip.
    pub look: Look,
    /// The lock glyph and "Protected" chip.
    pub protected: bool,
    /// The user-data chip.
    pub user_data: bool,
    /// The attention mark.
    pub attention: bool,
    /// The refused mark and its text.
    pub refused: bool,
    /// "Cannot be quarantined: …", or empty.
    pub refusal_text: String,
    /// The first warning's text, or empty.
    pub warning_text: String,
}

/// The glyph of an evidence line: ● explicit, ○ note, ⚠ warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceGlyph {
    /// ● in green.
    Explicit,
    /// ○ in grey.
    Note,
    /// ⚠ in red.
    Warning,
}

impl EvidenceGlyph {
    /// The character.
    pub fn glyph(self) -> &'static str {
        match self {
            EvidenceGlyph::Explicit => "\u{25CF}",
            EvidenceGlyph::Note => "\u{25CB}",
            EvidenceGlyph::Warning => "\u{26A0}",
        }
    }
}

/// One line of evidence in the detail pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceLine {
    /// Its glyph.
    pub glyph: EvidenceGlyph,
    /// Its text.
    pub text: String,
}

/// The detail pane of the selected candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailPane {
    /// The label's title, for a labelled registry row.
    pub title: Option<String>,
    /// The raw name.
    pub path: String,
    /// Its band chip.
    pub look: Look,
    /// The Protected chip.
    pub protected: bool,
    /// The user-data chip.
    pub user_data: bool,
    /// Ticked, not ticked, never removed, cannot be quarantined.
    pub preselect: &'static str,
    /// "Cannot be quarantined: …" for a refused item.
    pub refused: Option<String>,
    /// Blockers, then evidence; a band line when there is neither.
    pub evidence: Vec<EvidenceLine>,
    /// Its size, or "—".
    pub contents: String,
    /// What happens to it.
    pub if_removed: String,
    /// What it is and what it belongs to.
    pub found_by: String,
    /// "Shared with ….", for an item another program shares.
    pub owner: Option<String>,
}

/// The band chips and bar above the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BandSummary {
    /// Safe items.
    pub safe: usize,
    /// Likely and weak items.
    pub likely: usize,
    /// Protected items.
    pub protected: usize,
    /// "Safe n · size".
    pub safe_text: String,
    /// "Likely n · size".
    pub likely_text: String,
    /// "Protected n".
    pub protected_text: String,
}

/// The footer: counts, the verdict, the Move button and the delete-after box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Footer {
    /// "n of m selected" (AutomationId `FooterCount`).
    pub count: String,
    /// "n items · size".
    pub verdict: String,
    /// " · size, n file items, ...".
    pub detail: String,
    /// The Move button works (a sample never moves anything).
    pub move_enabled: bool,
    /// Its words (AutomationId `MoveText`).
    pub move_text: String,
    /// Its tooltip, for the sample.
    pub move_tip: Option<&'static str>,
    /// The delete-after box's words.
    pub delete_after_text: &'static str,
    /// Its tooltip.
    pub delete_after_help: &'static str,
    /// Its tick.
    pub delete_after: bool,
    /// Whether it works (not on the sample).
    pub delete_after_enabled: bool,
    /// The hint next to the button.
    pub hint: &'static str,
}

/// A bar's button on the Leftovers page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeftoversAction {
    /// "Scan again" ([`LeftoversModel::rescan`]).
    ScanAgain,
    /// "Show the scan": the shell shows the scan the Uninstall page holds.
    ShowHeldScan,
    /// "Go to Uninstall".
    GoToUninstall,
}

impl LeftoversAction {
    /// The button's words.
    pub fn text(self) -> &'static str {
        match self {
            LeftoversAction::ScanAgain => text::BAR_SCAN_AGAIN,
            LeftoversAction::ShowHeldScan => text::BAR_SHOW_SCAN,
            LeftoversAction::GoToUninstall => text::BAR_GO_UNINSTALL,
        }
    }
}

impl LeftoversModel {
    /// The list's rows: every visible group's header, then its visible rows when it is expanded.
    pub fn rows(&self) -> Vec<LeftoversRow> {
        let mut rows = Vec::new();
        for group in self.visible_groups() {
            rows.push(LeftoversRow::Group {
                group,
                hidden: self.hidden_count(group),
            });
            if self.groups[group].expanded {
                rows.extend(
                    self.visible_items(group)
                        .into_iter()
                        .map(LeftoversRow::Item),
                );
            }
        }
        rows
    }

    /// A group header as drawn; `hidden` from its row.
    pub fn group_header(&self, group: usize, hidden: usize) -> Option<GroupHeader> {
        let g = self.groups.get(group)?;
        let members: Vec<&LeftoverItem> = g.items.iter().map(|&i| &self.items[i]).collect();
        let checked_count = members.iter().filter(|i| i.checked).count();
        let can_tick = self.group_can_tick(group);
        let selectable: Vec<&&LeftoverItem> = members.iter().filter(|i| i.selectable()).collect();
        let checked = if !can_tick || selectable.is_empty() {
            Some(false)
        } else if selectable.iter().all(|i| i.checked) {
            Some(true)
        } else if selectable.iter().any(|i| i.checked) {
            None
        } else {
            Some(false)
        };
        let bytes = self.group_bytes(group);
        Some(GroupHeader {
            name: g.name.clone(),
            count_text: text::group_count(members.len().saturating_sub(hidden), hidden),
            checked,
            bar_fraction: if members.is_empty() {
                0.0
            } else {
                checked_count as f64 / members.len() as f64
            },
            bar_tip: text::of_selected(checked_count, members.len()),
            size_text: if bytes > 0 {
                format_size(bytes)
            } else {
                text::of(checked_count, members.len())
            },
            expanded: g.expanded,
            tick_visible: !g.is_section && members.iter().any(|i| i.selectable()),
            tick_enabled: can_tick,
            tick_tip: (!can_tick).then_some(text::GROUP_TICK_TIP),
            is_section: g.is_section,
        })
    }

    /// A candidate row as drawn.
    pub fn item_row(&self, index: usize) -> Option<ItemRow> {
        let item = self.items.get(index)?;
        let labelled = item.label.is_some();
        Some(ItemRow {
            candidate_id: item.candidate_id,
            title: item.title().to_owned(),
            location: item.location().to_owned(),
            labelled,
            raw_tip: labelled.then(|| item.display_name.clone()),
            why: item.why().to_owned(),
            size_text: item.size_text(),
            owner_text: match &item.owner_program {
                Some(owner) if !owner.is_empty() => format!("{}{owner}", text::SHARED_WITH),
                _ => String::new(),
            },
            path_opacity: if item.is_protected() { 0.6 } else { 1.0 },
            checked: item.checked,
            check_visible: item.selectable(),
            look: item.look,
            protected: item.is_protected(),
            user_data: item.is_user_data(),
            attention: item.attention,
            refused: item.refused,
            refusal_text: if item.refused {
                format!("{}{}", text::CANNOT_QUARANTINE, item.refusal_reason)
            } else {
                String::new()
            },
            warning_text: item
                .warnings
                .first()
                .map(|w| w.message.clone())
                .unwrap_or_default(),
        })
    }

    /// What a screen reader says for a row: the group and its count, or the item, its rating and
    /// whether it is ticked.
    pub fn row_name(&self, row: LeftoversRow) -> String {
        match row {
            LeftoversRow::Group { group, hidden } => self
                .group_header(group, hidden)
                .map(|h| format!("{}, {}", h.name, h.count_text))
                .unwrap_or_default(),
            LeftoversRow::Item(index) => {
                let Some(item) = self.items.get(index) else {
                    return String::new();
                };
                let band = if item.is_protected() {
                    text::BAND_PROTECTED
                } else {
                    item.look.word()
                };
                let state = if !item.selectable() {
                    text::CANNOT_BE_TICKED
                } else if item.checked {
                    text::A11Y_TICKED
                } else {
                    text::A11Y_NOT_TICKED
                };
                let user_data = if item.is_user_data() {
                    text::A11Y_USER_DATA
                } else {
                    ""
                };
                format!("{}, {band}{user_data}, {state}", item.title())
            }
        }
    }

    /// The detail pane of the selected candidate.
    pub fn detail(&self) -> Option<DetailPane> {
        let item = self.item(self.selected.as_ref()?)?;
        let mut evidence: Vec<EvidenceLine> = item
            .blockers
            .iter()
            .map(|b| line(EvidenceGlyph::Warning, b))
            .chain(
                item.evidence
                    .iter()
                    .map(|e| line(EvidenceGlyph::Explicit, e)),
            )
            .collect();
        if evidence.is_empty() {
            evidence.push(match item.look {
                Look::Protected => line(EvidenceGlyph::Note, item.why()),
                Look::Weak => line(EvidenceGlyph::Note, text::WEAK_NOTE),
                _ => line(EvidenceGlyph::Explicit, item.why()),
            });
        }
        let refusal = format!("{}{}", text::CANNOT_QUARANTINE, item.refusal_reason);
        let size = item.size_text();
        Some(DetailPane {
            title: item.label.as_ref().map(|l| l.title.clone()),
            path: item.display_name.clone(),
            look: item.look,
            protected: item.is_protected(),
            user_data: item.is_user_data(),
            preselect: if item.is_protected() {
                text::NEVER_REMOVED
            } else if item.refused {
                text::CANNOT_BE_QUARANTINED
            } else if item.checked {
                text::TICKED
            } else {
                text::NOT_TICKED
            },
            refused: item.refused.then(|| refusal.clone()),
            evidence,
            contents: if size.is_empty() {
                text::NO_CONTENTS.into()
            } else {
                size
            },
            if_removed: if item.is_protected() {
                text::NEVER_REMOVES_IT.into()
            } else if item.refused {
                refusal
            } else {
                text::MOVED_RESTORABLE.into()
            },
            found_by: item.kind_text(),
            owner: match &item.owner_program {
                Some(owner) if !owner.is_empty() => Some(format!("{}{owner}.", text::SHARED_WITH)),
                _ => None,
            },
        })
    }

    /// The band chips and bar.
    pub fn band_summary(&self) -> BandSummary {
        let sum = |looks: &[Look]| -> u64 {
            self.items
                .iter()
                .filter(|i| looks.contains(&i.look))
                .map(|i| i.size_bytes.unwrap_or(0))
                .sum()
        };
        let count = |looks: &[Look]| {
            self.items
                .iter()
                .filter(|i| looks.contains(&i.look))
                .count()
        };
        let (safe, likely, protected) = (
            count(&[Look::Safe]),
            count(&[Look::Likely, Look::Weak]),
            count(&[Look::Protected]),
        );
        BandSummary {
            safe,
            likely,
            protected,
            safe_text: format!("Safe {safe} · {}", format_size(sum(&[Look::Safe]))),
            likely_text: format!(
                "Likely {likely} · {}",
                format_size(sum(&[Look::Likely, Look::Weak]))
            ),
            protected_text: format!("Protected {protected}"),
        }
    }

    /// The footer.
    pub fn footer(&self) -> Footer {
        let selected = self.selected_count();
        let bytes = format_size(self.selected_bytes());
        let chosen: Vec<&LeftoverItem> = self.chosen().collect();
        let kinds = |kinds: &[ItemKind]| chosen.iter().filter(|i| kinds.contains(&i.kind)).count();
        let mut parts = vec![bytes.clone()];
        for (n, (one, many)) in [
            (kinds(&[ItemKind::File, ItemKind::Folder]), text::FILE_ITEM),
            (
                kinds(&[
                    ItemKind::RegistryKey,
                    ItemKind::RegistryValue,
                    ItemKind::RegistryData,
                ]),
                text::REGISTRY_ITEM,
            ),
            (
                kinds(&[ItemKind::Task, ItemKind::Service, ItemKind::FirewallRule]),
                text::TASK_ITEM,
            ),
        ] {
            if n > 0 {
                parts.push(text::part(n, one, many));
            }
        }
        Footer {
            count: text::of_selected(selected, self.selectable_count()),
            verdict: text::verdict(selected, &bytes),
            detail: format!(" · {}", parts.join(", ")),
            move_enabled: self.can_move() && !self.is_sample,
            move_text: self.move_text(),
            move_tip: self.is_sample.then_some(text::SAMPLE_MOVE_TIP),
            delete_after_text: text::DELETE_AFTER_TEXT,
            delete_after_help: text::DELETE_AFTER_HELP,
            delete_after: self.delete_after,
            delete_after_enabled: !self.is_sample,
            hint: if self.is_sample {
                text::SAMPLE_HINT
            } else if self.delete_after {
                text::TWO_PROMPTS_HINT
            } else {
                text::ONE_PROMPT_HINT
            },
        }
    }

    /// The bars above the page, in order. `held_scan` names the program whose scan the Uninstall
    /// page holds for this page; `queued_next` the next program "Uninstall N" queued (shown only
    /// while no scan is held).
    pub fn bars(
        &self,
        held_scan: Option<&str>,
        queued_next: Option<&str>,
    ) -> Vec<InfoBar<LeftoversAction>> {
        let mut bars = Vec::new();
        if let Some(name) = held_scan {
            // It does not replace a change's outcome on screen: it says when it comes.
            let changing = self.is_changing();
            let bar = InfoBar::new(
                Severity::Informational,
                text::bar_held_title(name),
                if changing {
                    text::BAR_HELD_CHANGING
                } else {
                    text::BAR_HELD_IDLE
                },
                false,
            );
            bars.push(if changing {
                bar
            } else {
                bar.with_action(LeftoversAction::ShowHeldScan)
            });
        } else if let Some(next) = queued_next {
            bars.push(
                InfoBar::new(
                    Severity::Informational,
                    text::bar_next_title(next),
                    text::BAR_NEXT_TEXT,
                    true,
                )
                .with_action(LeftoversAction::GoToUninstall),
            );
        }
        if let Some(error) = self.error.as_deref().filter(|e| !e.is_empty()) {
            bars.push(InfoBar::new(
                Severity::Error,
                text::BAR_REFUSED_OR_FAILED,
                error,
                true,
            ));
        } else if let Some(info) = self.info.as_deref().filter(|i| !i.is_empty()) {
            bars.push(InfoBar::new(Severity::Informational, "", info, true));
        }
        if !self.refusal_lines.is_empty() {
            let mut message = self
                .refusal_lines
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join(" · ");
            if self.refusal_lines.len() > 5 {
                message.push_str(&text::and_more(self.refusal_lines.len() - 5));
            }
            bars.push(InfoBar::new(
                Severity::Warning,
                text::BAR_SOME_REFUSED,
                message,
                true,
            ));
        }
        if self.rescan_offered {
            bars.push(
                InfoBar::new(
                    Severity::Informational,
                    text::BAR_BASELINE_TITLE,
                    text::BAR_BASELINE_TEXT,
                    true,
                )
                .with_action(LeftoversAction::ScanAgain),
            );
        }
        if let Some(rescan) = self.rescan_message.as_deref().filter(|m| !m.is_empty()) {
            bars.push(InfoBar::new(
                Severity::Success,
                text::BAR_RESCANNED,
                rescan,
                true,
            ));
        }
        if self.phase == LeftoversPhase::Review && self.is_sample {
            bars.push(InfoBar::new(
                Severity::Informational,
                text::BAR_SAMPLE_TITLE,
                text::BAR_SAMPLE_TEXT,
                true,
            ));
        } else if self.phase == LeftoversPhase::Review && self.is_forced() {
            // A forced scan ticks nothing on purpose (engine rule): say so.
            bars.push(InfoBar::new(
                Severity::Informational,
                text::BAR_FORCED_TITLE,
                text::BAR_FORCED_TEXT,
                true,
            ));
        }
        bars
    }
}

fn line(glyph: EvidenceGlyph, text: &str) -> EvidenceLine {
    EvidenceLine {
        glyph,
        text: text.to_owned(),
    }
}
