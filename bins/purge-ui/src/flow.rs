//! The uninstall flow's window state (UI-FLOW): the Uninstall page (`purge_ui_model::pipeline`'s
//! [`UninstallPage`]), the Leftovers page ([`LeftoversModel`]), the confirm dialog the pipeline
//! asks for, and the first-elevation explanation every broker launch goes through.
//!
//! The models decide; this holds them, the requests they made that `link` has still to send
//! ([`Flow::out`], [`Flow::lout`]), and what is open over the page. The actions the screens'
//! controls stand for are the `Model::flow_*` methods at the end, so `app` only maps an id to one.

use std::cell::Cell;
use std::collections::VecDeque;
use std::time::Instant;

use purge_rpc::methods::{ItemKind, RestorePoint};
use purge_ui_model::leftovers::{
    ItemLabel, LeftoversAction, LeftoversCall, LeftoversModel, LeftoversOptions,
};
use purge_ui_model::pipeline::page::{BarAction, BarClose, ConfirmButton, ConfirmDialog};
use purge_ui_model::pipeline::{PageRequest, UninstallConfirmation, UninstallPage};
use purge_ui_model::registry_label::RegistryLabel;

use crate::link::Owner;
use crate::model::{Model, Page};
use crate::screens::ARM_DELAY;

/// When a dialog was first drawn, kept with the dialog itself (review N5): a dialog made anew (a
/// confirmation that replaces the one open) starts unopened, and one never drawn is never armed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Opened(Cell<Option<Instant>>);

impl Opened {
    /// The dialog is drawn at `now`: the time it was first drawn.
    pub fn drawn(&self, now: Instant) -> Instant {
        let at = self.0.get().unwrap_or(now);
        self.0.set(Some(at));
        at
    }

    /// The dialog is not shown (another covers it): it waits its delay again when it is.
    pub fn reset(&self) {
        self.0.set(None);
    }

    /// Whether [`ARM_DELAY`] has passed at `now` since the dialog was first drawn; never for a
    /// dialog not drawn yet.
    pub fn armed(&self, now: Instant) -> bool {
        self.0
            .get()
            .is_some_and(|at| now.saturating_duration_since(at) >= ARM_DELAY)
    }
}

/// The confirm dialog while it is open: the model's content and its controls' positions.
#[derive(Debug, Clone)]
pub struct Confirm {
    pub dialog: ConfirmDialog,
    pub quiet_on: bool,
    pub restore_point: RestorePoint,
    /// When it was first drawn: its Uninstall waits [`ARM_DELAY`] after that.
    pub opened: Opened,
}

impl Confirm {
    pub fn new(confirmation: UninstallConfirmation) -> Confirm {
        let dialog = ConfirmDialog::new(confirmation);
        Confirm {
            quiet_on: dialog.quiet_on,
            restore_point: dialog.restore_point,
            dialog,
            opened: Opened::default(),
        }
    }

    /// The command line the dialog shows for the switch's position now.
    pub fn command(&self) -> &str {
        self.dialog.command_for(self.quiet_on)
    }
}

/// The first-elevation explanation (the port of `Shell/ElevationPrompts.cs`): shown before the
/// first Windows prompt of this run, whichever page asks for the broker. The pages that ask while
/// it is open wait their turn; the answer of each goes back to it through `link`.
#[derive(Debug, Default)]
pub struct Elevation {
    /// Shown and answered with Continue in this run (as the WinUI app kept it).
    pub explained: bool,
    /// The pages waiting for it, the shown one first, each with whether its launch only reads
    /// (the WinUI `LaunchIsReadOnly`: History's reads, never its restore or rollback).
    pub asking: VecDeque<(Owner, bool)>,
    /// The answers `link` has still to act on: Continue (true) or "Not now".
    pub answers: Vec<(Owner, bool)>,
}

impl Elevation {
    /// `owner` asks for the broker, for a launch that only reads (`read_only`) or not: true when
    /// it may launch now (explained already). A page that asks again while it waits keeps the
    /// words of a change once any of its asks was one.
    pub fn ask(&mut self, owner: Owner, read_only: bool) -> bool {
        if self.explained {
            return true;
        }
        match self.asking.iter_mut().find(|(o, _)| *o == owner) {
            Some((_, ro)) => *ro &= read_only,
            None => self.asking.push_back((owner, read_only)),
        }
        false
    }

    /// The page the dialog is open for.
    pub fn showing(&self) -> Option<Owner> {
        self.asking.front().map(|(o, _)| *o)
    }

    /// Whether the launch the dialog is open for only reads: its second paragraph says so.
    pub fn showing_read_only(&self) -> bool {
        self.asking.front().is_some_and(|(_, ro)| *ro)
    }

    /// The dialog's answer. After a Continue, the pages still waiting go on too: the explanation
    /// has been read.
    pub fn answer(&mut self, go: bool) {
        let Some((owner, _)) = self.asking.pop_front() else {
            return;
        };
        self.answers.push((owner, go));
        if go {
            self.explained = true;
            self.answers
                .extend(self.asking.drain(..).map(|(o, _)| (o, true)));
        }
    }
}

/// The question before one page's launch ends the broker session another page still holds work
/// in (S1). The hub holds one session where the WinUI app gave each page its own broker, so
/// the user decides: "End it" closes the holder's session and the launch goes on; "Not now"
/// leaves it and the asking page says the administrator part is in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Takeover {
    /// The page that asked for the broker.
    pub asking: Owner,
    /// The page whose session would end.
    pub holder: Owner,
    /// What the holder would lose, in a sentence.
    pub what: String,
    /// When it was first drawn: its "End it" waits [`ARM_DELAY`] after that.
    pub opened: Opened,
}

/// The two pages of the flow and what lies over them.
pub struct Flow {
    pub page: UninstallPage,
    /// The Uninstall page's requests `link` has still to send.
    pub out: Vec<PageRequest>,
    pub confirm: Option<Confirm>,
    /// The pipeline bars the user closed ([`BarClose::Hide`]), by title, until the page is
    /// left.
    pub hidden: Vec<String>,
    pub leftovers: LeftoversModel,
    /// The Leftovers page's calls `link` has still to send.
    pub lout: Vec<LeftoversCall>,
    /// The Leftovers bars the user closed, by title and message.
    pub closed_bars: Vec<(String, String)>,
    pub elevation: Elevation,
    /// The question before a launch ends another page's work, while it is open.
    pub takeover: Option<Takeover>,
    /// Its answer, which `link` has still to act on: "End it" (true) or "Not now".
    pub takeover_answer: Option<(Takeover, bool)>,
}

/// `RegistryLabel` as the Leftovers model's describer (registry rows in words).
fn describe(path: &str, kind: ItemKind, sid: Option<&str>) -> Option<ItemLabel> {
    RegistryLabel::describe(path, kind, sid).map(|l| ItemLabel {
        title: l.title,
        location: l.location,
    })
}

impl Flow {
    pub fn new() -> Flow {
        Flow {
            page: UninstallPage::new(),
            out: Vec::new(),
            confirm: None,
            hidden: Vec::new(),
            leftovers: LeftoversModel::new(Flow::options()),
            lout: Vec::new(),
            closed_bars: Vec::new(),
            elevation: Elevation::default(),
            takeover: None,
            takeover_answer: None,
        }
    }

    pub fn options() -> LeftoversOptions {
        LeftoversOptions {
            current_user_sid: None,
            can_relaunch: true,
            describe_label: Some(describe),
        }
    }

    pub fn take(&mut self, requests: Vec<PageRequest>) {
        self.out.extend(requests);
    }

    pub fn ltake(&mut self, calls: Vec<LeftoversCall>) {
        self.lout.extend(calls);
    }

    /// Something is open over the page: the confirmation, the explanation or the takeover
    /// question.
    pub fn dialog_open(&self) -> bool {
        self.confirm.is_some() || self.elevation.showing().is_some() || self.takeover.is_some()
    }
}

impl Default for Flow {
    fn default() -> Self {
        Self::new()
    }
}

// ---- the actions of the controls --------------------------------------------------------------

impl Model {
    /// The confirm dialog closed with `button`.
    pub fn flow_confirm(&mut self, button: ConfirmButton) {
        let Some(c) = self.flow.confirm.take() else {
            return;
        };
        if button == ConfirmButton::Uninstall && !c.dialog.can_uninstall(c.quiet_on) {
            // The dialog says the command is not known: it stays open.
            self.flow.confirm = Some(c);
            return;
        }
        let answer = c.dialog.answer(button, c.quiet_on, c.restore_point);
        let env = self.flow_env();
        let r = self.flow.page.answer(answer, env);
        self.flow.take(r);
    }

    /// The quiet switch: the dialog's while it is open, else the page's.
    pub fn flow_quiet(&mut self) {
        if let Some(c) = &mut self.flow.confirm {
            if c.dialog.quiet_enabled {
                c.quiet_on = !c.quiet_on;
            }
            return;
        }
        let v = self.flow.page.view(self.flow_env());
        if v.quiet_enabled {
            self.flow.page.set_quiet(!v.quiet_on);
        }
    }

    /// The restore-point box (its index: Off, high-risk only, always).
    pub fn flow_restore_point(&mut self, i: usize) {
        let rp = match i {
            0 => RestorePoint::Off,
            2 => RestorePoint::Always,
            _ => RestorePoint::HighRisk,
        };
        if let Some(c) = &mut self.flow.confirm {
            c.restore_point = rp;
            return;
        }
        if self.flow.page.view(self.flow_env()).restore_enabled {
            self.flow.page.set_restore_point(rp);
        }
    }

    /// The restore-point box's index now.
    pub fn flow_restore_index(&self) -> usize {
        let rp = match &self.flow.confirm {
            Some(c) => c.restore_point,
            None => self.flow.page.controller().restore_point(),
        };
        match rp {
            RestorePoint::Off => 0,
            RestorePoint::HighRisk => 1,
            RestorePoint::Always => 2,
        }
    }

    /// The button that does `action` on the Uninstall page's bar `bar`; nothing when that bar
    /// has no such button any more.
    pub fn flow_bar(&mut self, bar: usize, action: BarAction) {
        let env = self.flow_env();
        let bars = self.flow_bars();
        let Some(b) = bars
            .get(bar)
            .and_then(|b| b.buttons.iter().find(|b| b.action == action))
        else {
            return;
        };
        if !b.enabled {
            return;
        }
        let p = &mut self.flow.page;
        let r = match b.action {
            BarAction::Force => p.force(env),
            BarAction::Retry => p.retry(env),
            BarAction::StartOver => p.start_over(env),
            BarAction::ShowHeld => p.show_held(env),
            BarAction::ShowHanded => p.show_handed(),
        };
        self.flow.hidden.clear();
        self.flow.take(r);
    }

    /// The close button of the Uninstall page's bar `bar`.
    pub fn flow_close_bar(&mut self, bar: usize) {
        let bars = self.flow_bars();
        let Some(b) = bars.get(bar) else { return };
        match b.close {
            BarClose::No => {}
            BarClose::Hide => self.flow.hidden.push(b.title.clone()),
            BarClose::Handed => self.flow.page.dismiss_handed(),
            BarClose::Dropped => self.flow.page.dismiss_dropped(),
        }
    }

    /// The Uninstall page's bars the user has not closed.
    pub fn flow_bars(&self) -> Vec<purge_ui_model::pipeline::page::Bar> {
        let mut bars = self.flow.page.view(self.flow_env()).bars;
        bars.retain(|b| !(b.close == BarClose::Hide && self.flow.hidden.contains(&b.title)));
        bars
    }

    /// "Uninstall next" of the Next card.
    pub fn flow_next(&mut self) {
        let env = self.flow_env();
        let r = self.flow.page.uninstall_next(env);
        self.flow.take(r);
    }

    /// "Skip" of the Next card.
    pub fn flow_skip(&mut self) {
        let r = self.flow.page.skip_next();
        self.flow.take(r);
    }

    /// "Check again" of the running card.
    pub fn flow_recheck(&mut self) {
        let env = self.flow_env();
        let r = self.flow.page.recheck(env);
        self.flow.take(r);
    }

    /// The first-elevation explanation's Continue (true) or "Not now".
    pub fn flow_elevation(&mut self, go: bool) {
        self.flow.elevation.answer(go);
    }

    /// The takeover question's "End it" (true) or "Not now".
    pub fn flow_takeover(&mut self, end_it: bool) {
        if let Some(t) = self.flow.takeover.take() {
            self.flow.takeover_answer = Some((t, end_it));
        }
    }

    /// A bar action of the Leftovers page.
    pub fn flow_leftovers_action(&mut self, action: LeftoversAction) {
        match action {
            LeftoversAction::ScanAgain => {
                let r = self.flow.leftovers.rescan();
                self.flow.ltake(r);
            }
            LeftoversAction::ShowHeldScan => {
                let env = self.flow_env();
                let r = self.flow.page.show_held(env);
                self.flow.take(r);
            }
            LeftoversAction::GoToUninstall => self.page = Page::Pipeline,
        }
    }

    /// The Leftovers page's bars, as it shows them now (the closed ones left out).
    pub fn flow_leftovers_bars(&self) -> Vec<purge_ui_model::info_bar::InfoBar<LeftoversAction>> {
        let held = self.flow.page.held_program();
        let next = self.flow.page.queued_next();
        let mut bars = self.flow.leftovers.bars(held.as_deref(), next.as_deref());
        bars.retain(|b| {
            !(b.closable
                && self
                    .flow
                    .closed_bars
                    .iter()
                    .any(|(t, m)| *t == b.title && *m == b.message))
        });
        bars
    }

    /// Where the Leftovers page's "Done" goes: back to the Uninstall page when another program
    /// waits, else to Programs.
    pub fn flow_done_page(&self) -> Page {
        if self.flow.page.queued_next().is_some() {
            Page::Pipeline
        } else {
            Page::Programs
        }
    }

    /// The action button of the Leftovers page's bar `k`.
    pub fn flow_lbar(&mut self, k: usize) {
        if let Some(action) = self.flow_leftovers_bars().get(k).and_then(|b| b.action) {
            self.flow_leftovers_action(action);
        }
    }

    /// The close button of the Leftovers page's bar `k`: it stays closed while it says the same.
    pub fn flow_close_lbar(&mut self, k: usize) {
        if let Some(b) = self.flow_leftovers_bars().get(k).filter(|b| b.closable) {
            let seen = (b.title.clone(), b.message.clone());
            self.flow.closed_bars.push(seen);
        }
    }

    /// The page changed from `from`: the Uninstall page forgets the bars closed on it, and a scan
    /// the Uninstall page holds goes to the Leftovers page once the user left that page.
    pub fn flow_left(&mut self, from: Page) {
        if from == Page::Pipeline {
            self.flow.hidden.clear();
        }
        if from == Page::Leftovers {
            let env = self.flow_env();
            let r = self.flow.page.on_leftovers_left(env);
            self.flow.take(r);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_explanation_is_asked_once_and_its_continue_lets_the_waiting_pages_go() {
        let mut e = Elevation::default();
        assert!(!e.ask(Owner::Pipeline, false));
        assert!(!e.ask(Owner::Removed, false));
        assert!(!e.ask(Owner::Pipeline, false), "asked once");
        assert_eq!(e.showing(), Some(Owner::Pipeline));
        e.answer(true);
        assert_eq!(
            e.answers,
            vec![(Owner::Pipeline, true), (Owner::Removed, true)]
        );
        assert!(e.showing().is_none());
        assert!(e.ask(Owner::Leftovers, false), "explained: no dialog again");
    }

    #[test]
    fn not_now_answers_only_the_page_it_was_shown_for() {
        let mut e = Elevation::default();
        e.ask(Owner::Removed, false);
        e.ask(Owner::Pipeline, false);
        e.answer(false);
        assert_eq!(e.answers, vec![(Owner::Removed, false)]);
        assert_eq!(e.showing(), Some(Owner::Pipeline), "the next one is asked");
        assert!(!e.explained);
    }

    #[test]
    fn the_explanation_says_only_reads_for_a_read_and_never_for_a_change() {
        let mut e = Elevation::default();
        e.ask(Owner::History, true);
        assert!(e.showing_read_only(), "History's read");
        e.ask(Owner::History, false);
        assert!(
            !e.showing_read_only(),
            "a restore asked meanwhile: the words of a change"
        );
        let mut e = Elevation::default();
        e.ask(Owner::History, false);
        assert!(!e.showing_read_only(), "History's restore or rollback");
    }

    /// Review N5: the delay runs from the dialog's own first drawing, by the clock: one never
    /// drawn is never armed, and a covered one waits again.
    #[test]
    fn a_dialog_is_armed_only_its_delay_after_it_was_first_drawn() {
        let t0 = Instant::now();
        let opened = Opened::default();
        assert!(!opened.armed(t0 + ARM_DELAY * 10), "never drawn");
        assert_eq!(opened.drawn(t0), t0);
        assert_eq!(opened.drawn(t0 + ARM_DELAY), t0, "the first drawing counts");
        assert!(!opened.armed(t0 + ARM_DELAY / 2));
        assert!(opened.armed(t0 + ARM_DELAY));
        opened.reset();
        assert!(!opened.armed(t0 + ARM_DELAY * 2));
        let t1 = t0 + ARM_DELAY * 2;
        opened.drawn(t1);
        assert!(!opened.armed(t1 + ARM_DELAY / 2));
        assert!(opened.armed(t1 + ARM_DELAY));
    }

    #[test]
    fn registry_rows_are_described_in_words() {
        let label = describe(r"HKLM\SOFTWARE\Vendor\App", ItemKind::RegistryKey, None);
        assert!(label.is_some());
        assert!(describe(r"C:\x", ItemKind::Folder, None).is_none());
    }
}
