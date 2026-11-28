//! The toolkit dialog's state and its rules, pure: what is ticked, what has been seen, where the
//! keyboard is, and the one function that can answer [`Outcome::Approved`]. The window
//! ([`super::app`]) turns the pointer, the keys and UI Automation's requests into calls here, with the
//! time it read; nothing here reads a clock, draws or knows a window.
//!
//! The rules (the TaskDialog's, design 8.1):
//!
//! - Cancel has the keyboard when the dialog opens. Enter and Space press what has the keyboard, so on
//!   open they cancel. Esc cancels wherever the keyboard is.
//! - The button that approves is pressed only when it is enabled, and it is enabled only when all of
//!   these hold at the moment of the press, by the clock: the dialog has been on screen for
//!   [`ARM_DELAY`]; the end of the list has been on screen for [`ARM_DELAY`] (the TaskDialog has the
//!   button on its last page only, and starts the delay again when that page shows); and the
//!   verification box, when there is one, is ticked.
//! - The verification box is ticked only once the end of the list has been on screen: the
//!   TaskDialog clears it when the last page shows, so that it cannot be ticked before anything was
//!   read (review S6).
//! - A press before the dialog is on screen does nothing, whatever it is on, except that a cancel is
//!   always taken.
//! - A key the system repeats because it is held never presses a button.
//! - A click is a press and a release on the same control. On the button that approves, the button
//!   must have been enabled when the pointer went down too: a press that began on the disabled button
//!   and is let go after it armed presses nothing.

use std::sync::Arc;
use std::time::{Duration, Instant};

use mdshared_ui::keys::{KeyName, Mods};
use purge_win::taskdialog::Outcome;

use super::super::sheet::Sheet;

/// How long the button that approves stays disabled after the dialog is first on screen, and after
/// the end of its list is: the TaskDialog's delay (review M3-R1 S6), so that a click aimed at
/// another window, or at the list that was just scrolled, cannot land on it.
pub const ARM_DELAY: Duration = Duration::from_secs(1);

/// The controls of the dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ctl {
    /// The verification box.
    Verify,
    /// The button that approves.
    Approve,
    /// Cancel.
    Cancel,
    /// The close button of the title row: Cancel.
    Close,
}

/// How far a key moves the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scroll {
    /// Lines up or down (negative is up).
    Lines(i32),
    /// Screens up or down.
    Pages(i32),
    /// To the top.
    Top,
    /// To the end.
    End,
}

/// What an input did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Did {
    /// Nothing the window has to show.
    Nothing,
    /// Something changed: draw again.
    Changed,
    /// The list is to move.
    Scroll(Scroll),
    /// The dialog is answered.
    Answered(Outcome),
}

/// One dialog, from its first frame to its answer.
#[derive(Debug, Clone)]
pub struct Prompt {
    sheet: Arc<Sheet>,
    opened: Option<Instant>,
    ticked: bool,
    /// When the end of the list was first on screen.
    seen_end: Option<Instant>,
    focus: Ctl,
    ring: bool,
    /// The control a held press of the pointer began on, when a click may come of it.
    held: Option<Ctl>,
    answer: Option<Outcome>,
}

impl Prompt {
    /// A dialog for `sheet` that is not on screen yet: Cancel has the keyboard and shows it.
    pub fn new(sheet: Arc<Sheet>) -> Prompt {
        Prompt {
            sheet,
            opened: None,
            ticked: false,
            seen_end: None,
            focus: Ctl::Cancel,
            ring: true,
            held: None,
            answer: None,
        }
    }

    /// What the dialog says.
    pub fn sheet(&self) -> &Arc<Sheet> {
        &self.sheet
    }

    /// The dialog is on screen at `now`. The first call starts the arming delay; later ones change
    /// nothing. Returns whether this was the first.
    pub fn opened(&mut self, now: Instant) -> bool {
        if self.opened.is_some() {
            return false;
        }
        self.opened = Some(now);
        true
    }

    /// When the dialog was first on screen.
    pub fn opened_at(&self) -> Option<Instant> {
        self.opened
    }

    /// The end of the list is on screen at `now`. Counts only once the dialog itself is. The first
    /// call starts the delay of the end; later ones change nothing. Returns whether this was the
    /// first.
    pub fn saw_end(&mut self, now: Instant) -> bool {
        let Some(opened) = self.opened else {
            return false;
        };
        if self.seen_end.is_some() {
            return false;
        }
        // Never before the dialog: a clock read earlier than the one that opened it changes nothing.
        self.seen_end = Some(now.max(opened));
        true
    }

    /// Whether the end of the list has been on screen.
    pub fn seen_end(&self) -> bool {
        self.seen_end.is_some()
    }

    /// Whether the box is ticked.
    pub fn ticked(&self) -> bool {
        self.ticked
    }

    /// Whether the box can be ticked: there is one, and the end of the list has been on screen.
    pub fn verify_enabled(&self) -> bool {
        self.answer.is_none()
            && self.sheet.verification.is_some()
            && self.opened.is_some()
            && self.seen_end.is_some()
    }

    /// Whether [`ARM_DELAY`] has passed at `now` since the dialog was first on screen.
    pub fn armed(&self, now: Instant) -> bool {
        self.opened
            .is_some_and(|at| now.saturating_duration_since(at) >= ARM_DELAY)
    }

    /// Whether [`ARM_DELAY`] has passed at `now` since the end of the list was first on screen.
    pub fn end_armed(&self, now: Instant) -> bool {
        self.seen_end
            .is_some_and(|at| now.saturating_duration_since(at) >= ARM_DELAY)
    }

    /// When a delay that still runs at `now` is over: the dialog's, or the end's once it was on
    /// screen. `None` when none runs. For the window, which draws again then.
    pub fn arms_at(&self, now: Instant) -> Option<Instant> {
        let at = self.seen_end.or(self.opened)? + ARM_DELAY;
        (at > now).then_some(at)
    }

    /// Whether the button that approves can be pressed at `now`.
    pub fn approve_enabled(&self, now: Instant) -> bool {
        self.answer.is_none()
            && self.armed(now)
            && self.end_armed(now)
            && (self.sheet.verification.is_none() || self.ticked)
    }

    /// The control with the keyboard.
    pub fn focus(&self) -> Ctl {
        self.focus
    }

    /// Whether the keyboard's place is shown: after a key, and when the dialog opens (so that the
    /// default, Cancel, is seen), until the pointer is used.
    pub fn ring(&self) -> bool {
        self.ring
    }

    /// The answer, once there is one.
    pub fn answer(&self) -> Option<Outcome> {
        self.answer
    }

    /// The controls Tab visits at `now`, in order.
    fn stops(&self, now: Instant) -> Vec<Ctl> {
        let mut out = Vec::with_capacity(3);
        if self.verify_enabled() {
            out.push(Ctl::Verify);
        }
        if self.approve_enabled(now) {
            out.push(Ctl::Approve);
        }
        out.push(Ctl::Cancel);
        out
    }

    /// Whether `ctl` cannot be pressed at `now`: the button that approves while it is disabled, the
    /// box while it is.
    fn dead(&self, ctl: Ctl, now: Instant) -> bool {
        match ctl {
            Ctl::Approve => !self.approve_enabled(now),
            Ctl::Verify => !self.verify_enabled(),
            Ctl::Cancel | Ctl::Close => false,
        }
    }

    /// Keeps the keyboard off a control that cannot be pressed: back to Cancel.
    fn settle(&mut self, now: Instant) {
        if self.dead(self.focus, now) {
            self.focus = Ctl::Cancel;
        }
    }

    fn end(&mut self, outcome: Outcome) -> Did {
        self.answer = Some(outcome);
        Did::Answered(outcome)
    }

    /// The dialog is closed as Cancel: Esc, the close box, Alt+F4, the broker ending. Always taken.
    pub fn cancel(&mut self) -> Did {
        if let Some(answer) = self.answer {
            return Did::Answered(answer);
        }
        self.end(Outcome::Declined)
    }

    /// Presses `ctl` at `now`: a click released on it, Enter or Space with the keyboard on it, or UI
    /// Automation's Invoke or Toggle. The only way to [`Outcome::Approved`].
    pub fn press(&mut self, ctl: Ctl, now: Instant) -> Did {
        if let Some(answer) = self.answer {
            return Did::Answered(answer);
        }
        match ctl {
            Ctl::Cancel | Ctl::Close => self.cancel(),
            // Nothing else is taken before the dialog is on screen.
            _ if self.opened.is_none() => Did::Nothing,
            Ctl::Verify => {
                // No box, or its text's list not read to the end yet (review S6).
                if !self.verify_enabled() {
                    return Did::Nothing;
                }
                self.ticked = !self.ticked;
                self.focus = Ctl::Verify;
                Did::Changed
            }
            Ctl::Approve => {
                if !self.approve_enabled(now) {
                    return Did::Nothing;
                }
                self.end(Outcome::Approved)
            }
        }
    }

    /// The pointer went down on `ctl`: a click may come of it ([`Prompt::pointer_up`]), except on
    /// a control that is disabled at that moment (the button that approves, the box). The keyboard
    /// moves there (never to a disabled control, never to the close box) and its place is no longer
    /// shown.
    pub fn pointer_on(&mut self, ctl: Ctl, now: Instant) -> Did {
        self.ring = false;
        let dead = self.dead(ctl, now);
        self.held = (!dead).then_some(ctl);
        self.focus = match ctl {
            Ctl::Close => self.focus,
            _ if dead => self.focus,
            other => other,
        };
        self.settle(now);
        Did::Changed
    }

    /// The pointer came up over `over` (`None`: over no control). A click is a press and a release
    /// on the same control; anything else presses nothing.
    pub fn pointer_up(&mut self, over: Option<Ctl>, now: Instant) -> Did {
        match (self.held.take(), over) {
            (Some(held), Some(over)) if held == over => self.press(held, now),
            _ => Did::Nothing,
        }
    }

    /// The pointer was used somewhere else in the window: no click comes of a press held before.
    pub fn pointer_used(&mut self) -> Did {
        self.held = None;
        if !self.ring {
            return Did::Nothing;
        }
        self.ring = false;
        Did::Changed
    }

    /// Moves the keyboard to `ctl` because UI Automation asked. Refused for a control that is not
    /// there or cannot be pressed.
    pub fn focus_on(&mut self, ctl: Ctl, now: Instant) -> Did {
        self.settle(now);
        if ctl == Ctl::Close || !self.stops(now).contains(&ctl) || self.focus == ctl {
            return Did::Nothing;
        }
        self.focus = ctl;
        self.ring = true;
        Did::Changed
    }

    /// A key went down at `now`. `repeat`: the system repeats it because it is held.
    pub fn key(&mut self, key: &KeyName, mods: Mods, repeat: bool, now: Instant) -> Did {
        if self.answer.is_some() {
            return Did::Nothing;
        }
        self.settle(now);
        // Alt+F4 arrives as the window's close request, not here; a chord is nobody's.
        if mods.ctrl || mods.alt {
            return Did::Nothing;
        }
        match key {
            KeyName::Escape if !repeat => self.cancel(),
            KeyName::Tab => {
                let stops = self.stops(now);
                let at = stops.iter().position(|c| *c == self.focus).unwrap_or(0);
                let n = stops.len();
                let next = if mods.shift { at + n - 1 } else { at + 1 } % n;
                self.focus = stops[next];
                self.ring = true;
                Did::Changed
            }
            KeyName::Enter | KeyName::Space if !repeat => {
                self.ring = true;
                match self.press(self.focus, now) {
                    Did::Nothing => Did::Changed,
                    did => did,
                }
            }
            KeyName::Up => Did::Scroll(Scroll::Lines(-1)),
            KeyName::Down => Did::Scroll(Scroll::Lines(1)),
            KeyName::PageUp => Did::Scroll(Scroll::Pages(-1)),
            KeyName::PageDown => Did::Scroll(Scroll::Pages(1)),
            KeyName::Home => Did::Scroll(Scroll::Top),
            KeyName::End => Did::Scroll(Scroll::End),
            _ => Did::Nothing,
        }
    }

    /// Time passed: the keyboard leaves a button that can no longer be pressed. (The button turning
    /// on needs no call: [`Prompt::approve_enabled`] is asked with the time.)
    pub fn tick(&mut self, now: Instant) {
        self.settle(now);
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::sheet::{Block, Sheet};
    use super::super::super::view::Icon;
    use super::*;

    fn sheet(verification: bool) -> Arc<Sheet> {
        Arc::new(Sheet {
            title: "Purge security prompt".into(),
            icon: Icon::Shield,
            instruction: "Move 2 leftovers to quarantine?".into(),
            blocks: vec![Block::Summary("2 items".into())],
            verification: verification.then(|| "I reviewed the items".to_owned()),
            approve: "Move 2 items to quarantine".into(),
            footer: "Code A1B2-C3D4".into(),
        })
    }

    fn mods(ctrl: bool, shift: bool, alt: bool) -> Mods {
        Mods {
            ctrl,
            shift,
            alt,
            ..Mods::default()
        }
    }

    fn key(p: &mut Prompt, k: KeyName, now: Instant) -> Did {
        p.key(&k, Mods::default(), false, now)
    }

    /// A dialog that is on screen, past its delay, with its end seen.
    fn ready(verification: bool) -> (Prompt, Instant) {
        let t0 = Instant::now();
        let mut p = Prompt::new(sheet(verification));
        assert!(p.opened(t0));
        assert!(p.saw_end(t0));
        (p, t0 + ARM_DELAY)
    }

    #[test]
    fn cancel_has_the_keyboard_and_enter_on_open_cancels() {
        for k in [KeyName::Enter, KeyName::Space, KeyName::Escape] {
            let (mut p, now) = ready(false);
            assert_eq!(p.focus(), Ctl::Cancel);
            assert!(p.ring(), "the default is shown");
            assert!(p.approve_enabled(now));
            assert_eq!(key(&mut p, k, now), Did::Answered(Outcome::Declined));
            assert_eq!(p.answer(), Some(Outcome::Declined));
        }
    }

    #[test]
    fn nothing_approves_before_the_dialog_is_on_screen() {
        let t0 = Instant::now();
        let mut p = Prompt::new(sheet(false));
        // Not opened: no time is late enough, and the end cannot have been seen.
        assert!(!p.saw_end(t0));
        let late = t0 + ARM_DELAY * 100;
        assert!(!p.armed(late) && !p.end_armed(late) && !p.approve_enabled(late));
        assert_eq!(p.arms_at(t0), None);
        assert!(!p.seen_end() && !p.verify_enabled());
        assert_eq!(p.press(Ctl::Approve, late), Did::Nothing);
        assert_eq!(p.press(Ctl::Verify, late), Did::Nothing);
        assert_eq!(p.answer(), None);
        // A cancel is always taken.
        assert_eq!(p.press(Ctl::Close, t0), Did::Answered(Outcome::Declined));
    }

    #[test]
    fn the_button_arms_a_second_after_the_first_frame_by_the_clock() {
        let t0 = Instant::now();
        let mut p = Prompt::new(sheet(false));
        p.opened(t0);
        p.saw_end(t0);
        let early = t0 + ARM_DELAY - Duration::from_millis(1);
        assert_eq!(p.arms_at(early), Some(t0 + ARM_DELAY));
        assert_eq!(p.arms_at(t0 + ARM_DELAY), None);
        assert!(!p.approve_enabled(early));
        assert_eq!(p.press(Ctl::Approve, early), Did::Nothing);
        assert_eq!(p.answer(), None);
        // A second "opened" does not move the start, in either direction.
        assert!(!p.opened(t0 + ARM_DELAY * 5));
        assert_eq!(p.opened_at(), Some(t0));
        assert!(p.approve_enabled(t0 + ARM_DELAY));
        assert_eq!(
            p.press(Ctl::Approve, t0 + ARM_DELAY),
            Did::Answered(Outcome::Approved)
        );
    }

    #[test]
    fn the_box_gates_the_button_and_unticking_closes_it_again() {
        let (mut p, now) = ready(true);
        assert!(!p.approve_enabled(now));
        assert_eq!(p.press(Ctl::Approve, now), Did::Nothing);
        assert_eq!(p.press(Ctl::Verify, now), Did::Changed);
        assert!(p.ticked() && p.approve_enabled(now));
        assert_eq!(p.press(Ctl::Verify, now), Did::Changed);
        assert!(!p.ticked() && !p.approve_enabled(now));
        assert_eq!(p.press(Ctl::Approve, now), Did::Nothing);
        assert_eq!(p.answer(), None);
        p.press(Ctl::Verify, now);
        assert_eq!(p.press(Ctl::Approve, now), Did::Answered(Outcome::Approved));
    }

    #[test]
    fn ticking_in_the_first_second_does_not_enable_the_button() {
        let t0 = Instant::now();
        let mut p = Prompt::new(sheet(true));
        p.opened(t0);
        p.saw_end(t0);
        let early = t0 + Duration::from_millis(100);
        assert_eq!(p.press(Ctl::Verify, early), Did::Changed);
        assert!(p.ticked() && !p.approve_enabled(early));
        assert_eq!(p.press(Ctl::Approve, early), Did::Nothing);
        assert!(p.approve_enabled(t0 + ARM_DELAY));
    }

    #[test]
    fn the_end_of_the_list_must_have_been_on_screen() {
        let t0 = Instant::now();
        let mut p = Prompt::new(sheet(false));
        p.opened(t0);
        let now = t0 + ARM_DELAY * 3;
        assert!(p.armed(now) && !p.approve_enabled(now));
        assert_eq!(p.arms_at(now), None, "nothing runs until the end is seen");
        assert_eq!(p.press(Ctl::Approve, now), Did::Nothing);
        assert!(p.saw_end(now));
        assert!(!p.saw_end(now + ARM_DELAY), "told once");
        // The end coming into view starts the delay again (review S6): End and a click at once
        // press nothing, however long the dialog has been up.
        assert!(p.seen_end() && !p.end_armed(now) && !p.approve_enabled(now));
        assert_eq!(p.press(Ctl::Approve, now), Did::Nothing);
        p.pointer_on(Ctl::Approve, now);
        assert_eq!(p.pointer_up(Some(Ctl::Approve), now), Did::Nothing);
        let early = now + ARM_DELAY - Duration::from_millis(1);
        assert_eq!(p.arms_at(early), Some(now + ARM_DELAY));
        assert_eq!(p.press(Ctl::Approve, early), Did::Nothing);
        // A press that began in the delay is no click after it either.
        p.pointer_on(Ctl::Approve, early);
        let then = now + ARM_DELAY;
        assert_eq!(p.pointer_up(Some(Ctl::Approve), then), Did::Nothing);
        assert_eq!(p.answer(), None);
        assert!(p.end_armed(then) && p.approve_enabled(then));
        assert_eq!(p.arms_at(then), None);
        assert_eq!(
            p.press(Ctl::Approve, then),
            Did::Answered(Outcome::Approved)
        );
    }

    #[test]
    fn the_end_is_never_seen_before_the_dialog() {
        let t0 = Instant::now();
        let mut p = Prompt::new(sheet(false));
        let opened = t0 + ARM_DELAY;
        p.opened(opened);
        // A clock read before the one that opened the dialog counts from the opening.
        assert!(p.saw_end(t0));
        assert!(!p.approve_enabled(opened + ARM_DELAY - Duration::from_millis(1)));
        assert!(p.approve_enabled(opened + ARM_DELAY));
    }

    #[test]
    fn the_box_cannot_be_ticked_before_the_end_of_the_list_was_on_screen() {
        let t0 = Instant::now();
        let mut p = Prompt::new(sheet(true));
        p.opened(t0);
        let now = t0 + ARM_DELAY * 3;
        assert!(!p.verify_enabled());
        // Not by UI Automation or a key, not by a click, and the keyboard does not go there.
        assert_eq!(p.press(Ctl::Verify, now), Did::Nothing);
        p.pointer_on(Ctl::Verify, now);
        assert_eq!(p.focus(), Ctl::Cancel);
        assert_eq!(p.pointer_up(Some(Ctl::Verify), now), Did::Nothing);
        assert_eq!(p.focus_on(Ctl::Verify, now), Did::Nothing);
        assert_eq!(key(&mut p, KeyName::Tab, now), Did::Changed);
        assert_eq!(p.focus(), Ctl::Cancel, "Cancel is the only stop");
        assert!(!p.ticked());
        // A press held on the box from before the end was seen ticks nothing after it.
        p.pointer_on(Ctl::Verify, now);
        assert!(p.saw_end(now));
        assert!(p.verify_enabled());
        assert_eq!(p.pointer_up(Some(Ctl::Verify), now), Did::Nothing);
        assert!(!p.ticked());
        // Now it ticks, and the button still waits out the delay of the end.
        assert_eq!(p.press(Ctl::Verify, now), Did::Changed);
        assert!(p.ticked() && !p.approve_enabled(now));
        assert_eq!(p.press(Ctl::Approve, now), Did::Nothing);
        assert_eq!(
            p.press(Ctl::Approve, now + ARM_DELAY),
            Did::Answered(Outcome::Approved)
        );
    }

    #[test]
    fn tab_skips_the_button_while_it_is_disabled_and_never_reaches_close() {
        let (mut p, now) = ready(true);
        // Box, Cancel: the button is gated by the box.
        assert_eq!(key(&mut p, KeyName::Tab, now), Did::Changed);
        assert_eq!(p.focus(), Ctl::Verify);
        assert_eq!(key(&mut p, KeyName::Tab, now), Did::Changed);
        assert_eq!(p.focus(), Ctl::Cancel);
        p.key(&KeyName::Tab, mods(false, true, false), false, now);
        assert_eq!(p.focus(), Ctl::Verify);
        // Space ticks the box; then Tab reaches the button.
        assert_eq!(key(&mut p, KeyName::Space, now), Did::Changed);
        assert!(p.ticked());
        key(&mut p, KeyName::Tab, now);
        assert_eq!(p.focus(), Ctl::Approve);
        // Unticked while the keyboard is on the button: it goes back to Cancel, and the button
        // takes no focus while it is disabled.
        p.press(Ctl::Verify, now);
        assert_eq!(p.focus_on(Ctl::Approve, now), Did::Nothing);
        assert_ne!(p.focus(), Ctl::Approve);
        p.press(Ctl::Verify, now);
        assert_eq!(p.focus_on(Ctl::Approve, now), Did::Changed);
        assert_eq!(p.focus_on(Ctl::Close, now), Did::Nothing);
        assert_eq!(
            key(&mut p, KeyName::Enter, now),
            Did::Answered(Outcome::Approved)
        );
    }

    #[test]
    fn enter_on_the_button_before_it_is_armed_cannot_approve() {
        let t0 = Instant::now();
        let mut p = Prompt::new(sheet(false));
        p.opened(t0);
        p.saw_end(t0);
        let now = t0 + ARM_DELAY;
        key(&mut p, KeyName::Tab, now);
        assert_eq!(p.focus(), Ctl::Approve);
        // The clock is what counts, not what was drawn: asked with an earlier time, the keyboard
        // is back on Cancel, and Enter there cancels.
        let early = t0 + Duration::from_millis(10);
        assert_eq!(
            key(&mut p, KeyName::Enter, early),
            Did::Answered(Outcome::Declined)
        );
    }

    #[test]
    fn a_held_key_presses_nothing_and_a_chord_is_ignored() {
        let (mut p, now) = ready(false);
        for k in [KeyName::Enter, KeyName::Space, KeyName::Escape] {
            assert_eq!(p.key(&k, Mods::default(), true, now), Did::Nothing);
        }
        key(&mut p, KeyName::Tab, now);
        assert_eq!(p.focus(), Ctl::Approve);
        assert_eq!(
            p.key(&KeyName::Enter, Mods::default(), true, now),
            Did::Nothing
        );
        assert_eq!(
            p.key(&KeyName::Enter, mods(false, false, true), false, now),
            Did::Nothing
        );
        assert_eq!(
            p.key(&KeyName::Enter, mods(true, false, false), false, now),
            Did::Nothing
        );
        assert_eq!(p.answer(), None);
    }

    #[test]
    fn the_first_answer_stands() {
        let (mut p, now) = ready(false);
        assert_eq!(p.cancel(), Did::Answered(Outcome::Declined));
        assert_eq!(p.press(Ctl::Approve, now), Did::Answered(Outcome::Declined));
        assert_eq!(p.answer(), Some(Outcome::Declined));
        assert!(!p.approve_enabled(now));
        let (mut p, now) = ready(false);
        assert_eq!(p.press(Ctl::Approve, now), Did::Answered(Outcome::Approved));
        assert_eq!(p.cancel(), Did::Answered(Outcome::Approved));
    }

    #[test]
    fn a_click_is_a_press_and_a_release_on_the_same_enabled_control() {
        // Down and up on the enabled button: approved.
        let (mut p, now) = ready(false);
        p.pointer_on(Ctl::Approve, now);
        assert_eq!(
            p.pointer_up(Some(Ctl::Approve), now),
            Did::Answered(Outcome::Approved)
        );
        // Down on the button before it armed, up after: nothing, however long it is held.
        let t0 = Instant::now();
        let mut p = Prompt::new(sheet(false));
        p.opened(t0);
        p.saw_end(t0);
        p.pointer_on(Ctl::Approve, t0 + Duration::from_millis(900));
        let late = t0 + ARM_DELAY * 3;
        assert!(p.approve_enabled(late));
        assert_eq!(p.pointer_up(Some(Ctl::Approve), late), Did::Nothing);
        assert_eq!(p.answer(), None);
        // The same while the box was not ticked at the press (ticked by the keyboard meanwhile).
        let (mut p, now) = ready(true);
        p.pointer_on(Ctl::Approve, now);
        p.press(Ctl::Verify, now);
        assert!(p.approve_enabled(now));
        assert_eq!(p.pointer_up(Some(Ctl::Approve), now), Did::Nothing);
        // Down on one control and up on another, or on none: nothing. An up with no down: nothing.
        let (mut p, now) = ready(false);
        p.pointer_on(Ctl::Cancel, now);
        assert_eq!(p.pointer_up(Some(Ctl::Approve), now), Did::Nothing);
        p.pointer_on(Ctl::Approve, now);
        assert_eq!(p.pointer_up(None, now), Did::Nothing);
        assert_eq!(p.pointer_up(Some(Ctl::Approve), now), Did::Nothing);
        // A press elsewhere in between ends the held one.
        p.pointer_on(Ctl::Approve, now);
        p.pointer_used();
        assert_eq!(p.pointer_up(Some(Ctl::Approve), now), Did::Nothing);
        assert_eq!(p.answer(), None);
        // The box and Cancel click like any control.
        let (mut p, now) = ready(true);
        p.pointer_on(Ctl::Verify, now);
        assert_eq!(p.pointer_up(Some(Ctl::Verify), now), Did::Changed);
        assert!(p.ticked());
        p.pointer_on(Ctl::Close, now);
        assert_eq!(
            p.pointer_up(Some(Ctl::Close), now),
            Did::Answered(Outcome::Declined)
        );
    }

    #[test]
    fn the_pointer_moves_the_keyboard_but_not_to_a_disabled_button() {
        let (mut p, now) = ready(true);
        p.pointer_on(Ctl::Approve, now);
        assert_eq!(p.focus(), Ctl::Cancel);
        assert!(!p.ring());
        p.pointer_on(Ctl::Verify, now);
        assert_eq!(p.focus(), Ctl::Verify);
        p.pointer_on(Ctl::Close, now);
        assert_eq!(p.focus(), Ctl::Verify);
        assert_eq!(
            key(&mut p, KeyName::Down, now),
            Did::Scroll(Scroll::Lines(1))
        );
        assert_eq!(key(&mut p, KeyName::End, now), Did::Scroll(Scroll::End));
    }
}
