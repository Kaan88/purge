//! The application the host runs: it turns the host's events into changes of the model, and
//! draws the model. The toolkit's widgets call nothing back, so every reaction is here: a press
//! or a key finds the control it is for in the list the last frame declared, and `activate`
//! says what that control does.

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use mdshared_app::backdrop::Backdrop;
use mdshared_ui::a11y::{self, accesskit};
use mdshared_ui::cursor::Cursor;
use mdshared_ui::dropdown::Outcome as DdOutcome;
use mdshared_ui::focus::Focus;
use mdshared_ui::gfx::{Painter, Rect, Rgb};
use mdshared_ui::host::{App, Button, Cx, Event, KeyPress};
use mdshared_ui::keys::{KeyName, Mods};
use mdshared_ui::palette::{Entry, Outcome as PaletteOutcome, Palette as CommandPalette};
use mdshared_ui::platform;
use mdshared_ui::rows::Nav;
use mdshared_ui::scroll;
use mdshared_ui::segments;
use mdshared_ui::select::TypeAhead;
use mdshared_ui::theme::Palette;
use mdshared_ui::tokens::{self, Tokens};

use purge_ui_model::programs::strings as program_strings;
use purge_ui_model::programs::{Filter, ProgramCommand};

use crate::link::{Link, Source};
use crate::look::{Choice, Design, Preset, ThemeChoice, Transition};
use crate::markers::{self, BenchUntil};
use purge_ui_model::leftovers::LeftoversPhase;

use crate::model::DeleteFlyout;
use crate::model::{Model, Page, Programs, SortKey, Tab};
use crate::prefs::{Prefs, Store};
use crate::screens::{self, NAV, nav_id};
use crate::script::Script;
use crate::ui::{Ctl, Id, Key, Look, Role, SCOPE, Ui, id};
use crate::view::{
    DD_ALL, DD_BACKDROP, DD_DESIGN, DD_PRESET, DD_RESTORE, DD_SORT, DD_THEME, DD_TRANSITION, Toast,
    View,
};
use crate::winplace::Placer;
// UI-FULLFROST.
use crate::view::DD_COVERS;

const LIST: Id = Id("ProgramList", 0);
const SEARCH: Id = Id("SearchBox", 0);

/// What the command line asked for.
pub struct Options {
    /// The look and theme to start with: the saved settings, with the command line's over them.
    pub prefs: Prefs,
    /// The settings as the file has them: a choice made on the command line is for this run.
    pub saved: Prefs,
    /// Where the settings are saved.
    pub store: Store,
    /// Put the window where it was last time and save where it goes (`winplace`): false for the
    /// walk, timed runs and the bench.
    pub remember_place: bool,
    /// The page to open on (`--page`).
    pub page: Page,
    /// `--bench-exit`: close once the launch markers are written.
    /// Close after this many seconds (for a run with nobody at the keyboard).
    pub seconds: Option<u64>,
    /// Run the built-in walk through the screens, by made-up events.
    pub script: bool,
    /// Where the walk writes a PNG of each step, if anywhere.
    pub shots: Option<PathBuf>,
    /// `--shot`: the PNG of the last frame of a `--seconds` run.
    pub shot_at_end: Option<PathBuf>,
    pub bench_exit: bool,
    /// `--bench-until`: the marker the bench ends at.
    pub bench_until: BenchUntil,
    /// Where the program list comes from.
    pub source: Source,
    /// When `main` began, for the launch time.
    pub launched: Instant,
}

/// One row of tabs while the accessibility tree is built: its tabs so far and the rectangle
/// around them.
struct TabRow {
    label: &'static str,
    author: &'static str,
    tabs: Vec<accesskit::NodeId>,
    rect: Rect,
}

impl TabRow {
    fn new(label: &'static str, author: &'static str) -> TabRow {
        TabRow {
            label,
            author,
            tabs: Vec::new(),
            rect: Rect::default(),
        }
    }

    fn add(&mut self, tab: accesskit::NodeId, r: Rect) {
        self.rect = if self.tabs.is_empty() {
            r
        } else {
            let (x0, y0) = (self.rect.x.min(r.x), self.rect.y.min(r.y));
            let (x1, y1) = (
                self.rect.right().max(r.right()),
                self.rect.bottom().max(r.bottom()),
            );
            Rect::new(x0, y0, x1 - x0, y1 - y0)
        };
        self.tabs.push(tab);
    }
}

pub struct PurgeApp {
    pub model: Model,
    pub view: View,
    pub focus: Focus<Id>,
    /// The controls the last frame declared.
    pub ctls: Vec<Ctl>,
    pub hover: Option<Id>,
    pub pressed: Option<Id>,
    /// The control the open overlay's focus scope started on (which dialog it was opened for).
    scope_start: Option<Id>,
    pub pal: Palette,
    pub hc: bool,
    link_ink: Option<Rgb>,
    pointer: (f32, f32),
    type_ahead: TypeAhead,
    /// What the last frame declared, as one number: the accessibility tree is asked for again
    /// when a frame declares something else.
    tree_sig: u64,
    until: Option<Instant>,
    launched: Instant,
    frames: u32,
    pub script: Option<Script>,
    /// The file the next frame is written to.
    pub shot: Option<PathBuf>,
    shot_at_end: Option<PathBuf>,
    /// For the script: the modifiers a made-up click is held with, and high contrast as if the
    /// system had switched it on.
    pub fake_mods: Option<Mods>,
    pub hc_forced: Option<bool>,
    /// For the script: what a step's act leaves for its check.
    pub note: String,
    pub visited: Vec<Id>,
    store: Store,
    saved: Prefs,
    /// Whether the window's place is remembered, and from the start on, its placer.
    remember_place: bool,
    place: Option<Placer>,
    bench_exit: bool,
    bench_until: BenchUntil,
    /// The first frame was drawn and `presented` is still to be marked.
    presented_due: bool,
    /// A frame with the first real rows was drawn after the first frame, and `names_visible` is
    /// still to be marked once it is presented.
    names_due: bool,
    /// The first real rows were drawn (`rows_set`, `first_row`).
    rows_drawn: bool,
    /// A frame whose rows on screen all had their icons settled was drawn (`icons_visible`).
    icons_drawn: bool,
    /// ... and `icons_visible` is still to be marked once it is presented.
    icons_due: bool,
    /// When the bench gives up waiting for its end marker (`bench_timeout`).
    bench_deadline: Option<Instant>,
    /// The end marker was written with `--bench-exit` while the icon load still ran: the window
    /// closes when it ends, or at this time.
    close_after_icons: Option<Instant>,
    /// The marker line was written.
    markers_written: bool,
    /// The engine link, from the host's start on.
    pub link: Option<Link>,
    source: Source,
    /// The system's accent, read at each change of theme.
    accent: Option<Rgb>,
    /// With `PURGE_TX_LOG` set: the cost of the frames drawn while no page switch runs.
    idle_draws: Vec<f64>,
    /// For the walk: whether `paint`'s boxes and gradients came out as the toolkit's, checked
    /// on the first frame.
    pub paint_check: Option<Result<usize, String>>,
    /// UI-FULLFROST: the keys of the look in force and what they were made for.
    glass_keys: Option<(Palette, crate::glass::GlassPrefs, crate::glass::Keys)>,
}

impl PurgeApp {
    pub fn new(o: Options) -> PurgeApp {
        let sample = matches!(o.source, Source::Sample { .. });
        // The fingerprint-store probe of the removed-program check; the sample has no records.
        let programs = if sample {
            Programs::new(crate::clock::programs(), |_| false)
        } else {
            let dir = purge_client::fingerprint::default_directory();
            Programs::new(crate::clock::programs(), move |id| {
                purge_client::fingerprint::may_have_record(id, dir.as_deref())
            })
        };
        let mut model = Model::new(o.prefs, programs, sample);
        model.page = o.page;
        let mut view = View::new();
        view.dev |= o.script;
        PurgeApp {
            model,
            view,
            focus: Focus::new(),
            ctls: Vec::new(),
            hover: None,
            pressed: None,
            scope_start: None,
            pal: mdshared_ui::theme::LIGHT,
            hc: false,
            link_ink: None,
            pointer: (-1.0, -1.0),
            type_ahead: TypeAhead::new(),
            tree_sig: 0,
            until: o.seconds.map(|s| o.launched + Duration::from_secs(s)),
            launched: o.launched,
            frames: 0,
            script: o.script.then(|| Script::new(o.shots.clone())),
            shot: None,
            shot_at_end: o.shot_at_end,
            fake_mods: None,
            hc_forced: None,
            note: String::new(),
            visited: Vec::new(),
            store: o.store,
            saved: o.saved,
            remember_place: o.remember_place,
            place: None,
            bench_exit: o.bench_exit,
            bench_until: o.bench_until,
            presented_due: false,
            names_due: false,
            rows_drawn: false,
            icons_drawn: false,
            icons_due: false,
            bench_deadline: None,
            close_after_icons: None,
            markers_written: false,
            link: None,
            source: o.source,
            accent: None,
            idle_draws: Vec::new(),
            paint_check: None,
            // UI-FULLFROST.
            glass_keys: None,
        }
    }

    // ---- the look ----------------------------------------------------------------------------

    /// Makes the palette again from the system (light or dark, high contrast, the accent) and
    /// the user's choices: the colour preset in the theme mode, or under high contrast the
    /// system's own colours, with no backdrop.
    fn retheme(&mut self, cx: &mut Cx<'_, ()>) {
        let hc = self.hc_forced.unwrap_or(cx.high_contrast());
        let dark = self.model.prefs.theme.dark(platform::system_is_dark());
        self.accent = platform::system_accent();
        self.pal = if hc {
            Tokens::high_contrast_with(platform::system_contrast_colors().as_ref(), dark).palette
        } else {
            self.model.prefs.preset.palette(dark, self.accent)
        };
        self.hc = hc;
        // A contrast theme names its own colour for links.
        self.link_ink = if hc {
            platform::system_contrast_colors().map(|c| c.hot_light)
        } else {
            None
        };
        cx.set_dark(dark);
        let backdrop = tokens::allowed_backdrop(self.model.prefs.backdrop, hc);
        cx.set_backdrop(backdrop, &self.pal);
        cx.request_redraw_all();
    }

    /// Changes the user's choices, applies them at once and saves them.
    pub fn set_prefs(&mut self, cx: &mut Cx<'_, ()>, prefs: Prefs) {
        if self.model.prefs == prefs {
            return;
        }
        let old = self.model.prefs;
        let looks = (prefs.design, prefs.preset, prefs.theme, prefs.backdrop)
            != (old.design, old.preset, old.theme, old.backdrop);
        // Only what changed is written over the saved settings: what the command line chose
        // for this run stays this run's.
        let s = &mut self.saved;
        if prefs.design != old.design {
            s.design = prefs.design;
        }
        if prefs.preset != old.preset {
            s.preset = prefs.preset;
        }
        if prefs.theme != old.theme {
            s.theme = prefs.theme;
        }
        if prefs.transition != old.transition {
            s.transition = prefs.transition;
        }
        if prefs.backdrop != old.backdrop {
            s.backdrop = prefs.backdrop;
        }
        // UI-FULLFROST: each of the backdrop's two settings on its own.
        if prefs.glass.covers != old.glass.covers {
            s.glass.covers = prefs.glass.covers;
        }
        if prefs.glass.strength != old.glass.strength {
            s.glass.strength = prefs.glass.strength;
        }
        self.model.prefs = prefs;
        self.store.save(&self.saved);
        if looks {
            self.retheme(cx);
        }
        cx.request_redraw_all();
    }

    pub fn set_design(&mut self, cx: &mut Cx<'_, ()>, design: Design) {
        let p = Prefs {
            design,
            ..self.model.prefs
        };
        self.set_prefs(cx, p);
    }

    pub fn set_preset(&mut self, cx: &mut Cx<'_, ()>, preset: Preset) {
        let p = Prefs {
            preset,
            ..self.model.prefs
        };
        self.set_prefs(cx, p);
    }

    pub fn set_backdrop(&mut self, cx: &mut Cx<'_, ()>, backdrop: Backdrop) {
        let p = Prefs {
            backdrop,
            ..self.model.prefs
        };
        self.set_prefs(cx, p);
    }

    pub fn set_theme(&mut self, cx: &mut Cx<'_, ()>, theme: ThemeChoice) {
        let p = Prefs {
            theme,
            ..self.model.prefs
        };
        self.set_prefs(cx, p);
    }

    /// A new transition also plays itself in the Settings page's preview.
    pub fn set_transition(&mut self, cx: &mut Cx<'_, ()>, transition: Transition) {
        let p = Prefs {
            transition,
            ..self.model.prefs
        };
        if p != self.model.prefs {
            self.view.preview_b = !self.view.preview_b;
        }
        self.set_prefs(cx, p);
    }

    pub fn toast(&mut self, cx: &mut Cx<'_, ()>, text: &str) {
        self.view.toast = Some(Toast {
            text: text.to_string(),
            until: cx.now() + Duration::from_millis(3200),
        });
        cx.request_redraw_all();
    }

    // ---- the controls of the last frame --------------------------------------------------------

    fn overlay(&self) -> bool {
        self.model.flow.dialog_open() || self.view.palette.is_some()
    }

    /// Whether a press, a release, a wheel turn or the pointer at `x, y` is passed over: it is
    /// on a page still coming in, which is a picture moving into place, not the controls the
    /// page declared. Not while something open over the page takes the pointer.
    fn blocked(&self, cx: &Cx<'_, ()>, x: f32, y: f32) -> bool {
        if !self.view.page_tx.running() || self.overlay() || self.view.dds.open().is_some() {
            return false;
        }
        let lk = Look::of(self.model.prefs.design);
        let (w, h) = cx.size();
        x >= lk.rail_w && y >= lk.title_h && x < w && y < h
    }

    /// Whether the page the switch lays declared `id` (no switch: no page held).
    fn on_page(&self, id: Option<Id>) -> bool {
        id.is_some_and(|id| self.view.page_ctls.iter().any(|c| c.id == id))
    }

    pub fn ctl(&self, id: Id) -> Option<&Ctl> {
        self.ctls.iter().rev().find(|c| c.id == id)
    }

    /// What the control `id` stood for when the last frame drew it (a row's candidate,
    /// session, op or expiry id).
    pub fn key_of(&self, id: Id) -> Option<Key> {
        self.ctl(id).and_then(|c| c.key.clone())
    }

    /// The place, among `now`, of what the control `id` showed when it was drawn.
    fn keyed(&self, id: Id, mut now: impl Iterator<Item = Key>) -> Option<usize> {
        let shown = self.key_of(id)?;
        now.position(|k| k == shown)
    }

    /// The control under a point: the last declared wins, and while something is open over the
    /// page only its own controls answer.
    fn hit(&self, x: f32, y: f32) -> Option<&Ctl> {
        let overlay = self.overlay();
        self.ctls.iter().rev().find(|c| {
            !c.disabled
                && !matches!(c.role, Role::Text | Role::Progress(_))
                && c.rect.contains(x, y)
                && (c.modal || !overlay)
        })
    }

    /// Keeps the focus scope in step with what is open over the page: opening the confirmation
    /// puts the keyboard on "Not now", and closing it gives the keyboard back to where it was.
    fn sync_scope(&mut self) {
        let want = self.overlay();
        let open = self.focus.scope() == Some(SCOPE);
        // The dialog shown (the palette draws over a dialog, so it goes first).
        let start = if self.view.palette.is_some() {
            None
        } else if self.model.flow.confirm.is_some() {
            Some(id("ConfirmNotNowButton"))
        } else if self.model.flow.elevation.showing().is_some() {
            Some(id("DialogPrimaryButton"))
        } else if self.model.flow.takeover.is_some() {
            Some(id("TakeoverNotNowButton"))
        } else {
            None
        };
        // One dialog directly after another: the keyboard starts over on the new one, never on
        // a control of the one before.
        if want && open && start != self.scope_start {
            self.focus.pop_scope();
        }
        let open = self.focus.scope() == Some(SCOPE);
        if want && !open {
            match start {
                Some(on) => self.focus.push_scope_on(SCOPE, on),
                None => self.focus.push_scope(SCOPE),
            }
            self.scope_start = start;
        } else if !want && open {
            self.focus.pop_scope();
            self.scope_start = None;
        }
    }

    fn close_dropdowns(&mut self) -> bool {
        let mut any = false;
        for dd in DD_ALL {
            if let Some(d) = self.view.dds.get(dd) {
                any |= d.close();
            }
        }
        any
    }

    // ---- what a control does -----------------------------------------------------------------

    pub fn go(&mut self, page: Page) {
        if self.model.page != page {
            self.model.page = page;
            self.close_dropdowns();
            self.view.page_scroll = scroll::SmoothScroll::new();
            // UI-PAGES2: History's and Quarantine's lists scroll with it too.
            self.view.left_scroll = scroll::SmoothScroll::new();
        }
    }

    fn ask_uninstall(&mut self, cx: &mut Cx<'_, ()>) {
        if let Err(said) = self.model.ask_uninstall() {
            self.toast(cx, &said);
        }
    }

    /// A click, or Enter or Space, on the control `id`.
    pub fn activate(&mut self, cx: &mut Cx<'_, ()>, id: Id) {
        let n = id.1 as usize;
        if let Some((page, _)) = NAV.iter().find(|(_, name)| *name == id.0) {
            self.go(*page);
            cx.request_redraw_all();
            return;
        }
        match id.0 {
            "Minimize" => cx.minimize(),
            "Maximize" => cx.toggle_maximize(),
            "Close" => self.close(cx),

            // Programs.
            "TabApps" | "TabComponents" | "TabUnnamed" | "TabRecent" => {
                let tab = Tab::ALL[screens_tab_index(id.0)];
                self.model.programs.set_tab(tab);
                self.view.list.jump_top();
            }
            "SortName" => self.model.programs.sort_by(SortKey::Name),
            "SortSize" => self.model.programs.sort_by(SortKey::Size),
            "SortJunk" => self.model.programs.sort_by(SortKey::Junk),
            "SortDate" => self.model.programs.sort_by(SortKey::Date),
            "FilterButton" => {
                let on = !self.model.programs.only_junk;
                self.model.programs.set_filter(Filter::Leftovers, on);
                self.view.list.jump_top();
            }
            "UninstallButton" | "DUninstallButton" => self.ask_uninstall(cx),
            // The page's other commands (folder, web search, refresh, the other filters) are in
            // the command palette, which the "..." button opens.
            "Commands" => self.open_palette(),
            "DLocationText" => self.model.programs.command(ProgramCommand::OpenFolder),
            "NoticeDismiss" => {
                self.model.programs.page.dismiss_notice();
                self.model.programs.sync();
            }
            // By the program the row showed (`Ctl::key`): Dismiss cannot be undone.
            "RemovedCheck" | "RemovedDismiss" => {
                let shown = match self.key_of(id) {
                    Some(Key::Program(p)) => Some(p),
                    _ => None,
                };
                let pr = &mut self.model.programs;
                let rows = pr.view.removed.as_ref().map(|g| g.rows.as_slice());
                let row = rows
                    .and_then(|rows| rows.iter().find(|r| Some(&r.program_id) == shown.as_ref()));
                if let Some(program_id) = row.map(|r| r.program_id.clone()) {
                    let r = if id.0 == "RemovedCheck" {
                        pr.page.check_removed(&program_id)
                    } else {
                        pr.page.dismiss_removed(&program_id)
                    };
                    pr.take(r);
                }
            }
            "Commands.Expander" => self.view.commands_open = !self.view.commands_open,

            // The confirmation and the first-elevation explanation (UI-FLOW).
            // The Uninstall waits a moment after the dialog appears (`screens::ARM_DELAY`), for
            // the keyboard and the reader too: a click or key meant for what was there lands
            // nowhere.
            // The delay is the clock's since the dialog was first drawn (`flow::Opened`), never
            // the last frame's control: a confirmation not drawn yet, or one that replaced the one
            // drawn, cannot be confirmed (review N5).
            "ConfirmUninstallButton"
                if self.ctl(id).is_none_or(|c| c.disabled)
                    || !self
                        .model
                        .flow
                        .confirm
                        .as_ref()
                        .is_some_and(|c| c.opened.armed(cx.now())) => {}
            "ConfirmUninstallButton" | "ConfirmCheckAgainButton" | "ConfirmNotNowButton" => {
                self.close_dropdowns();
                if let Some(button) = screens::confirm_button(id.0) {
                    self.model.flow_confirm(button);
                }
            }
            "QuietSwitch" => self.model.flow_quiet(),
            "DialogPrimaryButton" => self.model.flow_elevation(true),
            "DialogCloseButton" => self.model.flow_elevation(false),
            // "End it" waits ARM_DELAY too, with the same guard as the Uninstall.
            "TakeoverEndButton"
                if self.ctl(id).is_none_or(|c| c.disabled)
                    || !self
                        .model
                        .flow
                        .takeover
                        .as_ref()
                        .is_some_and(|t| t.opened.armed(cx.now())) => {}
            "TakeoverEndButton" | "TakeoverNotNowButton" => {
                self.model.flow_takeover(id.0 == "TakeoverEndButton");
            }

            // The Uninstall page.
            "NextButton" => self.model.flow_next(),
            "SkipButton" => self.model.flow_skip(),
            "RecheckButton" => self.model.flow_recheck(),
            // The bars and groups act on what they showed (`Ctl::key`), never on a place.
            "BarButton" => {
                if let Some(shown @ Key::BarButton { action, .. }) = self.key_of(id) {
                    let bars = self.model.flow_bars();
                    if let Some(k) = bars.iter().position(|b| shown.on_bar(&b.title, &b.message)) {
                        self.model.flow_bar(k, action);
                    }
                }
            }
            "BarClose" => {
                let bars = self.model.flow_bars();
                if let Some(k) = self.keyed(id, bars.iter().map(|b| Key::bar(&b.title, &b.message)))
                {
                    self.model.flow_close_bar(k);
                }
            }
            "GoPrograms" => self.go(Page::Programs),

            // Leftovers.
            "LBarButton" | "LBarClose" => {
                let bars = self.model.flow_leftovers_bars();
                if let Some(k) = self.keyed(id, bars.iter().map(|b| Key::bar(&b.title, &b.message)))
                {
                    if id.0 == "LBarButton" {
                        self.model.flow_lbar(k);
                    } else {
                        self.model.flow_close_lbar(k);
                    }
                }
            }
            "Group" | "GroupTick" => {
                let shown = self.key_of(id);
                let l = &mut self.model.flow.leftovers;
                // Only over the list the frame drew: a re-scan (or anything else that built the
                // list again) since then leaves the click acting on nothing (review N7).
                let group = match shown {
                    Some(Key::Group { name, list }) if list == l.list_version() => {
                        l.group_named(&name)
                    }
                    _ => None,
                };
                match group {
                    Some(g) if id.0 == "Group" => l.toggle_expanded(g),
                    Some(g) => l.toggle_group(g),
                    None => {}
                }
            }
            // The rows act on what they showed (`Ctl::key`), never on a place in the list.
            "Item" => {
                if let Some(Key::Candidate(c)) = self.key_of(id) {
                    let r = self.model.flow.leftovers.select(c);
                    self.model.flow.ltake(r);
                }
            }
            "ItemTick" => {
                if let Some(Key::Candidate(c)) = self.key_of(id) {
                    let l = &mut self.model.flow.leftovers;
                    if let Some(on) = l.item(&c).map(|i| i.checked) {
                        l.set_checked(&c, !on);
                        let r = l.select(c);
                        self.model.flow.ltake(r);
                    }
                }
            }
            "ExpandButton" => self.model.flow.leftovers.expand_all(),
            "WeakButton" => self.model.flow.leftovers.toggle_weak(),
            "DeleteAfterBox" => {
                let l = &mut self.model.flow.leftovers;
                let on = !l.footer().delete_after;
                l.set_delete_after(on);
            }
            "MoveButton" => {
                let r = self.model.flow.leftovers.click_move();
                self.model.flow.ltake(r);
            }
            "UndoAllButton" => {
                let r = self.model.flow.leftovers.click_undo_all();
                self.model.flow.ltake(r);
            }
            "RetryHeldButton" => {
                let r = self.model.flow.leftovers.retry_held();
                self.model.flow.ltake(r);
            }
            "DoneButton" => {
                let to = self.model.flow_done_page();
                self.go(to);
            }
            "OpenHistory" => self.go(Page::History),
            "OpenVault" => self.go(Page::Quarantine),

            // History and Quarantine (UI-PAGES2).
            name if self.pages_activate(cx, name, n) => {}

            // Settings.
            "ConfirmEach" => {
                // The confirmation cannot be switched off: the switch says so and stays on.
                self.toast(
                    cx,
                    "Purge always asks before an uninstall. This cannot be turned off.",
                );
            }
            "SendNothing" => self.toast(
                cx,
                "Purge sends nothing and has nothing to send: there is no switch.",
            ),
            "OpenQuarantine" => self.go(Page::Quarantine),
            "ColourSwatch" => self.set_preset(cx, Preset::at(n.saturating_sub(1))),
            "PreviewTransition" => self.view.preview_b = !self.view.preview_b,
            "MarkersExpander" => {
                self.model.settings.markers_open = !self.model.settings.markers_open
            }
            "PaletteButton" | "CommandField" => self.open_palette(),
            _ => {}
        }
        cx.request_redraw_all();
    }

    fn dropdown_changed(&mut self, cx: &mut Cx<'_, ()>, dd: Id, i: usize) {
        match dd {
            DD_SORT => {
                let key = SortKey::ALL[i.min(SortKey::ALL.len() - 1)];
                if self.model.programs.sort != key {
                    self.model.programs.sort_menu(key);
                }
            }
            DD_THEME => self.set_theme(cx, ThemeChoice::at(i)),
            DD_DESIGN => self.set_design(cx, Design::at(i)),
            DD_TRANSITION => self.set_transition(cx, Transition::at(i)),
            DD_PRESET => self.set_preset(cx, Preset::at(i)),
            DD_BACKDROP => self.set_backdrop(cx, Backdrop::at(i)),
            // UI-FULLFROST.
            DD_COVERS => self.set_covers(cx, crate::look::Covers::at(i)),
            DD_RESTORE => self.model.flow_restore_point(i.min(2)),
            _ => {}
        }
        cx.request_redraw_all();
    }

    // ---- the command palette ------------------------------------------------------------------

    pub fn open_palette(&mut self) {
        self.close_dropdowns();
        let mut p = CommandPalette::new();
        p.set_placeholder("Type a command or a page");
        p.set_groups(vec![
            (0, "Go to".to_string()),
            (1, "Do".to_string()),
            (2, "Look".to_string()),
        ]);
        let mut entries: Vec<Entry> = Page::ALL
            .iter()
            .enumerate()
            .map(|(i, page)| {
                Entry::new(i as u32, page.title())
                    .group(0)
                    .hint(format!("Ctrl+{}", i + 1))
            })
            .collect();
        let n = self.model.programs.sel.len();
        entries.push(
            Entry::new(20, format!("Uninstall the {n} selected\u{2026}"))
                .group(1)
                .hint("Del")
                .enabled(n > 0),
        );
        entries.push(Entry::new(21, "Search programs").group(1).hint("Ctrl+F"));
        let c = &self.model.programs.view.commands;
        entries.push(
            Entry::new(26, "Open install folder")
                .group(1)
                .enabled(c.open_folder_enabled),
        );
        entries.push(
            Entry::new(27, "Search the web")
                .group(1)
                .enabled(c.web_enabled),
        );
        entries.push(Entry::new(28, "Refresh list").group(1));
        let f = self.model.programs.view.filters;
        let mark = |on: bool| if on { " (on)" } else { "" };
        for (no, text, on) in [
            (29, program_strings::FILTER_PER_USER, f.only_per_user),
            (30, program_strings::FILTER_32, f.only_32),
        ] {
            entries.push(Entry::new(no, format!("Filter: {text}{}", mark(on))).group(1));
        }
        entries.push(
            Entry::new(22, "Review leftovers")
                .group(1)
                .enabled(self.model.flow.leftovers.phase() == LeftoversPhase::Review),
        );
        entries.push(Entry::new(23, "Theme: light").group(1));
        entries.push(Entry::new(24, "Theme: dark").group(1));
        entries.push(Entry::new(25, "Theme: use system setting").group(1));
        for (i, d) in Design::ALL.iter().enumerate() {
            entries.push(Entry::new(10 + i as u32, format!("Look: {}", d.title())).group(2));
        }
        p.set_entries(entries);
        // The toolkit writes "Enter to choose  Esc to close" at the right of the footer itself.
        // It has room for about thirty characters before it is cut short.
        p.set_footer(Some("Uninstalling always asks first".to_string()));
        p.open("");
        self.view.palette = Some(p);
    }

    fn run_command(&mut self, cx: &mut Cx<'_, ()>, command: u32) {
        self.view.palette = None;
        match command {
            // Like Ctrl+1..6: focus goes with the page, so no ring stays on the page just left.
            0..=5 => {
                let page = Page::ALL[command as usize];
                self.go(page);
                // The palette's scope is closed first, or closing it later would put the
                // keyboard back where it was before the palette opened.
                self.sync_scope();
                self.focus.focus(nav_id(page));
            }
            10..=13 => self.set_design(cx, Design::at(command as usize - 10)),
            20 => {
                self.go(Page::Programs);
                self.ask_uninstall(cx);
            }
            21 => {
                self.go(Page::Programs);
                self.sync_scope();
                self.focus.focus(SEARCH);
                self.view.search.select_all();
            }
            // In the flow the review is part of the pipeline page while its run is still shown.
            22 if Look::of(self.model.prefs.design).flow
                && self.model.flow.page.controller().target().is_some() =>
            {
                self.go(Page::Pipeline)
            }
            22 => self.go(Page::Leftovers),
            26..=28 => {
                self.go(Page::Programs);
                let command = [
                    ProgramCommand::OpenFolder,
                    ProgramCommand::Web,
                    ProgramCommand::Refresh,
                ][command as usize - 26];
                self.model.programs.command(command);
            }
            29 | 30 => {
                self.go(Page::Programs);
                let f = self.model.programs.view.filters;
                let (filter, on) = if command == 29 {
                    (Filter::PerUser, !f.only_per_user)
                } else {
                    (Filter::Bits32, !f.only_32)
                };
                self.model.programs.set_filter(filter, on);
                self.view.list.jump_top();
            }
            23..=25 => {
                let theme = [ThemeChoice::Light, ThemeChoice::Dark, ThemeChoice::System]
                    [command as usize - 23];
                self.set_theme(cx, theme);
            }
            _ => {}
        }
        cx.request_redraw_all();
    }

    fn palette_outcome(&mut self, cx: &mut Cx<'_, ()>, o: PaletteOutcome) {
        match o {
            PaletteOutcome::Chosen(c) => self.run_command(cx, c),
            PaletteOutcome::Closed => {
                self.view.palette = None;
                cx.request_redraw_all();
            }
            PaletteOutcome::None | PaletteOutcome::Unused => {}
            _ => cx.request_redraw_all(),
        }
    }

    // ---- the pointer -------------------------------------------------------------------------

    fn pointer_move(&mut self, cx: &mut Cx<'_, ()>, x: f32, y: f32) {
        self.pointer = (x, y);
        // UI-FULLFROST: the strength slider's thumb in hand follows the pointer.
        if self.slider_drag(cx, x, y) {
            return;
        }
        if let Some(p) = &mut self.view.palette {
            if p.pointer_move(x, y) {
                cx.request_redraw_all();
            }
            cx.set_cursor(Cursor::Default);
            return;
        }
        if let Some(grip) = self.view.list.drag {
            if let Some((track, thumb)) = self.view.list.bar {
                let l = &mut self.view.list;
                let to = scroll::offset_for_thumb(track, thumb.h, y - grip, l.content(), l.area.h);
                l.scroll.jump_to(to, l.content(), l.area.h);
                cx.request_redraw_all();
            }
            return;
        }
        if let Some(open) = self.view.dds.open()
            && let Some(d) = self.view.dds.get(open)
            && d.pointer(x, y)
        {
            cx.request_redraw_all();
        }
        if self.blocked(cx, x, y) {
            // Over a page still coming in: nothing there is hot until it is in place (the
            // frame that ends the switch looks again). What the rail had hot no longer is.
            if self.hover.is_some() && !self.on_page(self.hover) {
                self.hover = None;
                cx.request_redraw_all();
            }
            cx.set_cursor(Cursor::Default);
            return;
        }
        let hit = self.hit(x, y).map(|c| (c.id, c.role.clone()));
        let hover = hit.as_ref().map(|h| h.0);
        let over_list = hover == Some(LIST);
        let row = if over_list {
            self.view.list.row_at(x, y)
        } else {
            None
        };
        let bar = over_list
            && self
                .view
                .list
                .bar
                .is_some_and(|(track, _)| x >= track.x - 4.0);
        if hover != self.hover || row != self.view.list.hot || bar != self.view.list.bar_hot {
            if row != self.view.list.hot
                || bar != self.view.list.bar_hot
                || self.on_page(hover)
                || self.on_page(self.hover)
            {
                self.view.page_dirty = true;
            }
            self.hover = hover;
            self.view.list.hot = if bar { None } else { row };
            self.view.list.bar_hot = bar;
            cx.request_redraw_all();
        }
        cx.set_cursor(match hit {
            Some((_, Role::Edit(_))) => Cursor::Text,
            Some((_, Role::Link)) => Cursor::Hand,
            _ => Cursor::Default,
        });
    }

    fn press(&mut self, cx: &mut Cx<'_, ()>, x: f32, y: f32, clicks: u32) {
        self.pointer = (x, y);
        self.focus.pointer_used();
        cx.request_redraw_all();
        if let Some(p) = &mut self.view.palette {
            let o = p.press(x, y, cx.mods(), clicks.min(3) as u8);
            return self.palette_outcome(cx, o);
        }
        // An open menu takes the press: on a row it is remembered, elsewhere the menu closes.
        if let Some(open) = self.view.dds.open() {
            let field = self.ctl(open).map(|c| c.rect).unwrap_or_default();
            if let Some(d) = self.view.dds.get(open) {
                d.press(field, x, y);
            }
            self.pressed = Some(open);
            return;
        }
        let Some(c) = self.hit(x, y).cloned() else {
            // The title row: drag the window, or maximize it on a double click.
            if y < Look::of(self.model.prefs.design).title_h && !self.overlay() {
                if clicks == 2 {
                    cx.title_double_click();
                } else {
                    cx.drag_window();
                }
            }
            return;
        };
        if c.focusable {
            self.focus.focus(c.id);
        }
        self.pressed = Some(c.id);
        match c.role {
            Role::List if c.id == LIST => self.press_list(cx, x, y),
            Role::Combo { .. } => {
                if let Some(d) = self.view.dds.get(c.id) {
                    d.press(c.rect, x, y);
                }
            }
            // UI-FULLFROST.
            Role::Slider(_) => {
                self.slider_drag(cx, x, y);
            }
            Role::Edit(_) => {
                let area = self.view.search_area;
                let stops = std::mem::take(&mut self.view.search_stops);
                if clicks == 2 {
                    self.view.search.select_word_at(x - area.x, &stops);
                } else if clicks >= 3 {
                    self.view.search.select_all();
                } else {
                    self.view.search.press(x - area.x, &stops, cx.mods().shift);
                }
                self.view.search_stops = stops;
            }
            _ => {}
        }
    }

    fn press_list(&mut self, cx: &mut Cx<'_, ()>, x: f32, y: f32) {
        let l = &mut self.view.list;
        if let Some((track, thumb)) = l.bar
            && x >= track.x - 4.0
        {
            if thumb.contains(x, y) || (y >= thumb.y && y <= thumb.bottom()) {
                l.drag = Some(y - thumb.y);
            } else {
                // A press on the track goes a page towards it.
                let page = l.area.h - l.row_h;
                let by = if y < thumb.y { -page } else { page };
                l.scroll.scroll_by(by, l.content(), l.area.h);
            }
            return;
        }
        let mods = self.fake_mods.unwrap_or(cx.mods());
        match l.row_at(x, y) {
            Some(row) => {
                // The box at the left adds or removes its row, like Ctrl+click.
                let in_box = x < l.area.x + 34.0;
                if in_box && !mods.shift {
                    self.model.programs.sel.toggle(row);
                } else {
                    self.model.programs.click(row, mods);
                }
            }
            None if !mods.ctrl && !mods.shift => self.model.programs.sel.clear(),
            None => {}
        }
    }

    fn release(&mut self, cx: &mut Cx<'_, ()>, x: f32, y: f32) {
        self.pointer = (x, y);
        cx.request_redraw_all();
        if let Some(p) = &mut self.view.palette {
            let o = p.release(x, y);
            return self.palette_outcome(cx, o);
        }
        self.view.list.drag = None;
        let Some(pressed) = self.pressed.take() else {
            return;
        };
        if DD_ALL.contains(&pressed) {
            let field = self.ctl(pressed).map(|c| c.rect).unwrap_or_default();
            if let Some(d) = self.view.dds.get(pressed)
                && let DdOutcome::Changed(i) = d.release(field, x, y)
            {
                self.dropdown_changed(cx, pressed, i);
            }
            return;
        }
        let over = self.hit(x, y).map(|c| (c.id, c.role.clone()));
        if let Some((over, role)) = over
            && over == pressed
            && matches!(
                role,
                Role::Button
                    | Role::Link
                    | Role::Check(_)
                    | Role::Switch(_)
                    | Role::Tab(_)
                    | Role::Expander(_)
                    | Role::Item(_)
            )
        {
            self.activate(cx, over);
        }
    }

    fn wheel(&mut self, cx: &mut Cx<'_, ()>, dy: f32) {
        let (x, y) = self.pointer;
        self.focus.pointer_used();
        if let Some(p) = &mut self.view.palette {
            if p.wheel(-dy) {
                cx.request_redraw_all();
            }
            return;
        }
        if let Some(open) = self.view.dds.open() {
            if let Some(d) = self.view.dds.get(open)
                && d.wheel(x, y, -dy)
            {
                cx.request_redraw_all();
            }
            return;
        }
        if self.overlay() {
            // The confirmation's body scrolls when it is taller than the window.
            let v = &mut self.view;
            if self.model.flow.confirm.is_some()
                && v.confirm_area.contains(x, y)
                && v.confirm_scroll
                    .scroll_by(-dy, v.confirm_content, v.confirm_area.h)
            {
                cx.request_redraw_all();
            }
            return;
        }
        let v = &mut self.view;
        let moved = if self.model.page == Page::Programs && v.list.area.contains(x, y) {
            let moved = v.list.wheel(dy);
            v.list.hot = None;
            moved
        } else if v.left_area.contains(x, y) {
            v.left_scroll.scroll_by(-dy, v.left_content, v.left_area.h)
        } else if v.page_area.contains(x, y) {
            v.page_scroll.scroll_by(-dy, v.page_content, v.page_area.h)
        } else {
            false
        };
        if moved {
            cx.request_redraw_all();
        }
    }

    // ---- the keyboard ------------------------------------------------------------------------

    fn key(&mut self, cx: &mut Cx<'_, ()>, k: KeyPress) {
        let Some(name) = k.name.clone() else {
            return;
        };
        let mods = k.mods;
        let plain = !mods.ctrl && !mods.alt && !mods.shift;
        cx.request_redraw_all();

        if let Some(p) = &mut self.view.palette {
            let o = p.key(&name, mods, k.text.as_deref());
            return self.palette_outcome(cx, o);
        }
        self.focus.key_used();

        // An open menu, or the drop-down the keyboard is on, takes its keys first.
        let dd = self
            .view
            .dds
            .open()
            .or(self.focus.focused().filter(|f| DD_ALL.contains(f)));
        if let Some(dd) = dd {
            let field = self.ctl(dd).map(|c| c.rect).unwrap_or_default();
            if let Some(d) = self.view.dds.get(dd) {
                let was_open = d.is_open();
                match d.key(field, &name, mods) {
                    DdOutcome::Changed(i) => return self.dropdown_changed(cx, dd, i),
                    DdOutcome::Unused if was_open && name == KeyName::Tab => {
                        d.close();
                    }
                    DdOutcome::Unused => {}
                    _ => return,
                }
            }
        }

        match name {
            KeyName::Escape => {
                if self.model.flow.confirm.is_some() {
                    self.close_dropdowns();
                    self.model
                        .flow_confirm(purge_ui_model::pipeline::page::ConfirmButton::NotNow);
                } else if self.model.flow.elevation.showing().is_some() {
                    self.model.flow_elevation(false);
                } else if self.model.flow.takeover.is_some() {
                    self.model.flow_takeover(false);
                } else if self.focus.is_focused(SEARCH) {
                    if self.view.search.is_empty() {
                        self.focus.focus(LIST);
                    } else {
                        self.view.search.clear();
                        self.model.programs.set_query("");
                    }
                } else if self.model.page == Page::Programs && !self.model.programs.sel.is_empty() {
                    self.model.programs.sel.clear();
                } else if self.model.page == Page::Quarantine
                    && self.model.quarantine.flyout.take().is_some()
                {
                    // UI-PAGES2: Esc closes the "Delete now" choice, as it closed the flyout.
                    self.focus.focus(id("VDeleteNow"));
                }
                return;
            }
            KeyName::Tab if !mods.ctrl && !mods.alt => {
                self.focus.tab(mods.shift);
                return;
            }
            _ => {}
        }
        if !self.overlay() && mods.ctrl && !mods.alt && !mods.shift {
            match name {
                KeyName::Char('f') => {
                    self.go(Page::Programs);
                    self.focus.focus(SEARCH);
                    self.view.search.select_all();
                    return;
                }
                KeyName::Char('k') => return self.open_palette(),
                KeyName::Char(c @ '1'..='6') => {
                    let page = Page::ALL[c as usize - '1' as usize];
                    self.go(page);
                    self.focus.focus(nav_id(page));
                    return;
                }
                _ => {}
            }
        }

        let Some(fid) = self.focus.focused() else {
            // Nothing has the keyboard yet: the arrows go to the list on the Programs page.
            if self.model.page == Page::Programs
                && !self.overlay()
                && matches!(name, KeyName::Down | KeyName::Up)
            {
                self.focus.focus(LIST);
                self.list_key(cx, &name, mods, None);
            }
            return;
        };
        let Some(c) = self.ctl(fid).cloned() else {
            return;
        };
        let press = plain && matches!(name, KeyName::Enter | KeyName::Space);
        match c.role {
            Role::Edit(_) => {
                match self
                    .view
                    .search
                    .handle_key(&name, mods, k.text.as_deref(), true)
                {
                    Some(true) => {
                        let q = self.view.search.text().to_string();
                        self.model.programs.set_query(&q);
                        self.view.list.jump_top();
                    }
                    Some(false) => {}
                    None if matches!(name, KeyName::Down | KeyName::Enter) => {
                        // Down the list from the search field.
                        self.focus.focus(LIST);
                        if self.model.programs.sel.cursor().is_none()
                            && !self.model.programs.rows.is_empty()
                        {
                            self.model.programs.sel.select_only(0);
                        }
                    }
                    None => {}
                }
            }
            Role::List => self.list_key(cx, &name, mods, k.text.as_deref()),
            Role::Tab(_) if screens::programs_tab(c.id).is_some() => {
                let at = screens::programs_tab(c.id).map(Tab::index);
                if let Some(to) = segments::selector_key(at, Tab::ALL.len(), &name) {
                    let tab = Tab::ALL[to];
                    self.focus.focus(screens::programs_tab_id(tab));
                    self.model.programs.set_tab(tab);
                    self.view.list.jump_top();
                } else if press {
                    self.activate(cx, c.id);
                }
            }
            Role::Tab(_) => {
                // The rail: the arrows move along it, Enter or Space opens the page.
                let at = NAV.iter().position(|(_, n)| *n == c.id.0);
                match (at, &name) {
                    (Some(i), KeyName::Down) if i + 1 < NAV.len() => {
                        self.focus.focus(id(NAV[i + 1].1));
                    }
                    (Some(i), KeyName::Up) if i > 0 => {
                        self.focus.focus(id(NAV[i - 1].1));
                    }
                    _ if press => self.activate(cx, c.id),
                    _ => {}
                }
            }
            Role::Item(_) => {
                // A short list: the arrows move to the item before or after and select it.
                let step = match name {
                    KeyName::Down => Some(1i64),
                    KeyName::Up => Some(-1),
                    _ => None,
                };
                if let Some(step) = step {
                    let same: Vec<Id> = self
                        .ctls
                        .iter()
                        .filter(|o| o.id.0 == c.id.0 && matches!(o.role, Role::Item(_)))
                        .map(|o| o.id)
                        .collect();
                    if let Some(at) = same.iter().position(|o| *o == c.id) {
                        let to = at as i64 + step;
                        if to >= 0 && (to as usize) < same.len() {
                            let to = same[to as usize];
                            self.focus.focus(to);
                            self.activate(cx, to);
                        }
                    }
                } else if press || (plain && name == KeyName::Char(' ')) {
                    self.activate(cx, c.id);
                }
            }
            Role::Expander(open) => {
                if press
                    || (plain && name == KeyName::Right && !open)
                    || (plain && name == KeyName::Left && open)
                {
                    self.activate(cx, c.id);
                }
            }
            Role::Button | Role::Link | Role::Check(_) | Role::Switch(_) if press => {
                self.activate(cx, c.id);
            }
            // UI-FULLFROST.
            Role::Slider(_) if !mods.ctrl && !mods.alt => self.slider_key(cx, c.id, &name),
            _ => {}
        }
    }

    fn list_key(&mut self, cx: &mut Cx<'_, ()>, name: &KeyName, mods: Mods, typed: Option<&str>) {
        let rows = self.view.list.rows_at_target();
        let nav = match name {
            KeyName::Up => Some(Nav::Up),
            KeyName::Down => Some(Nav::Down),
            KeyName::Home => Some(Nav::Home),
            KeyName::End => Some(Nav::End),
            KeyName::PageUp => Some(Nav::PageUp),
            KeyName::PageDown => Some(Nav::PageDown),
            _ => None,
        };
        let pr = &mut self.model.programs;
        if let Some(nav) = nav {
            let to = if mods.ctrl && !mods.shift {
                // Ctrl with an arrow moves the cursor and selects nothing new.
                let to = rows.nav(pr.sel.cursor(), nav);
                if let Some(to) = to {
                    pr.sel.set_cursor(to);
                }
                to
            } else {
                pr.sel.nav(&rows, nav, mods.shift)
            };
            if let Some(to) = to {
                self.view.list.reveal(to);
            }
            return;
        }
        match name {
            KeyName::Space => {
                if let Some(c) = pr.sel.cursor() {
                    pr.sel.toggle(c);
                }
            }
            KeyName::Char('a') if mods.ctrl => pr.sel.select_all(pr.rows.len()),
            KeyName::Enter | KeyName::Delete if !mods.ctrl && !mods.alt => self.ask_uninstall(cx),
            KeyName::Char(_) if !mods.ctrl && !mods.alt => {
                // Typing a name goes to the first program that starts with it.
                let Some(ch) = typed
                    .and_then(|t| t.chars().next())
                    .filter(|c| !c.is_control())
                else {
                    return;
                };
                let all = &pr.all;
                let shown = &pr.rows;
                let to = self
                    .type_ahead
                    .key(ch, cx.now(), shown.len(), pr.sel.cursor(), |i| {
                        all[shown[i]].name.as_str()
                    });
                if let Some(to) = to {
                    pr.sel.move_to(to, false);
                    self.view.list.reveal(to);
                }
            }
            _ => {}
        }
    }

    /// With `PURGE_TX_LOG` set: a frame's cost goes to the switch that runs, or to the idle
    /// frames, whose line is printed every 10.
    fn log_draw(&mut self, ms: f64, switching: bool) {
        if self.view.page_tx.running() {
            self.view.page_tx.note_draw(ms, self.view.page_drawn);
            return;
        }
        if self.view.flow_tx.running() {
            self.view.flow_tx.note_draw(ms, true);
            return;
        }
        if switching {
            // The switch's last frame: it printed its line.
            return;
        }
        self.idle_draws.push(ms);
        if self.idle_draws.len() >= 10 {
            let v = std::mem::take(&mut self.idle_draws);
            let max = v.iter().copied().fold(0.0, f64::max);
            let avg = v.iter().sum::<f64>() / v.len() as f64;
            println!(
                "idle {:?}: {} frames, draw {avg:.2} avg / {max:.2} max ms",
                self.model.page,
                v.len()
            );
        }
    }

    // ---- timers ------------------------------------------------------------------------------

    /// Asks for the earliest of the times still to come: the host gives one wake-up.
    /// The window closes: its place is saved first.
    fn close(&mut self, cx: &mut Cx<'_, ()>) {
        if let Some(state) = self.place.as_mut().and_then(|p| p.close(cx)) {
            self.store.save_window(&self.saved, state);
        }
        cx.exit();
    }

    fn timers(&mut self, cx: &mut Cx<'_, ()>) {
        let wakes = [
            (self.presented_due || self.names_due || self.icons_due).then(|| cx.now()),
            self.bench_deadline,
            self.close_after_icons,
            self.until,
            self.view.toast.as_ref().map(|t| t.until),
            self.script.as_ref().and_then(|s| s.due()),
            self.place.as_ref().and_then(|p| p.due(cx.now())),
        ];
        if let Some(at) = wakes.into_iter().flatten().min() {
            cx.wake_at(at);
        }
    }

    fn wake(&mut self, cx: &mut Cx<'_, ()>, now: Instant) {
        if let Some(state) = self.place.as_mut().and_then(|p| p.wake(cx, now)) {
            self.store.save_window(&self.saved, state);
        }
        if self.until.is_some_and(|u| u <= now)
            && let Some(path) = self.shot_at_end.take()
        {
            // The last frame is drawn into the file first; the window closes just after.
            self.shot = Some(path);
            self.until = Some(now + Duration::from_millis(500));
            cx.request_redraw_all();
            return;
        }
        if self.until.is_some_and(|u| u <= now) {
            println!("Purge: closing after the time asked for");
            cx.exit();
            return;
        }
        // The WinUI app's approximation of "presented": the next DWM composition after the frame
        // was drawn. One composition serves every marker due now.
        let mut flushed = false;
        let mut flush = || {
            if !std::mem::replace(&mut flushed, true) {
                markers::dwm_flush();
            }
        };
        if std::mem::take(&mut self.presented_due) {
            flush();
            let at = markers::mark("presented");
            let names = self.rows_drawn && !self.names_due;
            if names {
                markers::record("names_visible", at);
            }
            if self.end_marker(cx, BenchUntil::Presented)
                || (names && self.end_marker(cx, BenchUntil::Names))
            {
                return;
            }
        } else if std::mem::take(&mut self.names_due) {
            flush();
            markers::mark("names_visible");
            if self.end_marker(cx, BenchUntil::Names) {
                return;
            }
        }
        // After `names_visible`: a frame with icons has its rows.
        if !self.presented_due && !self.names_due && std::mem::take(&mut self.icons_due) {
            flush();
            markers::mark("icons_visible");
            if self.end_marker(cx, BenchUntil::Icons) {
                return;
            }
        }
        if self.bench_deadline.is_some_and(|d| d <= now) {
            self.bench_deadline = None;
            markers::mark("bench_timeout");
            if self.end_marker(cx, self.bench_until) {
                return;
            }
        }
        if self.bench_close(cx, now) {
            return;
        }
        if self.view.toast.as_ref().is_some_and(|t| t.until <= now) {
            self.view.toast = None;
            cx.request_redraw_all();
        }
        if self
            .script
            .as_ref()
            .is_some_and(|s| s.due().is_some_and(|d| d <= now))
            && let Some(mut script) = self.script.take()
        {
            self.view.page_dirty = true;
            let go_on = script.step(self, cx, now);
            if go_on {
                self.script = Some(script);
            } else {
                cx.exit();
            }
        }
    }

    /// Hands what the selection did to the Programs model, then routes the engine's events and
    /// the models' requests (`link`). Called after each event and each wake of a client.
    pub fn pump(&mut self, cx: &mut Cx<'_, ()>) {
        self.model.programs.commit_sel();
        let Some(link) = &mut self.link else {
            return;
        };
        if link.pump(&mut self.model) {
            self.view.page_dirty = true;
            cx.request_redraw_all();
        }
        if let Some(id) = self.model.programs.scroll_to.take()
            && let Some(row) = self.model.programs.row_of(&id)
        {
            self.view.list.reveal(row);
        }
    }

    /// At the bench's end marker (`--bench-until`; `reached` is the one that came now) the
    /// marker line is written, once, and `--bench-exit` closes the window: at once, or with a
    /// live engine once its icon load ended (at most [`markers::ICONS_SAVE_WAIT`]), so its atlas
    /// is saved for the next launch. True when it closes now. Not read back from the markers,
    /// which are kept only with `PURGE_BENCH_OUT` (without it `--bench-exit` never closed).
    fn end_marker(&mut self, cx: &mut Cx<'_, ()>, reached: BenchUntil) -> bool {
        if self.markers_written || reached != self.bench_until {
            return false;
        }
        self.markers_written = true;
        self.bench_deadline = None;
        markers::flush();
        if !self.bench_exit {
            return false;
        }
        self.close_after_icons = Some(Instant::now() + markers::ICONS_SAVE_WAIT);
        self.bench_close(cx, Instant::now())
    }

    /// The bench's `icons_visible`: the data is the live engine's and every row the list shows
    /// at its scroll has its icon settled: drawn from the atlas or `icon.batch`, or answered
    /// without one (its tile is its look). The sample sends no icons, so it never counts.
    fn icons_on_screen(&self) -> bool {
        let Some(link) = self.link.as_ref().filter(|l| l.live()) else {
            return false;
        };
        let pr = &self.model.programs;
        let l = &self.view.list;
        if !(l.row_h > 0.0 && l.offset.is_finite()) {
            return false;
        }
        let first = (l.offset / l.row_h).floor().max(0.0) as usize;
        let end = ((l.offset + l.area.h) / l.row_h).ceil().max(0.0) as usize;
        let end = end.min(pr.rows.len());
        first < end
            && pr.rows[first..end].iter().all(|&i| {
                let p = &pr.all[i];
                p.icon.is_some() || link.icon_settled(&p.id)
            })
    }

    /// `--bench-exit` after the end marker: closes once no live icon load runs, or at its time.
    /// True when it closed.
    fn bench_close(&mut self, cx: &mut Cx<'_, ()>, now: Instant) -> bool {
        let Some(at) = self.close_after_icons else {
            return false;
        };
        let loading = self
            .link
            .as_ref()
            .is_some_and(|l| l.live() && l.icons_loading());
        if loading && now < at {
            return false;
        }
        self.close_after_icons = None;
        if let Some(link) = &mut self.link {
            link.save_icons();
        }
        cx.exit();
        true
    }

    // ---- accessibility -----------------------------------------------------------------------

    fn signature(&self) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for c in &self.ctls {
            c.id.hash(&mut h);
            for v in [c.rect.x, c.rect.y, c.rect.w, c.rect.h] {
                v.to_bits().hash(&mut h);
            }
            c.label.hash(&mut h);
            format!("{:?}", c.role).hash(&mut h);
            (c.disabled, c.modal).hash(&mut h);
        }
        let pr = &self.model.programs;
        pr.rows.hash(&mut h);
        // A row's name changes with what the engine learns of it (a late patch, its kind).
        for &i in &pr.rows {
            pr.all[i].accessible.hash(&mut h);
        }
        for r in pr.sel.ranges() {
            (r.start, r.end).hash(&mut h);
        }
        pr.sel.cursor().hash(&mut h);
        self.view.list.offset.to_bits().hash(&mut h);
        self.focus.focused().hash(&mut h);
        h.finish()
    }

    fn node_of(c: &Ctl) -> accesskit::Node {
        let author = c.id.author();
        let (label, r) = (c.label.as_str(), c.rect);
        match &c.role {
            Role::Button => a11y::button(label, &author, r, c.disabled),
            Role::Link => a11y::link(label, &author, r, c.disabled),
            Role::Check(on) => a11y::check_box(label, &author, r, *on, c.disabled),
            Role::Switch(on) => a11y::switch(label, &author, r, *on, c.disabled),
            Role::Combo { value, open } => {
                let mut n = a11y::combo_box(label, &author, r, value, *open);
                // UI-FULLFROST: a drop-down that waits (the backdrop's cover, with none).
                if c.disabled {
                    n.set_disabled();
                    n.clear_actions();
                }
                n
            }
            // Its place in its row of tabs is set by `build_tree`, which knows the row.
            Role::Tab(on) => a11y::tab(label, &author, r, *on, 0),
            Role::Expander(open) => a11y::expander(label, &author, r, *open),
            Role::Text | Role::List => a11y::text(label, &author, r),
            Role::Edit(value) => a11y::text_input(label, &author, r, value, false),
            Role::Progress(f) => a11y::progress(label, &author, r, *f),
            // UI-FULLFROST.
            Role::Slider(v) => slider_node(label, &author, r, *v, c.disabled),
            Role::Item(on) => {
                let mut n = a11y::button(label, &author, r, c.disabled);
                n.set_role(accesskit::Role::ListBoxOption);
                n.set_selected(*on);
                n
            }
        }
    }

    /// Adds what the last frame declared to the host's tree and answers the node that has the
    /// keyboard. The host begins and ends the tree.
    fn build_tree(&self, tree: &mut a11y::Tree, title: &str, scale: f32) -> accesskit::NodeId {
        let overlay = self.overlay();
        let mut seen: HashSet<accesskit::NodeId> = HashSet::new();
        let mut top = Vec::new();
        let mut inside = Vec::new();
        let mut dialog_rect: Option<Rect> = None;
        let mut focus = tree.root();
        let focused = self.focus.focused();
        // The two rows of tabs: the rail's pages and the Programs page's filters. Each is one
        // tab list, which is where a reader's "2 of 6" comes from.
        let mut rows: [TabRow; 2] = [
            TabRow::new("Pages", "NavView"),
            TabRow::new("Show", "ProgramTabs"),
        ];
        for c in &self.ctls {
            let nid = a11y::id(&c.id.author());
            if !seen.insert(nid) {
                continue;
            }
            if c.role == Role::List && c.id == LIST {
                let pr = &self.model.programs;
                let l = a11y::List {
                    label: "Programs",
                    author: LIST.0,
                    area: c.rect,
                    row_h: self.view.list.row_h,
                    count: pr.rows.len(),
                    scroll: self.view.list.offset,
                    multiselect: true,
                };
                let list = a11y::list(tree, &l, |i| {
                    let g = &pr.all[pr.rows[i]];
                    a11y::Row {
                        key: pr.rows[i],
                        label: g.accessible.clone(),
                        author: String::new(),
                        selected: pr.sel.contains(i),
                    }
                });
                // Each row holds its two lines as one text, as the WinUI row's TextBlocks read
                // ("Name[  new]\nPublisher · Kind"): the rig finds a program's row by it.
                for (i, at) in pr.rows.iter().enumerate() {
                    let g = &pr.all[*at];
                    let row = a11y::item_id(list, *at);
                    let text = a11y::id(&format!("{}.Text.{at}", LIST.0));
                    let r = Rect::new(
                        c.rect.x,
                        c.rect.y + i as f32 * self.view.list.row_h,
                        c.rect.w,
                        self.view.list.row_h,
                    );
                    tree.add(text, a11y::text(&g.row_text, "", r));
                    if let Some(n) = tree.get_mut(row) {
                        n.push_child(text);
                    }
                }
                if overlay && let Some(n) = tree.get_mut(list) {
                    n.set_hidden();
                }
                if focused == Some(LIST) {
                    focus = match pr.sel.cursor().and_then(|r| pr.rows.get(r)) {
                        Some(key) => a11y::item_id(list, *key),
                        None => list,
                    };
                }
                top.push(list);
                continue;
            }
            let mut node = Self::node_of(c);
            if focused == Some(c.id) {
                focus = nid;
            }
            if matches!(c.role, Role::Tab(_)) && !c.modal {
                let row = &mut rows[usize::from(screens::programs_tab(c.id).is_some())];
                node.set_position_in_set(row.tabs.len());
                if overlay {
                    node.set_hidden();
                }
                if row.tabs.is_empty() {
                    // The row stands where its first tab was declared.
                    top.push(a11y::id(row.author));
                }
                row.add(nid, c.rect);
                tree.add(nid, node);
                continue;
            }
            if c.modal {
                dialog_rect = Some(match dialog_rect {
                    Some(d) => {
                        let (x0, y0) = (d.x.min(c.rect.x), d.y.min(c.rect.y));
                        let (x1, y1) = (
                            d.right().max(c.rect.right()),
                            d.bottom().max(c.rect.bottom()),
                        );
                        Rect::new(x0, y0, x1 - x0, y1 - y0)
                    }
                    None => c.rect,
                });
                inside.push(nid);
            } else {
                if overlay {
                    node.set_hidden();
                }
                top.push(nid);
            }
            tree.add(nid, node);
        }
        for row in rows {
            if row.tabs.is_empty() {
                continue;
            }
            let mut n = a11y::tab_list(row.label, row.author, row.rect, row.tabs);
            if overlay {
                n.set_hidden();
            }
            tree.add(a11y::id(row.author), n);
        }
        if !inside.is_empty() {
            let what = if let Some(c) = &self.model.flow.confirm {
                c.dialog.title.clone()
            } else if self.model.flow.elevation.showing().is_some() {
                screens::ELEVATION_TITLE.to_string()
            } else if let Some(t) = &self.model.flow.takeover {
                screens::takeover_title(t)
            } else {
                "Commands".to_string()
            };
            let did = a11y::id("ContentDialog");
            let r = dialog_rect.unwrap_or_default();
            tree.add(did, a11y::dialog(&what, "ContentDialog", r, true, inside));
            top.push(did);
        }
        let root = tree.root();
        tree.add(root, a11y::window(title, scale, top));
        focus
    }

    fn request(&mut self, cx: &mut Cx<'_, ()>, req: accesskit::ActionRequest) {
        let find = |app: &PurgeApp, node: accesskit::NodeId| {
            app.ctls
                .iter()
                .find(|c| a11y::id(&c.id.author()) == node)
                .cloned()
        };
        let row_of = |app: &PurgeApp, node: accesskit::NodeId| {
            let pr = &app.model.programs;
            let key = a11y::key_of(LIST.0, pr.all.len(), node)?;
            pr.rows.iter().position(|r| *r == key)
        };
        cx.request_redraw_all();
        match a11y::request(req) {
            a11y::Request::Click(node) => {
                if let Some(c) = find(self, node) {
                    if c.disabled || (self.overlay() && !c.modal) {
                        return;
                    }
                    if let Role::Combo { .. } = c.role {
                        if let Some(d) = self.view.dds.get(c.id) {
                            d.open_menu(c.rect);
                        }
                    } else {
                        self.activate(cx, c.id);
                    }
                } else if let Some(row) = row_of(self, node) {
                    // Select: that row only; a click on a selected row keeps it selected.
                    if !self.model.programs.sel.contains(row) {
                        self.model.programs.sel.select_only(row);
                    }
                    self.view.list.reveal(row);
                }
            }
            a11y::Request::Focus(node) => {
                if let Some(c) = find(self, node) {
                    if c.focusable {
                        self.focus.focus(c.id);
                    }
                } else if let Some(row) = row_of(self, node) {
                    self.focus.focus(LIST);
                    self.model.programs.sel.set_cursor(row);
                }
            }
            a11y::Request::ScrollIntoView(node) => {
                if let Some(row) = row_of(self, node) {
                    self.view.list.reveal(row);
                }
            }
            a11y::Request::Expand(node) | a11y::Request::Collapse(node) => {
                if let Some(c) = find(self, node) {
                    match c.role {
                        Role::Expander(_) => self.activate(cx, c.id),
                        Role::Combo { open, .. } => {
                            if let Some(d) = self.view.dds.get(c.id) {
                                if open {
                                    d.close();
                                } else {
                                    d.open_menu(c.rect);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            a11y::Request::SetValue(node, text) if a11y::id(&SEARCH.author()) == node => {
                self.view.search.set_text(&text);
                self.model.programs.set_query(&text);
                self.view.list.jump_top();
            }
            // UI-FULLFROST: the strength slider's RangeValue.
            other => self.slider_request(cx, other),
        }
    }
}

fn screens_tab_index(name: &str) -> usize {
    screens::TAB_NAMES
        .iter()
        .position(|n| *n == name)
        .unwrap_or(0)
}

// ---- UI-PAGES2: what the History and Quarantine pages' controls do -----------------------------

impl PurgeApp {
    /// A click on a control of the History or Quarantine page; false when `name` is not one.
    fn pages_activate(&mut self, cx: &mut Cx<'_, ()>, name: &'static str, n: usize) -> bool {
        // The rows act on what they showed when drawn (`Ctl::key`), not on a place in a list
        // that an answer may have changed since.
        let key = self.key_of(Id(name, n as u32));
        let h = &mut self.model.history;
        let q = &mut self.model.quarantine;
        match name {
            // History.
            "StripItem" | "Op" => {
                if let Some(Key::Session(id)) = key
                    && h.page.sessions().iter().any(|s| s.id == id)
                {
                    h.page.select(&id);
                    h.dismissed.clear();
                    self.view.page_scroll = scroll::SmoothScroll::new();
                }
            }
            "ShowItems" => {
                h.dismissed.clear();
                let r = h.page.show_items();
                h.take(r);
            }
            "DItemTick" => {
                let item = match key {
                    Some(Key::Op(op)) => h
                        .page
                        .items()
                        .and_then(|i| i.iter().find(|e| e.op == op))
                        .map(|e| (e.op, e.checked)),
                    _ => None,
                };
                if let Some((op, checked)) = item {
                    h.page.set_checked(op, !checked);
                }
            }
            "RestoreSelected" | "RestoreAll" => {
                h.dismissed.clear();
                let r = h.page.restore(name == "RestoreAll");
                h.take(r);
            }
            "CheckInterrupted" => {
                h.dismissed.clear();
                let r = h.page.check_interrupted();
                h.take(r);
            }
            "RecoverResume" | "RecoverRollBack" => {
                h.dismissed.clear();
                let r = h.page.recover(name == "RecoverRollBack");
                h.take(r);
            }
            "StateRetry" => {
                let r = h.page.load();
                h.take(r);
            }
            // By the bar it showed (`Ctl::key`), never by its place among the bars.
            "HBarClose" => {
                if let Some(Key::Bar(said)) = key
                    && h.page
                        .bars()
                        .iter()
                        .any(|b| format!("{} {}", b.title, b.message) == said)
                {
                    h.dismissed.push(said);
                }
            }

            // Quarantine.
            "Batch" => {
                let id = match key {
                    Some(Key::Session(id)) if q.page.batches().iter().any(|b| b.id == id) => {
                        Some(id)
                    }
                    _ => None,
                };
                if id.is_some() && id != q.selected {
                    q.selected = id;
                    q.flyout = None;
                    self.view.page_scroll = scroll::SmoothScroll::new();
                    if q.page.items_for() != q.selected.as_ref() {
                        q.page.close_items();
                    }
                }
            }
            "VRestore" => {
                if let Some(id) = q.selected.clone() {
                    let r = q.page.restore(&id);
                    q.take(r);
                }
            }
            "VChooseItems" => {
                if let Some(id) = q.selected.clone() {
                    let r = q.page.show_items(&id);
                    q.take(r);
                }
            }
            "VDeleteNow" => {
                q.flyout = match (&q.flyout, q.selected.clone()) {
                    (Some(_), _) | (_, None) => None,
                    (None, Some(session)) => Some(DeleteFlyout {
                        session,
                        also_backups: false,
                    }),
                };
            }
            "AlsoBackups" => {
                if let Some(f) = &mut q.flyout {
                    f.also_backups = !f.also_backups;
                }
            }
            "FlyoutContinue" => {
                if let Some(f) = q.flyout.take() {
                    let r = q.page.delete_now(&f.session, f.also_backups);
                    q.take(r);
                }
            }
            "FlyoutCancel" => q.flyout = None,
            "ItemsClose" => q.page.close_items(),
            "ItemDelete" => {
                // `delete_item_now` checks the id is still one of the items shown.
                if let Some(Key::Expiry(id)) = key {
                    let r = q.page.delete_item_now(id);
                    q.take(r);
                }
            }
            "ReviewButton" | "BarReview" => {
                let r = q.page.review_expired();
                q.take(r);
            }
            "VDetails" | "BarOpenHistory" => self.go(Page::History),
            _ => return false,
        }
        cx.request_redraw_all();
        true
    }
}

impl App for PurgeApp {
    type Message = ();

    fn start(&mut self, cx: &mut Cx<'_, ()>) {
        markers::mark("window_ctor");
        // The engine starts with the window: its events wake the loop with an empty message.
        let proxy = cx.proxy();
        let mut link = Link::new(move || {
            proxy.send(());
        });
        link.start(&self.source);
        self.link = Some(link);
        self.view.blink = platform::caret_blink_time();
        self.retheme(cx);
        if self.remember_place {
            self.place = Some(Placer::start(cx, self.store.window()));
        }
        self.timers(cx);
    }

    fn message(&mut self, cx: &mut Cx<'_, ()>, _: ()) {
        self.pump(cx);
        // The bench's window waits for the icon load to end before it closes.
        if self.bench_close(cx, Instant::now()) {
            return;
        }
        // A dialog the link's answer opened or closed takes the keyboard now, not at the next
        // input event.
        self.sync_scope();
        self.timers(cx);
    }

    fn event(&mut self, cx: &mut Cx<'_, ()>, event: Event) {
        // What may change what the page shows has it drawn again while it comes in
        // (`View::page_dirty`): the pointer's moves and the timers say so themselves, the
        // modifiers alone change nothing, and the presses, releases and wheel turns on a page
        // still coming in are passed over (`blocked`).
        let blocked = match event {
            Event::PointerMove { .. } | Event::Wake(_) | Event::Modifiers(_) => false,
            Event::Press { x, y, .. } | Event::Release { x, y, .. } if self.blocked(cx, x, y) => {
                // Nothing pressed before goes on past a passed-over press or release: the
                // button, the list's drag (its scroll bar) and a drop-down's press all end here
                // (review N8), as when the window loses the focus.
                let mut ended = self.view.list.drag.take().is_some();
                for dd in DD_ALL {
                    if let Some(d) = self.view.dds.get(dd) {
                        ended |= d.cancel();
                    }
                }
                if self.pressed.take().is_some() || ended {
                    self.view.page_dirty = true;
                    cx.request_redraw_all();
                }
                true
            }
            Event::Wheel { .. } if self.blocked(cx, self.pointer.0, self.pointer.1) => true,
            _ => {
                self.view.page_dirty = true;
                false
            }
        };
        match event {
            _ if blocked => {}
            Event::PointerMove { x, y } => self.pointer_move(cx, x, y),
            Event::PointerLeave => {
                // Gone: the end of a page switch has nothing to look under.
                self.pointer = (-1.0, -1.0);
                if self.hover.is_some() || self.view.list.hot.is_some() {
                    self.hover = None;
                    self.view.list.hot = None;
                    self.view.list.bar_hot = false;
                    cx.request_redraw_all();
                }
            }
            Event::Press {
                x,
                y,
                button: Button::Left,
                clicks,
            } => self.press(cx, x, y, clicks),
            Event::Release {
                x,
                y,
                button: Button::Left,
            } => self.release(cx, x, y),
            Event::Wheel { dy, .. } => self.wheel(cx, dy),
            Event::Key(k) => self.key(cx, k),
            Event::Text(t) => {
                if let Some(p) = &mut self.view.palette {
                    let o = p.key(&KeyName::Char(' '), Mods::default(), Some(&t));
                    self.palette_outcome(cx, o);
                } else if self.focus.is_focused(SEARCH) && self.view.search.insert(&t) {
                    let q = self.view.search.text().to_string();
                    self.model.programs.set_query(&q);
                    cx.request_redraw_all();
                }
            }
            Event::Focus(on) => {
                if !on {
                    self.pressed = None;
                    self.view.list.drag = None;
                    for dd in DD_ALL {
                        if let Some(d) = self.view.dds.get(dd) {
                            d.cancel();
                        }
                    }
                }
                cx.request_redraw_all();
            }
            Event::Theme { .. } | Event::Contrast(_) => self.retheme(cx),
            Event::Wake(now) => self.wake(cx, now),
            Event::CloseRequested => self.close(cx),
            Event::Action(req) => self.request(cx, req),
            _ => {}
        }
        self.pump(cx);
        self.sync_scope();
        if let Some(place) = &mut self.place {
            place.watch(cx, cx.now());
        }
        self.timers(cx);
    }

    fn draw(&mut self, cx: &mut Cx<'_, ()>, p: &mut Painter, _damage: Rect) {
        let began = Instant::now();
        if let Some(place) = &mut self.place {
            place.drawn(cx);
        }
        let size = cx.size();
        // UI-FULLFROST: where this frame draws (`glass`).
        self.view.glass.begin(p);
        self.focus.begin_frame();
        let switching = self.view.page_tx.running();
        let ctls = {
            let mut ui = Ui {
                p: &mut *p,
                cx: &mut *cx,
                pal: self.pal,
                look: Look::of(self.model.prefs.design),
                hc: self.hc,
                link_ink: self.link_ink,
                focus: &mut self.focus,
                ctls: Vec::with_capacity(160),
                hover: self.hover,
                pressed: self.pressed,
                modal: false,
                size,
            };
            screens::draw(&mut ui, &self.model, &mut self.view);
            ui.ctls
        };
        self.focus.end_frame();
        self.ctls = ctls;
        if self.script.is_some() && self.paint_check.is_none() {
            self.paint_check = Some(crate::paint::self_check(p));
        }
        // The pointer was not followed over the page while it came in (`blocked`): what is
        // under it now is hot.
        if switching && !self.view.page_tx.running() {
            let (x, y) = self.pointer;
            if x >= 0.0 && y >= 0.0 {
                self.pointer_move(cx, x, y);
            }
        }

        // The host reads the tree after the frame, so what this frame declared can be said
        // from here.
        let sig = self.signature();
        if sig != self.tree_sig {
            self.tree_sig = sig;
            cx.accessibility_changed();
        }
        if let Some(path) = self.shot.take() {
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            match p.bmp.write_png(&path) {
                Ok(()) => println!("shot: {}", path.display()),
                Err(e) => println!("shot failed: {}: {e}", path.display()),
            }
            if cx.frosted() {
                let over = path.with_extension("over-desktop.png");
                let mut shot = p.bmp.clone();
                let keys = self.glass_keys();
                over_desktop(&mut shot.pixels, shot.width as usize, &keys);
                match shot.write_png(&over) {
                    Ok(()) => println!("shot over a made-up desktop: {}", over.display()),
                    Err(e) => println!("shot failed: {}: {e}", over.display()),
                }
            } else if self.model.prefs.backdrop != Backdrop::Off && self.script.is_none() {
                println!("shot: the chrome was not frosted (no keyboard, or no backdrop here)");
            }
        }
        // UI-FULLFROST: the marked pixels keyed with the user's strength, the frame as drawn
        // kept for the next (`glass`). After the shot: it is the frame as drawn.
        let keys = cx.frosted().then(|| self.glass_keys());
        let lk = Look::of(self.model.prefs.design);
        let areas = crate::glass::areas(self.model.prefs.glass.covers, lk.title_h, lk.rail_w, size);
        let areas: Vec<Rect> = areas.into_iter().flatten().collect();
        self.view.glass.end(p, keys.as_ref(), &areas);
        if crate::transition::logging() {
            self.log_draw(began.elapsed().as_secs_f64() * 1000.0, switching);
        }
        self.frames += 1;
        // The launch markers at the moments they name: `first_tick` when the first frame is
        // drawn; `rows_set` and `first_row` when a frame first draws the list's rows (the first
        // frame itself when the list came first); `presented` on the next wake, once the host has
        // presented the first frame; `names_visible` once a frame with the rows is presented.
        // `icons_visible` (a live engine only) once a frame drew the rows on screen with their icons
        // settled. All of this before the first frame's deferred work below changes the model.
        let bench = markers::enabled() || self.bench_exit;
        let rows_now = !self.rows_drawn
            && self.model.programs.loaded
            && self.model.page == Page::Programs
            && !self.model.programs.rows.is_empty();
        let icons_now = bench
            && !self.icons_drawn
            && (self.rows_drawn || rows_now)
            && self.model.page == Page::Programs
            && self.icons_on_screen();
        if icons_now {
            self.icons_drawn = true;
            self.icons_due = true;
        }
        if self.frames == 1 {
            markers::mark("first_tick");
            self.presented_due = bench;
            if self.bench_exit && self.bench_until != BenchUntil::Presented {
                self.bench_deadline = Some(Instant::now() + markers::BENCH_TIMEOUT);
            }
            // The model's deferred work (sizes, icons, the removed group) waits for this frame.
            let r = self.model.programs.page.on_first_frame();
            self.model.programs.take(r);
            cx.request_redraw_all();
        }
        if rows_now {
            self.rows_drawn = true;
            let at = markers::mark("rows_set");
            markers::record("first_row", at);
            // Rows in the first frame are visible when it is presented; later ones need a
            // presentation of their own. Off the bench nothing waits for it.
            self.names_due = bench && self.frames > 1;
        }
        if self.frames == 1 {
            self.view.first_frame_ms = Some(self.launched.elapsed().as_secs_f64() * 1000.0);
            println!(
                "first-frame: {:.1} ms after main began ({} x {} at scale {})",
                self.launched.elapsed().as_secs_f64() * 1000.0,
                size.0,
                size.1,
                cx.scale()
            );
        }
        self.timers(cx);
    }

    fn accessibility(&mut self, cx: &mut Cx<'_, ()>, tree: &mut a11y::Tree) -> accesskit::NodeId {
        let title = cx.title().to_string();
        self.build_tree(tree, &title, cx.scale())
    }
}

/// `--shot`: what the compositor would show of a frosted frame laid over a desktop, for a look
/// at the chrome over a backdrop without one. The marked chrome is keyed out as the host does
/// when it presents (`frost::key_out`), then laid over a made-up "desktop": a smooth diagonal of
/// strong colours, about what Acrylic's blur makes of a busy screen behind the window (Mica's
/// tinted wallpaper is much flatter, so this is the harder case for it). `pixels` are BGRA.
/// UI-FULLFROST: keyed as the window is (`glass::Keys`: the user's strength, the whole window
/// when it covers it).
fn over_desktop(pixels: &mut [u8], width: usize, keys: &crate::glass::Keys) {
    if width == 0 {
        return;
    }
    let mut keyed = pixels.to_vec();
    crate::glass::key_copy(&mut keyed, keys);
    let px: Vec<u32> = keyed
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    let rows = px.len() / width;
    let span = (width + rows).max(1) as f32;
    for (i, (out, v)) in pixels.chunks_exact_mut(4).zip(px).enumerate() {
        let a = v >> 24;
        if a == 255 {
            continue;
        }
        let (x, y) = (i % width, i / width);
        let t = (x + y) as f32 / span;
        // Orange to teal, with a soft band across.
        let band = 0.5 + 0.5 * ((x as f32 / 90.0).sin() * (y as f32 / 70.0).cos());
        let d = [
            (230.0 * (1.0 - t) + 40.0 * t) * (0.8 + 0.2 * band),
            (120.0 * (1.0 - t) + 170.0 * t) * (0.8 + 0.2 * band),
            (40.0 * (1.0 - t) + 200.0 * t) * (0.8 + 0.2 * band),
        ];
        let keep = (255 - a) as f32 / 255.0;
        let c = [(v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff];
        let ch = |k: usize| (c[k] as f32 + keep * d[k]).round().min(255.0) as u8;
        out.copy_from_slice(&[ch(2), ch(1), ch(0), 255]);
    }
}

// ---- UI-FULLFROST: the backdrop's cover and strength ------------------------------------------

impl PurgeApp {
    /// The keys of the look in force (`glass::Keys`), made again when the palette or the
    /// setting changed.
    fn glass_keys(&mut self) -> crate::glass::Keys {
        let want = (self.pal, self.model.prefs.glass);
        match self.glass_keys {
            Some((pal, g, keys)) if (pal, g) == want => keys,
            _ => {
                let keys = crate::glass::Keys::new(&want.0, want.1.covers, want.1.strength);
                self.glass_keys = Some((want.0, want.1, keys));
                keys
            }
        }
    }

    pub fn set_covers(&mut self, cx: &mut Cx<'_, ()>, covers: crate::look::Covers) {
        let mut p = self.model.prefs;
        p.glass.covers = covers;
        self.set_prefs(cx, p);
    }

    pub fn set_strength(&mut self, cx: &mut Cx<'_, ()>, strength: u8) {
        let mut p = self.model.prefs;
        p.glass.strength = strength.min(100);
        self.set_prefs(cx, p);
    }

    /// The strength slider as the last frame declared it, if it can be used.
    fn strength_ctl(&self, id: Id) -> Option<Ctl> {
        self.ctl(id)
            .filter(|c| matches!(c.role, Role::Slider(_)) && !c.disabled)
            .cloned()
    }

    fn strength_slider(&self) -> mdshared_ui::slider::Slider {
        let v = f32::from(self.model.prefs.glass.strength);
        mdshared_ui::slider::Slider::new(0.0, 100.0, v).step(crate::glass::STEP)
    }

    /// With the slider's thumb in hand (pressed, or the press itself): the value under the
    /// pointer. False when no slider is held.
    fn slider_drag(&mut self, cx: &mut Cx<'_, ()>, x: f32, y: f32) -> bool {
        let Some(c) = self.pressed.and_then(|id| self.strength_ctl(id)) else {
            return false;
        };
        let v = self.strength_slider().value_at(c.rect, x, y);
        self.set_strength(cx, v.round() as u8);
        cx.request_redraw_all();
        true
    }

    /// The keys on the slider: the arrows a step of 5 %, Page Up and Down five steps, Home and
    /// End the ends.
    fn slider_key(&mut self, cx: &mut Cx<'_, ()>, id: Id, name: &KeyName) {
        use mdshared_ui::slider::Step;
        if self.strength_ctl(id).is_none() {
            return;
        }
        let step = match name {
            KeyName::Left | KeyName::Down => Step::Less,
            KeyName::Right | KeyName::Up => Step::More,
            KeyName::PageDown => Step::PageLess,
            KeyName::PageUp => Step::PageMore,
            KeyName::Home => Step::Min,
            KeyName::End => Step::Max,
            _ => return,
        };
        let mut s = self.strength_slider();
        if s.step_by(step) {
            self.set_strength(cx, s.value().round() as u8);
        }
    }

    /// What a reader asks of the slider: a value, or a step either way.
    fn slider_request(&mut self, cx: &mut Cx<'_, ()>, req: a11y::Request) {
        let (node, to) = match req {
            a11y::Request::SetNumber(node, v) => (node, Some(v)),
            a11y::Request::Other(r) => match r.action {
                accesskit::Action::Increment | accesskit::Action::Decrement => {
                    let mut s = self.strength_slider();
                    let up = r.action == accesskit::Action::Increment;
                    s.step_by(if up {
                        mdshared_ui::slider::Step::More
                    } else {
                        mdshared_ui::slider::Step::Less
                    });
                    (r.target_node, Some(f64::from(s.value())))
                }
                _ => return,
            },
            _ => return,
        };
        let usable = self
            .ctls
            .iter()
            .find(|c| a11y::id(&c.id.author()) == node)
            .and_then(|c| self.strength_ctl(c.id))
            .is_some();
        if let Some(v) = to.filter(|v| usable && v.is_finite()) {
            self.set_strength(cx, v.round().clamp(0.0, 100.0) as u8);
        }
    }
}

/// The slider's node: UIA RangeValue from 0 to 100 in steps of 5, settable, with Increment and
/// Decrement.
fn slider_node(label: &str, author: &str, r: Rect, value: f32, disabled: bool) -> accesskit::Node {
    let mut n = accesskit::Node::new(accesskit::Role::Slider);
    n.set_label(label);
    n.set_author_id(author);
    n.set_bounds(a11y::bounds(r));
    n.set_min_numeric_value(0.0);
    n.set_max_numeric_value(100.0);
    n.set_numeric_value_step(f64::from(crate::glass::STEP));
    n.set_numeric_value_jump(f64::from(crate::glass::STEP) * 5.0);
    n.set_numeric_value(f64::from(value));
    n.set_value(format!("{value:.0}%"));
    if disabled {
        n.set_disabled();
    } else {
        n.add_action(accesskit::Action::SetValue);
        n.add_action(accesskit::Action::Increment);
        n.add_action(accesskit::Action::Decrement);
        n.add_action(accesskit::Action::Focus);
    }
    n
}
