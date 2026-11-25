//! The application the host runs: it turns the host's events into changes of the model, and
//! draws the model. The toolkit's widgets call nothing back, so every reaction is here: a press
//! or a key finds the control it is for in the list the last frame declared, and `activate`
//! says what that control does.

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use mdshared_ui::a11y::{self, accesskit};
use mdshared_ui::cursor::Cursor;
use mdshared_ui::dropdown::Outcome as DdOutcome;
use mdshared_ui::focus::Focus;
use mdshared_ui::gfx::{Painter, Rect, Rgb, rgb};
use mdshared_ui::host::{App, Button, Cx, Event, KeyPress};
use mdshared_ui::keys::{KeyName, Mods};
use mdshared_ui::palette::{Entry, Outcome as PaletteOutcome, Palette as CommandPalette};
use mdshared_ui::platform;
use mdshared_ui::rows::Nav;
use mdshared_ui::scroll;
use mdshared_ui::segments;
use mdshared_ui::select::TypeAhead;
use mdshared_ui::theme::Palette;
use mdshared_ui::tokens::Tokens;

use crate::model::{
    Design, KEEP_DAYS, LeftoverPhase, Model, Page, RunPhase, SortKey, Tab, ThemeChoice,
};
use crate::screens::{self, NAV, nav_id};
use crate::script::Script;
use crate::ui::{Ctl, Id, Look, Role, SCOPE, Ui, id};
use crate::view::{DD_ALL, DD_DESIGN, DD_KEEP, DD_RESTORE, DD_SORT, DD_THEME, Toast, View};

const LIST: Id = Id("ProgramList", 0);
const SEARCH: Id = Id("SearchBox", 0);

/// What the command line asked for.
pub struct Options {
    pub design: Design,
    /// Close after this many seconds (for a run with nobody at the keyboard).
    pub seconds: Option<u64>,
    /// Run the built-in walk through the screens, by made-up events.
    pub script: bool,
    /// Where the walk writes a PNG of each step, if anywhere.
    pub shots: Option<PathBuf>,
    pub theme: ThemeChoice,
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
    pub pal: Palette,
    pub hc: bool,
    link_ink: Option<Rgb>,
    pointer: (f32, f32),
    type_ahead: TypeAhead,
    /// What the last frame declared, as one number: the accessibility tree is asked for again
    /// when a frame declares something else.
    tree_sig: u64,
    pipeline_due: Option<Instant>,
    until: Option<Instant>,
    launched: Instant,
    frames: u32,
    pub script: Option<Script>,
    /// The file the next frame is written to.
    pub shot: Option<PathBuf>,
    /// For the script: the modifiers a made-up click is held with, and high contrast as if the
    /// system had switched it on.
    pub fake_mods: Option<Mods>,
    pub hc_forced: Option<bool>,
    /// For the script: what a step's act leaves for its check.
    pub note: String,
    pub visited: Vec<Id>,
}

impl PurgeApp {
    pub fn new(o: Options) -> PurgeApp {
        let mut model = Model::new(o.design);
        model.settings.theme = o.theme;
        PurgeApp {
            model,
            view: View::new(),
            focus: Focus::new(),
            ctls: Vec::new(),
            hover: None,
            pressed: None,
            pal: mdshared_ui::theme::LIGHT,
            hc: false,
            link_ink: None,
            pointer: (-1.0, -1.0),
            type_ahead: TypeAhead::new(),
            tree_sig: 0,
            pipeline_due: None,
            until: o.seconds.map(|s| o.launched + Duration::from_secs(s)),
            launched: o.launched,
            frames: 0,
            script: o.script.then(|| Script::new(o.shots.clone())),
            shot: None,
            fake_mods: None,
            hc_forced: None,
            note: String::new(),
            visited: Vec::new(),
        }
    }

    // ---- the look ----------------------------------------------------------------------------

    /// Makes the palette again from the system (light or dark, high contrast, the accent) and
    /// the Settings page's choice.
    fn retheme(&mut self, cx: &mut Cx<'_, ()>) {
        let hc = self.hc_forced.unwrap_or(cx.high_contrast());
        let dark = match self.model.settings.theme {
            ThemeChoice::System => platform::system_is_dark(),
            ThemeChoice::Light => false,
            ThemeChoice::Dark => true,
        };
        let tokens = if hc {
            Tokens::high_contrast_with(platform::system_contrast_colors().as_ref(), dark)
        } else {
            let t = Tokens::new(dark);
            match (self.model.design, platform::system_accent()) {
                // D3 has a colour of its own.
                (Design::Bold, _) => t.with_accent(rgb(if dark { 0xB8A2FF } else { 0x6B4DE6 })),
                (_, Some(accent)) => t.with_accent(accent),
                _ => t,
            }
        };
        self.pal = tokens.palette;
        self.hc = hc;
        // A contrast theme names its own colour for links.
        self.link_ink = if hc {
            platform::system_contrast_colors().map(|c| c.hot_light)
        } else {
            None
        };
        cx.set_dark(dark);
        cx.set_backdrop(screens::backdrop_of(self.model.design), &self.pal);
        cx.request_redraw_all();
    }

    pub fn set_design(&mut self, cx: &mut Cx<'_, ()>, design: Design) {
        if self.model.design == design {
            return;
        }
        self.model.design = design;
        self.retheme(cx);
        self.toast(cx, design.title());
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
        self.model.confirm.is_some() || self.view.palette.is_some()
    }

    pub fn ctl(&self, id: Id) -> Option<&Ctl> {
        self.ctls.iter().rev().find(|c| c.id == id)
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
        if want && !open {
            if self.model.confirm.is_some() {
                self.focus.push_scope_on(SCOPE, id("CloseButton"));
            } else {
                self.focus.push_scope(SCOPE);
            }
        } else if !want && open {
            self.focus.pop_scope();
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
        }
    }

    fn ask_uninstall(&mut self, cx: &mut Cx<'_, ()>) {
        if !self.model.ask_uninstall() {
            self.toast(cx, "Select a program first.");
        }
    }

    /// A click, or Enter or Space, on the control `id`.
    pub fn activate(&mut self, cx: &mut Cx<'_, ()>, id: Id) {
        let now = cx.now();
        let n = id.1 as usize;
        if let Some((page, _)) = NAV.iter().find(|(_, name)| *name == id.0) {
            self.go(*page);
            cx.request_redraw_all();
            return;
        }
        match id.0 {
            "DesignChip" => self.set_design(cx, self.model.design.next()),
            "Minimize" => cx.minimize(),
            "Maximize" => cx.toggle_maximize(),
            "Close" => cx.exit(),

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
                self.model.programs.only_junk = !self.model.programs.only_junk;
                self.model.programs.refresh();
                self.view.list.jump_top();
            }
            "UninstallButton" | "DUninstallButton" => self.ask_uninstall(cx),
            "Commands" => self.toast(cx, "Open folder and web site: the mockup opens nothing."),
            "DLocationText" => self.toast(
                cx,
                "Would open the folder in File Explorer. The mockup opens nothing.",
            ),
            "Commands.Expander" => self.view.commands_open = !self.view.commands_open,

            // The confirmation.
            "PrimaryButton" => {
                self.close_dropdowns();
                self.model.confirm_uninstall(now);
            }
            "SecondaryButton" => {
                self.model.pipeline.still_running = false;
                self.toast(cx, "Checked again: firefox.exe is no longer running.");
            }
            "CloseButton" => {
                self.close_dropdowns();
                self.model.cancel_confirm();
            }
            "QuietSwitch" => self.model.pipeline.quiet = !self.model.pipeline.quiet,

            // The pipeline.
            "NextButton" => {
                let finished = self
                    .model
                    .pipeline
                    .run
                    .as_ref()
                    .is_some_and(|r| r.phase == RunPhase::Finished);
                if finished && self.model.leftovers.phase == LeftoverPhase::Review {
                    self.go(Page::Leftovers);
                } else if !self.model.pipeline.start_next(now) {
                    self.go(Page::Programs);
                }
            }
            "SkipButton" => {
                // Leaves the leftovers where they are and goes on with the queue.
                if self.model.leftovers.phase == LeftoverPhase::Review {
                    self.model.leftovers.done();
                }
                if !self.model.pipeline.start_next(now) {
                    self.model.pipeline.run = None;
                }
            }
            "GoPrograms" => self.go(Page::Programs),

            // Leftovers.
            "Group" => {
                if let Some(g) = self.model.leftovers.groups.get_mut(n.saturating_sub(1)) {
                    g.open = !g.open;
                }
            }
            "GroupTick" => self.model.leftovers.toggle_group(n.saturating_sub(1)),
            "Item" => self.model.leftovers.selected = Some(item_at(id.1)),
            "ItemTick" => {
                let at = item_at(id.1);
                self.model.leftovers.selected = Some(at);
                if !self.model.leftovers.toggle_item(at) {
                    self.toast(cx, "Protected: Purge never moves this.");
                }
            }
            "ExpandButton" => {
                let open = !self.model.leftovers.all_open();
                self.model.leftovers.set_all_open(open);
            }
            "WeakButton" => {
                let on = !self.model.leftovers.likely_ticked();
                self.model.leftovers.set_likely(on);
            }
            "DeleteAfterBox" => {
                self.model.leftovers.delete_after = !self.model.leftovers.delete_after
            }
            "MoveButton" => {
                if !self.model.leftovers.move_ticked() {
                    self.toast(cx, "Nothing is ticked.");
                }
            }
            "UndoAllButton" => {
                self.model.leftovers.undo();
            }
            "DoneButton" => {
                self.model.leftovers.done();
                if self.model.pipeline.queue.is_empty() {
                    self.model.pipeline.run = None;
                    self.go(Page::Programs);
                } else {
                    self.model.pipeline.start_next(now);
                    self.go(Page::Pipeline);
                }
            }
            "OpenHistory" => self.go(Page::History),
            "OpenVault" => self.go(Page::Quarantine),

            // History.
            "Op" | "StripItem" => {
                self.model.history.selected = n.saturating_sub(1);
                self.view.page_scroll = scroll::SmoothScroll::new();
            }
            "ShowItems" => self.model.history.show_items = !self.model.history.show_items,
            "RestoreSelected" => {
                let i = self.model.history.selected;
                if !self.model.history.restore(i) {
                    self.toast(cx, "Nothing to restore for this entry.");
                }
            }
            "RestoreAll" => {
                if self.model.history.restore_all() == 0 {
                    self.toast(cx, "Nothing left to undo.");
                }
            }
            "CheckInterrupted" => self.model.history.checked = true,
            "NoticeClose" => self.model.history.notice = None,

            // Quarantine.
            "Batch" => self.model.quarantine.selected = n.saturating_sub(1),
            "ReviewButton" => self.model.quarantine.reviewing = !self.model.quarantine.reviewing,
            "EmptyNow" => self.toast(
                cx,
                "Emptying the quarantine deletes for good: not in the mockup.",
            ),

            // Settings.
            "ConfirmEach" => {
                // The confirmation cannot be switched off: the switch says so and stays on.
                self.toast(
                    cx,
                    "Purge always asks before an uninstall. This cannot be turned off.",
                );
            }
            "ShowComponents" => {
                self.model.settings.show_components = !self.model.settings.show_components
            }
            "SendNothing" => self.model.settings.send_nothing = !self.model.settings.send_nothing,
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
                    self.model.programs.sort_by(key);
                }
            }
            DD_THEME => {
                self.model.settings.theme = ThemeChoice::ALL[i.min(2)];
                self.retheme(cx);
            }
            DD_DESIGN => self.set_design(cx, Design::ALL[i.min(3)]),
            DD_KEEP => {
                self.model.settings.keep = i.min(KEEP_DAYS.len() - 1);
                self.model.quarantine.keep_days = KEEP_DAYS[self.model.settings.keep];
            }
            DD_RESTORE => self.model.pipeline.restore_mode = i.min(2),
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
            (2, "Design".to_string()),
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
        entries.push(
            Entry::new(22, "Review leftovers")
                .group(1)
                .enabled(self.model.leftovers.phase == LeftoverPhase::Review),
        );
        entries.push(Entry::new(23, "Theme: light").group(1));
        entries.push(Entry::new(24, "Theme: dark").group(1));
        entries.push(Entry::new(25, "Theme: use system setting").group(1));
        for (i, d) in Design::ALL.iter().enumerate() {
            entries.push(Entry::new(10 + i as u32, d.title()).group(2));
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
            10..=13 => self.set_design(cx, Design::ALL[command as usize - 10]),
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
            // In D2 the review is part of the pipeline page while its run is still shown.
            22 if self.model.design == Design::Flow && self.model.pipeline.run.is_some() => {
                self.go(Page::Pipeline)
            }
            22 => self.go(Page::Leftovers),
            23..=25 => {
                self.model.settings.theme =
                    [ThemeChoice::Light, ThemeChoice::Dark, ThemeChoice::System]
                        [command as usize - 23];
                self.retheme(cx);
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
            if y < Look::of(self.model.design).title_h && !self.overlay() {
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

        // Ctrl+Shift+D: the next design, whatever is open.
        if mods.ctrl && mods.shift && name == KeyName::Char('d') {
            self.view.palette = None;
            let next = self.model.design.next();
            return self.set_design(cx, next);
        }
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
                if self.model.confirm.is_some() {
                    self.model.cancel_confirm();
                } else if self.focus.is_focused(SEARCH) {
                    if self.view.search.is_empty() {
                        self.focus.focus(LIST);
                    } else {
                        self.view.search.clear();
                        self.model.programs.set_query("");
                    }
                } else if self.model.page == Page::Programs && !self.model.programs.sel.is_empty() {
                    self.model.programs.sel.clear();
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

    // ---- timers ------------------------------------------------------------------------------

    /// Asks for the earliest of the times still to come: the host gives one wake-up.
    fn timers(&mut self, cx: &mut Cx<'_, ()>) {
        let wakes = [
            self.pipeline_due,
            self.until,
            self.view.toast.as_ref().map(|t| t.until),
            self.script.as_ref().and_then(|s| s.due()),
        ];
        if let Some(at) = wakes.into_iter().flatten().min() {
            cx.wake_at(at);
        }
    }

    fn wake(&mut self, cx: &mut Cx<'_, ()>, now: Instant) {
        if self.until.is_some_and(|u| u <= now) {
            println!("purge-mockup: closing after the time asked for");
            cx.exit();
            return;
        }
        if self.pipeline_due.is_some_and(|d| d <= now) {
            self.pipeline_due = None;
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
            let go_on = script.step(self, cx, now);
            if go_on {
                self.script = Some(script);
            } else {
                cx.exit();
            }
        }
    }

    /// Moves the pipeline on to now and arms its next step.
    fn tick(&mut self, cx: &mut Cx<'_, ()>) {
        let (changed, next) = self.model.tick(cx.now());
        self.pipeline_due = next;
        if changed {
            cx.request_redraw_all();
        }
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
            Role::Combo { value, open } => a11y::combo_box(label, &author, r, value, *open),
            // Its place in its row of tabs is set by `build_tree`, which knows the row.
            Role::Tab(on) => a11y::tab(label, &author, r, *on, 0),
            Role::Expander(open) => a11y::expander(label, &author, r, *open),
            Role::Text | Role::List => a11y::text(label, &author, r),
            Role::Edit(value) => a11y::text_input(label, &author, r, value, false),
            Role::Progress(f) => a11y::progress(label, &author, r, *f),
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
                        label: format!(
                            "{}, {}, {}",
                            g.name,
                            g.publisher,
                            crate::model::size_text(g.size_mb)
                        ),
                        author: String::new(),
                        selected: pr.sel.contains(i),
                    }
                });
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
            let what = if self.model.confirm.is_some() {
                "Confirm uninstall"
            } else {
                "Commands"
            };
            let did = a11y::id("ContentDialog");
            let r = dialog_rect.unwrap_or_default();
            tree.add(did, a11y::dialog(what, "ContentDialog", r, true, inside));
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
            _ => {}
        }
    }
}

fn screens_tab_index(name: &str) -> usize {
    screens::TAB_NAMES
        .iter()
        .position(|n| *n == name)
        .unwrap_or(0)
}

/// A leftover item's place from its control's number: group and item.
pub fn item_at(n: u32) -> (usize, usize) {
    let n = n.saturating_sub(1) as usize;
    (n / 100, n % 100)
}

/// The number of the control of a leftover item.
pub fn item_no(group: usize, item: usize) -> u32 {
    (group * 100 + item + 1) as u32
}

impl App for PurgeApp {
    type Message = ();

    fn start(&mut self, cx: &mut Cx<'_, ()>) {
        self.view.blink = platform::caret_blink_time();
        self.retheme(cx);
        self.timers(cx);
    }

    fn event(&mut self, cx: &mut Cx<'_, ()>, event: Event) {
        match event {
            Event::PointerMove { x, y } => self.pointer_move(cx, x, y),
            Event::PointerLeave => {
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
            Event::CloseRequested => cx.exit(),
            Event::Action(req) => self.request(cx, req),
            _ => {}
        }
        self.tick(cx);
        self.sync_scope();
        self.timers(cx);
    }

    fn draw(&mut self, cx: &mut Cx<'_, ()>, p: &mut Painter, _damage: Rect) {
        let now = cx.now();
        let size = cx.size();
        self.focus.begin_frame();
        let ctls = {
            let mut ui = Ui {
                p: &mut *p,
                cx: &mut *cx,
                pal: self.pal,
                look: Look::of(self.model.design),
                hc: self.hc,
                link_ink: self.link_ink,
                focus: &mut self.focus,
                ctls: Vec::with_capacity(160),
                hover: self.hover,
                pressed: self.pressed,
                modal: false,
                now,
                size,
            };
            screens::draw(&mut ui, &self.model, &mut self.view);
            ui.ctls
        };
        self.focus.end_frame();
        self.ctls = ctls;

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
        }
        self.frames += 1;
        if self.frames == 1 {
            // The marker for the launch time: the first frame is drawn (it is presented next).
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
