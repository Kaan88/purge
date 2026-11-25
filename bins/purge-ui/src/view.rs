//! The window's own state: what the toolkit's widgets keep between frames (a text field's
//! caret, a table's column widths, a scroll offset on its way, an open drop-down), and where the
//! last frame put the things the pointer can take hold of. None of it is the application's data:
//! that is `model`.

use std::time::{Duration, Instant};

use mdshared_ui::dropdown::Dropdown;
use mdshared_ui::gfx::Rect;
use mdshared_ui::palette::Palette as CommandPalette;
use mdshared_ui::rows::Rows;
use mdshared_ui::scroll::SmoothScroll;
use mdshared_ui::table::{Align, Column, Table};
use mdshared_ui::textfield::TextField;

use mdshared_app::backdrop::Backdrop;

use crate::look::{Choice, Design, Preset, ThemeChoice, Transition};
use crate::model::{Model, Page, SortKey};
use crate::transition::PageSwitch;
use crate::ui::{Ctl, Id};

/// A list of rows of one height, scrolled: the scroll on its way and the last frame's place.
pub struct ListView {
    pub scroll: SmoothScroll,
    /// The viewport, as last drawn.
    pub area: Rect,
    pub row_h: f32,
    pub count: usize,
    /// The offset the last frame drew at.
    pub offset: f32,
    /// The scrollbar's track and thumb, as last drawn.
    pub bar: Option<(Rect, Rect)>,
    /// The thumb is held: how far below its top.
    pub drag: Option<f32>,
    /// The row under the pointer.
    pub hot: Option<usize>,
    pub bar_hot: bool,
}

impl ListView {
    pub fn new() -> ListView {
        ListView {
            scroll: SmoothScroll::new(),
            area: Rect::default(),
            row_h: 40.0,
            count: 0,
            offset: 0.0,
            bar: None,
            drag: None,
            hot: None,
            bar_hot: false,
        }
    }

    pub fn content(&self) -> f32 {
        self.count as f32 * self.row_h
    }

    /// The rows as the last frame drew them.
    pub fn rows(&self) -> Rows {
        Rows {
            row_h: self.row_h,
            view: self.area.h,
            count: self.count,
            scroll: self.offset,
        }
    }

    /// The rows where the scroll is going, for the keys: a second arrow press while the list
    /// still glides counts from where it will stop.
    pub fn rows_at_target(&self) -> Rows {
        Rows {
            scroll: self.scroll.target(),
            ..self.rows()
        }
    }

    pub fn row_at(&self, x: f32, y: f32) -> Option<usize> {
        if !self.area.contains(x, y) {
            return None;
        }
        self.rows().row_at(self.area, x, y)
    }

    pub fn wheel(&mut self, dy: f32) -> bool {
        self.scroll.scroll_by(-dy, self.content(), self.area.h)
    }

    pub fn reveal(&mut self, row: usize) {
        let to = self.rows_at_target().reveal(row);
        self.scroll.scroll_to(to, self.content(), self.area.h);
    }

    pub fn jump_top(&mut self) {
        self.scroll.jump_to(0.0, self.content(), self.area.h);
    }
}

/// The drop-downs. Each holds indices; the model holds what they mean.
pub struct Dropdowns {
    pub sort: Dropdown<usize>,
    pub theme: Dropdown<usize>,
    pub design: Dropdown<usize>,
    pub transition: Dropdown<usize>,
    pub preset: Dropdown<usize>,
    pub backdrop: Dropdown<usize>,
    pub restore: Dropdown<usize>,
}

pub const DD_SORT: Id = Id("SortButton", 0);
pub const DD_THEME: Id = Id("ThemeChoice", 0);
pub const DD_DESIGN: Id = Id("LookChoice", 0);
pub const DD_TRANSITION: Id = Id("TransitionChoice", 0);
pub const DD_PRESET: Id = Id("ColourChoice", 0);
pub const DD_BACKDROP: Id = Id("BackdropChoice", 0);
pub const DD_RESTORE: Id = Id("RestorePointBox", 0);
pub const DD_ALL: [Id; 7] = [
    DD_SORT,
    DD_THEME,
    DD_DESIGN,
    DD_TRANSITION,
    DD_PRESET,
    DD_BACKDROP,
    DD_RESTORE,
];

/// The titles of a choice, for its drop-down.
fn titles<C: Choice>() -> Vec<String> {
    C::ALL.iter().map(|c| c.title().to_string()).collect()
}

pub const RESTORE_MODES: [&str; 3] = ["Off", "High-risk changes only (default)", "Always"];

impl Dropdowns {
    fn new() -> Dropdowns {
        let of = |labels: Vec<String>| Dropdown::new(labels.into_iter().enumerate(), 0);
        Dropdowns {
            sort: of(SortKey::ALL
                .iter()
                .map(|s| format!("Sort: {}", s.title()))
                .collect()),
            theme: of(titles::<ThemeChoice>()),
            design: of(titles::<Design>()),
            transition: of(titles::<Transition>()),
            preset: of(titles::<Preset>()),
            backdrop: of(titles::<Backdrop>()),
            restore: of(RESTORE_MODES.iter().map(|s| s.to_string()).collect()),
        }
    }

    pub fn get(&mut self, id: Id) -> Option<&mut Dropdown<usize>> {
        match id {
            DD_SORT => Some(&mut self.sort),
            DD_THEME => Some(&mut self.theme),
            DD_DESIGN => Some(&mut self.design),
            DD_TRANSITION => Some(&mut self.transition),
            DD_PRESET => Some(&mut self.preset),
            DD_BACKDROP => Some(&mut self.backdrop),
            DD_RESTORE => Some(&mut self.restore),
            _ => None,
        }
    }

    /// The drop-down whose menu is open, if any.
    pub fn open(&self) -> Option<Id> {
        [
            (DD_SORT, &self.sort),
            (DD_THEME, &self.theme),
            (DD_DESIGN, &self.design),
            (DD_TRANSITION, &self.transition),
            (DD_PRESET, &self.preset),
            (DD_BACKDROP, &self.backdrop),
            (DD_RESTORE, &self.restore),
        ]
        .into_iter()
        .find(|(_, d)| d.is_open())
        .map(|(id, _)| id)
    }

    /// Shows what the model holds: the model changes by a key or a shortcut too.
    pub fn sync(&mut self, m: &Model) {
        let set = |d: &mut Dropdown<usize>, i: usize| {
            if d.selected() != Some(i) {
                d.select(i);
            }
        };
        set(&mut self.sort, m.programs.sort.index());
        set(&mut self.theme, m.prefs.theme.index());
        set(&mut self.design, m.prefs.design.index());
        set(&mut self.transition, m.prefs.transition.index());
        set(&mut self.preset, m.prefs.preset.index());
        set(&mut self.backdrop, Choice::index(m.prefs.backdrop));
        set(&mut self.restore, m.flow_restore_index());
    }
}

/// A short message at the bottom of the page that goes away by itself.
pub struct Toast {
    pub text: String,
    pub until: Instant,
}

pub struct View {
    pub search: TextField,
    /// The search field's caret stops, measured by the last frame.
    pub search_stops: Vec<f32>,
    /// The search field's text area, as last drawn.
    pub search_area: Rect,
    pub blink: Option<Duration>,
    pub table: Table,
    pub list: ListView,
    pub dds: Dropdowns,
    /// "Commands and registry key" in the details pane.
    pub commands_open: bool,
    /// The leftovers list's scroll.
    pub left_scroll: SmoothScroll,
    pub left_area: Rect,
    pub left_content: f32,
    /// A page's own scroll (Settings, History's detail), by page.
    pub page_scroll: SmoothScroll,
    pub page_area: Rect,
    pub page_content: f32,
    /// The page and design the last frame drew, to start a transition when they change.
    pub shown: Option<(Page, Design)>,
    pub page_tx: PageSwitch,
    /// While a page comes in (`page_tx`), the page is drawn once and laid over the old one
    /// from then on: what it shows changed since (an event, the engine), so the next frame
    /// draws it again; whether the last frame drew it; and the controls it declared when it
    /// was drawn, which stand for it in the frames that lay it.
    pub page_dirty: bool,
    pub page_drawn: bool,
    pub page_ctls: Vec<Ctl>,
    /// D2: the stage of the flow the last frame drew, and the push from one stage to the next.
    pub flow_shown: Option<usize>,
    pub flow_tx: PageSwitch,
    /// Settings: the transition's preview tile, which of its two pages it shows, and its switch.
    pub preview_b: bool,
    pub preview_shown: Option<bool>,
    pub preview_tx: PageSwitch,
    /// A development run (a debug build, or `--script`): the launch markers' expander shows.
    pub dev: bool,
    pub toast: Option<Toast>,
    /// D3's command palette, while open.
    pub palette: Option<CommandPalette>,
    /// When the dialog over the page opened, to let it rise into place.
    pub dialog_opened: bool,
    /// The confirmation's body: its scroll, area and height, while it is open. (When it was
    /// first drawn is the dialog's own, `flow::Confirm::opened`.)
    pub confirm_scroll: SmoothScroll,
    pub confirm_area: Rect,
    pub confirm_content: f32,
    /// The launch marker: ms from the start of `main` to the first frame drawn.
    pub first_frame_ms: Option<f64>,
}

impl View {
    pub fn new() -> View {
        let table = Table::new(vec![
            Column::new(0, "", 72.0).min(72.0).unsortable().fixed(),
            Column::new(1, "Name", 220.0).min(160.0).flex(1.0),
            Column::new(2, "Size", 100.0).align(Align::Right).fixed(),
            Column::new(3, "Expected leftovers", 214.0).fixed(),
            Column::new(4, "Installed", 108.0).fixed(),
        ]);
        View {
            search: TextField::new(),
            search_stops: Vec::new(),
            search_area: Rect::default(),
            blink: None,
            table,
            list: ListView::new(),
            dds: Dropdowns::new(),
            commands_open: true,
            left_scroll: SmoothScroll::new(),
            left_area: Rect::default(),
            left_content: 0.0,
            page_scroll: SmoothScroll::new(),
            page_area: Rect::default(),
            page_content: 0.0,
            shown: None,
            page_tx: PageSwitch::new("page"),
            page_dirty: false,
            page_drawn: true,
            page_ctls: Vec::new(),
            flow_shown: None,
            flow_tx: PageSwitch::new("flow"),
            preview_b: false,
            preview_shown: None,
            preview_tx: PageSwitch::new("preview"),
            dev: cfg!(debug_assertions),
            toast: None,
            palette: None,
            dialog_opened: false,
            confirm_scroll: SmoothScroll::new(),
            confirm_area: Rect::default(),
            confirm_content: 0.0,
            first_frame_ms: None,
        }
    }
}

/// The table's column for a sort key.
pub fn column_of(key: SortKey) -> u32 {
    match key {
        // Publisher has no column: the Name column (its second line) shows the arrow.
        SortKey::Name | SortKey::Publisher => 1,
        SortKey::Size => 2,
        SortKey::Junk => 3,
        SortKey::Date => 4,
    }
}
