//! The window's state: the page shown, and one model per page, with the rules that
//! change them. Nothing here draws, measures text or knows a rectangle;
//! `mdshared_ui::select::Selection` is the toolkit's own selection model (ranges of row
//! numbers), used so that the rules of click, Ctrl, Shift and the arrow keys are the toolkit's.
//!
//! **The Programs page is real (UI-WIRE).** [`Programs`] is `purge-ui-model`'s Programs model,
//! fed by the engine (or the sample engine) through `link`.
//!
//! **History and Quarantine are still the mockup's sample pages.**
//! [`History`] and [`Quarantine`] hold sample data that changes nothing: they are drawn only while
//! the window shows sample data ([`Model::sample`]); with the real engine those pages say they are
//! not available yet in this preview. Each page draws from one struct of its own, and the screens
//! read only those structs' fields and methods. That is the seam for the rest of wave 2
//! (UI-PAGES): each struct is fed from `purge-ui-model`'s view state and `purge-client`'s events,
//! and the drawing in `screens` stays as it is. The Uninstall and Leftovers pages are wired
//! (UI-FLOW, [`crate::flow`]): their entry is [`Model::open_uninstall`]. Their rules that
//! guard safety (Likely and Protected start unticked, nothing reaches the pipeline without the
//! confirmation) are the ones the real models must keep; the tests below say so.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use mdshared_ui::keys::Mods;
use mdshared_ui::select::Selection;
use purge_model::{InstallerKind, ProgramId};
use purge_ui_model::pipeline::UninstallTarget;
use purge_ui_model::programs::page::ProgramsRequest;
use purge_ui_model::programs::row::BAR_MAX;
use purge_ui_model::programs::strings as program_strings;
use purge_ui_model::programs::{
    Clock, EngineState, Filter, ForecastVerdict, ProgramCommand, ProgramIcon, ProgramRow,
    ProgramTab, ProgramsModel, ProgramsPageView, SortKey as ModelSort,
};

use crate::icons::AtlasIcon;
use crate::prefs::Prefs;

// ---- pages -----------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Page {
    Programs,
    Pipeline,
    Leftovers,
    History,
    Quarantine,
    Settings,
}

impl Page {
    pub const ALL: [Page; 6] = [
        Page::Programs,
        Page::Pipeline,
        Page::Leftovers,
        Page::History,
        Page::Quarantine,
        Page::Settings,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Page::Programs => "Programs",
            Page::Pipeline => "Uninstall pipeline",
            Page::Leftovers => "Leftovers",
            Page::History => "History & undo",
            Page::Quarantine => "Quarantine",
            Page::Settings => "Settings",
        }
    }

    pub fn index(self) -> usize {
        Page::ALL.iter().position(|p| *p == self).unwrap_or(0)
    }

    /// The WinUI app's key for the page (`--page`, the rail's tags).
    pub fn key(self) -> &'static str {
        match self {
            Page::Programs => "programs",
            Page::Pipeline => "queue",
            Page::Leftovers => "leftovers",
            Page::History => "history",
            Page::Quarantine => "vault",
            Page::Settings => "settings",
        }
    }

    /// The page with this key (any case).
    pub fn parse_key(s: &str) -> Option<Page> {
        let s = s.trim().to_ascii_lowercase();
        Page::ALL.into_iter().find(|p| p.key() == s)
    }
}

// ---- programs --------------------------------------------------------------------------------

/// What Purge expects a program to leave behind (the forecast's verdict, as the drawing needs it).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Expect {
    Clean,
    Some,
    Large,
    Unknown,
}

impl From<ForecastVerdict> for Expect {
    fn from(v: ForecastVerdict) -> Expect {
        match v {
            ForecastVerdict::Clean => Expect::Clean,
            ForecastVerdict::Some => Expect::Some,
            ForecastVerdict::Large => Expect::Large,
            ForecastVerdict::Unknown => Expect::Unknown,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Tab {
    Apps,
    Components,
    Unnamed,
    Recent,
}

impl Tab {
    pub const ALL: [Tab; 4] = [Tab::Apps, Tab::Components, Tab::Unnamed, Tab::Recent];

    pub fn title(self) -> &'static str {
        match self {
            Tab::Apps => "Apps",
            Tab::Components => "Components",
            Tab::Unnamed => "Unnamed",
            Tab::Recent => "Recent",
        }
    }

    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    fn of(tab: ProgramTab) -> Tab {
        match tab {
            ProgramTab::Apps => Tab::Apps,
            ProgramTab::Components => Tab::Components,
            ProgramTab::Unnamed => Tab::Unnamed,
            ProgramTab::Recent => Tab::Recent,
        }
    }

    fn model(self) -> ProgramTab {
        match self {
            Tab::Apps => ProgramTab::Apps,
            Tab::Components => ProgramTab::Components,
            Tab::Unnamed => ProgramTab::Unnamed,
            Tab::Recent => ProgramTab::Recent,
        }
    }
}

/// The list's sort: the Sort menu's items, in its order (the WinUI app's, with Publisher).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SortKey {
    Name,
    Publisher,
    Size,
    Junk,
    Date,
}

impl SortKey {
    pub const ALL: [SortKey; 5] = [
        SortKey::Name,
        SortKey::Publisher,
        SortKey::Size,
        SortKey::Junk,
        SortKey::Date,
    ];

    pub fn title(self) -> &'static str {
        program_strings::SORT_MENU[self.index()]
    }

    pub fn index(self) -> usize {
        SortKey::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    fn of(key: ModelSort) -> SortKey {
        match key {
            ModelSort::Name => SortKey::Name,
            ModelSort::Publisher => SortKey::Publisher,
            ModelSort::Size => SortKey::Size,
            ModelSort::Junk => SortKey::Junk,
            ModelSort::Date => SortKey::Date,
        }
    }

    fn model(self) -> ModelSort {
        ModelSort::MENU[self.index()]
    }
}

/// One row of the list as the drawing reads it: the texts `purge-ui-model`'s row made, and the
/// facts the details pane and the (sample) pipeline show.
#[derive(Clone, Debug)]
pub struct Program {
    pub id: ProgramId,
    pub name: String,
    pub publisher: String,
    /// The second line of the name cell: "Publisher · Kind".
    pub sub: String,
    /// Installed in the last three days: "new" after the name.
    pub new_tag: bool,
    /// The measured size in MB; 0 until measured.
    pub size_mb: f32,
    /// "312 MB"; empty until measured.
    pub size: String,
    /// The size bar's share of the largest program, 0 to 1.
    pub bar: f32,
    pub expect: Expect,
    /// The Expected leftovers cell: "Clean", "~1.2 GB cache", "Not known yet".
    pub junk: String,
    /// Expected leftovers in MB, when the forecast says.
    pub junk_mb: f32,
    /// "5 Nov 2026", or empty.
    pub installed: String,
    pub location: String,
    pub uninstall: String,
    pub quiet: bool,
    /// The program's own icon, once the atlas or the engine gave it, as straight-alpha RGBA.
    pub icon: Option<Rc<AtlasIcon>>,
    /// Gone from the list after a (pretend) uninstall of the sample data.
    pub removed: bool,
    /// The row's text for the accessibility tree: "Name[  new]\nsub line", the WinUI row's.
    pub row_text: String,
    /// The row's name for a reader: name, publisher, size, the WinUI row's.
    pub accessible: String,
}

impl Program {
    fn of(r: &ProgramRow, icon: Option<Rc<AtlasIcon>>, removed: bool) -> Program {
        let e = &r.entry().entry;
        let forecast = r.forecast();
        let junk_mb = forecast
            .and_then(|f| f.estimate_bytes)
            .map_or(0.0, |b| b as f32 / 1_048_576.0);
        Program {
            id: r.id().clone(),
            name: r.name().to_string(),
            publisher: r.publisher().to_string(),
            sub: r.sub_line().to_string(),
            new_tag: !r.new_tag().is_empty(),
            size_mb: r.size_bytes().map_or(0.0, |b| b as f32 / 1_048_576.0),
            size: r.size_text().to_string(),
            bar: (r.bar_width / BAR_MAX) as f32,
            expect: r.verdict().into(),
            junk: r.leftover_text(),
            junk_mb,
            installed: r.installed_text().to_string(),
            location: e.install_location.clone().unwrap_or_default(),
            uninstall: e.uninstall_string.clone().unwrap_or_default(),
            quiet: e.quiet_uninstall_string.is_some() || e.installer_kind == InstallerKind::Msi,
            icon,
            removed,
            row_text: format!("{}{}\n{}", r.name(), r.new_tag(), r.sub_line()),
            accessible: r.accessible_name(),
        }
    }
}

/// Noon of 25 Nov 2026, UTC, in Unix seconds: the placeholder pages' "today".
pub const TODAY_UNIX: i64 = 1_795_608_000;

pub fn date_of(days_ago: u32) -> String {
    mdshared_app::fmt::date(TODAY_UNIX - i64::from(days_ago) * 86_400, 0)
}

pub fn size_text(mb: f32) -> String {
    // The sum of no sizes at all is -0.0, which would print as "-0.0 MB".
    let mb = if mb > 0.0 { mb } else { 0.0 };
    if mb >= 1000.0 {
        format!("{:.1} GB", mb / 1024.0)
    } else if mb >= 100.0 {
        format!("{mb:.0} MB")
    } else {
        format!("{mb:.1} MB")
    }
}

/// The Programs page: `purge-ui-model`'s [`ProgramsModel`] with what the shell's drawing reads of
/// it. Every change goes through the model; [`Programs::sync`] then copies its view into the
/// fields the screens read (`all`, `rows`, `sel`, `view`), and the model's requests wait in `out`
/// for the window to send (`link`).
///
/// The list's selection is the toolkit's [`Selection`] (row numbers of `rows`), so click, Ctrl,
/// Shift and the arrow keys keep the toolkit's rules; what it selects is handed to the model as
/// ticked programs ([`Programs::with_sel`]), and drawn back from the model's `selected`.
pub struct Programs {
    pub page: ProgramsModel,
    /// The model's view after the last change.
    pub view: ProgramsPageView,
    /// Every row, in list-reply order.
    pub all: Vec<Program>,
    /// The shown rows, in order: indices into `all`.
    pub rows: Vec<usize>,
    /// The selection, in row numbers of `rows`.
    pub sel: Selection,
    pub tab: Tab,
    pub query: String,
    pub sort: SortKey,
    pub descending: bool,
    /// "Would leave leftovers", the Filter button's one switch (the other two filters are in the
    /// command palette).
    pub only_junk: bool,
    /// The list reply is in (from the engine or the sample).
    pub loaded: bool,
    /// The requests the model made, for the window to send.
    pub out: Vec<ProgramsRequest>,
    /// The model asked for this program to be scrolled into view.
    pub scroll_to: Option<ProgramId>,
    icons: HashMap<ProgramId, Rc<AtlasIcon>>,
    by_id: HashMap<ProgramId, usize>,
    /// Programs a pretend uninstall of the sample data took off the list.
    gone: HashSet<ProgramId>,
}

impl Programs {
    pub fn new(clock: Clock, may_have_record: impl Fn(&ProgramId) -> bool + 'static) -> Programs {
        let page = ProgramsModel::new(clock, EngineState::default(), may_have_record);
        let view = page.view();
        Programs {
            page,
            view,
            all: Vec::new(),
            rows: Vec::new(),
            sel: Selection::new(),
            tab: Tab::Apps,
            query: String::new(),
            sort: SortKey::Name,
            descending: false,
            only_junk: false,
            loaded: false,
            out: Vec::new(),
            scroll_to: None,
            icons: HashMap::new(),
            by_id: HashMap::new(),
            gone: HashSet::new(),
        }
    }

    /// Takes the requests of a model call and copies the model's view.
    pub fn take(&mut self, requests: Vec<ProgramsRequest>) {
        self.out.extend(requests);
        self.sync();
    }

    /// Copies the model's view into what the screens read. The toolkit's selection is drawn again
    /// from the model's ticked rows only when they differ, so a Shift run keeps its anchor.
    pub fn sync(&mut self) {
        self.view = self.page.view();
        let cursor_id = self.cursor_id();
        let icons = &self.icons;
        let gone = &self.gone;
        self.all = self
            .page
            .rows()
            .iter()
            .map(|r| Program::of(r, icons.get(r.id()).cloned(), gone.contains(r.id())))
            .collect();
        self.by_id = self
            .all
            .iter()
            .enumerate()
            .map(|(i, p)| (p.id.clone(), i))
            .collect();
        let by_id = &self.by_id;
        let rows: Vec<usize> = self
            .view
            .shown
            .iter()
            .filter(|id| !gone.contains(*id))
            .filter_map(|id| by_id.get(id).copied())
            .collect();
        let row_of: HashMap<usize, usize> = rows.iter().enumerate().map(|(r, i)| (*i, r)).collect();
        let ticked = self.page.ticked();
        let mut want: Vec<usize> = rows
            .iter()
            .enumerate()
            .filter(|(_, i)| ticked.contains(&self.all[**i].id))
            .map(|(r, _)| r)
            .collect();
        want.sort_unstable();
        let same_rows = rows == self.rows;
        let have: Vec<usize> = self.sel.iter().collect();
        self.rows = rows;
        if !same_rows || have != want {
            self.sel.reset();
            for r in &want {
                self.sel.toggle(*r);
            }
            let cursor = cursor_id
                .and_then(|id| self.by_id.get(&id))
                .and_then(|i| row_of.get(i).copied())
                .or_else(|| {
                    self.page
                        .current()
                        .and_then(|id| self.by_id.get(id))
                        .and_then(|i| row_of.get(i).copied())
                });
            match cursor {
                Some(c) => self.sel.set_cursor(c),
                None if !want.is_empty() => self.sel.set_cursor(want[want.len() - 1]),
                None => {}
            }
        }
        let v = &self.view;
        self.tab = v
            .tabs
            .iter()
            .find(|t| t.selected)
            .map_or(Tab::Apps, |t| Tab::of(t.tab));
        self.query = v.query.clone();
        self.sort = SortKey::of(v.sort.key);
        self.descending = v.sort.descending;
        self.only_junk = v.filters.only_leftovers;
    }

    fn cursor_id(&self) -> Option<ProgramId> {
        self.sel
            .cursor()
            .and_then(|c| self.rows.get(c))
            .map(|i| self.all[*i].id.clone())
    }

    /// Tells the model what the toolkit's selection ticked and unticked since the model last
    /// said (the row under the cursor last, so the details pane follows it). The window calls it
    /// after each event; every change of the model calls it first. Ticked rows that are not
    /// shown stay ticked ("1 not shown").
    pub fn commit_sel(&mut self) {
        let after: Vec<ProgramId> = self
            .sel
            .iter()
            .filter_map(|r| self.rows.get(r))
            .map(|i| self.all[*i].id.clone())
            .collect();
        let ticked = self.page.ticked();
        let before: Vec<ProgramId> = self
            .rows
            .iter()
            .map(|i| &self.all[*i].id)
            .filter(|id| ticked.contains(*id))
            .cloned()
            .collect();
        let mut added: Vec<ProgramId> = after
            .iter()
            .filter(|id| !ticked.contains(*id))
            .cloned()
            .collect();
        let removed: Vec<ProgramId> = before
            .iter()
            .filter(|id| !after.contains(id))
            .cloned()
            .collect();
        let cursor = self.cursor_id();
        if let Some(c) = &cursor
            && let Some(at) = added.iter().position(|id| id == c)
        {
            let c = added.remove(at);
            added.push(c);
        }
        // The cursor moved onto a row that was already ticked (a click on one of several
        // selected): the details pane goes with it.
        let moved = added.is_empty()
            && removed.is_empty()
            && cursor.as_ref().is_some_and(|c| after.contains(c))
            && cursor.as_ref() != self.page.current()
            && after.len() == 1;
        if moved && let Some(c) = cursor {
            added.push(c);
        }
        if !added.is_empty() || !removed.is_empty() {
            let r = self.page.on_selection_changed(&added, &removed);
            self.take(r);
        }
    }

    /// Changes the selection by the toolkit's rules and tells the model.
    pub fn with_sel<R>(&mut self, f: impl FnOnce(&mut Selection) -> R) -> R {
        self.commit_sel();
        let out = f(&mut self.sel);
        self.commit_sel();
        out
    }
    /// The index into `all` of a program.
    pub fn index_of(&self, id: &ProgramId) -> Option<usize> {
        self.by_id.get(id).copied()
    }

    /// The row number of a program in the shown list.
    pub fn row_of(&self, id: &ProgramId) -> Option<usize> {
        let i = self.index_of(id)?;
        self.rows.iter().position(|r| *r == i)
    }

    /// The count a tab shows (with a search or a filter on: how many of its programs match).
    pub fn count(&self, tab: Tab) -> usize {
        let n = self
            .view
            .tabs
            .iter()
            .find(|t| t.tab == tab.model())
            .map_or(0, |t| t.count);
        let gone = self
            .page
            .rows()
            .iter()
            .filter(|r| self.gone.contains(r.id()) && r.in_tab(tab.model()))
            .count();
        n.saturating_sub(gone)
    }

    pub fn set_tab(&mut self, tab: Tab) {
        if self.tab != tab {
            self.commit_sel();
            let r = self.page.select_tab(tab.model());
            self.take(r);
        }
    }

    pub fn set_query(&mut self, q: &str) {
        self.commit_sel();
        let r = self.page.set_search(q);
        self.take(r);
    }

    /// A click on a column: the same column turns the order round, another starts as Purge
    /// starts it (size, leftovers and date with the largest or newest).
    pub fn sort_by(&mut self, key: SortKey) {
        self.commit_sel();
        let r = self.page.sort_by_header(key.model());
        self.take(r);
    }

    /// An item of the Sort menu.
    pub fn sort_menu(&mut self, key: SortKey) {
        self.commit_sel();
        let r = self.page.sort_by_menu(key.model());
        self.take(r);
    }

    pub fn set_filter(&mut self, filter: Filter, on: bool) {
        self.commit_sel();
        let r = self.page.set_filter(filter, on);
        self.take(r);
    }

    pub fn click(&mut self, row: usize, mods: Mods) {
        if row < self.rows.len() {
            self.with_sel(|s| s.click(row, mods));
        }
    }

    pub fn command(&mut self, command: ProgramCommand) {
        self.commit_sel();
        let r = self.page.run_command(command);
        self.take(r);
    }

    /// The programs selected, as indices into `all`, in the order shown.
    pub fn selected(&self) -> Vec<usize> {
        self.sel
            .iter()
            .filter_map(|r| self.rows.get(r).copied())
            .collect()
    }

    /// The program the details pane shows.
    pub fn current(&self) -> Option<usize> {
        self.view
            .details
            .as_ref()
            .and_then(|d| self.index_of(&d.program_id))
    }

    /// A pretend uninstall of the sample data took the program off the list.
    pub fn pretend_removed(&mut self, at: usize) {
        let Some(p) = self.all.get(at) else { return };
        let id = p.id.clone();
        self.gone.insert(id.clone());
        let r = self.page.on_selection_changed(&[], &[id]);
        self.take(r);
    }

    /// An icon the atlas or the engine gave.
    pub fn set_icon(&mut self, generation: u64, icon: ProgramIcon) {
        if let Some(bgra) = &icon.bgra {
            // The toolkit draws straight-alpha RGBA: the engine's BGRA is turned once here.
            let mut rgba = bgra.clone();
            for px in rgba.chunks_exact_mut(4) {
                px.swap(0, 2);
            }
            self.icons.insert(
                icon.program_id.clone(),
                Rc::new(AtlasIcon {
                    px: icon.px,
                    bgra: rgba,
                }),
            );
        }
        self.page.on_icon(generation, icon);
    }
}

pub fn kb_text(kb: u32) -> String {
    mdshared_app::fmt::size(u64::from(kb) * 1024)
}

// ---- history ---------------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OpState {
    /// Its items are in quarantine and can come back.
    Undoable,
    Restored,
    /// The quarantine's time ran out: the items are deleted.
    Expired,
}

pub struct Op {
    pub title: String,
    pub when_days: u32,
    pub time: &'static str,
    pub summary: String,
    pub items: Vec<(&'static str, &'static str)>,
    pub kb: u32,
    pub state: OpState,
    pub days_left: u32,
}

pub struct History {
    pub ops: Vec<Op>,
    pub selected: usize,
    pub show_items: bool,
    /// The bar at the top: what the last restore did.
    pub notice: Option<String>,
    /// "Check for interrupted work" was pressed: its answer is shown.
    pub checked: bool,
}

impl History {
    fn new() -> History {
        let op = |title: &str,
                  when_days: u32,
                  time: &'static str,
                  summary: &str,
                  items: Vec<(&'static str, &'static str)>,
                  kb: u32,
                  state: OpState,
                  days_left: u32| Op {
            title: title.to_string(),
            when_days,
            time,
            summary: summary.to_string(),
            items,
            kb,
            state,
            days_left,
        };
        History {
            ops: vec![
                op(
                    "Uninstalled Zoom Workplace",
                    2,
                    "16:42",
                    "Its own uninstaller ran (code 0). 6 leftovers moved to quarantine.",
                    vec![
                        (
                            "C:\\Users\\kaan\\AppData\\Roaming\\Zoom",
                            "Folder \u{b7} 18.2 MB",
                        ),
                        (
                            "C:\\Users\\kaan\\AppData\\Local\\Zoom\\logs",
                            "Folder \u{b7} 2.1 MB",
                        ),
                        ("HKCU\\Software\\Zoom", "Registry key"),
                        ("HKCU\\Software\\Classes\\zoommtg", "Registry key"),
                        ("\\ZoomUpdateTask-S-1-5-21", "Scheduled task"),
                        ("C:\\Users\\kaan\\Desktop\\Zoom.lnk", "Shortcut"),
                    ],
                    20_840,
                    OpState::Undoable,
                    28,
                ),
                op(
                    "Uninstalled CCleaner",
                    9,
                    "09:15",
                    "Its own uninstaller ran (code 0). 4 leftovers moved to quarantine.",
                    vec![
                        ("C:\\Program Files\\CCleaner", "Folder \u{b7} 310 KB"),
                        ("HKLM\\SOFTWARE\\Piriform", "Registry key"),
                        ("HKCU\\Software\\Piriform", "Registry key"),
                        ("\\CCleaner Update", "Scheduled task"),
                    ],
                    322,
                    OpState::Undoable,
                    21,
                ),
                op(
                    "Forced cleanup of WinRAR 6.24",
                    17,
                    "21:03",
                    "The uninstaller was missing. 11 items moved to quarantine.",
                    vec![
                        ("C:\\Program Files\\WinRAR", "Folder \u{b7} 9.4 MB"),
                        ("HKLM\\SOFTWARE\\WinRAR", "Registry key"),
                        ("HKCU\\Software\\WinRAR", "Registry key"),
                    ],
                    9_630,
                    OpState::Undoable,
                    13,
                ),
                op(
                    "Uninstalled Skype",
                    26,
                    "11:48",
                    "Its own uninstaller ran (code 0). 3 leftovers moved to quarantine.",
                    vec![
                        (
                            "C:\\Users\\kaan\\AppData\\Roaming\\Skype",
                            "Folder \u{b7} 44.0 MB",
                        ),
                        ("HKCU\\Software\\Skype", "Registry key"),
                    ],
                    45_060,
                    OpState::Undoable,
                    4,
                ),
                op(
                    "Uninstalled iTunes",
                    41,
                    "18:20",
                    "Its own uninstaller ran (code 0). 7 leftovers were moved; their 30 days ran out.",
                    vec![(
                        "C:\\ProgramData\\Apple Computer\\iTunes",
                        "Folder \u{b7} 1.2 MB",
                    )],
                    1_230,
                    OpState::Expired,
                    0,
                ),
            ],
            selected: 0,
            show_items: false,
            notice: None,
            checked: false,
        }
    }

    pub fn current(&self) -> Option<&Op> {
        self.ops.get(self.selected)
    }

    pub fn restore(&mut self, i: usize) -> bool {
        let Some(op) = self.ops.get_mut(i) else {
            return false;
        };
        if op.state != OpState::Undoable {
            return false;
        }
        op.state = OpState::Restored;
        self.notice = Some(format!(
            "{} item{} put back where {} came from.",
            op.items.len(),
            if op.items.len() == 1 { "" } else { "s" },
            if op.items.len() == 1 { "it" } else { "they" },
        ));
        true
    }

    pub fn restore_all(&mut self) -> usize {
        let mut n = 0;
        for op in &mut self.ops {
            if op.state == OpState::Undoable {
                op.state = OpState::Restored;
                n += 1;
            }
        }
        if n > 0 {
            self.notice = Some(format!(
                "{n} operations undone. Everything is back in place."
            ));
        }
        n
    }

    pub fn undoable(&self) -> usize {
        self.ops
            .iter()
            .filter(|o| o.state == OpState::Undoable)
            .count()
    }
}

// ---- quarantine ------------------------------------------------------------------------------

pub struct Batch {
    pub title: &'static str,
    pub items: u32,
    pub kb: u32,
    pub days_left: u32,
    pub volume: &'static str,
}

pub struct Quarantine {
    pub batches: Vec<Batch>,
    /// The batch whose items are listed.
    pub selected: usize,
    /// Days an item stays before it is deleted.
    pub keep_days: u32,
    /// The review of what is about to expire was opened.
    pub reviewing: bool,
}

impl Quarantine {
    fn new() -> Quarantine {
        Quarantine {
            batches: vec![
                Batch {
                    title: "Zoom Workplace",
                    items: 6,
                    kb: 20_840,
                    days_left: 28,
                    volume: "C:",
                },
                Batch {
                    title: "CCleaner",
                    items: 4,
                    kb: 322,
                    days_left: 21,
                    volume: "C:",
                },
                Batch {
                    title: "WinRAR 6.24",
                    items: 11,
                    kb: 9_630,
                    days_left: 13,
                    volume: "C:",
                },
                Batch {
                    title: "Skype",
                    items: 3,
                    kb: 45_060,
                    days_left: 4,
                    volume: "D:",
                },
            ],
            selected: 0,
            keep_days: 30,
            reviewing: false,
        }
    }

    pub fn total_kb(&self) -> u32 {
        self.batches.iter().map(|b| b.kb).sum()
    }

    pub fn total_items(&self) -> u32 {
        self.batches.iter().map(|b| b.items).sum()
    }

    /// The KB held on each volume, in the order first seen.
    pub fn volumes(&self) -> Vec<(&'static str, u32)> {
        let mut out: Vec<(&'static str, u32)> = Vec::new();
        for b in &self.batches {
            match out.iter_mut().find(|(v, _)| *v == b.volume) {
                Some((_, kb)) => *kb += b.kb,
                None => out.push((b.volume, b.kb)),
            }
        }
        out
    }
}

// ---- settings --------------------------------------------------------------------------------

/// What the Settings page shows besides the look (`prefs::Prefs`), which is saved; this is not.
pub struct Settings {
    /// The launch markers' expander is open.
    pub markers_open: bool,
    pub facts: Facts,
}

/// The versions the About line names: `engine` and `policy` come from the engine's hello; while
/// they are `None` the window shows the sample data and says so.
pub struct Facts {
    /// This build's version: the workspace version, which is also the exe's FILEVERSION.
    pub version: &'static str,
    pub engine: Option<String>,
    pub policy: Option<String>,
}

// ---- the whole model -------------------------------------------------------------------------

/// The confirmation before an uninstall: which programs it is for.
pub struct Model {
    /// The look and the theme the user chose, as saved (`prefs`).
    pub prefs: Prefs,
    pub page: Page,
    pub programs: Programs,
    /// The Uninstall and Leftovers pages (UI-FLOW), with the confirmation and the
    /// first-elevation explanation.
    pub flow: crate::flow::Flow,
    pub history: History,
    pub quarantine: Quarantine,
    pub settings: Settings,
    /// The window shows sample data (`--sample`, or the engine could not be used): the pages not
    /// wired yet show the mockup's sample pages, which change nothing. False with the real
    /// engine, where those pages say they are not available yet.
    pub sample: bool,
}

impl Model {
    pub fn new(prefs: Prefs, programs: Programs, sample: bool) -> Model {
        Model {
            prefs,
            page: Page::Programs,
            programs,
            flow: crate::flow::Flow::new(),
            history: History::new(),
            quarantine: Quarantine::new(),
            settings: Settings {
                markers_open: false,
                facts: Facts {
                    version: env!("CARGO_PKG_VERSION"),
                    engine: None,
                    policy: None,
                },
            },
            sample,
        }
    }

    // ---- the uninstall flow (UI-FLOW) ---------------------------------------------------------

    /// Uninstall (the toolbar, the details pane, Delete or Enter on the list): the programs go to
    /// the Uninstall page. False when nothing is picked and nothing was said.
    pub fn ask_uninstall(&mut self) -> bool {
        if self.sample {
            // The Programs model's Uninstall needs an engine that can change the PC; the sample
            // broker (`sample_broker`) plays the administrator part, so the targets are taken here.
            let targets = self.programs.page.uninstall_targets();
            return self.open_uninstall(targets);
        }
        self.programs.command(ProgramCommand::Uninstall);
        true
    }

    /// The Uninstall page's entry: `targets` from the Programs page (`ProgramsRequest::Uninstall`).
    /// The page starts the first (the broker's launch, its record, then the confirmation); a step
    /// that runs keeps them out (the page says nothing then, as the WinUI page did).
    pub fn open_uninstall(&mut self, targets: Vec<UninstallTarget>) -> bool {
        let targets: Vec<UninstallTarget> = targets
            .into_iter()
            .filter(|t| {
                self.programs
                    .index_of(&t.program_id)
                    .is_none_or(|i| !self.programs.all[i].removed)
            })
            .collect();
        if targets.is_empty() {
            return false;
        }
        let env = self.flow_env();
        let r = self.flow.page.begin(targets, env);
        self.flow.take(r);
        self.page = Page::Pipeline;
        true
    }

    /// What the Uninstall page needs to know of the rest of the window.
    pub fn flow_env(&self) -> purge_ui_model::pipeline::PageEnv {
        purge_ui_model::pipeline::PageEnv {
            check_running: self.programs.page.check_running(),
            leftovers_changing: self.flow.leftovers.is_changing(),
            leftovers_on_screen: self.page == Page::Leftovers
                || (self.page == Page::Pipeline && crate::ui::Look::of(self.prefs.design).flow),
        }
    }

    // ---- the rail ------------------------------------------------------------------------------

    /// The numbers the rail shows beside each page: (text, is a badge).
    pub fn badge(&self, page: Page) -> Option<(String, bool)> {
        match page {
            Page::Programs => Some((self.programs.count(Tab::Apps).to_string(), false)),
            Page::Pipeline => {
                let q = self.flow.page.queue();
                let n = if q.next().is_some() {
                    q.count().saturating_sub(q.position())
                } else {
                    usize::from(self.flow.page.is_busy())
                };
                (n > 0).then(|| (n.to_string(), true))
            }
            Page::Leftovers => {
                let l = &self.flow.leftovers;
                let n = l.selectable_count();
                (l.phase() == purge_ui_model::leftovers::LeftoversPhase::Review && n > 0)
                    .then(|| (n.to_string(), true))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use purge_client::{Answer, ClientEvent, Engine, SampleEngine, Sink};
    use purge_rpc::methods::{NoParams, StdioCall};
    use purge_ui_model::programs::ProgramEntry;
    use purge_ui_model::programs::date::{CivilDate, LocalOffset};

    /// The fixed clock of the tests: 25 Nov 2026, UTC.
    pub fn clock() -> Clock {
        Clock {
            today: CivilDate::new(2026, 11, 25),
            offset: LocalOffset::Fixed(0),
        }
    }

    /// The Programs page with the sample engine's list, as `--sample` shows it.
    pub fn sample_programs() -> Programs {
        let got: Arc<Mutex<Vec<ClientEvent>>> = Arc::default();
        let into = got.clone();
        let sink = Sink::from_fn(move |e| into.lock().unwrap().push(e));
        let engine = SampleEngine::new(sink);
        engine.request(StdioCall::ProgramsList(NoParams {}));
        let list = got
            .lock()
            .unwrap()
            .drain(..)
            .find_map(|e| match e {
                ClientEvent::Reply {
                    result: Ok(Answer::Programs(l)),
                    ..
                } => Some(l),
                _ => None,
            })
            .expect("the sample list");
        let mut p = Programs::new(clock(), |_| false);
        let r = p
            .page
            .on_list(Ok(ProgramEntry::from_list(&list.rows, &list.patches)));
        p.take(r);
        let r = p.page.on_first_frame();
        p.take(r);
        p.loaded = true;
        p
    }

    fn sample_model() -> Model {
        Model::new(Prefs::default(), sample_programs(), true)
    }

    #[test]
    fn the_list_is_the_models_and_the_selection_reaches_it() {
        let mut m = sample_model();
        let apps = m.programs.count(Tab::Apps);
        assert!(apps > 0 && m.programs.rows.len() == apps);
        m.programs.click(2, Mods::default());
        let id = m.programs.all[m.programs.rows[2]].id.clone();
        assert!(m.programs.page.ticked().contains(&id));
        assert_eq!(m.programs.current(), m.programs.index_of(&id));
        // Ctrl+click another adds it; the model ticks both.
        let ctrl = Mods {
            ctrl: true,
            ..Mods::default()
        };
        m.programs.click(4, ctrl);
        assert_eq!(m.programs.page.ticked().len(), 2);
        assert_eq!(m.programs.sel.len(), 2);
        // A plain click on another row leaves that one alone.
        m.programs.click(1, Mods::default());
        assert_eq!(m.programs.page.ticked().len(), 1);
    }

    #[test]
    fn a_sort_keeps_the_selection_on_the_same_programs() {
        let mut m = sample_model();
        m.programs.click(2, Mods::default());
        let before: Vec<ProgramId> = m
            .programs
            .selected()
            .iter()
            .map(|i| m.programs.all[*i].id.clone())
            .collect();
        m.programs.sort_by(SortKey::Size);
        let after: Vec<ProgramId> = m
            .programs
            .selected()
            .iter()
            .map(|i| m.programs.all[*i].id.clone())
            .collect();
        assert_eq!(after, before);
        m.programs.set_query("zzzz-no-such");
        assert!(m.programs.rows.is_empty());
        assert!(m.programs.view.no_match.is_some());
    }

    #[test]
    fn a_row_says_its_name_and_sub_line_as_the_winui_row_did() {
        let p = sample_programs();
        for r in &p.all {
            let (first, second) = r.row_text.split_once('\n').expect("two lines");
            assert!(first.starts_with(&r.name));
            assert_eq!(second, r.sub);
        }
    }
}
