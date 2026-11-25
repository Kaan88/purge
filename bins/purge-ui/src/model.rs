//! The window's state: the page shown, and one model per page, with the rules that
//! change them. Nothing here draws, measures text or knows a rectangle;
//! `mdshared_ui::select::Selection` is the toolkit's own selection model (ranges of row
//! numbers), used so that the rules of click, Ctrl, Shift and the arrow keys are the toolkit's.
//!
//! **The Programs page is real (UI-WIRE).** [`Programs`] is `purge-ui-model`'s Programs model,
//! fed by the engine (or the sample engine) through `link`.
//!
//! **The other pages are still the mockup's sample pages.** [`Pipeline`], [`Leftovers`],
//! [`History`] and [`Quarantine`] hold sample data that changes nothing: they are drawn only while
//! the window shows sample data ([`Model::sample`]); with the real engine those pages say they are
//! not available yet in this preview. Each page draws from one struct of its own, and the screens
//! read only those structs' fields and methods. That is the seam for the rest of wave 2
//! (UI-PAGES): each struct is fed from `purge-ui-model`'s view state and `purge-client`'s events,
//! and the drawing in `screens` stays as it is. The Uninstall page's entry is
//! [`Model::open_uninstall`]; the Leftovers page's is [`Model::leftovers_inbox`]. Their rules that
//! guard safety (Likely and Protected start unticked, nothing reaches the pipeline without the
//! confirmation) are the ones the real models must keep; the tests below say so.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::time::{Duration, Instant};

use mdshared_ui::keys::Mods;
use mdshared_ui::select::Selection;
use purge_model::{InstallerKind, ProgramId};
use purge_ui_model::pipeline::{StoredScanOutcome, UninstallTarget};
use purge_ui_model::programs::page::ProgramsRequest;
use purge_ui_model::programs::row::BAR_MAX;
use purge_ui_model::programs::strings as program_strings;
use purge_ui_model::programs::{
    Clock, EngineState, Filter, ForecastVerdict, ProgramCommand, ProgramIcon, ProgramRow,
    ProgramTab, ProgramsModel, ProgramsPageView, SortKey as ModelSort,
};

use purge_model::exec::session::{RetentionClass, SessionId};
use purge_ui_model::history::{HistoryCall, HistoryModel};
use purge_ui_model::local_time::Clock as LocalClock;
use purge_ui_model::vault::{VaultCall, VaultModel};

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
    /// The installer family in a word: MSI, NSIS, Inno, Burn, Store app, Other.
    pub kind: &'static str,
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
            kind: r.kind_chip(),
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

// ---- the uninstall pipeline ------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StepState {
    Waiting,
    Running,
    Done,
    Skipped,
}

pub struct Step {
    pub title: &'static str,
    pub detail: &'static str,
    /// What the step says when it is done.
    pub done: &'static str,
    pub takes: Duration,
}

pub const STEPS: [Step; 6] = [
    Step {
        title: "Create a restore point",
        detail: "Windows System Restore, before anything changes.",
        done: "Restore point made.",
        takes: Duration::from_millis(1400),
    },
    Step {
        title: "Check the program is closed",
        detail: "Purge never closes a program for you.",
        done: "Not running.",
        takes: Duration::from_millis(900),
    },
    Step {
        title: "Record what is installed",
        detail: "Files, registry keys, services and tasks, before the uninstaller runs.",
        done: "Recorded 1,284 files and 211 registry values.",
        takes: Duration::from_millis(1600),
    },
    Step {
        title: "Run the program's own uninstaller",
        detail: "Its own command, as Windows would run it.",
        done: "The uninstaller ended with code 0.",
        takes: Duration::from_millis(2600),
    },
    Step {
        title: "Check it is gone",
        detail: "The uninstall entry and the program's folder.",
        done: "The entry is gone.",
        takes: Duration::from_millis(900),
    },
    Step {
        title: "Look for leftovers",
        detail: "Compares what is there now with what was recorded.",
        done: "9 leftovers found.",
        takes: Duration::from_millis(2000),
    },
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RunPhase {
    /// Shown, with a Start button: nothing has run.
    Ready,
    Running,
    Finished,
}

/// One program going through the steps.
pub struct Run {
    pub program: usize,
    pub phase: RunPhase,
    /// The step that is running (or, when finished, `STEPS.len()`).
    pub step: usize,
    pub step_began: Option<Instant>,
}

pub struct Pipeline {
    /// Programs waiting their turn, as indices into `Programs::all`.
    pub queue: Vec<usize>,
    pub run: Option<Run>,
    /// The restore point for the cleanup step: 0 off, 1 high-risk changes only, 2 always.
    pub restore_mode: usize,
    /// The program in the confirmation is still running; "Check again" looks once more.
    pub still_running: bool,
    /// "Run quietly when the uninstaller can".
    pub quiet: bool,
    /// How many programs went through in this session.
    pub finished: usize,
}

impl Pipeline {
    fn new() -> Pipeline {
        Pipeline {
            queue: Vec::new(),
            run: None,
            restore_mode: 1,
            still_running: false,
            quiet: false,
            finished: 0,
        }
    }

    pub fn restore_point(&self) -> bool {
        self.restore_mode != 0
    }

    /// Programs in the pipeline: the one running and those waiting.
    pub fn pending(&self) -> usize {
        self.queue.len()
            + usize::from(
                self.run
                    .as_ref()
                    .is_some_and(|r| r.phase != RunPhase::Finished),
            )
    }

    pub fn enqueue(&mut self, programs: &[usize]) {
        for p in programs {
            let running = self.run.as_ref().is_some_and(|r| r.program == *p);
            if !running && !self.queue.contains(p) {
                self.queue.push(*p);
            }
        }
    }

    /// Takes the next program from the queue and starts its first step.
    pub fn start_next(&mut self, now: Instant) -> bool {
        if self
            .run
            .as_ref()
            .is_some_and(|r| r.phase == RunPhase::Running)
            || self.queue.is_empty()
        {
            return false;
        }
        let program = self.queue.remove(0);
        let mut run = Run {
            program,
            phase: RunPhase::Running,
            step: 0,
            step_began: Some(now),
        };
        if !self.restore_point() {
            run.step = 1;
        }
        self.run = Some(run);
        true
    }

    pub fn state_of(&self, step: usize) -> StepState {
        let Some(run) = &self.run else {
            return StepState::Waiting;
        };
        if step == 0 && !self.restore_point() && run.phase != RunPhase::Ready {
            return StepState::Skipped;
        }
        match run.phase {
            RunPhase::Ready => StepState::Waiting,
            RunPhase::Finished => StepState::Done,
            RunPhase::Running if step < run.step => StepState::Done,
            RunPhase::Running if step == run.step => StepState::Running,
            RunPhase::Running => StepState::Waiting,
        }
    }

    /// How far the running step is, 0 to 1.
    pub fn step_fraction(&self, now: Instant) -> f32 {
        let Some(run) = &self.run else { return 0.0 };
        match (run.phase, run.step_began) {
            (RunPhase::Running, Some(began)) => {
                let takes = STEPS[run.step.min(STEPS.len() - 1)].takes.as_secs_f32();
                (now.saturating_duration_since(began).as_secs_f32() / takes).clamp(0.0, 1.0)
            }
            (RunPhase::Finished, _) => 1.0,
            _ => 0.0,
        }
    }

    /// How far the whole run is, 0 to 1.
    pub fn fraction(&self, now: Instant) -> f32 {
        let Some(run) = &self.run else { return 0.0 };
        match run.phase {
            RunPhase::Ready => 0.0,
            RunPhase::Finished => 1.0,
            RunPhase::Running => (run.step as f32 + self.step_fraction(now)) / STEPS.len() as f32,
        }
    }

    /// Moves the run on to `now`. Returns what happened and when to be called again.
    pub fn tick(&mut self, now: Instant) -> (Ticked, Option<Instant>) {
        let Some(run) = &mut self.run else {
            return (Ticked::Nothing, None);
        };
        if run.phase != RunPhase::Running {
            return (Ticked::Nothing, None);
        }
        let mut what = Ticked::Nothing;
        loop {
            let began = run.step_began.unwrap_or(now);
            let ends = began + STEPS[run.step].takes;
            if now < ends {
                return (what, Some(ends));
            }
            run.step += 1;
            what = Ticked::Stepped;
            if run.step >= STEPS.len() {
                run.phase = RunPhase::Finished;
                run.step_began = None;
                self.finished += 1;
                return (Ticked::Finished(run.program), None);
            }
            run.step_began = Some(ends);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ticked {
    Nothing,
    Stepped,
    Finished(usize),
}

// ---- leftovers -------------------------------------------------------------------------------

/// How sure Purge is that an item belongs to the program and is safe to move.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Rating {
    /// Certain. Ticked by default.
    Safe,
    /// Probably the program's. NEVER ticked by default: the user ticks it.
    Likely,
    /// Shared or the system's. Cannot be ticked at all.
    Protected,
}

impl Rating {
    pub fn title(self) -> &'static str {
        match self {
            Rating::Safe => "Safe",
            Rating::Likely => "Likely",
            Rating::Protected => "Protected",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Leftover {
    pub path: String,
    pub what: &'static str,
    pub size_kb: u32,
    pub rating: Rating,
    pub ticked: bool,
    pub evidence: String,
    pub found_by: &'static str,
    pub if_removed: &'static str,
}

pub struct Group {
    pub title: &'static str,
    pub open: bool,
    pub items: Vec<Leftover>,
}

impl Group {
    /// The group's box: ticked, not ticked, or `None` for some of them.
    pub fn tick(&self) -> Option<bool> {
        let can: Vec<&Leftover> = self
            .items
            .iter()
            .filter(|i| i.rating != Rating::Protected)
            .collect();
        let on = can.iter().filter(|i| i.ticked).count();
        if on == 0 {
            Some(false)
        } else if on == can.len() {
            Some(true)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LeftoverPhase {
    /// No uninstall has finished: nothing to review.
    Empty,
    /// The scan is running (the pipeline's last step).
    Waiting,
    Review,
    /// The ticked items were moved to quarantine.
    Moved,
    /// The move was undone.
    Undone,
}

pub struct Leftovers {
    pub phase: LeftoverPhase,
    /// The program they belong to, an index into `Programs::all`.
    pub program: Option<usize>,
    pub groups: Vec<Group>,
    /// The item the evidence pane shows: group and item.
    pub selected: Option<(usize, usize)>,
    /// "Delete for good after 30 days" (off: kept until the user empties the quarantine).
    pub delete_after: bool,
    /// What the last move took: items and KB.
    pub moved: (usize, u32),
}

fn left(
    path: impl Into<String>,
    what: &'static str,
    size_kb: u32,
    rating: Rating,
    evidence: impl Into<String>,
    found_by: &'static str,
    if_removed: &'static str,
) -> Leftover {
    Leftover {
        path: path.into(),
        what,
        size_kb,
        rating,
        // The one rule of the defaults: only what is certain starts ticked.
        ticked: matches!(rating, Rating::Safe),
        evidence: evidence.into(),
        found_by,
        if_removed,
    }
}

/// The parts of a program's traces that name it. Everything else about what the (pretend)
/// scan finds is the same for every program: the same groups, ratings and sizes, so the same
/// rules hold whichever program ran.
struct Traces {
    folder: String,
    cache: String,
    profile: String,
    profile_what: &'static str,
    profile_evidence: &'static str,
    profile_removed: &'static str,
    updater: String,
    settings_key: String,
    vendor_key: String,
    vendor_evidence: String,
    shared_key: &'static str,
    shared_what: &'static str,
    shared_evidence: &'static str,
    task: String,
    shortcut: String,
}

/// `text` with only what a folder or key name can hold.
fn name_part(text: &str, dots: bool) -> String {
    let kept: String = text
        .chars()
        .filter(|c| {
            c.is_alphanumeric() || matches!(c, ' ' | '-' | '+' | '_') || (dots && *c == '.')
        })
        .collect();
    kept.trim().trim_end_matches('.').to_string()
}

impl Traces {
    /// Firefox's are those of the reference the Leftovers page was drawn from.
    fn firefox() -> Traces {
        Traces {
            folder: "C:\\Program Files\\Mozilla Firefox".to_string(),
            cache: "C:\\Users\\kaan\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\x1.default\\cache2".to_string(),
            profile: "C:\\Users\\kaan\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\x1.default".to_string(),
            profile_what: "Profile: bookmarks, history, saved logins",
            profile_evidence: "Inside the program's own data folder, but it holds what you made: bookmarks, history and saved logins.",
            profile_removed: "Your bookmarks and saved logins go to quarantine with it. Tick it only if you do not want them.",
            updater: "C:\\ProgramData\\Mozilla-1de4eec8".to_string(),
            settings_key: "HKCU\\Software\\Mozilla\\Firefox".to_string(),
            vendor_key: "HKLM\\SOFTWARE\\Mozilla".to_string(),
            vendor_evidence: "The vendor's key. No other Mozilla program is installed now, but another could share it.".to_string(),
            shared_key: "HKLM\\SOFTWARE\\Classes\\.html\\OpenWithProgids",
            shared_what: "File association list (shared)",
            shared_evidence: "A Windows key that every browser writes to. Purge removes the program's one value from it and never the key.",
            task: "\\Mozilla\\Firefox Default Browser Agent 308046B0AF4A39CB".to_string(),
            shortcut: "C:\\Users\\kaan\\Desktop\\Firefox.lnk".to_string(),
        }
    }

    fn of(p: &Program) -> Traces {
        if p.name.starts_with("Mozilla Firefox") {
            return Traces::firefox();
        }
        // The name without its version or platform: "Audacity 3.7.1" is "Audacity".
        let mut short = String::new();
        for word in p.name.split_whitespace() {
            let extra = word.starts_with(|c: char| c.is_ascii_digit() || c == '(');
            if extra && !short.is_empty() {
                break;
            }
            if !short.is_empty() {
                short.push(' ');
            }
            short.push_str(word);
        }
        let mut short = name_part(&short, true);
        if short.is_empty() {
            short = "Program".to_string();
        }
        let vendor = name_part(&p.publisher, false);
        let known = !vendor.is_empty() && !p.publisher.contains("not recorded");
        // Where the program keeps its own: under its vendor's name, when that is known.
        let base = if known {
            format!("{vendor}\\{short}")
        } else {
            short.clone()
        };
        let folder = if p.location.get(1..3) == Some(":\\") {
            p.location.clone()
        } else {
            format!("C:\\Program Files\\{short}")
        };
        Traces {
            folder,
            cache: format!("C:\\Users\\kaan\\AppData\\Local\\{base}\\Cache"),
            profile: format!("C:\\Users\\kaan\\AppData\\Roaming\\{base}"),
            profile_what: "Profile: settings and files you made",
            profile_evidence: "Inside the program's own data folder, but it holds what you made: your settings and recent files.",
            profile_removed: "Your settings go to quarantine with it. Tick it only if you do not want them.",
            updater: format!(
                "C:\\ProgramData\\{short}-{:08x}",
                p.name
                    .bytes()
                    .fold(0u32, |h, b| h.wrapping_mul(31).wrapping_add(u32::from(b)))
                    .wrapping_mul(2_654_435_761)
            ),
            settings_key: format!("HKCU\\Software\\{base}"),
            vendor_key: format!("HKLM\\SOFTWARE\\{}", if known { &vendor } else { &short }),
            vendor_evidence: if known {
                format!(
                    "The vendor's key. No other {vendor} program is installed now, but another could share it."
                )
            } else {
                "The vendor's key. No publisher is recorded, so another program could share it."
                    .to_string()
            },
            shared_key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SharedDLLs",
            shared_what: "Shared file counts (shared)",
            shared_evidence: "A Windows key that every installer writes to. Purge removes the program's one value from it and never the key.",
            task: format!("\\{base} Update Check"),
            shortcut: format!("C:\\Users\\kaan\\Desktop\\{short}.lnk"),
        }
    }
}

fn found(program: &Program) -> Vec<Group> {
    let t = Traces::of(program);
    vec![
        Group {
            title: "Files and folders",
            open: true,
            items: vec![
                left(
                    t.folder,
                    "Empty install folder",
                    12,
                    Rating::Safe,
                    "Made by the installer on 6 Nov 2026 and named in its uninstall entry. Only an empty folder tree is left.",
                    "Recorded before the uninstall; still there after.",
                    "Nothing uses it. Moving it frees the folder name.",
                ),
                left(
                    t.cache,
                    "Cache",
                    3_840,
                    Rating::Safe,
                    "Inside the program's own data folder; the files are cache entries the program rebuilds.",
                    "The program's folder under Local AppData.",
                    "Nothing is lost: a cache.",
                ),
                left(
                    t.profile,
                    t.profile_what,
                    1_120,
                    Rating::Likely,
                    t.profile_evidence,
                    "The program's folder under Roaming AppData.",
                    t.profile_removed,
                ),
                left(
                    t.updater,
                    "Updater state",
                    96,
                    Rating::Safe,
                    "Written only by the program's update service, which is gone.",
                    "Folder named after the installer's product code.",
                    "Nothing uses it.",
                ),
            ],
        },
        Group {
            title: "Registry",
            open: true,
            items: vec![
                left(
                    t.settings_key,
                    "Settings key",
                    4,
                    Rating::Safe,
                    "Created by the program; every value under it is the program's.",
                    "Recorded before the uninstall; still there after.",
                    "Nothing uses it.",
                ),
                left(
                    t.vendor_key,
                    "Vendor key",
                    2,
                    Rating::Likely,
                    t.vendor_evidence,
                    "The publisher's name in the uninstall entry.",
                    "Another program of the same vendor would lose shared settings.",
                ),
                left(
                    t.shared_key,
                    t.shared_what,
                    1,
                    Rating::Protected,
                    t.shared_evidence,
                    "Holds a value that names the program.",
                    "Never moved: it belongs to Windows.",
                ),
            ],
        },
        Group {
            title: "Services and scheduled tasks",
            open: false,
            items: vec![left(
                t.task,
                "Scheduled task",
                3,
                Rating::Safe,
                "The task starts a file that no longer exists.",
                "Its action points into the removed folder.",
                "Nothing: it can no longer run.",
            )],
        },
        Group {
            title: "Shortcuts",
            open: false,
            items: vec![left(
                t.shortcut,
                "Desktop shortcut",
                2,
                Rating::Safe,
                "Its target is the removed program file.",
                "Shortcut whose target is gone.",
                "Nothing: it opens nothing.",
            )],
        },
    ]
}

impl Leftovers {
    fn new() -> Leftovers {
        Leftovers {
            phase: LeftoverPhase::Empty,
            program: None,
            groups: Vec::new(),
            selected: None,
            delete_after: true,
            moved: (0, 0),
        }
    }

    /// The scan found its items for `program`: the review starts, with the defaults.
    pub fn found_for(&mut self, at: usize, program: &Program) {
        self.program = Some(at);
        self.groups = found(program);
        self.selected = Some((0, 0));
        self.phase = LeftoverPhase::Review;
    }

    pub fn item(&self, at: (usize, usize)) -> Option<&Leftover> {
        self.groups.get(at.0)?.items.get(at.1)
    }

    pub fn count(&self) -> usize {
        self.groups.iter().map(|g| g.items.len()).sum()
    }

    pub fn count_of(&self, rating: Rating) -> usize {
        self.groups
            .iter()
            .flat_map(|g| &g.items)
            .filter(|i| i.rating == rating)
            .count()
    }

    /// The ticked items: how many and how many KB.
    pub fn ticked(&self) -> (usize, u32) {
        let t = self
            .groups
            .iter()
            .flat_map(|g| &g.items)
            .filter(|i| i.ticked);
        t.fold((0, 0), |(n, kb), i| (n + 1, kb + i.size_kb))
    }

    /// Ticks or unticks one item. A protected item never takes a tick.
    pub fn toggle_item(&mut self, at: (usize, usize)) -> bool {
        let Some(item) = self
            .groups
            .get_mut(at.0)
            .and_then(|g| g.items.get_mut(at.1))
        else {
            return false;
        };
        if item.rating == Rating::Protected {
            return false;
        }
        item.ticked = !item.ticked;
        true
    }

    /// The group's box: when every Safe item is ticked, it unticks the whole group; otherwise
    /// it ticks the Safe ones. It never ticks a Likely item: that is the user's own choice,
    /// one item at a time.
    pub fn toggle_group(&mut self, g: usize) {
        let Some(group) = self.groups.get_mut(g) else {
            return;
        };
        let safe_all = group
            .items
            .iter()
            .filter(|i| i.rating == Rating::Safe)
            .all(|i| i.ticked);
        let any = group.items.iter().any(|i| i.ticked);
        for i in &mut group.items {
            match i.rating {
                Rating::Safe => i.ticked = !(safe_all && any),
                Rating::Likely if safe_all && any => i.ticked = false,
                _ => {}
            }
        }
    }

    pub fn set_all_open(&mut self, open: bool) {
        for g in &mut self.groups {
            g.open = open;
        }
    }

    pub fn all_open(&self) -> bool {
        self.groups.iter().all(|g| g.open)
    }

    /// "Select the likely ones too" / back: the one place several Likely items are ticked at
    /// once, and only because the user pressed the button that says so.
    pub fn set_likely(&mut self, on: bool) {
        for i in self.groups.iter_mut().flat_map(|g| &mut g.items) {
            if i.rating == Rating::Likely {
                i.ticked = on;
            }
        }
    }

    pub fn likely_ticked(&self) -> bool {
        let mut likely = self
            .groups
            .iter()
            .flat_map(|g| &g.items)
            .filter(|i| i.rating == Rating::Likely)
            .peekable();
        likely.peek().is_some() && likely.all(|i| i.ticked)
    }

    /// Moves the ticked items to quarantine (in the mockup: remembers how many).
    pub fn move_ticked(&mut self) -> bool {
        let t = self.ticked();
        if self.phase != LeftoverPhase::Review || t.0 == 0 {
            return false;
        }
        self.moved = t;
        self.phase = LeftoverPhase::Moved;
        true
    }

    pub fn undo(&mut self) -> bool {
        if self.phase != LeftoverPhase::Moved {
            return false;
        }
        self.phase = LeftoverPhase::Undone;
        true
    }

    pub fn done(&mut self) {
        self.phase = LeftoverPhase::Empty;
        self.program = None;
        self.groups.clear();
        self.selected = None;
    }
}

pub fn kb_text(kb: u32) -> String {
    mdshared_app::fmt::size(u64::from(kb) * 1024)
}

// ---- history (UI-PAGES2) ---------------------------------------------------------------------

/// The History page: `purge-ui-model`'s [`HistoryModel`], its requests waiting for `link`, and
/// the clock its dates are read with.
pub struct History {
    pub page: HistoryModel,
    /// What the page asked for and `link` has not sent yet.
    pub out: Vec<HistoryCall>,
    /// The clock of the last answer; read again from `now` at each answer.
    pub clock: LocalClock,
    now: fn() -> LocalClock,
    /// The closable bars the user closed ("title message"); shown again after the next action.
    pub dismissed: Vec<String>,
}

impl History {
    pub fn new(now: fn() -> LocalClock) -> History {
        History {
            page: HistoryModel::new(),
            out: Vec::new(),
            clock: now(),
            now,
            dismissed: Vec::new(),
        }
    }

    /// Keeps the model's requests for `link`.
    pub fn take(&mut self, calls: Vec<HistoryCall>) {
        self.out.extend(calls);
    }

    /// Reads the clock again (before an answer is handed to the model, and before a frame).
    pub fn tick_clock(&mut self) -> LocalClock {
        self.clock = (self.now)();
        self.clock
    }

    /// The session at this index of the model's list, and its id.
    pub fn session_id(&self, at: usize) -> Option<SessionId> {
        self.page.sessions().get(at).map(|s| s.id.clone())
    }

    /// The position of the selected session in the model's list.
    pub fn selected_at(&self) -> Option<usize> {
        let id = &self.page.selected()?.id;
        self.page.sessions().iter().position(|s| &s.id == id)
    }

    /// The number of sessions that still hold something to put back.
    pub fn undoable(&self) -> usize {
        self.page.sessions().iter().filter(|s| s.held).count()
    }
}

// ---- quarantine (UI-PAGES2) ------------------------------------------------------------------

/// The "Delete now" choice open under a cleanup: whose, and whether its registry backups go too
/// (off each time it opens).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteFlyout {
    pub session: SessionId,
    pub also_backups: bool,
}

/// The Quarantine page: `purge-ui-model`'s [`VaultModel`], its requests waiting for `link`, the
/// cleanup shown in the side pane and the "Delete now" choice while it is open.
pub struct Quarantine {
    pub page: VaultModel,
    pub out: Vec<VaultCall>,
    pub clock: LocalClock,
    now: fn() -> LocalClock,
    /// The cleanup the side pane shows.
    pub selected: Option<SessionId>,
    pub flyout: Option<DeleteFlyout>,
    /// Days a quarantined file is kept (the engine's retention, `RetentionClass::Quarantine`).
    pub keep_days: u32,
}

impl Quarantine {
    pub fn new(now: fn() -> LocalClock) -> Quarantine {
        Quarantine {
            page: VaultModel::new(),
            out: Vec::new(),
            clock: now(),
            now,
            selected: None,
            flyout: None,
            keep_days: RetentionClass::Quarantine.days(),
        }
    }

    pub fn take(&mut self, calls: Vec<VaultCall>) {
        self.out.extend(calls);
        self.sync();
    }

    pub fn tick_clock(&mut self) -> LocalClock {
        self.clock = (self.now)();
        self.clock
    }

    /// Keeps the selection on a listed cleanup (the first when it is gone), and closes a choice
    /// whose cleanup is no longer listed.
    pub fn sync(&mut self) {
        let batches = self.page.batches();
        let listed = |id: &SessionId| batches.iter().any(|b| &b.id == id);
        if !self.selected.as_ref().is_some_and(listed) {
            self.selected = batches.first().map(|b| b.id.clone());
        }
        if self
            .flyout
            .as_ref()
            .is_some_and(|f| !listed(&f.session) || self.page.busy())
        {
            self.flyout = None;
        }
    }

    /// The position of the selected cleanup in the model's list.
    pub fn selected_at(&self) -> Option<usize> {
        let id = self.selected.as_ref()?;
        self.page.batches().iter().position(|b| &b.id == id)
    }

    pub fn total_items(&self) -> u32 {
        self.page.batches().iter().map(|b| b.items).sum()
    }

    pub fn total_bytes(&self) -> u64 {
        self.page
            .batches()
            .iter()
            .fold(0u64, |sum, b| sum.saturating_add(b.bytes))
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
pub struct Confirm {
    pub programs: Vec<usize>,
}

pub struct Model {
    /// The look and the theme the user chose, as saved (`prefs`).
    pub prefs: Prefs,
    pub page: Page,
    pub programs: Programs,
    pub confirm: Option<Confirm>,
    pub pipeline: Pipeline,
    pub leftovers: Leftovers,
    pub history: History,
    pub quarantine: Quarantine,
    pub settings: Settings,
    /// The window shows sample data (`--sample`, or the engine could not be used): the pages not
    /// wired yet show the mockup's sample pages, which change nothing. False with the real
    /// engine, where those pages say they are not available yet.
    pub sample: bool,
    /// The seam of the Uninstall page (UI-PAGES): the programs an Uninstall click handed over,
    /// visible rows first. The page's own model takes them from here when it is wired; until then
    /// the page lists them and says that uninstalling is not available yet.
    pub uninstall_inbox: Vec<UninstallTarget>,
    /// The seam of the Leftovers page: the scan a removed program's check made, with the broker
    /// session handed over to the Leftovers owner (`link::Owner::Leftovers`).
    pub leftovers_inbox: Option<StoredScanOutcome>,
}

impl Model {
    pub fn new(prefs: Prefs, programs: Programs, sample: bool) -> Model {
        Model {
            prefs,
            page: Page::Programs,
            programs,
            confirm: None,
            pipeline: Pipeline::new(),
            leftovers: Leftovers::new(),
            history: History::new(crate::clock::now),
            quarantine: Quarantine::new(crate::clock::now),
            settings: Settings {
                markers_open: false,
                facts: Facts {
                    version: env!("CARGO_PKG_VERSION"),
                    engine: None,
                    policy: None,
                },
            },
            sample,
            uninstall_inbox: Vec::new(),
            leftovers_inbox: None,
        }
    }

    /// Uninstall (the toolbar, the details pane, Delete or Enter on the list): the programs go to
    /// the Uninstall page. False when nothing is picked and nothing was said.
    pub fn ask_uninstall(&mut self) -> bool {
        if self.sample {
            // The sample pipeline: the model's Uninstall needs an engine that can change the PC,
            // so the targets are taken here and go to the mockup's confirmation.
            let targets = self.programs.page.uninstall_targets();
            return self.open_uninstall(targets);
        }
        self.programs.command(ProgramCommand::Uninstall);
        true
    }

    /// The Uninstall page's entry: `targets` from the Programs page (`ProgramsRequest::Uninstall`).
    /// With sample data the mockup's confirmation opens for them; with the engine they wait in
    /// [`Model::uninstall_inbox`] for the Uninstall page and that page opens.
    pub fn open_uninstall(&mut self, targets: Vec<UninstallTarget>) -> bool {
        if targets.is_empty() {
            return false;
        }
        if !self.sample {
            self.uninstall_inbox = targets;
            self.page = Page::Pipeline;
            return true;
        }
        let programs: Vec<usize> = targets
            .iter()
            .filter_map(|t| self.programs.index_of(&t.program_id))
            .filter(|i| !self.programs.all[*i].removed)
            .collect();
        if programs.is_empty() {
            return false;
        }
        self.pipeline.still_running = programs
            .iter()
            .any(|p| self.programs.all[*p].name.contains("Firefox"));
        self.confirm = Some(Confirm { programs });
        true
    }

    /// "Uninstall" in the confirmation: the programs go to the pipeline and the first starts.
    /// This is the only way into the pipeline.
    pub fn confirm_uninstall(&mut self, now: Instant) -> bool {
        let Some(confirm) = self.confirm.take() else {
            return false;
        };
        self.pipeline.enqueue(&confirm.programs);
        self.pipeline.start_next(now);
        self.page = Page::Pipeline;
        true
    }

    pub fn cancel_confirm(&mut self) -> bool {
        self.confirm.take().is_some()
    }

    /// Moves the sample pipeline on; a finished run takes its program off the list and hands its
    /// leftovers to the review. Returns whether anything changed, and the next deadline.
    pub fn tick(&mut self, now: Instant) -> (bool, Option<Instant>) {
        let (what, next) = self.pipeline.tick(now);
        match what {
            Ticked::Nothing => (false, next),
            Ticked::Stepped => {
                let scanning = self
                    .pipeline
                    .run
                    .as_ref()
                    .is_some_and(|r| r.step == STEPS.len() - 1);
                if scanning && self.leftovers.phase == LeftoverPhase::Empty {
                    self.leftovers.phase = LeftoverPhase::Waiting;
                    self.leftovers.program = self.pipeline.run.as_ref().map(|r| r.program);
                }
                (true, next)
            }
            Ticked::Finished(program) => {
                self.programs.pretend_removed(program);
                if let Some(p) = self.programs.all.get(program) {
                    let p = p.clone();
                    self.leftovers.found_for(program, &p);
                }
                (true, next)
            }
        }
    }

    /// The numbers the rail shows beside each page: (text, is a badge).
    pub fn badge(&self, page: Page) -> Option<(String, bool)> {
        match page {
            Page::Programs => Some((self.programs.count(Tab::Apps).to_string(), false)),
            Page::Pipeline if !self.sample => {
                let n = self.uninstall_inbox.len();
                (n > 0).then(|| (n.to_string(), true))
            }
            Page::Pipeline => {
                let n = self.pipeline.pending();
                (n > 0).then(|| (n.to_string(), true))
            }
            Page::Leftovers if self.sample => {
                let n = self.leftovers.count();
                (self.leftovers.phase == LeftoverPhase::Review && n > 0)
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
    fn likely_and_protected_start_unticked() {
        let p = sample_programs();
        let mut l = Leftovers::new();
        l.found_for(0, &p.all[0]);
        for i in l.groups.iter().flat_map(|g| &g.items) {
            assert_eq!(i.ticked, i.rating == Rating::Safe, "{}", i.path);
        }
    }

    #[test]
    fn the_leftovers_name_the_program_that_ran() {
        let p = sample_programs();
        for (at, p) in p.all.iter().enumerate() {
            let mut l = Leftovers::new();
            l.found_for(at, p);
            assert_eq!(l.count(), 9, "{}", p.name);
            assert_eq!(l.ticked().0, 6, "{}", p.name);
            // Only a Mozilla program leaves Mozilla's traces.
            let mozilla = p.name.contains("Mozilla") || p.publisher.contains("Mozilla");
            for i in l.groups.iter().flat_map(|g| &g.items) {
                assert!(
                    !i.path.contains("\\\\") && !i.path.ends_with('\\'),
                    "{}",
                    i.path
                );
                assert!(
                    mozilla || !i.path.contains("Mozilla"),
                    "{} for {}",
                    i.path,
                    p.name
                );
            }
        }
    }

    #[test]
    fn a_group_box_never_ticks_likely_or_protected() {
        let p = sample_programs();
        let mut l = Leftovers::new();
        l.found_for(0, &p.all[0]);
        for g in 0..l.groups.len() {
            l.toggle_group(g); // all Safe ticked -> unticks the group
            assert!(l.groups[g].items.iter().all(|i| !i.ticked));
            l.toggle_group(g); // ticks the Safe ones again
            for i in &l.groups[g].items {
                assert_eq!(i.ticked, i.rating == Rating::Safe, "{}", i.path);
            }
        }
        assert!(!l.toggle_item((1, 2)), "a protected item takes no tick");
        assert!(!l.groups[1].items[2].ticked);
    }

    #[test]
    fn nothing_reaches_the_pipeline_without_the_confirmation() {
        let mut m = sample_model();
        assert!(!m.ask_uninstall(), "nothing selected, nothing asked");
        m.programs.click(3, Mods::default());
        assert!(m.pipeline.run.is_none() && m.pipeline.queue.is_empty());
        assert!(m.ask_uninstall());
        assert!(m.pipeline.run.is_none() && m.pipeline.queue.is_empty());
        assert!(m.cancel_confirm());
        assert!(m.pipeline.run.is_none() && m.pipeline.queue.is_empty());
        assert!(m.ask_uninstall());
        let now = Instant::now();
        assert!(m.confirm_uninstall(now));
        assert_eq!(m.page, Page::Pipeline);
        assert!(m.pipeline.run.is_some());
    }

    #[test]
    fn with_the_engine_uninstall_goes_to_the_uninstall_pages_inbox() {
        let mut m = Model::new(Prefs::default(), sample_programs(), false);
        m.programs.click(2, Mods::default());
        let name = m.programs.all[m.programs.rows[2]].name.clone();
        assert!(m.open_uninstall(m.programs.page.uninstall_targets()));
        assert!(
            m.confirm.is_none(),
            "no sample confirmation with the engine"
        );
        assert_eq!(m.page, Page::Pipeline);
        assert_eq!(m.uninstall_inbox.len(), 1);
        assert_eq!(m.uninstall_inbox[0].program_name, name);
        assert!(m.pipeline.run.is_none() && m.pipeline.queue.is_empty());
    }

    #[test]
    fn the_pipeline_runs_to_the_review() {
        let mut m = sample_model();
        let before = m.programs.count(Tab::Apps);
        m.programs.click(0, Mods::default());
        m.ask_uninstall();
        let t0 = Instant::now();
        m.confirm_uninstall(t0);
        let mut now = t0;
        let mut guard = 0;
        while let (_, Some(next)) = m.tick(now) {
            now = next;
            guard += 1;
            assert!(guard < 50);
        }
        assert_eq!(m.leftovers.phase, LeftoverPhase::Review);
        assert_eq!(m.programs.count(Tab::Apps), before - 1);
        assert_eq!(m.programs.rows.len(), before - 1);
        assert_eq!(m.leftovers.count(), 9);
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
