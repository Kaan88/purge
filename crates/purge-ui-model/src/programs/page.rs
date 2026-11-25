//! The Programs page (S1; the logic of `ui/Purge.App/Views/ProgramsView.xaml.cs`): the list with its
//! tabs, search, filters and sort; the ticked programs and the details pane; the "removed outside Purge"
//! group; sizes, icons, forecasts and details as they arrive; the footer counts.
//!
//! Every public method returns the requests to send ([`ProgramsRequest`]); the UI reads
//! [`ProgramsModel::view`] after it.

use std::collections::{HashMap, HashSet};

use purge_model::{InstallScope, InstallerKind, ProgramId, View};
use purge_rpc::methods::{InventoryChanges, ProgramDetails, ProgramPatch};

use super::date::Clock;
use super::entries::{ProgramEntry, ProgramIcon};
use super::forecast::{ForecastLineKind, ForecastVerdict, LeftoverForecast};
use super::row::{BAR_MAX, ProgramRow, initial_of, join};
use super::rules::{self, ProgramTab};
use super::strings;
use crate::casefold::starts_with_ignore_case;
use crate::pipeline::removed::{
    RemovedCheckState, RemovedGroup, RemovedLeftovers, RemovedRequest, StoredScanOutcome,
};
use crate::pipeline::{CallError, LaunchResult, NoticeKind, UninstallTarget};

/// Programs per `programs.forecast` request.
pub const FORECAST_BATCH: usize = 8;
/// Programs per `programs.sizes` request.
pub const SIZE_CHUNK: usize = 16;

/// What the engine link can do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EngineState {
    /// A real engine (not the sample data).
    pub live: bool,
    /// The engine may route an uninstaller (an Uninstall click may start the broker).
    pub can_change_pc: bool,
}

/// The other users of the one broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BrokerUsers {
    /// The Uninstall pipeline runs a step.
    pub uninstall_busy: bool,
    /// The Leftovers page applies a change.
    pub leftovers_changing: bool,
}

/// The list's sort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SortKey {
    /// By name.
    #[default]
    Name,
    /// By publisher.
    Publisher,
    /// By size.
    Size,
    /// By expected leftovers ("likely junk").
    Junk,
    /// By install date.
    Date,
}

impl SortKey {
    /// The sort menu's keys, in [`strings::SORT_MENU`] order.
    pub const MENU: [SortKey; 5] = [
        SortKey::Name,
        SortKey::Publisher,
        SortKey::Size,
        SortKey::Junk,
        SortKey::Date,
    ];

    /// Size, date and junk start descending.
    fn starts_descending(self) -> bool {
        matches!(self, SortKey::Size | SortKey::Date | SortKey::Junk)
    }
}

/// One choice of the Filter menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Filter {
    /// "Would leave leftovers".
    Leftovers,
    /// "Installed for this user only".
    PerUser,
    /// "32-bit only".
    Bits32,
}

impl Filter {
    /// The menu's items in order, with their texts.
    pub const MENU: [(Filter, &'static str); 3] = [
        (Filter::Leftovers, strings::FILTER_LEFTOVERS),
        (Filter::PerUser, strings::FILTER_PER_USER),
        (Filter::Bits32, strings::FILTER_32),
    ];
}

/// The Filter menu's choices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Filters {
    /// "Would leave leftovers".
    pub only_leftovers: bool,
    /// "Installed for this user only".
    pub only_per_user: bool,
    /// "32-bit only".
    pub only_32: bool,
}

impl Filters {
    /// How many are on.
    pub fn count(self) -> usize {
        usize::from(self.only_leftovers)
            + usize::from(self.only_per_user)
            + usize::from(self.only_32)
    }

    fn passes(self, r: &ProgramRow) -> bool {
        (!self.only_leftovers
            || matches!(r.verdict(), ForecastVerdict::Some | ForecastVerdict::Large))
            && (!self.only_per_user || r.entry().entry.scope == InstallScope::User)
            && (!self.only_32 || r.entry().entry.view == View::K32)
    }
}

/// A program the icon request wants, with what its atlas stamp is made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IconWanted {
    /// The program.
    pub program_id: ProgramId,
    /// Its version.
    pub version: Option<String>,
    /// Its earliest install-time hint (a FILETIME).
    pub install_time: Option<u64>,
}

/// What the Programs page asks the UI to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramsRequest {
    /// `programs.list` (Refresh list, or after an uninstall); answer with [`ProgramsModel::on_list`].
    List,
    /// `programs.get {program_id}`; answer with [`ProgramsModel::on_details`] (`gone` is `Ok(None)`).
    Details {
        /// The program.
        program_id: ProgramId,
    },
    /// `programs.sizes` for one chunk; `size.ready` goes to [`ProgramsModel::on_sizes`], the reply to
    /// [`ProgramsModel::on_sizes_done`]. A newer `generation` replaces an older one.
    Sizes {
        /// The enrichment this chunk belongs to.
        generation: u64,
        /// The programs, at most [`SIZE_CHUNK`].
        program_ids: Vec<ProgramId>,
    },
    /// Icons in this order: the atlas first, then `programs.icons` for the misses, in chunks; each icon
    /// goes to [`ProgramsModel::on_icon`]. A newer `generation` cancels an older one.
    Icons {
        /// The enrichment this load belongs to.
        generation: u64,
        /// The programs, visible rows first.
        wanted: Vec<IconWanted>,
    },
    /// `programs.forecast` (proposed; the live engine has none) for one batch; answer with
    /// [`ProgramsModel::on_forecasts`].
    Forecasts {
        /// The programs, at most [`FORECAST_BATCH`].
        program_ids: Vec<ProgramId>,
    },
    /// `inventory.forget {program_ids}`; a failure is ignored.
    Forget {
        /// The programs.
        program_ids: Vec<ProgramId>,
    },
    /// A request of the removed-program check (never `Completed`, which the page handles): `Launch`,
    /// `Stored`, `ScanStored`, `Cancel`, `CloseBroker`, `AdminPromptCancelled`.
    Check(RemovedRequest),
    /// The check's scan goes to the Leftovers page with the check's broker session.
    OpenLeftovers(StoredScanOutcome),
    /// The check's scan could not go there (the Leftovers page applies a change): end its session.
    CloseCheckSession,
    /// A removed program's check started or ended: the Uninstall page's actions follow
    /// ([`ProgramsModel::check_running`]).
    CheckRunningChanged,
    /// Open the Uninstall page with these programs.
    Uninstall {
        /// The programs, visible rows first.
        targets: Vec<UninstallTarget>,
    },
    /// Open the folder in Explorer when it exists; otherwise call [`ProgramsModel::folder_missing`].
    OpenFolder {
        /// The install folder.
        path: String,
    },
    /// Open the web search in the browser.
    OpenWeb {
        /// The URL.
        url: String,
    },
    /// Scroll the list to the program.
    ScrollIntoView(ProgramId),
}

/// A command of the toolbar, the "…" menu or the command box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramCommand {
    /// "Open install folder".
    OpenFolder,
    /// "Search the web".
    Web,
    /// "Refresh list".
    Refresh,
    /// "Uninstall".
    Uninstall,
}

/// A bar of the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramsNotice {
    /// Its severity.
    pub kind: NoticeKind,
    /// The text.
    pub message: String,
}

/// One tab button.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TabView {
    /// The tab.
    pub tab: ProgramTab,
    /// Its label.
    pub label: &'static str,
    /// Its count; with a search or a filter on, how many of its programs it would show.
    pub count: usize,
    /// The selected tab.
    pub selected: bool,
}

/// The sort headers and the Sort button.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortView {
    /// The key.
    pub key: SortKey,
    /// Descending.
    pub descending: bool,
    /// "Name ↑".
    pub name: String,
    /// "Size".
    pub size: String,
    /// "Expected leftovers".
    pub junk: String,
    /// "Installed".
    pub date: String,
    /// "Sort: Name".
    pub button: String,
}

/// The toolbar's and the details pane's command states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandView {
    /// The toolbar's Uninstall.
    pub uninstall_enabled: bool,
    /// Its tooltip.
    pub uninstall_tooltip: Option<&'static str>,
    /// Its label: "Uninstall 3".
    pub uninstall_label: String,
    /// Its accessible name.
    pub uninstall_name: String,
    /// The details pane's Uninstall.
    pub details_uninstall_enabled: bool,
    /// Its tooltip.
    pub details_uninstall_tooltip: Option<&'static str>,
    /// "Open install folder".
    pub open_folder_enabled: bool,
    /// "Search the web".
    pub web_enabled: bool,
}

/// One line of "What Purge expects".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectLine {
    /// What it says (`None`: not known, the "unknown" glyph).
    pub kind: Option<ForecastLineKind>,
    /// The text.
    pub text: String,
    /// The detail beside it.
    pub detail: String,
}

/// The details pane of one program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetailsView {
    /// The program.
    pub program_id: ProgramId,
    /// Its name.
    pub name: String,
    /// "Publisher · 1.0 · Inno".
    pub sub: String,
    /// The tile's letter (empty with an icon).
    pub initial: String,
    /// The tile's colour: an index into [`super::row::TILE_COLORS`].
    pub tile: usize,
    /// Whether the icon replaces the tile.
    pub has_icon: bool,
    /// The uninstaller line.
    pub uninstaller: String,
    /// The location line.
    pub location: String,
    /// The location's tooltip: the folder.
    pub location_tooltip: Option<String>,
    /// "5 Nov 2026 · for all users".
    pub installed: String,
    /// The size line.
    pub size: String,
    /// "64-bit".
    pub platform: &'static str,
    /// "What Purge expects".
    pub expects: Vec<ExpectLine>,
    /// "Also owns", comma-separated; empty hides the row.
    pub owns: String,
    /// The uninstall command.
    pub uninstall_command: String,
    /// The quiet command.
    pub quiet_command: String,
    /// The product (or upgrade) code; `None` hides the row.
    pub product_code: Option<String>,
    /// The registry key.
    pub key_path: String,
}

/// One row of the "removed outside Purge" group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedRowView {
    /// The program.
    pub program_id: ProgramId,
    /// Its name.
    pub name: String,
    /// The tile's letter.
    pub initial: String,
    /// The line under the name.
    pub detail: String,
    /// The button's text.
    pub button_text: &'static str,
    /// Whether the button shows.
    pub button_visible: bool,
    /// Whether the button can be clicked.
    pub can_check: bool,
    /// The button's tooltip.
    pub check_hint: Option<&'static str>,
    /// Whether the row can be dismissed.
    pub can_dismiss: bool,
}

/// The "removed outside Purge" group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovedGroupView {
    /// The header.
    pub header: String,
    /// The rows.
    pub rows: Vec<RemovedRowView>,
}

/// Everything the Programs page shows (the rows themselves: [`ProgramsModel::row`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramsPageView {
    /// The tabs, in order.
    pub tabs: Vec<TabView>,
    /// The list, in order.
    pub shown: Vec<ProgramId>,
    /// The ticked programs the list shows, in selection order.
    pub selected: Vec<ProgramId>,
    /// The search text.
    pub query: String,
    /// The summary under the title.
    pub summary: String,
    /// The list's header: "ALL APPS · 12".
    pub all_label: String,
    /// The footer's left part.
    pub status_left: String,
    /// The footer's right part.
    pub status_right: String,
    /// "No programs match" with its hint.
    pub no_match: Option<(String, &'static str)>,
    /// The sort.
    pub sort: SortView,
    /// The filters.
    pub filters: Filters,
    /// The Filter button.
    pub filter_text: String,
    /// "3 selected".
    pub selected_count: String,
    /// The commands.
    pub commands: CommandView,
    /// The details pane; `None` closes it.
    pub details: Option<DetailsView>,
    /// The "removed outside Purge" group; `None` hides it.
    pub removed: Option<RemovedGroupView>,
    /// The bar.
    pub notice: Option<ProgramsNotice>,
}

/// The page's layout at a width (`OnPageSizeChanged`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PageLayout {
    /// Search, filter and sort go under the tabs.
    pub stack_tools: bool,
    /// Whether the details pane shows.
    pub details: bool,
    /// The details column's width (0 without it).
    pub details_width: f64,
    /// The spacing between list and details.
    pub spacing: f64,
}

impl PageLayout {
    /// A narrow page: search, filter and sort move under the tabs, the details pane gets narrower and,
    /// below 640 px, goes (the toolbar's Uninstall still works on the ticked programs).
    pub fn fit(width: f64) -> Self {
        let details = width >= 640.0;
        Self {
            stack_tools: width < 900.0,
            details,
            details_width: if !details {
                0.0
            } else if width < 1000.0 {
                280.0
            } else {
                330.0
            },
            spacing: if details { 16.0 } else { 0.0 },
        }
    }
}

/// The Programs page's model.
pub struct ProgramsModel {
    clock: Clock,
    engine: EngineState,
    users: BrokerUsers,
    loaded: bool,
    all: Vec<ProgramRow>,
    by_id: HashMap<ProgramId, usize>,
    sizes: HashMap<ProgramId, i64>,
    icons: HashMap<ProgramId, ProgramIcon>,
    forecasts: HashMap<ProgramId, Option<LeftoverForecast>>,
    tab: ProgramTab,
    query: String,
    sort: SortKey,
    descending: bool,
    filters: Filters,
    first_frame: bool,
    started: bool,
    shown: Vec<ProgramId>,
    selected: Vec<ProgramId>,
    ticked: HashSet<ProgramId>,
    current: Option<ProgramId>,
    // Enrichment.
    generation: u64,
    size_queue: Vec<ProgramId>,
    size_pos: usize,
    sizes_done: usize,
    sizing: bool,
    forecast_queue: Vec<ProgramId>,
    forecast_pos: usize,
    // The "removed outside Purge" group.
    changes: Option<Option<InventoryChanges>>,
    changes_shown: bool,
    group: Option<RemovedGroup>,
    removed: RemovedLeftovers,
    check_was_running: bool,
    notice_serial_shown: u64,
    uninstalled_here: HashSet<ProgramId>,
    notice: Option<ProgramsNotice>,
    out: Vec<ProgramsRequest>,
}

impl std::fmt::Debug for ProgramsModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProgramsModel")
            .field("rows", &self.all.len())
            .field("tab", &self.tab)
            .field("query", &self.query)
            .field("current", &self.current)
            .finish_non_exhaustive()
    }
}

impl ProgramsModel {
    /// A page with no list yet. `may_have_record` is the fingerprint-store probe of the removed-program
    /// check (see [`RemovedLeftovers::new`]).
    pub fn new(
        clock: Clock,
        engine: EngineState,
        may_have_record: impl Fn(&ProgramId) -> bool + 'static,
    ) -> Self {
        Self {
            clock,
            engine,
            users: BrokerUsers::default(),
            loaded: false,
            all: vec![],
            by_id: HashMap::new(),
            sizes: HashMap::new(),
            icons: HashMap::new(),
            forecasts: HashMap::new(),
            tab: ProgramTab::Apps,
            query: String::new(),
            sort: SortKey::Name,
            descending: false,
            filters: Filters::default(),
            first_frame: false,
            started: false,
            shown: vec![],
            selected: vec![],
            ticked: HashSet::new(),
            current: None,
            generation: 0,
            size_queue: vec![],
            size_pos: 0,
            sizes_done: 0,
            sizing: false,
            forecast_queue: vec![],
            forecast_pos: 0,
            changes: None,
            changes_shown: false,
            group: None,
            removed: RemovedLeftovers::new(may_have_record),
            check_was_running: false,
            notice_serial_shown: 0,
            uninstalled_here: HashSet::new(),
            notice: None,
            out: vec![],
        }
    }

    // ---- reads ------------------------------------------------------------------------------------

    /// A row by id.
    pub fn row(&self, id: &ProgramId) -> Option<&ProgramRow> {
        self.by_id.get(id).map(|&i| &self.all[i])
    }

    /// All rows, in list-reply order (for the command box).
    pub fn rows(&self) -> &[ProgramRow] {
        &self.all
    }

    /// The tab.
    pub fn tab(&self) -> ProgramTab {
        self.tab
    }

    /// The search text.
    pub fn query(&self) -> &str {
        &self.query
    }

    /// The program of the details pane.
    pub fn current(&self) -> Option<&ProgramId> {
        self.current.as_ref()
    }

    /// The ticked programs.
    pub fn ticked(&self) -> &HashSet<ProgramId> {
        &self.ticked
    }

    /// True while a removed program's leftovers check runs (the Uninstall page's actions wait meanwhile).
    pub fn check_running(&self) -> bool {
        self.removed.is_busy()
    }

    /// The removed-program check.
    pub fn removed_check(&self) -> &RemovedLeftovers {
        &self.removed
    }

    // ---- inputs from the window -------------------------------------------------------------------

    /// The engine link's state changed (it started, or it ended).
    pub fn set_engine(&mut self, engine: EngineState) -> Vec<ProgramsRequest> {
        self.engine = engine;
        self.render_removed();
        self.take()
    }

    /// The Uninstall pipeline started or finished a step, or the Leftovers page started or finished a
    /// change: the removed rows' buttons follow it.
    pub fn set_broker_users(&mut self, users: BrokerUsers) -> Vec<ProgramsRequest> {
        self.users = users;
        self.render_removed();
        self.take()
    }

    /// The first frame is out: the deferred work starts (the removed group, sizes and icons, forecasts).
    pub fn on_first_frame(&mut self) -> Vec<ProgramsRequest> {
        if !self.first_frame {
            self.first_frame = true;
            self.show_details();
            if self.loaded {
                self.start_after_first_frame();
            }
        }
        self.take()
    }

    // ---- answers ----------------------------------------------------------------------------------

    /// The answer of `programs.list` ([`ProgramEntry::from_list`] of its batches and patches). The first
    /// one loads the page; a later one (Refresh, after an uninstall) rebuilds it and measures again.
    pub fn on_list(&mut self, list: Result<Vec<ProgramEntry>, CallError>) -> Vec<ProgramsRequest> {
        match list {
            Err(e) if self.loaded => {
                self.show_notice(strings::list_failed(e.message()), NoticeKind::Warning)
            }
            Err(e) => self.show_notice(e.message().to_owned(), NoticeKind::Warning),
            Ok(entries) => {
                let first = !self.loaded;
                self.loaded = true;
                self.rebuild(entries);
                if first {
                    // The list can arrive after the first frame; then what it would have started starts here.
                    if self.first_frame {
                        self.start_after_first_frame();
                    }
                } else {
                    self.start_enrichment();
                }
            }
        }
        self.take()
    }

    /// Patches that came after the list reply: applied to the rows, which move between tabs when they change.
    pub fn on_late_patches(&mut self, patches: &[ProgramPatch]) -> Vec<ProgramsRequest> {
        if !self.loaded {
            return vec![];
        }
        let mut changed = false;
        for patch in patches {
            if let Some(&i) = self.by_id.get(&patch.program_id) {
                let mut entry = self.all[i].entry().clone();
                entry.apply_patch(patch);
                self.all[i].update(entry);
                changed = true;
            }
        }
        if changed {
            self.refresh();
        }
        self.take()
    }

    /// The answer of `inventory.changes` (`None` when the engine could not answer): the "removed outside
    /// Purge" group shows once, when there is something in it.
    pub fn on_changes(&mut self, changes: Option<InventoryChanges>) -> Vec<ProgramsRequest> {
        if self.changes.is_none() {
            self.changes = Some(changes);
        }
        if self.started {
            self.show_removed();
        }
        self.take()
    }

    /// One `size.ready` batch of the current enrichment.
    pub fn on_sizes(
        &mut self,
        generation: u64,
        sizes: &[purge_rpc::methods::ProgramSize],
    ) -> Vec<ProgramsRequest> {
        if generation != self.generation {
            return vec![];
        }
        for size in sizes {
            self.sizes_done += 1;
            let Some(bytes) = size.bytes else { continue };
            let bytes = i64::try_from(bytes).unwrap_or(i64::MAX);
            self.sizes.insert(size.program_id.clone(), bytes);
            if let Some(&i) = self.by_id.get(&size.program_id) {
                self.all[i].set_size(Some(bytes));
            }
        }
        self.update_bars();
        self.take()
    }

    /// The reply of one `programs.sizes` chunk: the next chunk, or the end of the measuring. A failed
    /// chunk ends it too.
    pub fn on_sizes_done(
        &mut self,
        generation: u64,
        result: Result<(), CallError>,
    ) -> Vec<ProgramsRequest> {
        if generation != self.generation || !self.sizing {
            return vec![];
        }
        if matches!(result, Err(CallError::Cancelled)) {
            return vec![];
        }
        if result.is_ok() && self.size_pos < self.size_queue.len() {
            self.next_size_chunk();
        } else {
            self.sizing = false;
            if self.sort == SortKey::Size {
                self.refresh();
            }
        }
        self.take()
    }

    /// One icon of the current enrichment (from the atlas or the engine). An icon without pixels keeps
    /// the placeholder tile.
    pub fn on_icon(&mut self, generation: u64, icon: ProgramIcon) {
        if generation != self.generation || icon.bgra.is_none() {
            return;
        }
        if let Some(&i) = self.by_id.get(&icon.program_id) {
            self.all[i].set_icon(icon.clone());
        }
        self.icons.insert(icon.program_id.clone(), icon);
    }

    /// The answer of one `programs.forecast` batch. A failure leaves the rest "Not known yet".
    pub fn on_forecasts(
        &mut self,
        result: Result<Vec<LeftoverForecast>, CallError>,
    ) -> Vec<ProgramsRequest> {
        let start = self.forecast_pos;
        if start >= self.forecast_queue.len() {
            return vec![];
        }
        let end = (start + FORECAST_BATCH).min(self.forecast_queue.len());
        let Ok(got) = result else {
            self.forecast_pos = self.forecast_queue.len();
            return vec![];
        };
        let batch: Vec<ProgramId> = self.forecast_queue[start..end].to_vec();
        self.forecast_pos = end;
        for id in &batch {
            self.forecasts.insert(id.clone(), None);
        }
        for f in got {
            self.forecasts.insert(f.program_id.clone(), Some(f));
        }
        for id in &batch {
            if let Some(&i) = self.by_id.get(id) {
                self.all[i].set_forecast(self.forecasts[id].clone());
            }
        }
        if self.current.as_ref().is_some_and(|c| batch.contains(c)) {
            self.show_details();
        }
        self.next_forecast_batch();
        self.take()
    }

    /// The answer of `programs.get` (`Ok(None)`: the program is gone). A failure shows what the list knew.
    pub fn on_details(
        &mut self,
        program_id: &ProgramId,
        result: Result<Option<ProgramDetails>, CallError>,
    ) -> Vec<ProgramsRequest> {
        let Some(&i) = self.by_id.get(program_id) else {
            return vec![];
        };
        let row = &mut self.all[i];
        // A row made again by a reload asks for its own details.
        if !row.details_requested {
            return vec![];
        }
        if let Ok(Some(details)) = result {
            let mut entry = row.entry().clone();
            entry.apply_details(&details);
            row.update(entry);
        }
        row.details_loaded = true;
        self.take()
    }

    // ---- the removed-program check ----------------------------------------------------------------

    /// "Check for leftovers" (or "Stop") on a removed row.
    pub fn check_removed(&mut self, program_id: &ProgramId) -> Vec<ProgramsRequest> {
        if self.removed.is_busy() {
            // The running row's button reads Stop; the others are disabled meanwhile.
            if self.removed.active_program() == Some(program_id) {
                let requests = self.removed.cancel();
                self.forward(requests);
            }
            self.render_removed();
            return self.take();
        }
        if self.users.uninstall_busy {
            return self.notice_now(strings::UNINSTALL_RUNNING);
        }
        if self.users.leftovers_changing {
            return self.notice_now(strings::LEFTOVERS_CHANGING);
        }
        let name = self
            .group
            .as_ref()
            .and_then(|g| g.shown().iter().find(|p| p.program_id == *program_id))
            .map(|p| p.name.clone())
            .unwrap_or_default();
        let requests = self.removed.check(program_id, &name);
        self.forward(requests);
        self.render_removed();
        self.take()
    }

    /// "Dismiss" on a removed row: it leaves the group (not while its own check runs).
    pub fn dismiss_removed(&mut self, program_id: &ProgramId) -> Vec<ProgramsRequest> {
        if self.removed.can_dismiss(program_id) {
            self.acknowledge_removed(program_id);
        }
        self.take()
    }

    /// See [`RemovedLeftovers::on_launch`].
    pub fn on_check_launch(
        &mut self,
        launch: Result<LaunchResult, CallError>,
    ) -> Vec<ProgramsRequest> {
        let requests = self.removed.on_launch(launch);
        self.after_check(requests)
    }

    /// See [`RemovedLeftovers::on_stored`].
    pub fn on_check_stored(
        &mut self,
        stored: Result<Vec<ProgramId>, CallError>,
    ) -> Vec<ProgramsRequest> {
        let requests = self.removed.on_stored(stored);
        self.after_check(requests)
    }

    /// See [`RemovedLeftovers::on_scan_progress`].
    pub fn on_check_progress(&mut self, phase: &str) {
        self.removed.on_scan_progress(phase);
    }

    /// See [`RemovedLeftovers::on_scan`].
    pub fn on_check_scan(
        &mut self,
        scan: Result<purge_rpc::methods::ScanResult, CallError>,
    ) -> Vec<ProgramsRequest> {
        let requests = self.removed.on_scan(scan);
        self.after_check(requests)
    }

    /// The Uninstall page's uninstaller ran and the broker checked the program. When Purge removed it,
    /// the engine forgets it, so no later session lists it as removed outside Purge. The list is then read
    /// again, so the program leaves it now and the stored list agrees; a program still in the registry stays.
    pub fn on_uninstall_run_ended(
        &mut self,
        program_id: &ProgramId,
        removed_by_purge: bool,
    ) -> Vec<ProgramsRequest> {
        if !self.engine.live {
            return vec![];
        }
        if removed_by_purge {
            self.uninstalled_here.insert(program_id.clone());
            if self.group.as_ref().is_some_and(|g| g.contains(program_id)) {
                self.acknowledge_removed(program_id);
            } else {
                self.out.push(ProgramsRequest::Forget {
                    program_ids: vec![program_id.clone()],
                });
            }
        }
        self.out.push(ProgramsRequest::List);
        self.take()
    }

    // ---- user actions -----------------------------------------------------------------------------

    /// The search box changed.
    pub fn set_search(&mut self, query: &str) -> Vec<ProgramsRequest> {
        let trimmed = query.trim();
        if trimmed != self.query {
            self.query = trimmed.to_owned();
            self.refresh();
        }
        self.take()
    }

    /// A tab was clicked.
    pub fn select_tab(&mut self, tab: ProgramTab) -> Vec<ProgramsRequest> {
        self.tab = tab;
        self.refresh();
        self.take()
    }

    /// A column header was clicked: the same key turns the order around.
    pub fn sort_by_header(&mut self, key: SortKey) -> Vec<ProgramsRequest> {
        if self.sort == key {
            self.descending = !self.descending;
        } else {
            self.sort = key;
            self.descending = key.starts_descending();
        }
        self.refresh();
        self.take()
    }

    /// An item of the Sort menu.
    pub fn sort_by_menu(&mut self, key: SortKey) -> Vec<ProgramsRequest> {
        self.sort = key;
        self.descending = key.starts_descending();
        self.refresh();
        self.take()
    }

    /// An item of the Filter menu.
    pub fn set_filter(&mut self, filter: Filter, on: bool) -> Vec<ProgramsRequest> {
        match filter {
            Filter::Leftovers => self.filters.only_leftovers = on,
            Filter::PerUser => self.filters.only_per_user = on,
            Filter::Bits32 => self.filters.only_32 = on,
        }
        self.refresh();
        self.take()
    }

    /// The list's selection changed (a multiple-selection list: a click ticks or unticks). The details
    /// pane follows the row most recently ticked; unticking it falls back to another ticked row.
    pub fn on_selection_changed(
        &mut self,
        added: &[ProgramId],
        removed: &[ProgramId],
    ) -> Vec<ProgramsRequest> {
        for id in removed {
            self.selected.retain(|s| s != id);
            self.ticked.remove(id);
        }
        for id in added {
            if !self.selected.contains(id) {
                self.selected.push(id.clone());
            }
            self.ticked.insert(id.clone());
        }
        if let Some(last) = added.last() {
            self.current = Some(last.clone());
        } else if self.current.as_ref().is_some_and(|c| removed.contains(c)) {
            self.current = self.selected.last().cloned();
        }
        self.show_details();
        self.take()
    }

    /// Ticks or unticks one row (a click in the multiple-selection list).
    pub fn toggle(&mut self, id: &ProgramId) -> Vec<ProgramsRequest> {
        if self.selected.contains(id) {
            self.on_selection_changed(&[], std::slice::from_ref(id))
        } else {
            self.on_selection_changed(std::slice::from_ref(id), &[])
        }
    }

    /// Selects one program (from the command box) and shows it.
    pub fn reveal(&mut self, id: &ProgramId) -> Vec<ProgramsRequest> {
        let Some(row) = self.row(id) else {
            return vec![];
        };
        if !row.in_tab(self.tab) {
            self.tab = if row.is_app() {
                ProgramTab::Apps
            } else if row.is_component() {
                ProgramTab::Components
            } else {
                ProgramTab::Unnamed
            };
        }
        self.query.clear();
        self.refresh();
        self.ticked.clear();
        self.ticked.insert(id.clone());
        self.selected = if self.shown.contains(id) {
            vec![id.clone()]
        } else {
            vec![]
        };
        self.current = Some(id.clone());
        self.out.push(ProgramsRequest::ScrollIntoView(id.clone()));
        self.show_details();
        self.take()
    }

    /// Runs a program command. Buttons and the command box both come here, so a typed command takes
    /// exactly the steps its button takes.
    pub fn run_command(&mut self, command: ProgramCommand) -> Vec<ProgramsRequest> {
        let current = self.current.as_ref().and_then(|c| self.row(c));
        match command {
            ProgramCommand::OpenFolder => match current {
                None => return self.info_now(strings::SELECT_FIRST),
                Some(row) => match &row.entry().entry.install_location {
                    Some(dir) => {
                        let path = dir.clone();
                        self.out.push(ProgramsRequest::OpenFolder { path });
                    }
                    None => return self.notice_now(strings::NO_FOLDER),
                },
            },
            ProgramCommand::Web => match current {
                None => return self.info_now(strings::SELECT_FIRST),
                Some(row) => {
                    let terms = join(" ", &[row.name(), row.publisher()]);
                    let url = format!("https://www.bing.com/search?q={}", escape_data(&terms));
                    self.out.push(ProgramsRequest::OpenWeb { url });
                }
            },
            ProgramCommand::Refresh if self.engine.live => self.out.push(ProgramsRequest::List),
            ProgramCommand::Refresh => return self.info_now(strings::SAMPLE_NO_REFRESH),
            ProgramCommand::Uninstall if self.engine.can_change_pc && self.check_running() => {
                let hint = self.command_hint();
                return self.notice_now(hint);
            }
            ProgramCommand::Uninstall if self.engine.can_change_pc => {
                let targets = self.uninstall_targets();
                if targets.is_empty() {
                    return self.info_now(strings::SELECT_TO_UNINSTALL_FIRST);
                }
                // Several ticked: the Uninstall page runs them one after another, each with its own steps.
                self.out.push(ProgramsRequest::Uninstall { targets });
            }
            ProgramCommand::Uninstall => {
                let hint = self.uninstall_hint();
                return self.notice_now(hint);
            }
        }
        self.take()
    }

    /// The folder of an [`ProgramsRequest::OpenFolder`] is not on this PC.
    pub fn folder_missing(&mut self) {
        self.show_notice(strings::NO_FOLDER.into(), NoticeKind::Warning);
    }

    /// Shows why the engine could not be used (startup).
    pub fn show_engine_notice(&mut self, message: &str) {
        self.show_notice(message.into(), NoticeKind::Warning);
    }

    /// The bar was closed.
    pub fn dismiss_notice(&mut self) {
        self.notice = None;
    }

    /// The programs "Uninstall" acts on: every ticked one (visible ones in list order first), else the
    /// details pane's.
    pub fn uninstall_targets(&self) -> Vec<UninstallTarget> {
        let mut seen = HashSet::new();
        let mut targets: Vec<UninstallTarget> = self
            .shown
            .iter()
            .chain(self.all.iter().map(|r| r.id()))
            .filter(|id| self.ticked.contains(*id) && seen.insert((*id).clone()))
            .filter_map(|id| self.row(id))
            .map(|r| UninstallTarget::new(r.id().clone(), r.name()))
            .collect();
        if targets.is_empty()
            && let Some(row) = self.current.as_ref().and_then(|c| self.row(c))
        {
            targets.push(UninstallTarget::new(row.id().clone(), row.name()));
        }
        targets
    }

    // ---- the view ---------------------------------------------------------------------------------

    /// Everything the page shows now.
    pub fn view(&self) -> ProgramsPageView {
        let size_of = |ids: &mut dyn Iterator<Item = &ProgramRow>| -> i64 {
            ids.map(|r| r.size_bytes().unwrap_or(0)).sum()
        };
        let total = size_of(&mut self.all.iter());
        let would_leave = (self.forecasts.len() >= self.all.len()
            && self.forecasts.values().any(Option::is_some))
        .then(|| {
            self.all
                .iter()
                .filter(|r| {
                    r.is_app()
                        && matches!(r.verdict(), ForecastVerdict::Some | ForecastVerdict::Large)
                })
                .count()
        });
        let shown_size = size_of(&mut self.shown.iter().filter_map(|id| self.row(id)));
        let mut status_right = if self.engine.live {
            strings::ENGINE_CONNECTED.to_owned()
        } else {
            strings::SAMPLE_DATA.to_owned()
        };
        if self.engine.live && self.sizing && !self.all.is_empty() {
            status_right.push_str(&strings::measuring(
                self.sizes_done.min(self.all.len()),
                self.all.len(),
            ));
        }
        let n = self.ticked.len();
        let hidden = n.saturating_sub(self.selected.len());
        let current_name = self
            .current
            .as_ref()
            .and_then(|c| self.row(c))
            .map(ProgramRow::name);
        ProgramsPageView {
            tabs: self.tab_views(),
            shown: self.shown.clone(),
            selected: self.selected.clone(),
            query: self.query.clone(),
            summary: strings::summary(self.all.len(), &rules::format_size(total), would_leave),
            all_label: strings::all_label(self.tab, self.shown.len()),
            status_left: strings::status_left(
                self.shown.len(),
                self.tab,
                &rules::format_size(shown_size),
            ),
            status_right,
            no_match: (self.shown.is_empty()
                && (!self.query.is_empty() || self.filters.count() > 0))
                .then(|| strings::no_match(&self.query, self.filters.count() > 0, self.tab)),
            sort: self.sort_view(),
            filters: self.filters,
            filter_text: strings::filter_text(self.filters.count()),
            selected_count: strings::selected_count(n, hidden),
            commands: self.command_view(n, current_name),
            details: self.details_view(),
            removed: self.removed_view(),
            notice: self.notice.clone(),
        }
    }

    fn tab_views(&self) -> Vec<TabView> {
        let filtering = !self.query.is_empty() || self.filters.count() > 0;
        let matching: Vec<&ProgramRow> = self
            .all
            .iter()
            .filter(|r| !filtering || (r.matches(&self.query) && self.filters.passes(r)))
            .collect();
        ProgramTab::ALL
            .iter()
            .map(|&tab| TabView {
                tab,
                label: strings::tab_label(tab),
                count: matching.iter().filter(|r| r.in_tab(tab)).count(),
                selected: tab == self.tab,
            })
            .collect()
    }

    fn sort_view(&self) -> SortView {
        let arrow = if self.descending {
            strings::ARROW_DOWN
        } else {
            strings::ARROW_UP
        };
        let header = |text: &str, key: SortKey| {
            format!("{text}{}", if self.sort == key { arrow } else { "" })
        };
        SortView {
            key: self.sort,
            descending: self.descending,
            name: header(strings::HEADER_NAME, SortKey::Name),
            size: header(strings::HEADER_SIZE, SortKey::Size),
            junk: header(strings::HEADER_LEFTOVERS, SortKey::Junk),
            date: header(strings::HEADER_INSTALLED, SortKey::Date),
            button: format!(
                "Sort: {}",
                match self.sort {
                    SortKey::Publisher => "Publisher",
                    SortKey::Size => "Size",
                    SortKey::Junk => "Expected leftovers",
                    SortKey::Date => "Install date",
                    SortKey::Name => "Name",
                }
            ),
        }
    }

    fn command_view(&self, ticked: usize, current_name: Option<&str>) -> CommandView {
        let can = self.engine.can_change_pc && !self.check_running();
        let hint = (!can).then(|| self.command_hint());
        // The toolbar button needs a program; the details pane's button only shows with one.
        let picked = self.current.is_some() || ticked > 0;
        let current = self.current.as_ref().and_then(|c| self.row(c));
        CommandView {
            uninstall_enabled: can && picked,
            uninstall_tooltip: hint.or((!picked).then_some(strings::SELECT_TO_UNINSTALL)),
            uninstall_label: strings::uninstall_label(ticked),
            uninstall_name: strings::uninstall_name(ticked, current_name),
            details_uninstall_enabled: can,
            details_uninstall_tooltip: hint,
            open_folder_enabled: current
                .is_some_and(|r| r.entry().entry.install_location.is_some()),
            web_enabled: current.is_some(),
        }
    }

    fn command_hint(&self) -> &'static str {
        if self.engine.can_change_pc && self.check_running() {
            strings::CHECK_RUNNING_HINT
        } else {
            self.uninstall_hint()
        }
    }

    fn uninstall_hint(&self) -> &'static str {
        if self.engine.live {
            strings::ENGINE_NOT_USABLE
        } else {
            strings::SAMPLE_NO_ENGINE
        }
    }

    fn details_view(&self) -> Option<DetailsView> {
        use strings::details as d;
        if !self.first_frame {
            return None;
        }
        let row = self.row(self.current.as_ref()?)?;
        let e = &row.entry().entry;
        let reading = !row.details_loaded;
        let uninstaller = if reading {
            d::READING.to_owned()
        } else if e.uninstall_string.is_none() {
            d::NONE_REGISTERED.to_owned()
        } else {
            let quiet =
                e.quiet_uninstall_string.is_some() || e.installer_kind == InstallerKind::Msi;
            format!(
                "{}{}",
                row.kind_text(),
                if quiet { d::QUIET_AVAILABLE } else { "" }
            )
        };
        let expects = match row.forecast() {
            Some(f) => f
                .lines
                .iter()
                .map(|l| ExpectLine {
                    kind: Some(l.kind),
                    text: l.text.clone(),
                    detail: l.detail.clone().unwrap_or_default(),
                })
                .collect(),
            None => vec![ExpectLine {
                kind: None,
                text: if self.forecasts.contains_key(row.id()) {
                    d::NOT_KNOWN.into()
                } else {
                    d::CHECKING.into()
                },
                detail: String::new(),
            }],
        };
        let scope = format!("for {}", row.scope_text());
        Some(DetailsView {
            program_id: row.id().clone(),
            name: row.name().to_owned(),
            sub: join(" · ", &[row.publisher(), row.version(), row.kind_chip()]),
            initial: if row.has_icon() {
                String::new()
            } else {
                row.initial().to_owned()
            },
            tile: row.tile(),
            has_icon: row.has_icon(),
            uninstaller,
            location: if reading {
                d::READING.to_owned()
            } else {
                e.install_location
                    .clone()
                    .unwrap_or_else(|| d::NOT_RECORDED.to_owned())
            },
            location_tooltip: e.install_location.clone(),
            installed: join(" · ", &[row.installed_text(), &scope]),
            size: if !row.size_text().is_empty() {
                row.size_text().to_owned()
            } else if self.sizing {
                d::MEASURING.to_owned()
            } else {
                d::NOT_MEASURED.to_owned()
            },
            platform: row.bits_text(),
            expects,
            owns: self.related_to(row).join(", "),
            uninstall_command: if reading {
                d::ELLIPSIS.to_owned()
            } else {
                e.uninstall_string
                    .clone()
                    .unwrap_or_else(|| d::NONE.to_owned())
            },
            quiet_command: if reading {
                d::ELLIPSIS.to_owned()
            } else {
                e.quiet_uninstall_string
                    .clone()
                    .unwrap_or_else(|| d::NONE.to_owned())
            },
            product_code: e.product_code.clone().or_else(|| e.upgrade_code.clone()),
            key_path: e.key_path.clone(),
        })
    }

    /// Entries that belong with this one: its child keys, and same-publisher entries named after it
    /// ("Mozilla Firefox" → "Mozilla Maintenance Service"). A UI hint only; ownership is the engine's job.
    fn related_to(&self, row: &ProgramRow) -> Vec<String> {
        let key = rules::key_name(&row.entry().entry.key_path);
        let first_word = row.name().split(' ').next().unwrap_or("");
        self.all
            .iter()
            .filter(|r| {
                r.id() != row.id()
                    && r.entry().entry.flags.has_display_name
                    && (r.entry().entry.flags.parent_key.as_deref() == Some(key)
                        || (!r.publisher().is_empty()
                            && r.publisher() == row.publisher()
                            && !r.is_child()
                            && first_word.encode_utf16().count() >= 4
                            && starts_with_ignore_case(r.name(), first_word)))
            })
            .map(|r| r.name().to_owned())
            .take(3)
            .collect()
    }

    fn removed_view(&self) -> Option<RemovedGroupView> {
        use strings::removed as s;
        let group = self.group.as_ref().filter(|g| !g.is_empty())?;
        let busy = self.removed.is_busy();
        let active = self.removed.active_program();
        // One broker at a time: while the Uninstall pipeline runs a step or the Leftovers page applies a
        // change over its link, no check starts.
        let elsewhere = if self.users.uninstall_busy {
            Some(s::WAITS_UNINSTALL)
        } else if self.users.leftovers_changing {
            Some(s::WAITS_LEFTOVERS)
        } else {
            None
        };
        let rows = group
            .shown()
            .iter()
            .map(|p| {
                let mine = active == Some(&p.program_id);
                let wait_hint = if busy && !mine {
                    Some(s::WAITS_CHECK)
                } else {
                    elsewhere
                };
                let state = self
                    .removed
                    .known_state(&p.program_id)
                    .unwrap_or(RemovedCheckState::Record);
                let progress = if mine {
                    self.removed.progress_text()
                } else {
                    None
                };
                let running = matches!(
                    state,
                    RemovedCheckState::Checking | RemovedCheckState::Scanning
                );
                RemovedRowView {
                    program_id: p.program_id.clone(),
                    name: p.name.clone(),
                    initial: initial_of(&p.name),
                    detail: match state {
                        RemovedCheckState::NoRecord => s::NO_RECORD.to_owned(),
                        RemovedCheckState::Starting => s::STARTING.to_owned(),
                        RemovedCheckState::Checking => s::CHECKING.to_owned(),
                        RemovedCheckState::Scanning => s::scanning(progress),
                        RemovedCheckState::Record => s::RECORD.to_owned(),
                    },
                    button_text: if running { s::STOP } else { s::CHECK },
                    button_visible: state != RemovedCheckState::NoRecord,
                    can_check: running
                        || (state == RemovedCheckState::Record
                            && self.engine.can_change_pc
                            && wait_hint.is_none()),
                    check_hint: Some(if running {
                        s::STOP_HINT
                    } else if !self.engine.can_change_pc {
                        self.uninstall_hint()
                    } else {
                        wait_hint.unwrap_or(s::CHECK_HINT)
                    }),
                    can_dismiss: !matches!(
                        state,
                        RemovedCheckState::Starting
                            | RemovedCheckState::Checking
                            | RemovedCheckState::Scanning
                    ),
                }
            })
            .collect();
        Some(RemovedGroupView {
            header: group.header(self.engine.live),
            rows,
        })
    }

    // ---- internals --------------------------------------------------------------------------------

    fn take(&mut self) -> Vec<ProgramsRequest> {
        std::mem::take(&mut self.out)
    }

    fn show_notice(&mut self, message: String, kind: NoticeKind) {
        self.notice = Some(ProgramsNotice { kind, message });
    }

    fn notice_now(&mut self, message: &str) -> Vec<ProgramsRequest> {
        self.show_notice(message.to_owned(), NoticeKind::Warning);
        self.take()
    }

    fn info_now(&mut self, message: &str) -> Vec<ProgramsRequest> {
        self.show_notice(message.to_owned(), NoticeKind::Info);
        self.take()
    }

    fn rebuild(&mut self, entries: Vec<ProgramEntry>) {
        let today = self.clock.today;
        self.all = entries
            .into_iter()
            .map(|e| {
                let size = self.sizes.get(e.id()).copied();
                let installed = rules::install_date(&e.entry, &self.clock);
                ProgramRow::new(e, size, installed, today)
            })
            .collect();
        self.by_id = self
            .all
            .iter()
            .enumerate()
            .map(|(i, r)| (r.id().clone(), i))
            .collect();
        for row in &mut self.all {
            if let Some(icon) = self.icons.get(row.id()) {
                row.set_icon(icon.clone());
            }
            if let Some(f) = self.forecasts.get(row.id()) {
                row.set_forecast(f.clone());
            }
        }
        self.update_bars();
        if self
            .current
            .as_ref()
            .is_some_and(|c| !self.by_id.contains_key(c))
        {
            self.current = None;
        }
        let by_id = &self.by_id;
        self.ticked.retain(|id| by_id.contains_key(id));
        self.refresh();
    }

    fn update_bars(&mut self) {
        let max = self
            .all
            .iter()
            .map(|r| r.size_bytes().unwrap_or(0))
            .max()
            .unwrap_or(0)
            .max(1);
        for r in &mut self.all {
            r.bar_width = match r.size_bytes() {
                Some(b) if b > 0 => (BAR_MAX * b as f64 / max as f64).max(2.0),
                _ => 0.0,
            };
        }
    }

    fn start_after_first_frame(&mut self) {
        if self.started {
            return;
        }
        self.started = true;
        self.show_removed();
        self.start_enrichment();
        self.start_forecasts();
    }

    /// The order the deferred loads take: what the list shows now first, then the rest in list order.
    fn enrich_order(&self) -> Vec<ProgramId> {
        let mut seen = HashSet::new();
        self.shown
            .iter()
            .chain(self.all.iter().map(|r| r.id()))
            .filter(|id| seen.insert((*id).clone()))
            .cloned()
            .collect()
    }

    /// Fills the rows' icons and sizes, viewport first. The engine answers one request at a time, so
    /// sizes go in small chunks and a details request waits for at most one of them.
    fn start_enrichment(&mut self) {
        self.generation += 1;
        let order = self.enrich_order();
        let wanted = order
            .iter()
            .filter_map(|id| self.row(id))
            .map(|r| IconWanted {
                program_id: r.id().clone(),
                version: r.entry().entry.version.clone(),
                install_time: r
                    .entry()
                    .entry
                    .install_time_evidence
                    .iter()
                    .map(|e| e.time.0)
                    .min(),
            })
            .collect();
        self.out.push(ProgramsRequest::Icons {
            generation: self.generation,
            wanted,
        });
        self.size_queue = order;
        self.size_pos = 0;
        self.sizes_done = 0;
        self.sizing = true;
        if self.size_queue.is_empty() {
            self.sizing = false;
        } else {
            self.next_size_chunk();
        }
    }

    fn next_size_chunk(&mut self) {
        let end = (self.size_pos + SIZE_CHUNK).min(self.size_queue.len());
        let program_ids = self.size_queue[self.size_pos..end].to_vec();
        self.size_pos = end;
        self.out.push(ProgramsRequest::Sizes {
            generation: self.generation,
            program_ids,
        });
    }

    /// Asks for expected leftovers in small batches, in list order, so the visible rows fill first.
    fn start_forecasts(&mut self) {
        self.forecast_queue = self.enrich_order();
        self.forecast_pos = 0;
        self.next_forecast_batch();
    }

    fn next_forecast_batch(&mut self) {
        if self.forecast_pos >= self.forecast_queue.len() {
            return;
        }
        let end = (self.forecast_pos + FORECAST_BATCH).min(self.forecast_queue.len());
        self.out.push(ProgramsRequest::Forecasts {
            program_ids: self.forecast_queue[self.forecast_pos..end].to_vec(),
        });
    }

    /// The rows the list shows for the tab, search, filters and sort; then the ticked rows that are still
    /// in it are selected again (by id: a reload makes new rows). Nothing is picked for the user: when
    /// the ticked rows left the list, nothing is selected and the details pane closes.
    fn refresh(&mut self) {
        let rows: Vec<&ProgramRow> = self
            .all
            .iter()
            .filter(|r| r.in_tab(self.tab) && r.matches(&self.query) && self.filters.passes(r))
            .collect();
        fn entry<'a>(r: &'a &ProgramRow) -> &'a purge_model::InventoryEntry {
            &r.entry().entry
        }
        let ordered = match self.sort {
            SortKey::Publisher => rules::order(
                &rows,
                entry,
                |a, b| rules::compare_text(a.publisher(), b.publisher()),
                self.descending,
            ),
            SortKey::Size => rules::order(
                &rows,
                entry,
                |a, b| {
                    a.size_bytes()
                        .unwrap_or(-1)
                        .cmp(&b.size_bytes().unwrap_or(-1))
                },
                self.descending,
            ),
            SortKey::Junk => rules::order(
                &rows,
                entry,
                |a, b| a.junk_rank().cmp(&b.junk_rank()),
                self.descending,
            ),
            SortKey::Date => rules::order(
                &rows,
                entry,
                |a, b| a.installed().cmp(&b.installed()),
                self.descending,
            ),
            SortKey::Name => rules::order(
                &rows,
                entry,
                |a, b| rules::compare_text(a.name(), b.name()),
                self.descending,
            ),
        };
        self.shown = ordered.iter().map(|r| r.id().clone()).collect();

        let mut ticked = self.ticked.clone();
        if let Some(c) = &self.current {
            ticked.insert(c.clone());
        }
        self.selected = self
            .shown
            .iter()
            .filter(|id| ticked.contains(*id))
            .cloned()
            .collect();
        let keep = self
            .current
            .clone()
            .filter(|c| self.shown.contains(c))
            .or_else(|| self.selected.last().cloned());
        self.current = keep;
        self.show_details();
    }

    /// The details pane follows `current`: the list rows carry no uninstaller, folder or product code, so
    /// `programs.get` brings them, once per row.
    fn show_details(&mut self) {
        if !self.first_frame {
            return;
        }
        let Some(&i) = self.current.as_ref().and_then(|c| self.by_id.get(c)) else {
            return;
        };
        let live = self.engine.live;
        let row = &mut self.all[i];
        if !live {
            row.details_loaded = true;
        } else if !row.details_requested {
            row.details_requested = true;
            let program_id = row.id().clone();
            self.out.push(ProgramsRequest::Details { program_id });
        }
    }

    fn show_removed(&mut self) {
        if self.changes_shown {
            return;
        }
        let Some(changes) = self.changes.take() else {
            return;
        };
        self.changes_shown = true;
        let Some(changes) = changes.filter(|c| !c.disappeared.is_empty()) else {
            return;
        };
        let mut group = RemovedGroup::new(changes.disappeared);
        // A program Purge uninstalled while the answer was on its way is not one that went outside Purge.
        let here: Vec<ProgramId> = self.uninstalled_here.iter().cloned().collect();
        for id in here {
            if group.acknowledge(&id) {
                self.out.push(ProgramsRequest::Forget {
                    program_ids: vec![id],
                });
            }
        }
        if group.is_empty() {
            return;
        }
        // Which of them Purge may have a fingerprint for: a file-system lookup by name, no prompt.
        self.removed
            .classify(group.shown().iter().map(|p| &p.program_id));
        self.group = Some(group);
        self.render_removed();
    }

    /// The user has dealt with a removed program (checked or dismissed it, or Purge uninstalled it): it
    /// leaves the group and the engine forgets it.
    fn acknowledge_removed(&mut self, program_id: &ProgramId) {
        let Some(group) = &mut self.group else {
            return;
        };
        if group.acknowledge(program_id) {
            self.out.push(ProgramsRequest::Forget {
                program_ids: vec![program_id.clone()],
            });
            // Rows that move up are probed when they are first shown.
            let shown: Vec<ProgramId> =
                group.shown().iter().map(|p| p.program_id.clone()).collect();
            self.removed.classify(shown.iter());
            self.render_removed();
        }
    }

    fn after_check(&mut self, requests: Vec<RemovedRequest>) -> Vec<ProgramsRequest> {
        self.forward(requests);
        self.render_removed();
        self.take()
    }

    fn forward(&mut self, requests: Vec<RemovedRequest>) {
        for request in requests {
            match request {
                RemovedRequest::Completed(outcome) => self.open_stored_scan(outcome),
                // A cancelled or declined admin prompt comes back as the check's notice, shown in this
                // page's bar (the window has no bar for it).
                RemovedRequest::AdminPromptCancelled { .. } => {}
                other => self.out.push(ProgramsRequest::Check(other)),
            }
        }
    }

    /// The scan from the stored fingerprint goes to the Leftovers page, which takes the broker link (the
    /// S3 hand-off). While that page applies another change its link is not replaced: this scan's broker
    /// is ended and a bar says so.
    fn open_stored_scan(&mut self, outcome: StoredScanOutcome) {
        if self.users.leftovers_changing {
            let message = strings::stored_scan_not_opened(&outcome.program_name);
            self.out.push(ProgramsRequest::CloseCheckSession);
            self.show_notice(message, NoticeKind::Warning);
            return;
        }
        // The check finished and its scan is on the Leftovers page: whatever it found, the program has
        // been looked at, so it leaves the group and does not come back in a later session.
        let id = outcome.program_id.clone();
        self.out.push(ProgramsRequest::OpenLeftovers(outcome));
        self.acknowledge_removed(&id);
    }

    /// What drawing the removed rows did besides drawing: a change of "a check runs" is told to the
    /// window, and a new notice of the check goes in the bar.
    fn render_removed(&mut self) {
        let busy = self.removed.is_busy();
        if busy != self.check_was_running {
            self.check_was_running = busy;
            self.out.push(ProgramsRequest::CheckRunningChanged);
        }
        if self.removed.notice_serial() != self.notice_serial_shown {
            self.notice_serial_shown = self.removed.notice_serial();
            if let Some(n) = self.removed.notice() {
                let message = format!("{} {}", n.title, n.message);
                let kind = n.kind;
                self.show_notice(message, kind);
            }
        }
    }
}

/// `Uri.EscapeDataString`: everything but the RFC 3986 unreserved characters is percent-encoded (UTF-8).
pub fn escape_data(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}
