//! Every user-visible text of the Programs page models, word for word as the WinUI app had them (they
//! were reviewed): `ProgramRow.cs`, `ProgramsView.xaml(.cs)`.

use super::rules::ProgramTab;

/// After the name of a program installed in the last three days.
pub const NEW_TAG: &str = "  new";
/// The Leftovers cell: nothing expected.
pub const LEFTOVERS_CLEAN: &str = "Clean";
/// The Leftovers cell: no answer yet.
pub const LEFTOVERS_UNKNOWN: &str = "Not known yet";
/// The Leftovers cell: some, size unknown.
pub const LEFTOVERS_SOME: &str = "Some";

/// The page's title.
pub const TITLE: &str = "Programs";
/// The search box's placeholder.
pub const SEARCH_PLACEHOLDER: &str = "Search programs (Ctrl+F)";
/// The search box's accessible name.
pub const SEARCH_NAME: &str = "Search programs";
/// The "…" button's tooltip and accessible name.
pub const MORE_ACTIONS: &str = "More actions";

/// A tab's label.
pub fn tab_label(tab: ProgramTab) -> &'static str {
    match tab {
        ProgramTab::Apps => "Apps",
        ProgramTab::Components => "Components",
        ProgramTab::Unnamed => "Unnamed",
        ProgramTab::Recent => "Recent",
    }
}

/// The summary under the title.
pub fn summary(entries: usize, size: &str, would_leave: Option<usize>) -> String {
    let mut s = format!("{entries} entries · {size}");
    if let Some(n) = would_leave {
        s.push_str(&format!(" · {n} would leave leftovers"));
    }
    s
}

/// The list's header: "ALL APPS · 12".
pub fn all_label(tab: ProgramTab, shown: usize) -> String {
    format!("ALL {} · {shown}", tab_label(tab).to_uppercase())
}

/// The footer's left part: "12 apps · 1.4 GB".
pub fn status_left(shown: usize, tab: ProgramTab, size: &str) -> String {
    format!("{shown} {} · {size}", tab_label(tab).to_lowercase())
}

/// The footer's right part with a live engine.
pub const ENGINE_CONNECTED: &str = "Engine connected";
/// The footer's right part with sample data.
pub const SAMPLE_DATA: &str = "Sample data · engine not connected";

/// While sizes are measured.
pub fn measuring(done: usize, all: usize) -> String {
    format!(" · measuring sizes {done} of {all}")
}

/// "No programs match" over the empty list.
pub fn no_match(query: &str, filters: bool, tab: ProgramTab) -> (String, &'static str) {
    let tab = tab_label(tab);
    if query.is_empty() {
        (
            format!("No programs in {tab} match the filters."),
            "Turn a filter off, or try another tab.",
        )
    } else {
        (
            format!(
                "No programs match \u{201C}{query}\u{201D}{} in {tab}.",
                if filters { " and the filters" } else { "" }
            ),
            if filters {
                "Try fewer letters, turn a filter off, or press Esc to clear the search."
            } else {
                "Try fewer letters, another tab, or press Esc to clear the search."
            },
        )
    }
}

/// The sort arrows.
pub const ARROW_DOWN: &str = " ↓";
/// The sort arrows.
pub const ARROW_UP: &str = " ↑";
/// Column header.
pub const HEADER_NAME: &str = "Name";
/// Column header.
pub const HEADER_SIZE: &str = "Size";
/// Column header.
pub const HEADER_LEFTOVERS: &str = "Expected leftovers";
/// Column header.
pub const HEADER_INSTALLED: &str = "Installed";

/// The sort menu's items, in menu order, with their keys.
pub const SORT_MENU: [&str; 5] = [
    "Name",
    "Publisher",
    "Size",
    "Expected leftovers",
    "Install date",
];

/// The Filter button.
pub fn filter_text(count: usize) -> String {
    if count == 0 {
        "Filter".into()
    } else {
        format!("Filter ({count})")
    }
}

/// The filter menu's items.
pub const FILTER_LEFTOVERS: &str = "Would leave leftovers";
/// The filter menu's items.
pub const FILTER_PER_USER: &str = "Installed for this user only";
/// The filter menu's items.
pub const FILTER_32: &str = "32-bit only";

/// "3 selected (1 not shown)".
pub fn selected_count(n: usize, hidden: usize) -> String {
    if n == 0 {
        return String::new();
    }
    let mut s = format!("{n} selected");
    if hidden > 0 {
        s.push_str(&format!(" ({hidden} not shown)"));
    }
    s
}

/// The toolbar's Uninstall label.
pub fn uninstall_label(n: usize) -> String {
    if n > 1 {
        format!("Uninstall {n}")
    } else {
        "Uninstall".into()
    }
}

/// The toolbar's Uninstall accessible name.
pub fn uninstall_name(n: usize, current: Option<&str>) -> String {
    if n > 1 {
        format!("Uninstall {n} programs")
    } else if let Some(name) = current {
        format!("Uninstall {name}")
    } else {
        "Uninstall".into()
    }
}

/// The Uninstall button's tooltip with nothing picked.
pub const SELECT_TO_UNINSTALL: &str = "Select a program to uninstall.";
/// Why Uninstall waits for a removed program's check.
pub const CHECK_RUNNING_HINT: &str =
    "A leftovers check is running. Uninstall when it has finished.";
/// Why Uninstall is off with a live engine.
pub const ENGINE_NOT_USABLE: &str = "The engine is not usable, so an uninstaller cannot be routed.";
/// Why Uninstall is off with sample data.
pub const SAMPLE_NO_ENGINE: &str = "Sample data: no engine is connected.";

/// Notice: a command needs a program.
pub const SELECT_FIRST: &str = "Select a program first.";
/// Notice: no install folder.
pub const NO_FOLDER: &str =
    "The install folder is not recorded for this program, or is not on this PC any more.";
/// Notice: Refresh with sample data.
pub const SAMPLE_NO_REFRESH: &str = "Sample data: there is no engine to read the list from.";
/// Notice: Uninstall with nothing picked.
pub const SELECT_TO_UNINSTALL_FIRST: &str = "Select a program to uninstall first.";
/// Notice: the list could not be read.
pub fn list_failed(message: &str) -> String {
    format!("Couldn't read the program list: {message}")
}
/// Notice: a check is asked while an uninstall runs.
pub const UNINSTALL_RUNNING: &str =
    "An uninstall is running. Check for leftovers when it has finished.";
/// Notice: a check is asked while the Leftovers page changes.
pub const LEFTOVERS_CHANGING: &str =
    "The Leftovers page is applying a change. Check for leftovers when it has finished.";

/// Notice: a check's scan could not go to the Leftovers page.
pub fn stored_scan_not_opened(name: &str) -> String {
    format!(
        "The Leftovers page is still applying another change, so the leftovers of {name} were not opened. Nothing was changed; check again when it has finished."
    )
}

/// The details pane's labels.
pub mod details {
    /// Label.
    pub const UNINSTALLER: &str = "Uninstaller";
    /// Label.
    pub const LOCATION: &str = "Location";
    /// Label.
    pub const INSTALLED: &str = "Installed";
    /// Label.
    pub const SIZE: &str = "Size";
    /// Label.
    pub const PLATFORM: &str = "Platform";
    /// Label.
    pub const ALSO_OWNS: &str = "Also owns";
    /// Label.
    pub const UNINSTALL: &str = "Uninstall";
    /// Label.
    pub const QUIET: &str = "Quiet";
    /// Label.
    pub const PRODUCT_CODE: &str = "Product code";
    /// Label.
    pub const REGISTRY_KEY: &str = "Registry key";
    /// Heading.
    pub const WHAT_PURGE_EXPECTS: &str = "What Purge expects";

    /// While `programs.get` is out.
    pub const READING: &str = "Reading…";
    /// No uninstaller.
    pub const NONE_REGISTERED: &str = "None registered";
    /// After the installer kind, with a quiet mode.
    pub const QUIET_AVAILABLE: &str = " · quiet mode available";
    /// No install folder.
    pub const NOT_RECORDED: &str = "Not recorded";
    /// Size while sizes are measured.
    pub const MEASURING: &str = "Measuring…";
    /// Size not measured.
    pub const NOT_MEASURED: &str = "Not measured";
    /// The commands while `programs.get` is out.
    pub const ELLIPSIS: &str = "…";
    /// No command.
    pub const NONE: &str = "None";
    /// The forecast line when the engine has none.
    pub const NOT_KNOWN: &str = "Not known yet. Purge has no record of what this installer put on the PC, so it will scan after the uninstaller ran.";
    /// The forecast line before the engine answered.
    pub const CHECKING: &str = "Checking what this program is expected to leave…";
}

/// The "removed outside Purge" rows.
pub mod removed {
    /// No record.
    pub const NO_RECORD: &str = "Removed outside Purge. Purge did not record what this program installed, so it cannot tell which leftovers are its own.";
    /// The prompt is up.
    pub const STARTING: &str =
        "Removed outside Purge. Purge is asking for administrator permission…";
    /// `leftovers.stored`.
    pub const CHECKING: &str = "Removed outside Purge. Reading Purge's record of it…";
    /// A record.
    pub const RECORD: &str =
        "Removed outside Purge. Purge recorded it before, so it can look for what it left.";

    /// The scan runs.
    pub fn scanning(progress: Option<&str>) -> String {
        match progress {
            Some(p) if !p.is_empty() => format!("Looking for what it left · {p}"),
            _ => "Looking for what it left…".into(),
        }
    }

    /// The button.
    pub const CHECK: &str = "Check for leftovers";
    /// The button while its check runs.
    pub const STOP: &str = "Stop";
    /// The button's tooltip while its check runs.
    pub const STOP_HINT: &str = "Stops the check; nothing is changed";
    /// The button's tooltip.
    pub const CHECK_HINT: &str =
        "Asks for administrator permission, then looks for what it left on the PC";
    /// Why it waits: another row's check.
    pub const WAITS_CHECK: &str = "Waits until the running check has finished";
    /// Why it waits: an uninstall.
    pub const WAITS_UNINSTALL: &str = "Waits until the running uninstall has finished";
    /// Why it waits: the Leftovers page.
    pub const WAITS_LEFTOVERS: &str = "Waits until the Leftovers page has finished its change";
}
