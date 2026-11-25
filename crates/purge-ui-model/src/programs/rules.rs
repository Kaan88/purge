//! The Programs page's list rules (the port of `ui/Purge.Client/Model/ProgramRules.cs`): which tab an
//! entry is in, search, the order with child rows under their parent, install dates and sizes as text.

use std::cmp::Ordering;
use std::collections::HashSet;

use purge_model::{InstallTimeSource, InventoryEntry};

use super::date::{CivilDate, Clock};
use crate::casefold::contains_ignore_case;

/// The tabs of the Programs page. Grouping is UI policy; the engine never hides entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProgramTab {
    /// Named programs that are neither system components nor children.
    #[default]
    Apps,
    /// Named system components and child entries (updates, Burn children).
    Components,
    /// Entries without a `DisplayName`.
    Unnamed,
    /// Apps installed within [`RECENT_DAYS`] days.
    Recent,
}

impl ProgramTab {
    /// The four tabs in the order the page shows them.
    pub const ALL: [ProgramTab; 4] = [
        ProgramTab::Apps,
        ProgramTab::Components,
        ProgramTab::Unnamed,
        ProgramTab::Recent,
    ];
}

/// Where an entry belongs on the Programs page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProgramClass {
    /// In the Apps tab.
    pub is_app: bool,
    /// In the Components tab.
    pub is_component: bool,
    /// In the Unnamed tab.
    pub is_unnamed: bool,
    /// In the Recent tab.
    pub is_recent: bool,
    /// A child entry (it has a `ParentKeyName`).
    pub is_child: bool,
}

impl ProgramClass {
    /// Whether the entry shows in `tab`.
    pub fn in_tab(self, tab: ProgramTab) -> bool {
        match tab {
            ProgramTab::Apps => self.is_app,
            ProgramTab::Components => self.is_component,
            ProgramTab::Unnamed => self.is_unnamed,
            ProgramTab::Recent => self.is_recent,
        }
    }
}

/// Days an app counts as "Recent" after it was installed.
pub const RECENT_DAYS: i64 = 14;

/// The tab of an entry. Apps are named, not system components and not children; Components are named
/// system components and child entries (updates, Burn children); Unnamed have no DisplayName; Recent is an
/// app installed within [`RECENT_DAYS`] days. An AppX package is an app.
pub fn classify(
    entry: &InventoryEntry,
    installed: Option<CivilDate>,
    today: CivilDate,
) -> ProgramClass {
    let child = entry.flags.parent_key.is_some();
    let named = entry.flags.has_display_name;
    let app = named && !entry.flags.system_component && !child;
    ProgramClass {
        is_app: app,
        is_component: named && (entry.flags.system_component || child),
        is_unnamed: !named,
        is_recent: app && installed.is_some_and(|d| today.days_since(d) <= RECENT_DAYS),
        is_child: child,
    }
}

/// Whether the search text occurs in the name, publisher, version or install folder (not case sensitive).
pub fn matches(entry: &InventoryEntry, query: &str) -> bool {
    let hit = |s: &Option<String>| s.as_deref().is_some_and(|s| contains_ignore_case(s, query));
    query.is_empty()
        || contains_ignore_case(&entry.display_name, query)
        || hit(&entry.publisher)
        || hit(&entry.version)
        || hit(&entry.install_location)
}

/// The program list's optional columns: which of them fit beside a readable Name column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListColumns {
    /// The Size column.
    pub size: bool,
    /// The Expected leftovers column.
    pub leftovers: bool,
    /// The Installed column.
    pub installed: bool,
}

impl Default for ListColumns {
    fn default() -> Self {
        Self {
            size: true,
            leftovers: true,
            installed: true,
        }
    }
}

/// Narrowest Name column the list keeps; the optional columns go before it gets narrower.
pub const MIN_NAME_WIDTH: f64 = 180.0;

/// Width of the list that is not columns: tile, column spacing and row padding.
pub const LIST_CHROME: f64 = 28.0 + 4.0 * 10.0 + 40.0;

/// The Size column's width when shown.
pub const SIZE_WIDTH: f64 = 100.0;
/// The Expected leftovers column's width when shown.
pub const LEFTOVERS_WIDTH: f64 = 150.0;
/// The Installed column's width when shown.
pub const INSTALLED_WIDTH: f64 = 92.0;

/// The optional columns that fit in a list `width` px wide: Installed goes first, then Expected
/// leftovers, then Size; Name is always shown.
pub fn fit_columns(width: f64) -> ListColumns {
    let room = width - LIST_CHROME - MIN_NAME_WIDTH;
    let size = room >= SIZE_WIDTH;
    let leftovers = size && room >= SIZE_WIDTH + LEFTOVERS_WIDTH;
    let installed = leftovers && room >= SIZE_WIDTH + LEFTOVERS_WIDTH + INSTALLED_WIDTH;
    ListColumns {
        size,
        leftovers,
        installed,
    }
}

/// The last segment of an entry's key path: the name a child's `ParentKey` refers to.
pub fn key_name(key_path: &str) -> &str {
    key_path.rsplit('\\').next().unwrap_or(key_path)
}

/// Orders `rows` by `cmp`, with each child row directly under its parent. A child whose parent is not
/// among `rows` (another tab, or filtered out) is ordered like any other row, so it is never lost. A key
/// name can repeat on a real machine (the same key under the 32- and the 64-bit view, or HKLM and HKCU),
/// so a child follows every row of that name. The sort is stable, as LINQ's `OrderBy` is.
pub fn order<T: Clone>(
    rows: &[T],
    entry: impl Fn(&T) -> &InventoryEntry,
    cmp: impl Fn(&T, &T) -> Ordering,
    descending: bool,
) -> Vec<T> {
    let by_key: HashSet<&str> = rows.iter().map(|r| key_name(&entry(r).key_path)).collect();
    let has_parent = |r: &T| {
        entry(r)
            .flags
            .parent_key
            .as_deref()
            .is_some_and(|p| by_key.contains(p))
    };
    let mut parents: Vec<&T> = rows.iter().filter(|r| !has_parent(r)).collect();
    if descending {
        parents.sort_by(|a, b| cmp(b, a));
    } else {
        parents.sort_by(|a, b| cmp(a, b));
    }
    let children: Vec<&T> = rows.iter().filter(|r| has_parent(r)).collect();
    let mut out = Vec::with_capacity(rows.len());
    for parent in parents {
        out.push(parent.clone());
        let name = key_name(&entry(parent).key_path);
        for child in &children {
            if entry(child).flags.parent_key.as_deref() == Some(name) {
                out.push((*child).clone());
            }
        }
    }
    out
}

/// The install date: the ARP or MSI date first, then another hint, as a local date.
pub fn install_date(entry: &InventoryEntry, clock: &Clock) -> Option<CivilDate> {
    let evidence = &entry.install_time_evidence;
    let pick = evidence
        .iter()
        .find(|h| {
            matches!(
                h.source,
                InstallTimeSource::ArpInstallDate | InstallTimeSource::MsiInstallDate
            )
        })
        .or_else(|| evidence.first())?;
    // A FILETIME outside the range of DateTime is a damaged value: no date.
    clock.local_date(pick.time)
}

/// "1.4 GB", "312 MB", "0 B".
pub fn format_size(bytes: i64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    // .NET's "F0"/"F1" round a midpoint away from zero; `f64::round` does too.
    let text = if v >= 100.0 || u == 0 {
        format!("{:.0}", v.round())
    } else {
        format!("{:.1}", (v * 10.0).round() / 10.0)
    };
    format!("{text} {}", UNITS[u])
}

/// The culture-aware order the WinUI app's `OrderBy` on a string gave in an English culture: not case
/// sensitive first, lower case before upper case on a tie.
pub fn compare_text(a: &str, b: &str) -> Ordering {
    a.to_lowercase()
        .cmp(&b.to_lowercase())
        .then_with(|| b.cmp(a))
}
