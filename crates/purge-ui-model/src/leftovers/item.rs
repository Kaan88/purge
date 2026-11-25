//! One candidate as the Leftovers page keeps it, its group, a plan's attention row, the size format
//! and the `--sample` rows (the port of `LeftoverItemModel`, `LeftoverGroup`, `AttentionModel` and
//! `LeftoversSample`).

use purge_model::{Band, Category};
use purge_rpc::methods::{AttentionReason, CandidateRef, CandidateRow, ItemKind, Warning};

use super::text;

/// The band a row is shown in: the wire's `Blocked` is "Protected" in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Look {
    /// Proven to belong to the removed app.
    Safe,
    /// Probably the app's.
    Likely,
    /// The name matches only.
    Weak,
    /// Blocked: shown, never removed.
    Protected,
}

impl Look {
    /// The look of a wire band.
    pub fn of(band: Band) -> Self {
        match band {
            Band::Safe => Look::Safe,
            Band::Likely => Look::Likely,
            Band::Weak => Look::Weak,
            Band::Blocked => Look::Protected,
        }
    }

    /// The wire band of a look.
    pub fn band(self) -> Band {
        match self {
            Look::Safe => Band::Safe,
            Look::Likely => Band::Likely,
            Look::Weak => Band::Weak,
            Look::Protected => Band::Blocked,
        }
    }

    /// The word a screen reader says for it.
    pub fn word(self) -> &'static str {
        match self {
            Look::Safe => "Safe",
            Look::Likely => "Likely",
            Look::Weak => "Weak",
            Look::Protected => "Protected",
        }
    }
}

/// A registry item in words (`RegistryLabel` of the Programs model): what it is and where it lives.
/// Display only: the raw wire path stays the authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemLabel {
    /// What the key or value is, e.g. "Settings of Mozilla Firefox".
    pub title: String,
    /// Where it lives, e.g. "Your account › Software".
    pub location: String,
}

/// Describes a registry wire path for a kind and the signed-in user's SID; `None` for a non-registry
/// kind or an unknown root. The UI passes the Programs model's `RegistryLabel::describe` here (it is
/// package UI-MODEL-A's), so this model does not hold a second copy of the rules.
pub type DescribeLabel = fn(&str, ItemKind, Option<&str>) -> Option<ItemLabel>;

/// One candidate of `scan.candidates` as the page keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftoverItem {
    /// The candidate.
    pub candidate_id: CandidateRef,
    /// The broker's exact name (a registry item's wire path); the tooltip and the detail pane show it.
    pub display_name: String,
    /// A registry item in words; `None` for other kinds or an unknown root.
    pub label: Option<ItemLabel>,
    /// The list group it belongs to.
    pub group_name: String,
    /// The band it is shown in.
    pub look: Look,
    /// The wire band.
    pub wire_band: Band,
    /// Its category.
    pub category: Category,
    /// What kind of thing it is.
    pub kind: ItemKind,
    /// The program it is shared with, when known.
    pub owner_program: Option<String>,
    /// Bytes, for files and folders.
    pub size_bytes: Option<u64>,
    /// The broker's warnings about it.
    pub warnings: Vec<Warning>,
    /// Whether Purge preselected it.
    pub preselected: bool,
    /// The user's (or Purge's) tick; only selectable rows may hold one.
    pub checked: bool,
    /// `plan.create` would not bind it; shown as "cannot be quarantined", unticked.
    pub refused: bool,
    /// Why it was refused.
    pub refusal_reason: String,
    /// Listed in the plan's attention list.
    pub attention: bool,
    /// The evidence lines of `candidate.explain`.
    pub evidence: Vec<String>,
    /// The blocker lines of `candidate.explain` (or the explain call's failure).
    pub blockers: Vec<String>,
}

impl LeftoverItem {
    /// A row of `scan.candidates`, ticked as Purge preselected it.
    pub fn from_row(
        row: CandidateRow,
        label: Option<DescribeLabel>,
        current_user_sid: Option<&str>,
    ) -> Self {
        let label =
            label.and_then(|describe| describe(&row.display_name, row.kind, current_user_sid));
        Self {
            group_name: group_name_of(row.category, row.kind).into(),
            look: Look::of(row.band),
            wire_band: row.band,
            category: row.category,
            kind: row.kind,
            owner_program: row.owner_program,
            size_bytes: row.size_bytes,
            warnings: row.warnings,
            preselected: row.preselected,
            checked: row.preselected,
            candidate_id: row.candidate_id,
            display_name: row.display_name,
            label,
            refused: false,
            refusal_reason: String::new(),
            attention: false,
            evidence: Vec::new(),
            blockers: Vec::new(),
        }
    }

    /// The row's main line: the registry label's title, else the display name.
    pub fn title(&self) -> &str {
        self.label
            .as_ref()
            .map_or(&self.display_name, |label| &label.title)
    }

    /// The row's readable location line; empty when the row shows the raw name.
    pub fn location(&self) -> &str {
        self.label.as_ref().map_or("", |label| &label.location)
    }

    /// User data: the category, or a warning that says so.
    pub fn is_user_data(&self) -> bool {
        self.category == Category::UserData || self.warning_code_has("userdata")
    }

    /// Blocked items are listed under "Protected" and never ticked.
    pub fn is_protected(&self) -> bool {
        self.wire_band == Band::Blocked
    }

    /// A weak match: hidden by default, never ticked for you.
    pub fn is_weak(&self) -> bool {
        self.wire_band == Band::Weak
    }

    /// Report-only items are shown, never acted on. The row does not carry the plan action, so this
    /// is read from a warning the broker may attach; `plan.create`'s refusals remain the authority.
    pub fn is_report_only(&self) -> bool {
        self.warning_code_has("reportonly")
    }

    /// Whether the user may tick it.
    pub fn selectable(&self) -> bool {
        !self.is_protected() && !self.is_report_only() && !self.refused
    }

    /// Its size, or empty.
    pub fn size_text(&self) -> String {
        self.size_bytes.map(format_size).unwrap_or_default()
    }

    /// What the item is and what it belongs to, in words (the detail pane's "Kind" line).
    pub fn kind_text(&self) -> String {
        format!(
            "{} · {}",
            kind_words(self.kind),
            category_words(self.category)
        )
    }

    /// The row's reason line.
    pub fn why(&self) -> &str {
        if let Some(blocker) = self.blockers.first() {
            blocker
        } else if let Some(warning) = self.warnings.first() {
            &warning.message
        } else if self.refused && !self.refusal_reason.is_empty() {
            &self.refusal_reason
        } else {
            match self.look {
                Look::Safe => text::WHY_SAFE,
                Look::Likely => text::WHY_LIKELY,
                Look::Weak => text::WHY_WEAK,
                Look::Protected => text::WHY_PROTECTED,
            }
        }
    }

    fn warning_code_has(&self, needle: &str) -> bool {
        self.warnings
            .iter()
            .any(|w| w.code.to_ascii_lowercase().contains(needle))
    }
}

fn kind_words(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::File => "File",
        ItemKind::Folder => "Folder",
        ItemKind::RegistryKey => "Registry key",
        ItemKind::RegistryValue => "Registry value",
        ItemKind::RegistryData => "Registry data",
        ItemKind::Service => "Service",
        ItemKind::Task => "Scheduled task",
        ItemKind::FirewallRule => "Firewall rule",
        ItemKind::Package => "App package",
    }
}

fn category_words(category: Category) -> &'static str {
    match category {
        Category::AppFiles => "the program's files",
        Category::AppData => "the program's settings and data",
        Category::UserData => "your own data",
        Category::Cache => "a cache",
        Category::Registration => "the program's registration",
        Category::Association => "a file type or link association",
        Category::ShellCom => "Explorer and COM registration",
        Category::Startup => "something that starts with Windows",
        Category::System => "a system setting",
        Category::Privacy => "usage traces",
        Category::Package => "an app package",
    }
}

/// The list group of a category and kind.
pub fn group_name_of(category: Category, kind: ItemKind) -> &'static str {
    use ItemKind as K;
    match (category, kind) {
        (Category::Association, _) => text::GROUP_ASSOCIATIONS,
        (Category::ShellCom, _) => text::GROUP_SHELL,
        (Category::Privacy, _) => text::GROUP_PRIVACY,
        (Category::Package, _) | (_, K::Package) => text::GROUP_PACKAGES,
        (Category::Startup, _) | (_, K::Service | K::Task) => text::GROUP_SERVICES,
        (_, K::FirewallRule) => text::GROUP_FIREWALL,
        (Category::Registration, _) | (_, K::RegistryKey | K::RegistryValue | K::RegistryData) => {
            text::GROUP_REGISTRY
        }
        _ => text::GROUP_FILES,
    }
}

/// A size in B, KB, MB, GB or TB: one decimal below 100, none above.
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// One group header: the eight list groups, then the Protected and report-only sections. Holds the
/// indexes of its items in the page's item list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftoverGroup {
    /// Its name.
    pub name: String,
    /// A section (Protected, report only): no tick box.
    pub is_section: bool,
    /// Whether its rows are shown.
    pub expanded: bool,
    /// Its items, as indexes into the page's item list.
    pub items: Vec<usize>,
}

/// One row of the plan's attention list, from `plan.create` itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttentionRow {
    /// The candidate (it may be one absorbed into another, so not in the list).
    pub candidate_id: CandidateRef,
    /// The name shown.
    pub display_name: String,
    /// Its band.
    pub look: Look,
    /// What kind of thing it is.
    pub kind: ItemKind,
    /// Bytes, for files and folders.
    pub size_bytes: Option<u64>,
    /// Why it needs attention.
    pub reasons: Vec<AttentionReason>,
}

impl AttentionRow {
    /// Its size, or empty.
    pub fn size_text(&self) -> String {
        self.size_bytes.map(format_size).unwrap_or_default()
    }

    /// The reasons in words, joined by " · ".
    pub fn reasons_text(&self) -> String {
        self.reasons
            .iter()
            .map(|reason| match reason {
                AttentionReason::UserData => "holds your data",
                AttentionReason::NotPreselected => "you ticked it; Purge did not preselect it",
                AttentionReason::Large => "very large",
                AttentionReason::NoUndo => "cannot be put back",
                AttentionReason::Inside => "inside another item",
                AttentionReason::Name => "its name needed escaping",
            })
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

/// The Firefox sample of `--sample` and the Settings preview; no scan exists for it.
pub fn sample_items(label: Option<DescribeLabel>) -> Vec<LeftoverItem> {
    use Category as C;
    use ItemKind as K;
    #[allow(clippy::type_complexity)]
    let rows: [(u64, &str, &str, Look, Category, ItemKind, u64, bool, &str); 10] = [
        (
            1,
            r"C:\Users\tester\AppData\Local\Mozilla",
            text::GROUP_FILES,
            Look::Safe,
            C::AppData,
            K::Folder,
            2_726_297,
            true,
            "App cache · only Firefox data inside · vendor folder",
        ),
        (
            2,
            r"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38",
            text::GROUP_FILES,
            Look::Safe,
            C::AppData,
            K::Folder,
            98_304,
            true,
            "",
        ),
        (
            3,
            r"C:\Users\tester\AppData\Roaming\Mozilla",
            text::GROUP_FILES,
            Look::Likely,
            C::UserData,
            K::Folder,
            2_202_009,
            false,
            "",
        ),
        (
            4,
            r"HKCU\Software\Mozilla\Firefox",
            text::GROUP_REGISTRY,
            Look::Safe,
            C::Registration,
            K::RegistryKey,
            0,
            true,
            "",
        ),
        (
            5,
            r"HKLM\Software\Classes\FirefoxHTML-308046B0AF4A39CB",
            text::GROUP_ASSOCIATIONS,
            Look::Safe,
            C::Association,
            K::RegistryKey,
            0,
            true,
            "",
        ),
        (
            6,
            r"HKLM\Software\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}",
            text::GROUP_SHELL,
            Look::Likely,
            C::ShellCom,
            K::RegistryKey,
            0,
            false,
            "",
        ),
        (
            7,
            "Task: Firefox Default Browser Agent 308046B0AF4A39CB",
            text::GROUP_SERVICES,
            Look::Safe,
            C::Registration,
            K::Task,
            0,
            true,
            "",
        ),
        (
            8,
            "Service: Mozilla Maintenance Service",
            text::GROUP_SERVICES,
            Look::Likely,
            C::Registration,
            K::Service,
            0,
            false,
            "",
        ),
        (
            9,
            r"C:\Windows\Prefetch",
            text::GROUP_PROTECTED,
            Look::Protected,
            C::System,
            K::Folder,
            0,
            false,
            "",
        ),
        (
            10,
            r"C:\Users\tester\AppData\Local\Temp\firefox-crash-reports",
            text::GROUP_FILES,
            Look::Weak,
            C::Cache,
            K::Folder,
            655_360,
            false,
            "",
        ),
    ];
    rows.into_iter()
        .map(|(id, name, group, look, category, kind, bytes, pre, why)| {
            sample_item(
                id,
                name.into(),
                group,
                look,
                category,
                kind,
                bytes,
                pre,
                why,
                label,
            )
        })
        .collect()
}

/// `count` items for the launch bench's S3 timer (M3 design 9.1, "S3 page open, 2,000-item
/// fixture"): the sample items repeated in order, each copy with its own id and a numbered name, so
/// every group of the sample, the Protected section included, grows in proportion.
pub fn sample_fixture(count: usize, label: Option<DescribeLabel>) -> Vec<LeftoverItem> {
    let template = sample_items(label);
    (0..count)
        .map(|i| {
            let t = &template[i % template.len()];
            let copy = i / template.len();
            let name = if copy == 0 {
                t.display_name.clone()
            } else {
                format!(r"{}\fixture-{copy:04}", t.display_name)
            };
            sample_item(
                i as u64 + 1,
                name,
                &t.group_name,
                t.look,
                t.category,
                t.kind,
                t.size_bytes.unwrap_or(0),
                t.preselected,
                t.blockers.first().map_or("", String::as_str),
                label,
            )
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn sample_item(
    id: u64,
    name: String,
    group: &str,
    look: Look,
    category: Category,
    kind: ItemKind,
    bytes: u64,
    preselected: bool,
    why: &str,
    label: Option<DescribeLabel>,
) -> LeftoverItem {
    LeftoverItem {
        candidate_id: CandidateRef::from_bits(id),
        label: label.and_then(|describe| describe(&name, kind, None)),
        display_name: name,
        group_name: group.into(),
        look,
        wire_band: look.band(),
        category,
        kind,
        owner_program: None,
        size_bytes: (bytes != 0).then_some(bytes),
        warnings: Vec::new(),
        preselected,
        checked: false,
        refused: false,
        refusal_reason: String::new(),
        attention: false,
        evidence: Vec::new(),
        blockers: if why.is_empty() {
            Vec::new()
        } else {
            vec![why.into()]
        },
    }
}
