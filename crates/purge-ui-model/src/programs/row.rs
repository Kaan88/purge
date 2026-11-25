//! One row of the program list (the port of the logic of `ui/Purge.App/Views/ProgramRow.cs`),
//! precomputed so drawing only reads strings. Patches, sizes, icons, forecasts and details arrive later
//! and update the row in place.

use purge_model::{InstallScope, InstallerKind, View};

use super::date::CivilDate;
use super::entries::{ProgramEntry, ProgramIcon};
use super::forecast::{ForecastVerdict, LeftoverForecast};
use super::rules::{self, ProgramClass, ProgramTab};
use super::strings;

/// Placeholder tile colours until an icon arrives, as RGB: one per publisher (or name).
pub const TILE_COLORS: [[u8; 3]; 10] = [
    [0x0F, 0x6C, 0xBD],
    [0x87, 0x64, 0xB8],
    [0xC2, 0x39, 0xB3],
    [0xCA, 0x50, 0x10],
    [0x49, 0x82, 0x05],
    [0x03, 0x83, 0x87],
    [0x98, 0x6F, 0x0B],
    [0x4F, 0x6B, 0xED],
    [0x3B, 0x3B, 0x3B],
    [0xC4, 0x31, 0x4B],
];

/// The left indent of a child row under its parent, in px.
pub const CHILD_INDENT: f64 = 28.0;

/// The widest size bar, in px.
pub const BAR_MAX: f64 = 96.0;

/// The placeholder tile colour of a publisher (or name), stable across runs: an index into
/// [`TILE_COLORS`] (FNV-1a over the UTF-16 code units, as the WinUI app hashed).
pub fn tile_for(key: &str) -> usize {
    let mut h: u32 = 2_166_136_261;
    for c in key.encode_utf16() {
        h = (h ^ u32::from(c)).wrapping_mul(16_777_619);
    }
    (h % TILE_COLORS.len() as u32) as usize
}

/// The tile's letter: the first character in upper case, or `?` when it is not a letter or digit.
pub fn initial_of(name: &str) -> String {
    match name.chars().next() {
        // A character outside the BMP was two UTF-16 units in the WinUI app, neither a letter alone.
        Some(c) if c.is_alphanumeric() && (c as u32) <= 0xFFFF => {
            crate::casefold::fold(c).to_string()
        }
        _ => "?".into(),
    }
}

/// One row of the program list.
#[derive(Debug, Clone)]
pub struct ProgramRow {
    entry: ProgramEntry,
    name: String,
    version: String,
    publisher: String,
    installed: Option<CivilDate>,
    installed_text: String,
    initial: String,
    today: CivilDate,
    class: ProgramClass,
    new_tag: &'static str,
    sub_line: String,
    size_bytes: Option<i64>,
    size_text: String,
    /// Width of the size bar in px (0 to [`BAR_MAX`]), relative to the largest program in the list.
    pub bar_width: f64,
    icon: Option<ProgramIcon>,
    /// True once `programs.get` was asked for this row.
    pub details_requested: bool,
    /// True once the details of `programs.get` are in the entry (or the entry already had them).
    pub details_loaded: bool,
    forecast: Option<LeftoverForecast>,
}

impl ProgramRow {
    /// A row for `entry`, with its measured size when known. `installed` is its local install date
    /// ([`rules::install_date`]).
    pub fn new(
        entry: ProgramEntry,
        size_bytes: Option<i64>,
        installed: Option<CivilDate>,
        today: CivilDate,
    ) -> Self {
        let name = entry.entry.display_name.clone();
        let mut row = Self {
            version: entry.entry.version.clone().unwrap_or_default(),
            publisher: entry.entry.publisher.clone().unwrap_or_default(),
            initial: initial_of(&name),
            installed_text: installed.map(|d| d.to_string()).unwrap_or_default(),
            name,
            installed,
            today,
            class: ProgramClass::default(),
            new_tag: "",
            sub_line: String::new(),
            size_text: size_bytes.map(rules::format_size).unwrap_or_default(),
            size_bytes,
            bar_width: 0.0,
            icon: None,
            details_requested: false,
            details_loaded: false,
            forecast: None,
            entry,
        };
        row.classify();
        row
    }

    /// Classifies the row again from its entry (after a patch).
    fn classify(&mut self) {
        self.class = rules::classify(&self.entry.entry, self.installed, self.today);
        self.new_tag = if self
            .installed
            .is_some_and(|n| self.today.days_since(n) <= 3)
        {
            strings::NEW_TAG
        } else {
            ""
        };
        self.sub_line = if self.publisher.is_empty() {
            self.kind_chip().to_owned()
        } else {
            format!("{} · {}", self.publisher, self.kind_chip())
        };
    }

    /// Takes what `programs.patch` or a later reading says about the program.
    pub fn update(&mut self, entry: ProgramEntry) {
        self.entry = entry;
        self.classify();
    }

    /// The entry as the engine described it so far.
    pub fn entry(&self) -> &ProgramEntry {
        &self.entry
    }

    /// The program id.
    pub fn id(&self) -> &purge_model::ProgramId {
        &self.entry.entry.program_id
    }

    /// The display name (as listed; a patch does not rename it).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The version, or empty.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// The publisher, or empty.
    pub fn publisher(&self) -> &str {
        &self.publisher
    }

    /// The local install date.
    pub fn installed(&self) -> Option<CivilDate> {
        self.installed
    }

    /// "5 Nov 2026", or empty.
    pub fn installed_text(&self) -> &str {
        &self.installed_text
    }

    /// The placeholder tile's letter.
    pub fn initial(&self) -> &str {
        &self.initial
    }

    /// The placeholder tile's colour: an index into [`TILE_COLORS`].
    pub fn tile(&self) -> usize {
        tile_for(if self.publisher.is_empty() {
            &self.name
        } else {
            &self.publisher
        })
    }

    /// "  new" for a program installed in the last three days, else empty (drawn after the name).
    pub fn new_tag(&self) -> &str {
        self.new_tag
    }

    /// Second line of the name cell: publisher and installer kind.
    pub fn sub_line(&self) -> &str {
        &self.sub_line
    }

    /// The row's tabs.
    pub fn class(&self) -> ProgramClass {
        self.class
    }

    /// A child entry, drawn [`CHILD_INDENT`] px in.
    pub fn is_child(&self) -> bool {
        self.class.is_child
    }

    /// In the Apps tab.
    pub fn is_app(&self) -> bool {
        self.class.is_app
    }

    /// In the Components tab.
    pub fn is_component(&self) -> bool {
        self.class.is_component
    }

    /// In the Unnamed tab.
    pub fn is_unnamed(&self) -> bool {
        self.class.is_unnamed
    }

    /// In the Recent tab.
    pub fn is_recent(&self) -> bool {
        self.class.is_recent
    }

    /// Whether the row shows in `tab`.
    pub fn in_tab(&self, tab: ProgramTab) -> bool {
        self.class.in_tab(tab)
    }

    /// Whether the search text matches the row.
    pub fn matches(&self, query: &str) -> bool {
        rules::matches(&self.entry.entry, query)
    }

    /// The full name cell for its tooltip: names are trimmed in the list, and look-alike rows differ here.
    pub fn full_text(&self) -> String {
        let first = join(" ", &[&self.name, &self.version]);
        let scope = format!("for {}", self.scope_text());
        let second = join(" · ", &[&self.sub_line, self.bits_text(), &scope]);
        format!("{first}\n{second}")
    }

    /// What a screen reader says for the row (the list item's name): the program, not the type.
    pub fn accessible_name(&self) -> String {
        let mut s = self.name.clone();
        if !self.new_tag.is_empty() {
            s.push_str(", new");
        }
        if !self.sub_line.is_empty() {
            s.push_str(", ");
            s.push_str(&self.sub_line);
        }
        s
    }

    /// Measured size on disk; `None` until `size.ready` has it.
    pub fn size_bytes(&self) -> Option<i64> {
        self.size_bytes
    }

    /// "312 MB", or empty.
    pub fn size_text(&self) -> &str {
        &self.size_text
    }

    /// Takes a measured size (`None`: could not be measured).
    pub fn set_size(&mut self, bytes: Option<i64>) {
        self.size_bytes = bytes;
        self.size_text = bytes.map(rules::format_size).unwrap_or_default();
    }

    /// The program's icon; `None` shows the placeholder tile.
    pub fn icon(&self) -> Option<&ProgramIcon> {
        self.icon.as_ref()
    }

    /// Whether an icon replaced the placeholder tile.
    pub fn has_icon(&self) -> bool {
        self.icon.is_some()
    }

    /// Shows an icon instead of the placeholder tile.
    pub fn set_icon(&mut self, icon: ProgramIcon) {
        self.icon = Some(icon);
    }

    /// Expected leftovers; `None` until the engine has answered (shown as "Not known yet").
    pub fn forecast(&self) -> Option<&LeftoverForecast> {
        self.forecast.as_ref()
    }

    /// Takes the forecast (`None`: the engine has none).
    pub fn set_forecast(&mut self, forecast: Option<LeftoverForecast>) {
        self.forecast = forecast;
    }

    /// The forecast's verdict.
    pub fn verdict(&self) -> ForecastVerdict {
        self.forecast
            .as_ref()
            .map_or(ForecastVerdict::Unknown, |f| f.verdict)
    }

    /// The Leftovers cell text after its glyph: "Clean", "~1.2 GB cache", "Not known yet".
    pub fn leftover_text(&self) -> String {
        match (self.verdict(), &self.forecast) {
            (ForecastVerdict::Clean, _) => strings::LEFTOVERS_CLEAN.into(),
            (ForecastVerdict::Unknown, _) | (_, None) => strings::LEFTOVERS_UNKNOWN.into(),
            (_, Some(f)) => {
                let mut s = match f.estimate_bytes {
                    Some(b) => format!("~{}", rules::format_size(b)),
                    None => strings::LEFTOVERS_SOME.into(),
                };
                if let Some(w) = &f.what {
                    s.push(' ');
                    s.push_str(w);
                }
                s
            }
        }
    }

    /// For sorting by "likely junk": large first, unknown in the middle, clean last.
    pub fn junk_rank(&self) -> i64 {
        match self.verdict() {
            ForecastVerdict::Large | ForecastVerdict::Some => {
                1_000_000_000_000
                    + self
                        .forecast
                        .as_ref()
                        .and_then(|f| f.estimate_bytes)
                        .unwrap_or(0)
            }
            ForecastVerdict::Unknown => 0,
            ForecastVerdict::Clean => -1,
        }
    }

    /// The installer kind in a word: "MSI", "Inno", "Store app", ...
    pub fn kind_chip(&self) -> &'static str {
        if self.entry.appx {
            return "Store app";
        }
        match self.entry.entry.installer_kind {
            InstallerKind::Msi => "MSI",
            InstallerKind::Inno => "Inno",
            InstallerKind::Nsis => "NSIS",
            InstallerKind::Burn => "Burn",
            InstallerKind::Unknown => "Other",
        }
    }

    /// The installer kind in words: "Inno Setup", "WiX Burn", ...
    pub fn kind_text(&self) -> &'static str {
        if self.entry.appx {
            return "Store app";
        }
        match self.entry.entry.installer_kind {
            InstallerKind::Msi => "MSI",
            InstallerKind::Inno => "Inno Setup",
            InstallerKind::Nsis => "NSIS",
            InstallerKind::Burn => "WiX Burn",
            InstallerKind::Unknown => "Other installer",
        }
    }

    /// "32-bit" or "64-bit".
    pub fn bits_text(&self) -> &'static str {
        match self.entry.entry.view {
            View::K32 => "32-bit",
            View::K64 => "64-bit",
        }
    }

    /// "this user" or "all users".
    pub fn scope_text(&self) -> &'static str {
        match self.entry.entry.scope {
            InstallScope::User => "this user",
            InstallScope::Machine => "all users",
        }
    }
}

/// `string.Join(separator, parts.Where(p => !string.IsNullOrEmpty(p)))`.
pub(crate) fn join(separator: &str, parts: &[&str]) -> String {
    parts
        .iter()
        .filter(|p| !p.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(separator)
}
