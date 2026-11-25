//! The mockup's state: plain data and the rules that change it. Nothing here draws, measures
//! text or knows a rectangle; `mdshared_ui::select::Selection` is the toolkit's own selection
//! model (ranges of row numbers), used so that the rules of click, Ctrl, Shift and the arrow keys
//! are the toolkit's and not a second copy.
//!
//! All of it is made up. No program is listed, started, removed or changed.

use std::time::{Duration, Instant};

use mdshared_ui::keys::Mods;
use mdshared_ui::select::Selection;

// ---- designs and pages -----------------------------------------------------------------------

/// The four designs of the ladder. One model serves them all.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Design {
    /// D0: today's WinUI layout, the reference.
    Winui,
    /// D1: the same structure, refined.
    Refined,
    /// D2: the pipeline and the leftovers as one flow.
    Flow,
    /// D3: command palette first, compact rail.
    Bold,
}

impl Design {
    pub const ALL: [Design; 4] = [Design::Winui, Design::Refined, Design::Flow, Design::Bold];

    pub fn name(self) -> &'static str {
        match self {
            Design::Winui => "winui",
            Design::Refined => "refined",
            Design::Flow => "flow",
            Design::Bold => "bold",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Design::Winui => "D0 \u{b7} WinUI (reference)",
            Design::Refined => "D1 \u{b7} Refined",
            Design::Flow => "D2 \u{b7} Flow",
            Design::Bold => "D3 \u{b7} Bold",
        }
    }

    pub fn parse(s: &str) -> Option<Design> {
        let s = s.trim().to_ascii_lowercase();
        Design::ALL
            .into_iter()
            .enumerate()
            .find(|(i, d)| d.name() == s || s == format!("d{i}") || s == i.to_string())
            .map(|(_, d)| d)
    }

    pub fn index(self) -> usize {
        Design::ALL.iter().position(|d| *d == self).unwrap_or(0)
    }

    pub fn next(self) -> Design {
        Design::ALL[(self.index() + 1) % Design::ALL.len()]
    }
}

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
}

// ---- programs --------------------------------------------------------------------------------

/// What Purge expects a program to leave behind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Expect {
    Clean,
    Some,
    Large,
    Unknown,
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
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SortKey {
    Name,
    Size,
    Junk,
    Date,
}

impl SortKey {
    pub const ALL: [SortKey; 4] = [SortKey::Name, SortKey::Size, SortKey::Junk, SortKey::Date];

    pub fn title(self) -> &'static str {
        match self {
            SortKey::Name => "Name",
            SortKey::Size => "Size",
            SortKey::Junk => "Expected leftovers",
            SortKey::Date => "Install date",
        }
    }

    pub fn index(self) -> usize {
        SortKey::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }
}

#[derive(Clone, Debug)]
pub struct Program {
    pub name: String,
    pub publisher: String,
    /// The installer family: MSI, NSIS, Inno, Store app, Other.
    pub kind: &'static str,
    pub tab: Tab,
    pub size_mb: f32,
    pub expect: Expect,
    /// What the leftovers are expected to be, in words; empty for Clean and Unknown.
    pub junk: String,
    /// Expected leftovers in MB, for sorting.
    pub junk_mb: f32,
    /// Days before today the program was installed.
    pub days_ago: u32,
    pub version: String,
    pub location: String,
    pub uninstall: String,
    pub quiet: bool,
    pub key: String,
    pub x64: bool,
    /// Gone from the list after a (pretend) uninstall.
    pub removed: bool,
}

impl Program {
    pub fn recent(&self) -> bool {
        self.days_ago <= 30
    }
}

/// Noon of 25 Nov 2026, UTC, in Unix seconds: the mockup's "today".
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

/// A tiny generator, so the made-up list is the same in every run.
struct Lcg(u32);

impl Lcg {
    fn next(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        self.0 >> 8
    }
    fn below(&mut self, n: u32) -> u32 {
        self.next() % n.max(1)
    }
}

type Seed = (
    &'static str,
    &'static str,
    &'static str,
    f32,
    Expect,
    &'static str,
    f32,
    u32,
);

const SEEDS: [Seed; 14] = [
    (
        "7-Zip 24.08 (x64)",
        "Igor Pavlov",
        "NSIS",
        5.6,
        Expect::Clean,
        "",
        0.0,
        268,
    ),
    (
        "Adobe Acrobat Reader",
        "Adobe",
        "MSI",
        612.0,
        Expect::Some,
        "~84 MB cache and settings",
        84.0,
        311,
    ),
    (
        "Audacity 3.7.1",
        "Audacity Team",
        "Inno",
        128.0,
        Expect::Some,
        "~12 MB profile",
        12.0,
        442,
    ),
    (
        "Blender",
        "Blender Foundation",
        "MSI",
        1130.0,
        Expect::Some,
        "~40 MB settings",
        40.0,
        148,
    ),
    (
        "Discord",
        "Discord Inc.",
        "Other",
        412.0,
        Expect::Large,
        "~1.3 GB cache and profile",
        1331.0,
        284,
    ),
    (
        "Git 2.51.0",
        "The Git Development Community",
        "Inno",
        362.0,
        Expect::Clean,
        "",
        0.0,
        4,
    ),
    (
        "GIMP 3.0.4",
        "The GIMP Team",
        "Inno",
        890.0,
        Expect::Some,
        "~22 MB profile",
        22.0,
        106,
    ),
    (
        "Mozilla Firefox (x64 en-US)",
        "Mozilla",
        "NSIS",
        247.0,
        Expect::Some,
        "~5 MB profile and cache",
        5.0,
        19,
    ),
    (
        "Notepad++ (64-bit x64)",
        "Notepad++ Team",
        "NSIS",
        15.2,
        Expect::Clean,
        "",
        0.0,
        235,
    ),
    (
        "OBS Studio",
        "OBS Project",
        "NSIS",
        486.0,
        Expect::Some,
        "~30 MB scenes and logs",
        30.0,
        182,
    ),
    (
        "PuTTY release 0.83",
        "Simon Tatham",
        "MSI",
        8.9,
        Expect::Clean,
        "",
        0.0,
        348,
    ),
    (
        "Spotify",
        "Spotify AB",
        "Store app",
        356.0,
        Expect::Unknown,
        "",
        0.0,
        53,
    ),
    (
        "Steam",
        "Valve Corporation",
        "NSIS",
        2200.0,
        Expect::Large,
        "~4.8 GB downloaded games",
        4915.0,
        494,
    ),
    (
        "VLC media player",
        "VideoLAN",
        "NSIS",
        168.0,
        Expect::Clean,
        "",
        0.0,
        48,
    ),
];

const NAMES: [&str; 38] = [
    "Aurora", "Basalt", "Cinder", "Delta", "Ember", "Fathom", "Garnet", "Harbor", "Indigo",
    "Juniper", "Kestrel", "Lumen", "Meridian", "Nimbus", "Onyx", "Pivot", "Quartz", "Rivet",
    "Sable", "Tundra", "Umbra", "Vertex", "Willow", "Xenon", "Yarrow", "Zephyr", "Anchor",
    "Bramble", "Copper", "Dune", "Echo", "Flint", "Glacier", "Hazel", "Iris", "Jasper", "Krill",
    "Larch",
];
const WHAT: [&str; 12] = [
    "Notes", "Studio", "Sync", "Viewer", "Player", "Capture", "Toolkit", "Backup", "Terminal",
    "Reader", "Paint", "Mail",
];
const PUBLISHERS: [&str; 14] = [
    "Northwind Traders",
    "Contoso Ltd",
    "Fabrikam, Inc.",
    "Tailspin Toys",
    "Adventure Works",
    "Litware",
    "Proseware",
    "Wide World Importers",
    "Lucerne Publishing",
    "Graphic Design Institute",
    "Trey Research",
    "Margie's Travel",
    "Blue Yonder Airlines",
    "Humongous Insurance",
];
const KINDS: [&str; 5] = ["MSI", "NSIS", "Inno", "Other", "Store app"];
const COMPONENTS: [&str; 8] = [
    "Microsoft Visual C++ 20{} Redistributable (x64)",
    "Microsoft Visual C++ 20{} Redistributable (x86)",
    "Microsoft .NET Runtime {}.0 (x64)",
    "Microsoft Windows Desktop Runtime {}.0",
    "Windows SDK AddOn {}",
    "Microsoft Edge WebView{} Runtime",
    "Update Helper {}",
    "Device Driver Package {}",
];

fn made_up() -> Vec<Program> {
    let mut rng = Lcg(0x5eed_1234);
    let mut out: Vec<Program> = Vec::new();
    let finish = |p: &mut Program| {
        // The name as a folder would carry it: "7-Zip 24.08 (x64)" is "7-Zip 24.08".
        let folder = name_part(p.name.split('(').next().unwrap_or(""), true);
        let folder = if folder.is_empty() {
            name_part(&p.name, true)
        } else {
            folder
        };
        p.location = format!(
            "C:\\Program Files{}\\{}",
            if p.x64 { "" } else { " (x86)" },
            folder
        );
        p.uninstall = match p.kind {
            "MSI" => format!(
                "MsiExec.exe /X{{{:08X}-51A2-4C0E-9D3B-7A61F0C2E9B4}}",
                p.days_ago * 7919 + 17
            ),
            "Store app" => "Remove-AppxPackage (through Windows)".to_string(),
            "Inno" => format!("\"{}\\unins000.exe\"", p.location),
            _ => format!("\"{}\\uninstall.exe\"", p.location),
        };
        p.quiet = matches!(p.kind, "MSI" | "Inno" | "NSIS");
        p.key = format!(
            "HKLM\\SOFTWARE\\{}Microsoft\\Windows\\CurrentVersion\\Uninstall\\{}",
            if p.x64 { "" } else { "WOW6432Node\\" },
            folder.replace(' ', "")
        );
    };
    for (name, publisher, kind, size, expect, junk, junk_mb, days) in SEEDS {
        let mut p = Program {
            name: name.to_string(),
            publisher: publisher.to_string(),
            kind,
            tab: Tab::Apps,
            size_mb: size,
            expect,
            junk: junk.to_string(),
            junk_mb,
            days_ago: days,
            version: format!("{}.{}.{}", 1 + days % 9, days % 13, days % 7),
            location: String::new(),
            uninstall: String::new(),
            quiet: false,
            key: String::new(),
            x64: true,
            removed: false,
        };
        finish(&mut p);
        out.push(p);
    }
    // 114 more apps: 128 in all, as the mockups show.
    let mut n = 0usize;
    while out.len() < 128 {
        let name = format!(
            "{} {}",
            NAMES[n % NAMES.len()],
            WHAT[(n / NAMES.len() + n * 5) % WHAT.len()]
        );
        n += 1;
        if out.iter().any(|p| p.name == name) {
            continue;
        }
        let expect = match rng.below(10) {
            0..=4 => Expect::Clean,
            5..=7 => Expect::Some,
            8 => Expect::Large,
            _ => Expect::Unknown,
        };
        let junk_mb = match expect {
            Expect::Some => 2.0 + rng.below(90) as f32,
            Expect::Large => 600.0 + rng.below(3000) as f32,
            _ => 0.0,
        };
        let what =
            ["cache", "profile", "settings", "logs", "cache and settings"][rng.below(5) as usize];
        let junk = match expect {
            Expect::Some => format!("~{junk_mb:.0} MB {what}"),
            Expect::Large => format!("~{:.1} GB {what}", junk_mb / 1024.0),
            _ => String::new(),
        };
        let size = match rng.below(6) {
            0 => 2.0 + rng.below(180) as f32 / 10.0,
            1..=3 => 20.0 + rng.below(400) as f32,
            4 => 400.0 + rng.below(900) as f32,
            _ => 1200.0 + rng.below(5000) as f32,
        };
        let days = rng.below(900) + if n.is_multiple_of(11) { 0 } else { 31 };
        let mut p = Program {
            name,
            publisher: PUBLISHERS[rng.below(PUBLISHERS.len() as u32) as usize].to_string(),
            kind: KINDS[rng.below(KINDS.len() as u32) as usize],
            tab: Tab::Apps,
            size_mb: size,
            expect,
            junk,
            junk_mb,
            days_ago: if n.is_multiple_of(11) {
                rng.below(29) + 1
            } else {
                days
            },
            version: format!("{}.{}.{}", 1 + rng.below(12), rng.below(20), rng.below(900)),
            location: String::new(),
            uninstall: String::new(),
            quiet: false,
            key: String::new(),
            x64: rng.below(5) != 0,
            removed: false,
        };
        finish(&mut p);
        out.push(p);
    }
    // 64 components.
    for i in 0..64u32 {
        let pattern = COMPONENTS[i as usize % COMPONENTS.len()];
        let name = pattern.replace("{}", &format!("{}", 10 + i / 8 + i % 3));
        let name = format!("{name} - {}.{}.{}", 10 + i % 5, i % 40, 30_000 + i * 131);
        let mut p = Program {
            name,
            publisher: "Microsoft Corporation".to_string(),
            kind: "MSI",
            tab: Tab::Components,
            size_mb: 1.0 + rng.below(900) as f32 / 10.0,
            expect: Expect::Clean,
            junk: String::new(),
            junk_mb: 0.0,
            days_ago: 40 + rng.below(1200),
            version: format!("{}.{}.{}", 10 + i % 5, i % 40, 30_000 + i * 131),
            location: String::new(),
            uninstall: String::new(),
            quiet: false,
            key: String::new(),
            x64: i % 2 == 0,
            removed: false,
        };
        finish(&mut p);
        out.push(p);
    }
    // 9 entries with no display name: Purge shows their key.
    for i in 0..9u32 {
        let mut p = Program {
            name: format!(
                "{{{:08X}-0000-4000-8000-{:012X}}}",
                0x1A2B_3C4D + i * 0x0101_0101,
                77 + i * 31
            ),
            publisher: "Publisher not recorded".to_string(),
            kind: "Other",
            tab: Tab::Unnamed,
            size_mb: rng.below(300) as f32 / 10.0,
            expect: Expect::Unknown,
            junk: String::new(),
            junk_mb: 0.0,
            days_ago: 200 + rng.below(1500),
            version: String::new(),
            location: String::new(),
            uninstall: String::new(),
            quiet: false,
            key: String::new(),
            x64: true,
            removed: false,
        };
        finish(&mut p);
        p.location = "Not recorded".to_string();
        out.push(p);
    }
    out
}

/// The Programs page: every entry, what is shown of them and what is selected.
pub struct Programs {
    pub all: Vec<Program>,
    pub tab: Tab,
    pub query: String,
    pub sort: SortKey,
    pub descending: bool,
    /// The Filter button's one switch: only programs expected to leave something.
    pub only_junk: bool,
    /// The shown rows, in order: indices into `all`.
    pub rows: Vec<usize>,
    /// The selection, in row numbers of `rows`.
    pub sel: Selection,
}

impl Programs {
    fn new() -> Programs {
        let mut p = Programs {
            all: made_up(),
            tab: Tab::Apps,
            query: String::new(),
            sort: SortKey::Name,
            descending: false,
            only_junk: false,
            rows: Vec::new(),
            sel: Selection::new(),
        };
        p.refresh();
        p
    }

    fn in_tab(p: &Program, tab: Tab) -> bool {
        !p.removed
            && match tab {
                Tab::Recent => p.recent(),
                t => p.tab == t,
            }
    }

    pub fn count(&self, tab: Tab) -> usize {
        self.all.iter().filter(|p| Self::in_tab(p, tab)).count()
    }

    /// Recomputes the shown rows from the tab, the search, the filter and the sort, and keeps
    /// the selection on the same programs (those still shown).
    pub fn refresh(&mut self) {
        let selected: Vec<usize> = self
            .sel
            .iter()
            .filter_map(|r| self.rows.get(r).copied())
            .collect();
        let cursor = self.sel.cursor().and_then(|r| self.rows.get(r).copied());
        let needle = self.query.trim().to_lowercase();
        let mut rows: Vec<usize> = (0..self.all.len())
            .filter(|&i| {
                let p = &self.all[i];
                Self::in_tab(p, self.tab)
                    && (!self.only_junk || matches!(p.expect, Expect::Some | Expect::Large))
                    && (needle.is_empty()
                        || p.name.to_lowercase().contains(&needle)
                        || p.publisher.to_lowercase().contains(&needle))
            })
            .collect();
        let all = &self.all;
        rows.sort_by(|&a, &b| {
            let (a, b) = (&all[a], &all[b]);
            let by_name = mdshared_app::fmt::natural_cmp(&a.name, &b.name);
            let o = match self.sort {
                SortKey::Name => by_name,
                SortKey::Size => a.size_mb.total_cmp(&b.size_mb).then(by_name),
                SortKey::Junk => a.junk_mb.total_cmp(&b.junk_mb).then(by_name),
                // "Install date" ascending is oldest first.
                SortKey::Date => b.days_ago.cmp(&a.days_ago).then(by_name),
            };
            if self.descending { o.reverse() } else { o }
        });
        self.rows = rows;
        self.sel.reset();
        for prog in selected {
            if let Some(r) = self.rows.iter().position(|&i| i == prog) {
                self.sel.toggle(r);
            }
        }
        match cursor.and_then(|c| self.rows.iter().position(|&i| i == c)) {
            Some(r) => self.sel.set_cursor(r),
            None => {
                if let Some(first) = self.sel.first() {
                    self.sel.set_cursor(first);
                }
            }
        }
    }

    pub fn set_tab(&mut self, tab: Tab) {
        if self.tab != tab {
            self.tab = tab;
            self.sel.reset();
            self.refresh();
        }
    }

    pub fn set_query(&mut self, q: &str) {
        if self.query != q {
            self.query = q.to_string();
            self.refresh();
        }
    }

    /// A click on a column: the same column turns the order round, another starts ascending
    /// (size and leftovers start with the largest, as Purge does).
    pub fn sort_by(&mut self, key: SortKey) {
        if self.sort == key {
            self.descending = !self.descending;
        } else {
            self.sort = key;
            self.descending = matches!(key, SortKey::Size | SortKey::Junk);
        }
        self.refresh();
    }

    pub fn click(&mut self, row: usize, mods: Mods) {
        if row < self.rows.len() {
            self.sel.click(row, mods);
        }
    }

    /// The programs selected, as indices into `all`, in the order shown.
    pub fn selected(&self) -> Vec<usize> {
        self.sel
            .iter()
            .filter_map(|r| self.rows.get(r).copied())
            .collect()
    }

    /// The program the details pane shows: the one under the cursor.
    pub fn current(&self) -> Option<usize> {
        self.sel
            .cursor()
            .filter(|c| self.sel.contains(*c) || self.sel.is_empty())
            .or(self.sel.first())
            .and_then(|r| self.rows.get(r).copied())
            .filter(|_| !self.sel.is_empty())
    }

    pub fn total_mb(&self, tab: Tab) -> f32 {
        self.all
            .iter()
            .filter(|p| Self::in_tab(p, tab))
            .map(|p| p.size_mb)
            .sum()
    }

    pub fn with_junk(&self) -> usize {
        self.all
            .iter()
            .filter(|p| {
                Self::in_tab(p, Tab::Apps) && matches!(p.expect, Expect::Some | Expect::Large)
            })
            .count()
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
                p.days_ago.wrapping_mul(2_654_435_761)
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

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ThemeChoice {
    System,
    Light,
    Dark,
}

impl ThemeChoice {
    pub const ALL: [ThemeChoice; 3] = [ThemeChoice::System, ThemeChoice::Light, ThemeChoice::Dark];

    pub fn title(self) -> &'static str {
        match self {
            ThemeChoice::System => "Use system setting",
            ThemeChoice::Light => "Light",
            ThemeChoice::Dark => "Dark",
        }
    }

    pub fn index(self) -> usize {
        ThemeChoice::ALL
            .iter()
            .position(|t| *t == self)
            .unwrap_or(0)
    }
}

pub struct Settings {
    pub theme: ThemeChoice,
    /// Days the quarantine keeps an item: an index into `KEEP_DAYS`.
    pub keep: usize,
    pub confirm_each: bool,
    pub show_components: bool,
    pub markers_open: bool,
    pub send_nothing: bool,
}

pub const KEEP_DAYS: [u32; 4] = [7, 14, 30, 90];

// ---- the whole model -------------------------------------------------------------------------

/// The confirmation before an uninstall: which programs it is for.
pub struct Confirm {
    pub programs: Vec<usize>,
}

pub struct Model {
    pub design: Design,
    pub page: Page,
    pub programs: Programs,
    pub confirm: Option<Confirm>,
    pub pipeline: Pipeline,
    pub leftovers: Leftovers,
    pub history: History,
    pub quarantine: Quarantine,
    pub settings: Settings,
}

impl Model {
    pub fn new(design: Design) -> Model {
        Model {
            design,
            page: Page::Programs,
            programs: Programs::new(),
            confirm: None,
            pipeline: Pipeline::new(),
            leftovers: Leftovers::new(),
            history: History::new(),
            quarantine: Quarantine::new(),
            settings: Settings {
                theme: ThemeChoice::System,
                keep: 2,
                confirm_each: true,
                show_components: false,
                markers_open: false,
                send_nothing: true,
            },
        }
    }

    /// Opens the confirmation for the selected programs. Nothing is opened for none.
    pub fn ask_uninstall(&mut self) -> bool {
        let programs = self.programs.selected();
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

    /// Moves the pipeline on; a finished run removes its program from the list and hands its
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
                if let Some(p) = self.programs.all.get_mut(program) {
                    p.removed = true;
                }
                self.programs.refresh();
                if let Some(p) = self.programs.all.get(program) {
                    self.leftovers.found_for(program, p);
                }
                (true, next)
            }
        }
    }

    /// The numbers the rail shows beside each page: (text, is a badge).
    pub fn badge(&self, page: Page) -> Option<(String, bool)> {
        match page {
            Page::Programs => Some((self.programs.count(Tab::Apps).to_string(), false)),
            Page::Pipeline => {
                let n = self.pipeline.pending();
                (n > 0).then(|| (n.to_string(), true))
            }
            Page::Leftovers => {
                let n = self.leftovers.count();
                (self.leftovers.phase == LeftoverPhase::Review && n > 0)
                    .then(|| (n.to_string(), true))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn likely_and_protected_start_unticked() {
        let mut l = Leftovers::new();
        l.found_for(0, &made_up()[0]);
        for i in l.groups.iter().flat_map(|g| &g.items) {
            assert_eq!(i.ticked, i.rating == Rating::Safe, "{}", i.path);
        }
    }

    #[test]
    fn the_leftovers_name_the_program_that_ran() {
        let all = made_up();
        for (at, p) in all.iter().enumerate() {
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
        let mut l = Leftovers::new();
        l.found_for(0, &made_up()[0]);
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
        let mut m = Model::new(Design::Winui);
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
    fn the_pipeline_runs_to_the_review() {
        let mut m = Model::new(Design::Winui);
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
        assert_eq!(m.leftovers.count(), 9);
    }

    #[test]
    fn the_lists_have_the_sizes_the_mockups_show() {
        let m = Model::new(Design::Winui);
        assert_eq!(m.programs.count(Tab::Apps), 128);
        assert_eq!(m.programs.count(Tab::Components), 64);
        assert_eq!(m.programs.count(Tab::Unnamed), 9);
    }

    #[test]
    fn a_sort_keeps_the_selection_on_the_same_programs() {
        let mut m = Model::new(Design::Winui);
        m.programs.click(2, Mods::default());
        let before = m.programs.selected();
        m.programs.sort_by(SortKey::Size);
        assert_eq!(m.programs.selected(), before);
        m.programs.set_query("zzzz-no-such");
        assert!(m.programs.rows.is_empty());
    }

    #[test]
    fn designs_parse() {
        assert_eq!(Design::parse("flow"), Some(Design::Flow));
        assert_eq!(Design::parse("D3"), Some(Design::Bold));
        assert_eq!(Design::parse("0"), Some(Design::Winui));
        assert_eq!(Design::parse("nope"), None);
    }
}
