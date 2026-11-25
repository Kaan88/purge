//! The model parts of `ProgramsPageTests.cs` (patches, details, icons, the list rules), the column theory
//! of `UninstallQueueTests.cs`, and the Programs page's own behaviour (`ProgramsView.xaml.cs` had no tests;
//! these pin what it did). The wire client, the icon atlas and the sample engine are `purge-client`'s.

use purge_model::{
    FileTime, InstallTimeEvidence, InstallTimeSource, InstallerKind, ProgramId, WritableBy,
};
use purge_rpc::methods::{
    Icon, IconBatch, InventoryChanges, ProgramDetails, ProgramPatch, ProgramRow as WireRow,
    ProgramsBatch, ProgramsPatch, SizeReady,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::page::{IconWanted, ProgramsNotice};
use super::rules::{self, fit_columns};
use super::*;
use crate::pipeline::{CallError, NoticeKind, RemovedRequest, UninstallTarget};

const HKLM: &str = "HKLM|64|";

fn wire<T: DeserializeOwned>(v: Value) -> T {
    serde_json::from_value(v).expect("a wire value")
}

/// A file of the repository, by its path from the root.
fn fixture<T: DeserializeOwned>(path: &str) -> T {
    let path = format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).expect("the fixture");
    serde_json::from_str(&text).expect("the fixture's shape")
}

fn pid(key: &str) -> ProgramId {
    format!("{HKLM}{key}").parse().expect("a program id")
}

fn row(key: &str, name: &str) -> WireRow {
    wire(json!({
        "program_id": format!("{HKLM}{key}"),
        "name": name,
        "publisher": "Vendor",
        "version": "1.0",
        "scope": "Machine",
    }))
}

fn patch(v: Value) -> ProgramPatch {
    wire(v)
}

fn entry(key: &str, name: &str) -> ProgramEntry {
    ProgramEntry::from_row(&row(key, name))
}

fn with_parent(mut e: ProgramEntry, parent: &str) -> ProgramEntry {
    e.entry.flags.parent_key = Some(parent.to_owned());
    e
}

const TODAY: CivilDate = CivilDate::new(2026, 11, 21);

fn clock() -> Clock {
    Clock {
        today: TODAY,
        offset: LocalOffset::Fixed(0),
    }
}

fn class(e: &ProgramEntry) -> rules::ProgramClass {
    rules::classify(&e.entry, None, TODAY)
}

// ---- patches and details ----------------------------------------------------------------------------

#[test]
fn patches_fill_in_installer_msi_burn_appx_system_and_unnamed() {
    let rows = [
        row("Plain", "Plain App"),
        row("Msi", "Msi App"),
        row("Burn", "Burn Bundle"),
        row("Child", "Burn Child"),
        row("Store", "Store App"),
        row("Sys", "System Thing"),
        row("{AAAA}", "{AAAA}"),
    ];
    let bundle = format!("{HKLM}Burn");
    let patches = [
        patch(json!({ "program_id": format!("{HKLM}Plain"), "installer": "Inno" })),
        patch(
            json!({ "program_id": format!("{HKLM}Msi"), "installer": "Msi", "product_code": "{PC}" }),
        ),
        patch(json!({ "program_id": bundle, "installer": "Burn", "bundle": bundle })),
        patch(json!({
            "program_id": format!("{HKLM}Child"), "installer": "Burn", "bundle": bundle,
            "parent_key": "Burn",
        })),
        patch(json!({ "program_id": format!("{HKLM}Store"), "appx": true })),
        patch(json!({ "program_id": format!("{HKLM}Sys"), "system_component": true })),
        patch(json!({ "program_id": format!("{HKLM}{{AAAA}}"), "unnamed": true })),
        // A patch for an id the list did not send is dropped.
        patch(json!({ "program_id": format!("{HKLM}Other"), "unnamed": true })),
    ];
    let entries = ProgramEntry::from_list(&rows, &patches);
    assert_eq!(entries.len(), 7);
    let e = |key: &str| {
        entries
            .iter()
            .find(|x| *x.id() == pid(key))
            .expect("the entry")
    };

    assert_eq!(e("Plain").entry.installer_kind, InstallerKind::Inno);
    assert_eq!(e("Msi").entry.installer_kind, InstallerKind::Msi);
    assert_eq!(e("Msi").entry.product_code.as_deref(), Some("{PC}"));
    assert!(e("Msi").entry.flags.windows_installer);
    assert_eq!(e("Burn").entry.installer_kind, InstallerKind::Burn);
    assert!(e("Burn").entry.flags.parent_key.is_none());
    assert_eq!(e("Child").entry.flags.parent_key.as_deref(), Some("Burn"));
    assert!(e("Store").appx);
    assert!(!e("Plain").appx);
    assert!(e("Sys").entry.flags.system_component);
    assert!(!e("{AAAA}").entry.flags.has_display_name);

    // The tabs follow from the patched flags.
    assert!(class(e("Plain")).is_app);
    assert!(class(e("Store")).is_app);
    assert!(class(e("Burn")).is_app);
    let child = class(e("Child"));
    assert!(child.is_component && child.is_child && !child.is_app);
    assert!(class(e("Sys")).is_component);
    let unnamed = class(e("{AAAA}"));
    assert!(unnamed.is_unnamed && !unnamed.is_app && !unnamed.is_component);
}

#[test]
fn a_bundle_other_than_its_own_id_makes_the_entry_a_child_of_that_bundle() {
    let mut e = entry("Child", "Child");
    e.apply_patch(&patch(
        json!({ "program_id": format!("{HKLM}Child"), "bundle": format!("{HKLM}Bundle") }),
    ));
    assert_eq!(e.entry.flags.parent_key.as_deref(), Some("Bundle"));
}

#[test]
fn a_row_without_a_patch_reads_as_a_named_app() {
    let entries = ProgramEntry::from_list(&[row("Plain", "Plain App")], &[]);
    assert!(class(&entries[0]).is_app);
    assert_eq!(entries[0].entry.installer_kind, InstallerKind::Unknown);
}

#[test]
fn a_late_patch_applies_to_the_entry() {
    let mut e = entry("Sys", "System Thing");
    e.apply_patch(&patch(
        json!({ "program_id": format!("{HKLM}Sys"), "system_component": true }),
    ));
    assert!(e.entry.flags.system_component);
}

#[test]
fn the_list_fixtures_read_as_entries() {
    let batch: ProgramsBatch = fixture("ui/Purge.Client.Tests/Samples/stdio.programs.batch.json");
    let patches: ProgramsPatch =
        fixture("crates/purge-rpc/fixtures/notification.programs.patch.json");
    let entries = ProgramEntry::from_list(&batch.rows, &patches.patches);
    let git = &entries[0];
    assert_eq!(git.entry.display_name, "Git");
    assert_eq!(git.entry.installer_kind, InstallerKind::Inno);
    assert!(!git.appx);
    assert!(rules::install_date(&git.entry, &clock()).is_some());
}

#[test]
fn details_fill_in_the_uninstaller() {
    let details: ProgramDetails =
        fixture("crates/purge-rpc/fixtures/stdio.programs.get.result.json");
    let mut e = ProgramEntry::from_row(&wire(
        json!({ "program_id": "HKLM|64|Git_is1", "name": "Git", "scope": "Machine" }),
    ));
    e.apply_details(&details);
    assert_eq!(
        e.entry.install_location.as_deref(),
        Some(r"C:\Program Files\Git\")
    );
    assert_eq!(
        e.entry.uninstall_string.as_deref(),
        Some(r#""C:\Program Files\Git\unins000.exe""#)
    );
    assert_eq!(
        e.entry.quiet_uninstall_string.as_deref(),
        Some(r#""C:\Program Files\Git\unins000.exe" /SILENT"#)
    );
    assert_eq!(e.entry.installer_kind, InstallerKind::Inno);
    assert_eq!(e.entry.writable_by, WritableBy::Admin);
}

#[test]
fn icons_are_decoded_and_a_failed_or_malformed_one_has_no_pixels() {
    let batch: IconBatch = fixture("crates/purge-rpc/fixtures/notification.icon.batch.json");
    let icons: Vec<ProgramIcon> = batch.icons.iter().map(ProgramIcon::from_wire).collect();
    // 1 px = 4 bytes; "AAAA/w==" is 00 00 00 FF.
    assert_eq!(icons[0].bgra.as_deref(), Some(&[0u8, 0, 0, 255][..]));
    assert!(icons[1].bgra.is_none());
    let wrong: Icon =
        wire(json!({ "program_id": format!("{HKLM}C"), "px": 24, "bgra": "AAAA/w==" }));
    assert!(
        ProgramIcon::from_wire(&wrong).bgra.is_none(),
        "24 px asked for, 4 bytes given"
    );
    let bad: Icon = wire(json!({ "program_id": format!("{HKLM}C"), "px": 1, "bgra": "AA*A/w==" }));
    assert!(ProgramIcon::from_wire(&bad).bgra.is_none());
}

// ---- list rules -------------------------------------------------------------------------------------

#[test]
fn children_stay_under_their_parent_in_every_sort_and_an_orphan_sorts_alone() {
    let parent = entry("Zeta", "Zeta Suite");
    let child = with_parent(entry("Alpha-Update", "Alpha Update"), "Zeta");
    let other = entry("Beta", "Beta");
    let orphan = with_parent(entry("Orphan", "Aardvark"), "Missing");
    let all = [child.clone(), other.clone(), parent, orphan];
    let names = |v: Vec<ProgramEntry>| -> Vec<String> {
        v.into_iter().map(|e| e.entry.display_name).collect()
    };
    let by_name = |rows: &[ProgramEntry], descending| {
        rules::order(
            rows,
            |e| &e.entry,
            |a, b| rules::compare_text(&a.entry.display_name, &b.entry.display_name),
            descending,
        )
    };

    assert_eq!(
        names(by_name(&all, false)),
        ["Aardvark", "Beta", "Zeta Suite", "Alpha Update"]
    );
    assert_eq!(
        names(by_name(&all, true)),
        ["Zeta Suite", "Alpha Update", "Beta", "Aardvark"]
    );
    // A tab or search that hides the parent shows the child like any other row.
    assert_eq!(
        names(by_name(&[child, other], false)),
        ["Alpha Update", "Beta"]
    );
}

#[test]
fn search_reads_name_publisher_version_and_folder() {
    let mut e = entry("A", "Firefox");
    e.entry.install_location = Some(r"C:\Apps\Fox".into());
    for q in ["", "fire", "VENDOR", "1.0", r"apps\fox"] {
        assert!(rules::matches(&e.entry, q), "{q}");
    }
    assert!(!rules::matches(&e.entry, "chrome"));
}

#[test]
fn recent_is_an_app_installed_within_fourteen_days() {
    let app = entry("A", "A");
    let recent = |e: &ProgramEntry, d| rules::classify(&e.entry, d, TODAY).is_recent;
    assert!(recent(&app, Some(TODAY.add_days(-14))));
    assert!(!recent(&app, Some(TODAY.add_days(-15))));
    assert!(!recent(&app, None));
    let mut system = entry("S", "S");
    system.entry.flags.system_component = true;
    assert!(!recent(&system, Some(TODAY)));
}

#[test]
fn a_damaged_install_time_is_no_date() {
    let mut e = entry("A", "A");
    e.entry.install_time_evidence = vec![InstallTimeEvidence {
        source: InstallTimeSource::ArpInstallDate,
        time: FileTime(u64::MAX),
    }];
    assert!(rules::install_date(&e.entry, &clock()).is_none());
    e.entry.install_time_evidence = vec![InstallTimeEvidence {
        source: InstallTimeSource::KeyLastWrite,
        time: FileTime(134_076_753_020_000_000),
    }];
    assert!(rules::install_date(&e.entry, &clock()).is_some());
}

#[test]
fn sizes_read_in_the_unit_that_fits() {
    assert_eq!(rules::format_size(0), "0 B");
    assert!(rules::format_size(5 * 1024 * 1024).contains("MB"));
    assert!(rules::format_size(3 * 1024 * 1024 * 1024).contains("GB"));
    assert_eq!(rules::format_size(345_000_000), "329 MB");
    assert_eq!(rules::format_size(1536), "1.5 KB");
}

#[test]
fn narrow_lists_drop_installed_then_leftovers_then_size_and_keep_the_name() {
    let base = rules::LIST_CHROME + rules::MIN_NAME_WIDTH;
    for (width, size, leftovers, installed) in [
        (2000.0, true, true, true),
        (base + 342.0, true, true, true),
        (base + 341.0, true, true, false),
        (base + 249.0, true, false, false),
        (base + 99.0, false, false, false),
        (120.0, false, false, false),
    ] {
        assert_eq!(
            fit_columns(width),
            ListColumns {
                size,
                leftovers,
                installed
            },
            "{width}"
        );
    }
}

#[test]
fn the_page_layout_follows_the_width() {
    let narrow = PageLayout::fit(600.0);
    assert!(narrow.stack_tools && !narrow.details);
    assert_eq!(narrow.details_width, 0.0);
    let middle = PageLayout::fit(800.0);
    assert!(middle.stack_tools && middle.details);
    assert_eq!(middle.details_width, 280.0);
    let wide = PageLayout::fit(1200.0);
    assert!(!wide.stack_tools);
    assert_eq!(wide.details_width, 330.0);
    assert_eq!(wide.spacing, 16.0);
}

// ---- the page ---------------------------------------------------------------------------------------

const LIVE: EngineState = EngineState {
    live: true,
    can_change_pc: true,
};

fn entries() -> Vec<ProgramEntry> {
    let mut sys = entry("Sys", "System Thing");
    sys.entry.flags.system_component = true;
    let mut unnamed = entry("{AAAA}", "{AAAA}");
    unnamed.entry.flags.has_display_name = false;
    let mut firefox = entry("Firefox", "Mozilla Firefox");
    firefox.entry.publisher = Some("Mozilla".into());
    let mut service = entry("Maint", "Mozilla Maintenance Service");
    service.entry.publisher = Some("Mozilla".into());
    let mut user = entry("User", "User Tool");
    user.entry.scope = purge_model::InstallScope::User;
    vec![
        entry("Beta", "Beta"),
        firefox,
        entry("Alpha", "alpha"),
        sys,
        unnamed,
        service,
        user,
    ]
}

/// A live page with the list in and its first frame out; the requests of that start are returned too.
fn page() -> (ProgramsModel, Vec<ProgramsRequest>) {
    let mut m = ProgramsModel::new(clock(), LIVE, |_| true);
    let mut out = m.on_list(Ok(entries()));
    out.extend(m.on_first_frame());
    (m, out)
}

fn shown_names(m: &ProgramsModel) -> Vec<String> {
    m.view()
        .shown
        .iter()
        .map(|id| m.row(id).expect("a row").name().to_owned())
        .collect()
}

fn scan() -> purge_rpc::methods::ScanResult {
    fixture("crates/purge-rpc/fixtures/pipe.leftovers.scan.result.json")
}

#[test]
fn the_first_frame_starts_icons_sizes_and_forecasts_in_list_order() {
    let mut m = ProgramsModel::new(clock(), LIVE, |_| true);
    assert!(
        m.on_list(Ok(entries())).is_empty(),
        "nothing before the first frame"
    );
    let out = m.on_first_frame();
    let [
        ProgramsRequest::Icons {
            generation: 1,
            wanted,
        },
        ProgramsRequest::Sizes {
            generation: 1,
            program_ids,
        },
        ProgramsRequest::Forecasts {
            program_ids: forecast,
        },
    ] = out.as_slice()
    else {
        panic!("{out:?}");
    };
    // What the list shows first (Apps by name), then the rest in list order.
    let first: Vec<&ProgramId> = wanted.iter().map(|w: &IconWanted| &w.program_id).collect();
    assert_eq!(first[0], &pid("Alpha"));
    assert_eq!(wanted.len(), 7);
    assert_eq!(program_ids.len(), 7);
    assert_eq!(forecast.len(), 7);
    assert!(m.on_first_frame().is_empty(), "once");
    assert_eq!(
        m.view().status_right,
        "Engine connected · measuring sizes 0 of 7"
    );
}

#[test]
fn the_apps_tab_sorts_by_name_and_the_counts_follow_the_tabs() {
    let (m, _) = page();
    assert_eq!(
        shown_names(&m),
        [
            "alpha",
            "Beta",
            "Mozilla Firefox",
            "Mozilla Maintenance Service",
            "User Tool"
        ]
    );
    let v = m.view();
    let counts: Vec<(&str, usize)> = v.tabs.iter().map(|t| (t.label, t.count)).collect();
    assert_eq!(
        counts,
        [
            ("Apps", 5),
            ("Components", 1),
            ("Unnamed", 1),
            ("Recent", 0)
        ]
    );
    assert_eq!(v.all_label, "ALL APPS · 5");
    assert_eq!(v.summary, "7 entries · 0 B");
    assert_eq!(v.status_left, "5 apps · 0 B");
    assert_eq!(v.sort.name, "Name ↑");
    assert_eq!(v.sort.button, "Sort: Name");
    assert_eq!(v.filter_text, "Filter");
    assert!(v.no_match.is_none());
    assert!(v.details.is_none(), "nothing is picked for the user");
}

#[test]
fn search_and_filters_say_why_nothing_matches() {
    let (mut m, _) = page();
    m.set_search("  zzz ");
    let v = m.view();
    assert_eq!(v.query, "zzz");
    assert_eq!(
        v.no_match,
        Some((
            "No programs match \u{201C}zzz\u{201D} in Apps.".to_owned(),
            "Try fewer letters, another tab, or press Esc to clear the search."
        ))
    );
    assert!(v.tabs.iter().all(|t| t.count == 0));

    m.set_search("");
    m.set_filter(Filter::Bits32, true);
    let v = m.view();
    assert_eq!(v.filter_text, "Filter (1)");
    assert_eq!(
        v.no_match,
        Some((
            "No programs in Apps match the filters.".to_owned(),
            "Turn a filter off, or try another tab."
        ))
    );
    m.set_search("beta");
    assert_eq!(
        m.view().no_match.map(|n| n.0),
        Some("No programs match \u{201C}beta\u{201D} and the filters in Apps.".to_owned())
    );

    m.set_search("");
    m.set_filter(Filter::Bits32, false);
    m.set_filter(Filter::PerUser, true);
    assert_eq!(shown_names(&m), ["User Tool"]);
}

#[test]
fn the_headers_turn_the_order_around_and_a_new_key_starts_descending_for_size() {
    let (mut m, _) = page();
    m.sort_by_header(SortKey::Name);
    assert_eq!(m.view().sort.name, "Name ↓");
    assert_eq!(shown_names(&m)[0], "User Tool");

    m.sort_by_header(SortKey::Size);
    let v = m.view();
    assert!(v.sort.descending);
    assert_eq!(v.sort.size, "Size ↓");
    assert_eq!(v.sort.name, "Name");
    assert_eq!(v.sort.button, "Sort: Size");

    m.sort_by_menu(SortKey::Publisher);
    assert!(!m.view().sort.descending);
    assert_eq!(m.view().sort.button, "Sort: Publisher");
}

#[test]
fn sizes_fill_the_rows_and_the_footer_and_the_last_chunk_ends_the_measuring() {
    let (mut m, out) = page();
    let Some(ProgramsRequest::Sizes { generation, .. }) = out
        .iter()
        .find(|r| matches!(r, ProgramsRequest::Sizes { .. }))
    else {
        panic!("{out:?}");
    };
    let generation = *generation;
    let ready: SizeReady = wire(json!({
        "request": 4,
        "sizes": [
            { "program_id": format!("{HKLM}Beta"), "bytes": 345000000u64 },
            { "program_id": format!("{HKLM}Alpha"), "bytes": null },
        ],
    }));
    assert!(
        m.on_sizes(generation + 1, &ready.sizes).is_empty(),
        "another load's"
    );
    m.on_sizes(generation, &ready.sizes);
    let beta = m.row(&pid("Beta")).expect("a row");
    assert_eq!(beta.size_text(), "329 MB");
    assert_eq!(beta.bar_width, row::BAR_MAX);
    assert_eq!(m.view().summary, "7 entries · 329 MB");
    assert!(m.view().status_right.ends_with("measuring sizes 2 of 7"));

    // One chunk of 7 (fewer than 16): its reply ends the measuring.
    assert!(m.on_sizes_done(generation, Ok(())).is_empty());
    assert_eq!(m.view().status_right, "Engine connected");
}

#[test]
fn a_selection_asks_for_the_details_once_and_the_pane_reads_them() {
    let (mut m, _) = page();
    let fox = pid("Firefox");
    let out = m.on_selection_changed(std::slice::from_ref(&fox), &[]);
    assert_eq!(
        out,
        vec![ProgramsRequest::Details {
            program_id: fox.clone()
        }]
    );
    let d = m.view().details.expect("the pane");
    assert_eq!(d.uninstaller, "Reading…");
    assert_eq!(d.location, "Reading…");
    assert_eq!(d.uninstall_command, "…");
    assert_eq!(d.size, "Measuring…");
    assert_eq!(d.owns, "Mozilla Maintenance Service");
    assert_eq!(d.sub, "Mozilla · 1.0 · Other");
    assert_eq!(d.installed, "for all users");
    assert_eq!(d.platform, "64-bit");
    assert_eq!(
        d.expects[0].text,
        "Checking what this program is expected to leave…"
    );

    let details: ProgramDetails =
        fixture("crates/purge-rpc/fixtures/stdio.programs.get.result.json");
    m.on_details(&fox, Ok(Some(details)));
    let d = m.view().details.expect("the pane");
    assert_eq!(d.uninstaller, "Inno Setup · quiet mode available");
    assert_eq!(d.location, r"C:\Program Files\Git\");
    assert_eq!(
        d.quiet_command,
        r#""C:\Program Files\Git\unins000.exe" /SILENT"#
    );
    assert_eq!(d.product_code, None);

    // Unticked, the pane closes; ticked again, no second request.
    m.on_selection_changed(&[], std::slice::from_ref(&fox));
    assert!(m.view().details.is_none());
    assert!(
        m.on_selection_changed(std::slice::from_ref(&fox), &[])
            .is_empty()
    );

    // The forecast answered nothing for it: "not known yet".
    m.on_forecasts(Ok(vec![]));
    assert!(
        m.view().details.expect("the pane").expects[0]
            .text
            .starts_with("Not known yet.")
    );
}

#[test]
fn a_gone_program_keeps_what_the_list_knew() {
    let (mut m, _) = page();
    let beta = pid("Beta");
    m.on_selection_changed(std::slice::from_ref(&beta), &[]);
    m.on_details(&beta, Ok(None));
    let d = m.view().details.expect("the pane");
    assert_eq!(d.uninstaller, "None registered");
    assert_eq!(d.location, "Not recorded");
    assert_eq!(d.uninstall_command, "None");
}

#[test]
fn ticking_several_shows_the_count_and_uninstalls_them_in_list_order() {
    let (mut m, _) = page();
    m.on_selection_changed(&[pid("User"), pid("Beta")], &[]);
    let v = m.view();
    assert_eq!(v.selected_count, "2 selected");
    assert_eq!(v.commands.uninstall_label, "Uninstall 2");
    assert_eq!(v.commands.uninstall_name, "Uninstall 2 programs");
    assert!(v.commands.uninstall_enabled);
    assert_eq!(v.details.map(|d| d.name), Some("Beta".to_owned()));

    // One leaves the list: it stays ticked, and the count says so.
    m.set_search("user");
    assert_eq!(m.view().selected_count, "2 selected (1 not shown)");
    let out = m.run_command(ProgramCommand::Uninstall);
    assert_eq!(
        out,
        vec![ProgramsRequest::Uninstall {
            targets: vec![
                UninstallTarget::new(pid("User"), "User Tool"),
                UninstallTarget::new(pid("Beta"), "Beta"),
            ]
        }]
    );
}

#[test]
fn commands_without_a_program_or_a_folder_say_so() {
    let (mut m, _) = page();
    assert!(m.run_command(ProgramCommand::OpenFolder).is_empty());
    assert_eq!(
        m.view().notice,
        Some(ProgramsNotice {
            kind: NoticeKind::Info,
            message: "Select a program first.".into()
        })
    );
    assert!(m.run_command(ProgramCommand::Uninstall).is_empty());
    assert_eq!(
        m.view().notice.map(|n| n.message),
        Some("Select a program to uninstall first.".into())
    );
    let v = m.view();
    assert!(!v.commands.uninstall_enabled);
    assert_eq!(
        v.commands.uninstall_tooltip,
        Some("Select a program to uninstall.")
    );

    m.on_selection_changed(&[pid("Firefox")], &[]);
    assert!(m.run_command(ProgramCommand::OpenFolder).is_empty());
    assert_eq!(
        m.view().notice.map(|n| (n.kind, n.message)),
        Some((
            NoticeKind::Warning,
            "The install folder is not recorded for this program, or is not on this PC any more."
                .into()
        ))
    );
    assert_eq!(
        m.run_command(ProgramCommand::Web),
        vec![ProgramsRequest::OpenWeb {
            url: "https://www.bing.com/search?q=Mozilla%20Firefox%20Mozilla".into()
        }]
    );
    assert_eq!(
        m.run_command(ProgramCommand::Refresh),
        vec![ProgramsRequest::List]
    );
    m.dismiss_notice();
    assert!(m.view().notice.is_none());
}

#[test]
fn sample_data_cannot_refresh_or_uninstall() {
    let mut m = ProgramsModel::new(clock(), EngineState::default(), |_| true);
    m.on_list(Ok(entries()));
    m.on_first_frame();
    assert_eq!(m.view().status_right, "Sample data · engine not connected");
    assert!(m.run_command(ProgramCommand::Refresh).is_empty());
    assert_eq!(
        m.view().notice.map(|n| n.message),
        Some("Sample data: there is no engine to read the list from.".into())
    );
    // Sample rows need no programs.get.
    assert!(m.on_selection_changed(&[pid("Beta")], &[]).is_empty());
    assert_eq!(
        m.view().details.map(|d| d.uninstaller),
        Some("None registered".into())
    );
    let v = m.view();
    assert!(!v.commands.uninstall_enabled);
    assert_eq!(
        v.commands.uninstall_tooltip,
        Some("Sample data: no engine is connected.")
    );
    m.run_command(ProgramCommand::Uninstall);
    assert_eq!(
        m.view().notice.map(|n| n.message),
        Some("Sample data: no engine is connected.".into())
    );
}

#[test]
fn reveal_switches_to_the_programs_tab_and_clears_the_search() {
    let (mut m, _) = page();
    m.set_search("beta");
    let out = m.reveal(&pid("Sys"));
    assert!(out.contains(&ProgramsRequest::ScrollIntoView(pid("Sys"))));
    assert_eq!(m.tab(), ProgramTab::Components);
    assert_eq!(m.query(), "");
    assert_eq!(m.view().selected, vec![pid("Sys")]);
}

#[test]
fn a_late_patch_moves_a_row_to_its_tab() {
    let (mut m, _) = page();
    m.on_late_patches(&[patch(
        json!({ "program_id": format!("{HKLM}Beta"), "system_component": true }),
    )]);
    assert!(!shown_names(&m).contains(&"Beta".to_owned()));
    assert_eq!(m.view().tabs[1].count, 2);
}

#[test]
fn a_failed_reload_keeps_the_list_and_says_why() {
    let (mut m, _) = page();
    m.on_list(Err(CallError::Link("The engine ended.".into())));
    assert_eq!(
        m.view().notice.map(|n| n.message),
        Some("Couldn't read the program list: The engine ended.".into())
    );
    assert_eq!(m.rows().len(), 7);
}

#[test]
fn a_reload_measures_again_with_a_new_generation_and_keeps_the_ticked_rows() {
    let (mut m, _) = page();
    m.on_selection_changed(&[pid("Beta")], &[]);
    let out = m.on_list(Ok(entries()));
    // The new rows ask for the pane's details again, then the enrichment starts over.
    assert!(matches!(out[0], ProgramsRequest::Details { .. }));
    assert!(matches!(
        out[1],
        ProgramsRequest::Icons { generation: 2, .. }
    ));
    assert!(matches!(
        out[2],
        ProgramsRequest::Sizes { generation: 2, .. }
    ));
    assert_eq!(m.view().selected, vec![pid("Beta")]);
}

#[test]
fn the_web_search_escapes_like_escape_data_string() {
    assert_eq!(page::escape_data("A&B C/ü~"), "A%26B%20C%2F%C3%BC~");
}

// ---- the "removed outside Purge" group --------------------------------------------------------------

fn changes() -> InventoryChanges {
    fixture("crates/purge-rpc/fixtures/stdio.inventory.changes.result.json")
}

fn git() -> ProgramId {
    pid("Git_is1")
}

#[test]
fn the_removed_group_shows_once_with_its_rows() {
    let (mut m, _) = page();
    m.on_changes(Some(changes()));
    let group = m.view().removed.expect("the group");
    assert_eq!(group.header, "REMOVED OUTSIDE PURGE · 1");
    let r = &group.rows[0];
    assert_eq!(r.name, "Git");
    assert_eq!(r.initial, "G");
    assert_eq!(
        r.detail,
        "Removed outside Purge. Purge recorded it before, so it can look for what it left."
    );
    assert_eq!(r.button_text, "Check for leftovers");
    assert!(r.can_check);
    assert_eq!(
        r.check_hint,
        Some("Asks for administrator permission, then looks for what it left on the PC")
    );

    // No record: no button.
    let mut none = ProgramsModel::new(clock(), LIVE, |_| false);
    none.on_list(Ok(entries()));
    none.on_changes(Some(changes()));
    assert!(none.view().removed.is_none(), "not before the first frame");
    none.on_first_frame();
    let r = &none.view().removed.expect("the group").rows[0];
    assert!(!r.button_visible);
    assert!(
        r.detail
            .starts_with("Removed outside Purge. Purge did not record")
    );
}

#[test]
fn a_finished_check_opens_the_leftovers_and_the_row_leaves_the_group() {
    let (mut m, _) = page();
    m.on_changes(Some(changes()));
    let out = m.check_removed(&git());
    assert_eq!(
        out,
        vec![
            ProgramsRequest::Check(RemovedRequest::Launch),
            ProgramsRequest::CheckRunningChanged
        ]
    );
    assert!(m.check_running());
    let v = m.view();
    assert_eq!(
        v.removed.expect("the group").rows[0].detail,
        "Removed outside Purge. Purge is asking for administrator permission…"
    );
    assert_eq!(
        v.commands.details_uninstall_tooltip,
        Some("A leftovers check is running. Uninstall when it has finished.")
    );

    let out = m.on_check_launch(Ok(crate::pipeline::LaunchResult::started()));
    assert_eq!(
        out,
        vec![ProgramsRequest::Check(RemovedRequest::Stored {
            program_ids: vec![git()]
        })]
    );
    m.on_check_stored(Ok(vec![git()]));
    m.on_check_progress("reading roots");
    let r = &m.view().removed.expect("the group").rows[0];
    assert_eq!(r.detail, "Looking for what it left · reading roots");
    assert_eq!(r.button_text, "Stop");
    assert_eq!(r.check_hint, Some("Stops the check; nothing is changed"));
    assert!(!r.can_dismiss);

    let out = m.on_check_scan(Ok(scan()));
    assert!(matches!(out[0], ProgramsRequest::OpenLeftovers(ref o) if o.program_id == git()));
    assert!(out.contains(&ProgramsRequest::Forget {
        program_ids: vec![git()]
    }));
    assert!(out.contains(&ProgramsRequest::CheckRunningChanged));
    assert!(m.view().removed.is_none(), "the group is empty");
}

#[test]
fn a_check_waits_for_an_uninstall_or_a_leftovers_change() {
    let (mut m, _) = page();
    m.on_changes(Some(changes()));
    m.set_broker_users(BrokerUsers {
        uninstall_busy: true,
        leftovers_changing: false,
    });
    let r = &m.view().removed.expect("the group").rows[0];
    assert!(!r.can_check);
    assert_eq!(
        r.check_hint,
        Some("Waits until the running uninstall has finished")
    );
    assert!(m.check_removed(&git()).is_empty());
    assert_eq!(
        m.view().notice.map(|n| n.message),
        Some("An uninstall is running. Check for leftovers when it has finished.".into())
    );

    m.set_broker_users(BrokerUsers {
        uninstall_busy: false,
        leftovers_changing: true,
    });
    assert!(m.check_removed(&git()).is_empty());
    assert_eq!(
        m.view().notice.map(|n| n.message),
        Some(
            "The Leftovers page is applying a change. Check for leftovers when it has finished."
                .into()
        )
    );
}

#[test]
fn a_scan_that_cannot_go_to_the_leftovers_page_ends_its_session_and_keeps_the_row() {
    let (mut m, _) = page();
    m.on_changes(Some(changes()));
    m.check_removed(&git());
    m.on_check_launch(Ok(crate::pipeline::LaunchResult::started()));
    m.on_check_stored(Ok(vec![git()]));
    m.set_broker_users(BrokerUsers {
        uninstall_busy: false,
        leftovers_changing: true,
    });
    let out = m.on_check_scan(Ok(scan()));
    assert!(out.contains(&ProgramsRequest::CloseCheckSession));
    assert_eq!(
        m.view().notice.map(|n| n.message),
        Some("The Leftovers page is still applying another change, so the leftovers of Git were not opened. Nothing was changed; check again when it has finished.".into())
    );
    assert!(m.view().removed.is_some());
}

#[test]
fn a_cancelled_prompt_shows_the_checks_bar_on_the_page() {
    let (mut m, _) = page();
    m.on_changes(Some(changes()));
    m.check_removed(&git());
    m.on_check_launch(Ok(crate::pipeline::LaunchResult::of(
        crate::pipeline::LaunchState::Cancelled,
        "",
    )));
    assert_eq!(
        m.view().notice.map(|n| n.message),
        Some("Not checked: administrator permission was not given. The Windows prompt was cancelled. Nothing was changed.".into())
    );
    assert!(!m.check_running());
}

#[test]
fn stop_on_the_running_row_cancels_the_check() {
    let (mut m, _) = page();
    m.on_changes(Some(changes()));
    m.check_removed(&git());
    assert_eq!(
        m.check_removed(&git()),
        vec![ProgramsRequest::Check(RemovedRequest::Cancel)]
    );
}

#[test]
fn dismiss_takes_a_row_out_and_the_engine_forgets_it() {
    let (mut m, _) = page();
    m.on_changes(Some(changes()));
    assert_eq!(
        m.dismiss_removed(&git()),
        vec![ProgramsRequest::Forget {
            program_ids: vec![git()]
        }]
    );
    assert!(m.view().removed.is_none());
}

#[test]
fn an_uninstall_by_purge_forgets_the_program_and_reads_the_list_again() {
    let (mut m, _) = page();
    assert_eq!(
        m.on_uninstall_run_ended(&pid("Beta"), true),
        vec![
            ProgramsRequest::Forget {
                program_ids: vec![pid("Beta")]
            },
            ProgramsRequest::List
        ]
    );
    assert_eq!(
        m.on_uninstall_run_ended(&pid("Beta"), false),
        vec![ProgramsRequest::List]
    );

    // The changes answer arrives after Purge uninstalled one of them: it is not shown as removed outside.
    let mut late = ProgramsModel::new(clock(), LIVE, |_| true);
    late.on_list(Ok(entries()));
    late.on_uninstall_run_ended(&git(), true);
    late.on_first_frame();
    let out = late.on_changes(Some(changes()));
    assert!(out.contains(&ProgramsRequest::Forget {
        program_ids: vec![git()]
    }));
    assert!(late.view().removed.is_none());
}
