//! The rule about what a value holds, against every scanner (`ScanCtx::value_content_unproven`,
//! applied by `CandidateBuilder::build`).
//!
//! A table of hostile value data (every case the reviews of M1a found: the app's path next to
//! somebody else's text) is planted in every kind of place a scanner reads, with every record
//! that could make the value look like the app's, and **all** scanners of the catalog run over
//! each. Nothing on the planted value, and no key that holds it, may come out Safe or ticked.
//! The same places with data that is wholly the app's are the controls: they must be Safe, or
//! the table would prove nothing.
//!
//! A scanner that is added to the catalog must be entered in [`REGISTRY_SCANNERS`],
//! [`M1B_REGISTRY_SCANNERS`] or [`OTHER_SCANNERS`]; one that reads a new kind of place gets that place
//! in [`places`].

use purge_model::{Band, Candidate, InnoRecordKind, RefCarrier, Target};
use purge_policy::band::{PolicyCtx, TargetScope, decide};
use purge_scan::catalog;
use purge_source::fixture::FixtureBuilder;
use purge_source::types::{REG_BINARY, REG_EXPAND_SZ, REG_NONE, REG_SZ, RegData};

use crate::golden;
use crate::world::*;

/// The scanners that can offer a registry value, an entry of one, or a key with values in it.
const REGISTRY_SCANNERS: [&str; 13] = [
    "REG-SOFTWARE",
    "REG-APPPATHS",
    "REG-RUN",
    "REG-ENV",
    "REF-ANY",
    "CLS-PROGID",
    "CLS-ASSOC",
    "CLS-FILEEXTS",
    "CLS-TOASTS",
    "CLS-AUMID",
    "CLS-VERBS",
    "CLS-PROTOCOL",
    "CLS-REGAPPS",
];

/// The M1b scanners that offer registry keys and values. They read places this table does not plant
/// into (COM classes and interfaces, shell-extension lists, Windows Installer and Burn records, the
/// privacy stores, the diagnostics keys); their own suites (`tests/com`, `tests/shellex`,
/// `tests/msireg`, `tests/burn`, `tests/privacy`, `tests/diag`) hold their hostile values. Here they
/// may offer registry targets, and they have no positive control.
const M1B_REGISTRY_SCANNERS: [&str; 9] = [
    "COM-CLASS",
    "COM-INTERFACE",
    "COM-SHELLEX",
    "SYS-BURNDEPS",
    "REG-ARP-MSI",
    "REG-SHAREDDLLS",
    "REG-INSTFOLDERS",
    "REG-PRIVACY",
    "REG-DIAG",
];

/// The scanners that offer files, folders, shortcuts, packages and system objects only.
const OTHER_SCANNERS: [&str; 11] = [
    "FS-INSTALLDIR",
    "FS-UNINSTALLER",
    "FS-APPDATA",
    "FS-VENDORPARENT",
    "FS-SHORTCUTS",
    "SYS-APPX",
    "SYS-SERVICE",
    "SYS-TASK",
    "SYS-FIREWALL",
    "FS-PKGCACHE",
    "FS-WER",
];

const TOOLS: &str = r"C:\Users\tester\tools";
const TOOL: &str = r"C:\Users\tester\my tool.exe";

/// The app's folder that the hostile data names (gone, like the whole install directory).
fn app_dir() -> String {
    format!(r"{FIREFOX}\browser")
}

/// One value's data.
#[derive(Debug, Clone)]
enum Data {
    Sz(String),
    Multi(Vec<String>),
    /// A string that is hostile as a path or a list, and as a command line starts a program of
    /// the app with arguments: not planted where values are command lines.
    NotACommand(String),
    /// Data of any type, as bytes (`REG_BINARY`, `REG_NONE`, a string with text after its NUL).
    Raw(u32, Vec<u8>),
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Data that holds somebody else's text next to the app's path: the union of the reviews' cases.
fn hostile() -> Vec<Data> {
    let app = app_dir();
    let sz = |text: String| Data::Sz(text);
    let command = format!(r#""{TOOL}" --with "{app}\x.exe""#);
    vec![
        sz(command.clone()),
        sz(format!(r#""{app}" "{TOOLS}""#)),
        sz(format!("{app},{TOOLS}")),
        sz(format!("{app} {TOOLS}")),
        sz(format!("{TOOLS},{app}")),
        sz(format!(r"C:\Users\tester\bin {app}")),
        sz(format!("{TOOLS};{app}")),
        sz(format!("foo;{app}")),
        sz(format!(r#"bin;"{app}" "{TOOLS}""#)),
        sz(format!(r#"C:\Users\tester\bin;"{app}" "{TOOLS}";relative"#)),
        sz(format!(r"C:\Users\tester\bin;{app};relative")),
        sz(format!(r"{app}\..\..\..\Users\tester\tools")),
        sz(format!(r"{app};{app}\..\..\..\Users\tester\tools")),
        sz(format!("{app};{app}\\x\ty")),
        sz(format!(r"{app} \Users\tester\tools")),
        Data::NotACommand(format!(r"{app}\x.exe user text")),
        sz("%MYDIRS%".to_owned()),
        // Characters no file name can hold, after the app's path.
        sz(format!(r"{app}\x.exe|user text")),
        sz(format!("{app}|user text")),
        sz(format!(r"{app}\x.exe?a=b")),
        sz(format!(r"{app}\x.exe*user")),
        sz(format!(r"{app}\x.exe<user>")),
        sz(format!(r"{FIREFOX}\firefox.exe|Users\tester\tool.exe")),
        // A string with a second string after its terminating NUL.
        Data::Raw(REG_SZ, utf16(&format!("{app}\0{TOOLS}\0"))),
        Data::Raw(REG_EXPAND_SZ, utf16(&format!("{app}\0{TOOLS}"))),
        // Data that is no string type and holds somebody else's text next to the app's path.
        Data::Raw(REG_BINARY, utf16(&format!("{command}\0"))),
        Data::Raw(REG_NONE, utf16(&format!("{command}\0"))),
        Data::Raw(REG_BINARY, utf16(&format!("{app}\0{TOOLS}\0"))),
        // An id of the app inside somebody else's text is not "exactly one of its ids".
        sz(format!(r"{TOOLS}\{HASH};{app}")),
        sz(format!("FirefoxHTML-{HASH} {TOOLS};{app}")),
        // Command lines that start something else.
        sz(format!(r"C:\Users\tester\tool.exe {app}")),
        sz(format!(
            r#"powershell -File C:\Users\tester\backup.ps1 -Fx "{app}\firefox.exe""#
        )),
        sz(format!(
            r#"cmd.exe /c start "" "C:\Users\tester\x.bat" & "{app}\firefox.exe""#
        )),
        sz(format!(r#"rundll32.exe "{TOOLS}\x.dll",Run {app}\y.dll"#)),
        Data::Multi(vec![app.clone(), command.clone()]),
        Data::Multi(vec![format!("{TOOLS};{app}")]),
        Data::Multi(vec![format!("{TOOLS},{app}"), "1".into()]),
        Data::Multi(vec![command, "1".into()]),
        Data::Multi(vec![format!(r"C:\Users\tester\bin {app}"), "1".into()]),
        Data::Multi(vec![
            r"C:\Users\tester\bin".into(),
            format!("{app} {TOOLS}"),
        ]),
        Data::Multi(vec![format!("{app},{TOOLS}")]),
        Data::Multi(vec![
            app.clone(),
            format!(r"{app}\..\..\..\Users\tester\tools"),
        ]),
    ]
}

/// One place a value can stand in.
struct Place {
    /// What kind of place it is, for the messages.
    what: &'static str,
    /// The key as the registry spells it, and as plans name it.
    key: String,
    plan_key: String,
    /// The value's name.
    name: &'static str,
    /// The value is the app's whatever it holds, by a documented route: its key is the app's own
    /// place, or its name is the app's. Planted and scanned like every place (these are the
    /// places the association scanners read), and exempt from the ban on Safe.
    own: bool,
    /// Values the place needs next to the planted one (`URL Protocol` of a scheme key).
    also: Vec<(String, &'static str, &'static str)>,
}

impl Place {
    /// Whether string values here are command lines (`ScanCtx::value_content_unproven`).
    fn commands(&self) -> bool {
        self.what.starts_with("Run") || self.key.ends_with(r"\command")
    }
}

fn place(what: &'static str, key: impl Into<String>, name: &'static str) -> Place {
    let key = key.into();
    Place {
        what,
        plan_key: key.clone(),
        key,
        name,
        own: false,
        also: Vec::new(),
    }
}

/// A place that is the app's by a documented route (see [`Place::own`]).
fn own_place(what: &'static str, key: impl Into<String>, name: impl Into<String>) -> Place {
    Place {
        own: true,
        ..place(what, key, Box::leak(name.into().into_boxed_str()))
    }
}

/// The app's ProgID, AUMID and extension in the table's fingerprint.
fn progid() -> String {
    format!("FirefoxHTML-{HASH}")
}

fn aumid() -> String {
    format!("FirefoxToast-{HASH}")
}

const EXT: &str = ".fxx";

/// Every kind of place that is not the app's own: another vendor's key, a sibling product's key
/// below the app's vendor key, and the shared places the scanners read.
fn places() -> Vec<Place> {
    let cv = format!(r"HKLM\SOFTWARE\{CV}");
    let user_cv = format!(r"{}\{CV}", hkcu());
    let mut all = vec![
        place(
            "foreign key",
            r"HKLM\SOFTWARE\Other Vendor\Tool",
            "SearchPath",
        ),
        place(
            "foreign key, user",
            format!(r"{}\Other\Recent", hkcu()),
            "Last",
        ),
        place(
            "sibling product",
            r"HKLM\SOFTWARE\Mozilla\Thunderbird\Paths",
            "Helper",
        ),
        place(
            "sibling product",
            r"HKLM\SOFTWARE\Mozilla\Firefox Developer Edition\Paths",
            "Helper",
        ),
        place(
            "sibling product",
            r"HKLM\SOFTWARE\Mozilla\SeaMonkey",
            "Helper",
        ),
        place(
            "sibling product, user",
            format!(r"{}\Mozilla\Thunderbird", hkcu()),
            "Helper",
        ),
        place("vendor key", r"HKLM\SOFTWARE\mozilla.org\Mozilla", "Helper"),
        place("Run", format!(r"{cv}\Run"), "Agent"),
        place(
            "Run, 32-bit",
            format!(r"HKLM\SOFTWARE\WOW6432Node\{CV}\Run"),
            "Agent",
        ),
        place("Run, user", format!(r"{user_cv}\Run"), "Agent"),
        place("RunOnce", format!(r"{cv}\RunOnce"), "Agent"),
        place(
            "App Paths, other program",
            format!(r"{cv}\App Paths\tool.exe"),
            "",
        ),
        place(
            "App Paths, other program",
            format!(r"{cv}\App Paths\tool.exe"),
            "Path",
        ),
        place(
            "shell verb",
            r"HKLM\SOFTWARE\Classes\Directory\shell\fx\command",
            "",
        ),
        place("extension", r"HKLM\SOFTWARE\Classes\.fxx", ""),
        place(
            "extension, OpenWithProgids",
            r"HKLM\SOFTWARE\Classes\.fxx\OpenWithProgids",
            "Tool.Document",
        ),
        place(
            "another program's class",
            r"HKLM\SOFTWARE\Classes\Tool.Document\shell\open\command",
            "",
        ),
        place(
            "another client",
            r"HKLM\SOFTWARE\Clients\Mail\Other Mail\shell\open\command",
            "",
        ),
        place(
            "RegisteredApplications",
            r"HKLM\SOFTWARE\RegisteredApplications",
            "Tool",
        ),
        place(
            "FileExts",
            format!(r"{user_cv}\Explorer\FileExts\.fxx\OpenWithList"),
            "a",
        ),
        place(
            "toasts",
            format!(r"{user_cv}\ApplicationAssociationToasts"),
            "Tool.Document_.fxx",
        ),
        place(
            "environment, user",
            format!(r"HKU\{SID}\Environment"),
            "FX_HOME",
        ),
        place(
            "environment, user Path",
            format!(r"HKU\{SID}\Environment"),
            "Path",
        ),
    ];
    all.push(Place {
        plan_key: MACHINE_ENV_PLAN.into(),
        ..place("environment, machine", MACHINE_ENV, "FX_HOME")
    });
    all.push(Place {
        plan_key: MACHINE_ENV_PLAN.into(),
        ..place("environment, machine Path", MACHINE_ENV, "Path")
    });
    // Value names that look like the app's and are not, or are the app's in a place where the
    // name decides nothing.
    let exe = format!(r"{FIREFOX}\firefox.exe");
    let leak = |text: String| -> &'static str { Box::leak(text.into_boxed_str()) };
    all.push(place(
        "foreign key, name with text after the app's program",
        r"HKLM\SOFTWARE\Other Vendor\Tool",
        leak(format!("{exe} user text")),
    ));
    all.push(place(
        "foreign key, name with a second path",
        r"HKLM\SOFTWARE\Other Vendor\Tool",
        leak(format!("{exe};{TOOLS}")),
    ));
    all.push(place(
        "foreign key, named like a program of the app",
        r"HKLM\SOFTWARE\Other Vendor\Tool",
        "firefox.exe",
    ));
    all.push(place(
        "foreign key, token inside a word of the name",
        r"HKLM\SOFTWARE\Other Vendor\Tool",
        leak(format!("cache{HASH}x")),
    ));
    all.push(place(
        "Run, token in the name",
        format!(r"{cv}\Run"),
        leak(format!("my {HASH} thing")),
    ));
    all.push(place(
        "Run, named by the app's program",
        format!(r"{cv}\Run"),
        leak(exe.clone()),
    ));
    all.push(place(
        "Run, user, token path in the name",
        format!(r"{user_cv}\Run"),
        leak(format!(r"{TOOLS}\{HASH}\notes.txt")),
    ));
    // A URL scheme of somebody's: a command place the protocol scanner reads.
    let mut scheme = place(
        "URL scheme",
        r"HKLM\SOFTWARE\Classes\fxproto\shell\open\command",
        "",
    );
    scheme.also = vec![(r"HKLM\SOFTWARE\Classes\fxproto".into(), "URL Protocol", "")];
    all.push(scheme);
    // The app's own registrations and the values named by its ids: what the association
    // scanners read.
    all.push(own_place(
        "own ProgID, verb",
        format!(r"HKLM\SOFTWARE\Classes\{}\shell\open\command", progid()),
        "",
    ));
    all.push(own_place(
        "own ProgID, icon",
        format!(r"HKLM\SOFTWARE\Classes\{}\DefaultIcon", progid()),
        "",
    ));
    all.push(own_place(
        "own AUMID",
        format!(r"HKLM\SOFTWARE\Classes\AppUserModelId\{}", aumid()),
        "IconUri",
    ));
    all.push(own_place(
        "extension, OpenWithProgids, own ProgID",
        format!(r"HKLM\SOFTWARE\Classes\{EXT}\OpenWithProgids"),
        progid(),
    ));
    all.push(own_place(
        "FileExts, OpenWithProgids, own ProgID",
        format!(r"{user_cv}\Explorer\FileExts\{EXT}\OpenWithProgids"),
        progid(),
    ));
    all.push(own_place(
        "toasts, own ProgID",
        format!(r"{user_cv}\ApplicationAssociationToasts"),
        format!("{}_{EXT}", progid()),
    ));
    all
}

/// What the fingerprint says about the planted value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Record {
    /// Nothing.
    None,
    /// The harvest saw the value refer to the app.
    Snapshot,
    /// The installer's log records the value, and the harvest saw it.
    Value,
    /// The installer's log deletes the key whole, and the harvest saw the value.
    WholeKey,
}

const RECORDS: [Record; 4] = [
    Record::None,
    Record::Snapshot,
    Record::Value,
    Record::WholeKey,
];

fn plant(place: &Place, data: &Data) -> FixtureBuilder {
    match data {
        Data::Sz(text) | Data::NotACommand(text) if place.name == "Path" || text.contains('%') => {
            machine().expand_sz(&place.key, place.name, text)
        }
        Data::Sz(text) | Data::NotACommand(text) => machine().sz(&place.key, place.name, text),
        Data::Multi(strings) => {
            let strings: Vec<&str> = strings.iter().map(String::as_str).collect();
            machine().multi_sz(&place.key, place.name, &strings)
        }
        Data::Raw(ty, bytes) => {
            machine().value(&place.key, place.name, RegData::new(*ty, bytes.clone()))
        }
    }
}

/// The table's fingerprint: Firefox with a ProgID, an AUMID and an extension of its own.
fn table_fp() -> purge_model::Fingerprint {
    let mut fp = firefox();
    fp.anchors.progids = vec![progid(), format!("FirefoxURL-{HASH}")];
    fp.anchors.aumids = vec![aumid()];
    fp.ext_journal = vec![purge_model::ExtJournalEntry {
        ext: EXT.into(),
        key: format!(r"HKLM\SOFTWARE\Classes\{EXT}"),
        openwith_ours: vec![progid()],
        openwith_others: Vec::new(),
        subkey_count: 1,
        default: None,
        previous_default: None,
        other_values: Vec::new(),
        other_subkeys: Vec::new(),
        ti_owned: false,
        vendor_backup: None,
        file_exts_key: Some(format!(r"{}\{CV}\Explorer\FileExts\{EXT}", hkcu())),
        toast_values: vec![format!("{}_{EXT}", progid())],
    }];
    fp
}

fn world(place: &Place, data: &Data, record: Record) -> World {
    let mut fp = table_fp();
    let target = value(place.plan_key.clone(), place.name);
    if record != Record::None {
        fp.ref_snapshot.push(snap(
            target.clone(),
            RefCarrier::Data,
            purge_model::AnchorKind::Root,
            FIREFOX,
        ));
    }
    match record {
        Record::Value => fp.inno.push(inno(InnoRecordKind::RegDeleteValue, target)),
        Record::WholeKey => fp.inno.push(inno(
            InnoRecordKind::RegDeleteEntireKey,
            key(place.plan_key.clone()),
        )),
        Record::None | Record::Snapshot => {}
    }
    let mut fixture = plant(place, data);
    for (key, name, text) in &place.also {
        fixture = fixture.sz(key, name, text);
    }
    let mut world = World::new(fixture, fp);
    world
        .env
        .insert("MYDIRS".into(), format!("{TOOLS};{}", app_dir()));
    world
}

/// Every candidate of every scanner of the catalog, decided by the policy.
fn decided(world: &World) -> Vec<(Candidate, Band, bool)> {
    let mut out = Vec::new();
    let app = purge_scan::framework::AppIdentityView::from_fingerprint(&world.fp, &world.env);
    for scanner in catalog::all_scanners() {
        // As the engine runs a scanner (`ScanCtx::run`). What `CandidateBuilder::build` let
        // through is what the driver lets through: a difference is a candidate that left the
        // scanner unjudged, or one the driver judged as somebody else's.
        let found = world.ctx().run(scanner.as_ref(), &app);
        assert_eq!(
            found,
            world.scan(scanner.as_ref()),
            "{}: the driver changed what the scanner finished",
            scanner.id()
        );
        for c in found {
            let user = matches!(&c.target,
                Target::RegKey { path } | Target::RegValue { path, .. }
                | Target::RegMultiSzSegment { path, .. } if path.starts_with("HKU"));
            let decision = decide(
                &c,
                &PolicyCtx {
                    mode: purge_model::ScanMode::Post,
                    verify_gone: purge_model::VerifyGone::new(true, true, true),
                    target_scope: if user {
                        TargetScope::PerUser
                    } else {
                        TargetScope::Machine
                    },
                },
            );
            out.push((c, decision.band, decision.preselected));
        }
    }
    out
}

/// Whether a candidate is the planted value, an entry of it, or a key that holds it.
fn touches(c: &Candidate, place: &Place) -> bool {
    let same = |path: &str| path.eq_ignore_ascii_case(&place.plan_key);
    match &c.target {
        Target::RegValue { path, name } | Target::RegMultiSzSegment { path, name, .. } => {
            same(path) && name.eq_ignore_ascii_case(place.name)
        }
        Target::RegKey { path } => purge_guard::prefix::is_same_or_inside(&place.plan_key, path),
        _ => false,
    }
}

/// A key the log deletes whole is the app's own place when it is an ordinary key: there the
/// table does not apply. A key that only holds other parties' values never is.
fn own_by_record(place: &Place, record: Record) -> bool {
    let container = place.what.starts_with("Run")
        || place.what.starts_with("toasts")
        || place.what.starts_with("environment")
        || place.what == "RegisteredApplications";
    record == Record::WholeKey && !container
}

#[test]
fn every_scanner_of_the_catalog_is_in_the_table() {
    let mut catalog: Vec<&str> = catalog::all_scanners().iter().map(|s| s.id()).collect();
    let mut table: Vec<&str> = REGISTRY_SCANNERS
        .into_iter()
        .chain(M1B_REGISTRY_SCANNERS)
        .chain(OTHER_SCANNERS)
        .collect();
    catalog.sort_unstable();
    table.sort_unstable();
    assert_eq!(
        catalog, table,
        "a scanner was added or removed: enter it in tests/reg/hostile.rs, and give the table the \
         places it reads"
    );
}

#[test]
fn no_scanner_offers_a_value_that_holds_foreign_text_as_safe() {
    let (mut rows, mut offered) = (0usize, 0usize);
    let mut offering: Vec<&'static str> = Vec::new();
    let mut failures = Vec::new();
    for place in places() {
        for data in hostile() {
            for record in RECORDS {
                if own_by_record(&place, record)
                    || (place.commands() && matches!(data, Data::NotACommand(_)))
                {
                    continue;
                }
                // A place that is the app's by a documented route is scanned for the scanners
                // that read it; what they offer there may be Safe.
                let exempt = place.own;
                rows += 1;
                for (c, band, ticked) in decided(&world(&place, &data, record)) {
                    if !touches(&c, &place) {
                        continue;
                    }
                    offered += 1;
                    if let Some(id) = REGISTRY_SCANNERS.iter().find(|id| **id == c.scanner) {
                        if !offering.contains(id) {
                            offering.push(id);
                        }
                    } else if !M1B_REGISTRY_SCANNERS.contains(&c.scanner.as_str()) {
                        failures.push(format!(
                            "{} offers a registry target but is not a registry scanner",
                            c.scanner
                        ));
                    }
                    // An entry that is exactly the app's folder may be taken out of a list
                    // that holds other things: the rest of the list stays.
                    let own_entry = matches!(&c.target, Target::RegMultiSzSegment { segment, .. }
                        if segment.trim_matches('"').trim_end_matches('\\')
                            .eq_ignore_ascii_case(&app_dir()));
                    if (band == Band::Safe || ticked) && !own_entry && !exempt {
                        failures.push(format!(
                            "{} | {} = {data:?} ({record:?}): {} {:?} {band:?} ticked={ticked}\n{}",
                            place.what,
                            place.name,
                            c.scanner,
                            c.action,
                            golden::render(std::slice::from_ref(&c))
                        ));
                    }
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {rows} rows:\n{}",
        failures.len(),
        failures.join("\n")
    );
    // The table is live: the hostile values are found and listed, by more than one scanner.
    assert!(offered > rows / 4, "{offered} candidates on {rows} rows");
    // Positive controls: every registry scanner offered something on a planted value somewhere
    // in the table. A scanner that never does is not tested by it.
    for id in REGISTRY_SCANNERS {
        assert!(offering.contains(&id), "{id} offered nothing: {offering:?}");
    }
}

/// The controls: in the same places, with the same records, data that is wholly the app's is
/// Safe. Without them the table above would pass for an engine that offers nothing.
#[test]
fn a_value_that_holds_only_the_apps_path_is_safe_in_the_same_places() {
    let app = app_dir();
    let exe = format!(r"{FIREFOX}\firefox.exe");
    let safe = |what: &str, name: &'static str, data: Data, record: Record| {
        let place = places()
            .into_iter()
            .find(|p| p.what == what && p.name == name)
            .unwrap_or_else(|| panic!("no place {what} | {name}"));
        let found = decided(&world(&place, &data, record));
        let on_value: Vec<_> = found
            .iter()
            .filter(|(c, ..)| touches(c, &place) && !matches!(c.target, Target::RegKey { .. }))
            .collect();
        assert!(
            on_value
                .iter()
                .any(|(_, band, ticked)| *band == Band::Safe && *ticked),
            "{what} | {name} = {data:?} ({record:?}):\n{}",
            golden::render(&on_value.iter().map(|(c, ..)| c.clone()).collect::<Vec<_>>())
        );
    };
    let sz = |text: &str| Data::Sz(text.to_owned());
    safe("foreign key", "SearchPath", sz(&app), Record::Value);
    safe(
        "foreign key",
        "SearchPath",
        sz(&format!(r#""{app}\""#)),
        Record::Value,
    );
    safe(
        "foreign key",
        "SearchPath",
        sz(&format!("{app};{FIREFOX}")),
        Record::Value,
    );
    safe(
        "foreign key",
        "SearchPath",
        sz(&format!("{exe},0")),
        Record::Value,
    );
    safe(
        "foreign key",
        "SearchPath",
        sz(&format!("@{exe},-101")),
        Record::Value,
    );
    safe(
        "foreign key",
        "SearchPath",
        Data::Multi(vec![app.clone(), exe.clone()]),
        Record::Value,
    );
    safe("sibling product", "Helper", sz(&exe), Record::Value);
    safe(
        "Run",
        "Agent",
        sz(&format!(r#""{exe}" --background"#)),
        Record::Value,
    );
    safe(
        "Run",
        "Agent",
        sz(&format!(r"{exe} --background")),
        Record::Value,
    );
    safe(
        "Run, user",
        "Agent",
        sz(&format!(
            r#""{exe}" -url "C:\Users\tester\start page.html""#
        )),
        Record::Value,
    );
    safe(
        "shell verb",
        "",
        sz(&format!(r#""{exe}" "%1""#)),
        Record::Value,
    );
    safe(
        "environment, machine",
        "FX_HOME",
        sz(FIREFOX),
        Record::Value,
    );
    safe(
        "environment, machine Path",
        "Path",
        sz(&format!(r"C:\Windows;{app}")),
        Record::Value,
    );
    // A foreign key the log deletes whole is the app's place, whatever the value holds.
    safe(
        "foreign key",
        "SearchPath",
        sz(&format!(r#""{exe}" --with "{TOOLS}""#)),
        Record::WholeKey,
    );
}

/// A scanner that returns candidates made elsewhere, as one that builds them by hand or adds
/// evidence after `CandidateBuilder::build` would.
struct Handmade(Vec<Candidate>);

impl purge_scan::framework::Scanner for Handmade {
    fn id(&self) -> &'static str {
        "HANDMADE"
    }
    fn captured_roots(&self) -> &[purge_scan::framework::RootSpec] {
        &[]
    }
    fn scan(
        &self,
        _: &purge_scan::framework::ScanCtx<'_>,
        _: &purge_scan::framework::AppIdentityView,
    ) -> Vec<Candidate> {
        self.0.clone()
    }
}

/// The second place the rule is applied: `ScanCtx::run`, through which the engine runs every
/// scanner. Tier A evidence that never passed `build` does not survive it.
#[test]
fn the_scan_driver_applies_the_rule_to_whatever_a_scanner_returns() {
    use purge_model::Tier;
    use purge_scan::framework::{AppIdentityView, Scanner};
    let place = places().remove(0);
    let tier_a = |c: &Candidate| c.evidence.iter().any(|e| e.weight > 0 && e.tier == Tier::A);
    // Tier A evidence on the value, gathered while it held the app's path alone.
    let clean = world(&place, &Data::Sz(app_dir()), Record::Value);
    let handmade: Vec<Candidate> = catalog::all_scanners()
        .iter()
        .flat_map(|scanner| clean.scan(scanner.as_ref()))
        .filter(|c| touches(c, &place) && tier_a(c))
        .collect();
    assert!(!handmade.is_empty(), "the control is not Tier A");
    let scanner = Handmade(handmade);
    let run = |world: &World| {
        let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
        world.ctx().run(&scanner, &app)
    };
    // The same value, now with somebody else's text in it.
    let dirty = world(
        &place,
        &Data::Sz(format!("{TOOLS};{}", app_dir())),
        Record::Value,
    );
    let app = AppIdentityView::from_fingerprint(&dirty.fp, &dirty.env);
    assert!(scanner.scan(&dirty.ctx(), &app).iter().all(tier_a));
    let sealed = run(&dirty);
    assert!(
        !sealed.is_empty() && !sealed.iter().any(tier_a),
        "{sealed:#?}"
    );
    assert!(sealed.iter().all(|c| {
        c.evidence
            .iter()
            .any(|e| e.detail.get("unproven").is_some())
    }));
    // Where the data is the app's alone, the driver changes nothing.
    assert_eq!(run(&clean), scanner.0);

    // Data that was not read in full: what was not read may be anybody's.
    let mut cut_short = purge_source::types::RegData::from_sz(&app_dir());
    cut_short.truncated = true;
    let unknown = purge_source::types::RegData::unknown(purge_source::types::REG_SZ, 80);
    // Binary data too large to be read for the text in it.
    let large = RegData::new(
        REG_BINARY,
        vec![0u8; purge_source::types::BINARY_UTF16_SCAN_MAX + 2],
    );
    for data in [cut_short, unknown, large] {
        let mut partial = world(&place, &Data::Sz(app_dir()), Record::Value);
        partial
            .fixture
            .set_value(&place.key, place.name, data.clone());
        let sealed = run(&partial);
        assert!(!sealed.is_empty() && !sealed.iter().any(tier_a), "{data:?}");
    }
    // Binary data whose text is no path (a word, a counter) says nothing about anybody: it
    // is not judged.
    let mut worded = world(&place, &Data::Sz(app_dir()), Record::Value);
    worded.fixture.set_value(
        &place.key,
        place.name,
        RegData::new(REG_BINARY, utf16("enabled since yesterday\0")),
    );
    assert_eq!(run(&worded), scanner.0);
    // A value that cannot be read (the capture holds no values): nothing shows what is in it.
    let mut unread = world(&place, &Data::Sz(app_dir()), Record::Value);
    assert!(unread.fixture.remove_value(&place.key, place.name));
    unread.fixture.set_values_captured(false);
    let sealed = run(&unread);
    assert!(!sealed.is_empty() && !sealed.iter().any(tier_a));
    // A value that is gone is a record of the harvest: there is nothing in it to judge.
    let mut gone = world(&place, &Data::Sz(app_dir()), Record::Value);
    assert!(gone.fixture.remove_value(&place.key, place.name));
    assert_eq!(run(&gone), scanner.0);

    // An entry of a list, made by hand: the entry's own text is judged.
    let entry = |text: String| {
        let mut c = scanner.0[0].clone();
        c.target = segment(place.plan_key.clone(), place.name, &text);
        Handmade(vec![c])
    };
    let app = AppIdentityView::from_fingerprint(&clean.fp, &clean.env);
    let own = entry(app_dir());
    assert_eq!(clean.ctx().run(&own, &app), own.0);
    for text in [
        format!("{},{TOOLS}", app_dir()),
        TOOLS.to_owned(),
        format!(r"{}\..\..\Users", app_dir()),
    ] {
        let sealed = clean.ctx().run(&entry(text.clone()), &app);
        assert!(!sealed.iter().any(tier_a), "{text}");
    }
}

/// REF-ANY offers a record (a `REG_MULTI_SZ` value that is no list) whole on the evidence of its
/// entries. An entry that is the app's program, recorded by the harvest and by the installer, is
/// Tier A evidence about the entry; the value holds the other entries too.
#[test]
fn a_record_with_somebody_elses_entries_is_not_safe_on_the_evidence_of_one_entry() {
    use purge_model::{AnchorKind, Tier};
    let place = places().remove(0);
    let exe = format!(r"{FIREFOX}\firefox.exe");
    let with = |others: &[&str]| {
        let mut strings = vec![exe.clone()];
        strings.extend(others.iter().map(|s| (*s).to_owned()));
        let mut world = world(&place, &Data::Multi(strings), Record::Value);
        world.fp.ref_snapshot.push(snap(
            segment(place.plan_key.clone(), place.name, &exe),
            RefCarrier::Segment,
            AnchorKind::Root,
            FIREFOX,
        ));
        decided(&world)
            .into_iter()
            .filter(|(c, ..)| matches!(c.target, Target::RegValue { .. }) && touches(c, &place))
            .collect::<Vec<_>>()
    };
    let hostile = with(&["--open", r"C:\Users\tester\notes.txt"]);
    assert!(!hostile.is_empty());
    for (c, band, ticked) in &hostile {
        assert!(
            *band != Band::Safe && !ticked && c.evidence.iter().all(|e| e.tier != Tier::A),
            "{}",
            golden::render(std::slice::from_ref(c))
        );
    }
}

/// The switch of a start entry the uninstaller removed is the app's only when the command the
/// harvest recorded started a program of the app's.
#[test]
fn the_switch_of_a_recorded_start_entry_follows_what_the_command_started() {
    use purge_model::Tier;
    let run = format!(r"HKLM\SOFTWARE\{CV}\Run");
    let approved = format!(r"HKLM\SOFTWARE\{CV}\Explorer\StartupApproved\Run");
    let switch = |command: String| {
        let mut fp = firefox();
        fp.anchors.run_entries = vec![purge_model::RunEntry {
            key: run.clone(),
            name: "Agent".into(),
            data: command,
        }];
        fp.inno.push(inno(
            InnoRecordKind::RegDeleteValue,
            value(run.clone(), "Agent"),
        ));
        let world = World::new(
            machine().binary(&approved, "Agent", vec![2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            fp,
        );
        let found = world.scan(&purge_scan::reg_run::RegRun);
        let c = found
            .iter()
            .find(|c| c.target == value(approved.clone(), "Agent"))
            .unwrap_or_else(|| panic!("no switch:\n{}", golden::render(&found)))
            .clone();
        c.evidence.iter().any(|e| e.weight > 0 && e.tier == Tier::A)
    };
    assert!(switch(format!(r#""{FIREFOX}\firefox.exe" --background"#)));
    assert!(!switch(format!(
        r#""{TOOL}" --with "{FIREFOX}\firefox.exe""#
    )));
    assert!(!switch(format!(
        r#"cmd.exe /c start "" "{FIREFOX}\firefox.exe""#
    )));
}

/// A directory the app only refers to (the user's project folder) is an anchor of the app and
/// not the app's: a value that holds exactly it, alone or next to the app's folder, is not the
/// app's alone, whatever the installer recorded.
#[test]
fn a_referenced_data_directory_is_not_a_path_of_the_app() {
    use purge_model::{AnchorKind, Root, RootKind, RootSource, SourceTrust};
    const PROJECTS: &str = r"C:\Users\tester\Projects";
    for place in places().into_iter().filter(|place| !place.own) {
        for data in [
            PROJECTS.to_owned(),
            format!("{PROJECTS};{}", app_dir()),
            format!(r"{PROJECTS}\site"),
        ] {
            for record in RECORDS {
                if own_by_record(&place, record) {
                    continue;
                }
                let mut world = world(&place, &Data::Sz(data.clone()), record);
                world.fp.roots.push(Root {
                    path: PROJECTS.into(),
                    kind: RootKind::ReferencedDataDir,
                    source: RootSource::Referenced,
                    trust: SourceTrust::AdminOnly,
                    volume_serial: None,
                    parent_existed: true,
                });
                if record != Record::None {
                    world.fp.ref_snapshot.push(snap(
                        value(place.plan_key.clone(), place.name),
                        RefCarrier::Data,
                        AnchorKind::Root,
                        PROJECTS,
                    ));
                }
                for (c, band, ticked) in decided(&world) {
                    let own_entry = matches!(&c.target, Target::RegMultiSzSegment { segment, .. }
                        if segment.eq_ignore_ascii_case(&app_dir()));
                    assert!(
                        !touches(&c, &place) || own_entry || (band != Band::Safe && !ticked),
                        "{} | {} = {data:?} ({record:?}): {band:?}\n{}",
                        place.what,
                        place.name,
                        golden::render(std::slice::from_ref(&c))
                    );
                }
            }
        }
    }
}

/// A product that went with the app (Firefox's Maintenance Service) is scanned with its own
/// fingerprint, and the driver judges its candidates with that fingerprint too: the product's
/// path is "a path of the app" for the product. Every scanner gives the same through the
/// driver as on its own, and the product's recorded value keeps its Tier A.
#[test]
fn a_co_removed_products_value_is_judged_as_the_products() {
    use purge_model::{AnchorKind, Tier};
    use purge_scan::framework::AppIdentityView;
    let key = r"HKLM\SOFTWARE\Other Vendor\Tool";
    let service = format!(r"{MAINTENANCE}\maintenanceservice.exe");
    let target = value(key, "Updater");
    let world_with = |data: &str| {
        let mut fp = firefox();
        let product = fp.co_removed[0]
            .fingerprint
            .as_mut()
            .expect("the service has a fingerprint");
        product
            .inno
            .push(inno(InnoRecordKind::RegDeleteValue, target.clone()));
        product.ref_snapshot.push(snap(
            target.clone(),
            RefCarrier::Data,
            AnchorKind::Root,
            MAINTENANCE,
        ));
        World::new(machine().sz(key, "Updater", data), fp)
    };
    let tier_a = |c: &Candidate| c.evidence.iter().any(|e| e.weight > 0 && e.tier == Tier::A);
    let on_value = |world: &World| {
        let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
        let mut found = Vec::new();
        for scanner in catalog::all_scanners() {
            let driven = world.ctx().run(scanner.as_ref(), &app);
            assert_eq!(driven, world.scan(scanner.as_ref()), "{}", scanner.id());
            found.extend(driven.into_iter().filter(|c| c.target == target));
        }
        found
    };
    let own = on_value(&world_with(&service));
    assert!(own.iter().any(tier_a), "{}", golden::render(&own));
    assert!(
        own.iter()
            .all(|c| c.owner.display_name == "Mozilla Maintenance Service")
    );
    // The rule holds for the product as for the app: somebody else's text next to its path.
    let hostile = on_value(&world_with(&format!(r#""{TOOL}" --with "{service}""#)));
    assert!(!hostile.is_empty() && !hostile.iter().any(tier_a));
    // And the app's own path is not the product's.
    let apps = on_value(&world_with(&format!(r"{FIREFOX}\firefox.exe")));
    assert!(
        apps.iter()
            .all(|c| c.owner.display_name != "Mozilla Maintenance Service" || !tier_a(c))
    );
}

// ---------------------------------------------------------------------------------------------------------
// The eleventh review's cases
// ---------------------------------------------------------------------------------------------------------

/// Whatever the fingerprint records about the planted value, nothing on it is Safe or ticked. As
/// in the table, a key the log deletes whole is the app's own place unless it is a `container`
/// (a key that holds other parties' values, like the start places).
fn assert_never_safe(what: &str, place: &Place, data: &Data, container: bool) {
    for record in RECORDS {
        if record == Record::WholeKey && !container {
            continue;
        }
        for (c, band, ticked) in decided(&world(place, data, record)) {
            if touches(&c, place) {
                assert!(
                    band != Band::Safe && !ticked,
                    "{what}, {record:?}: {} {band:?} ticked={ticked}\n{c:?}",
                    c.scanner
                );
            }
        }
    }
}

fn foreign_key_place() -> Place {
    places()
        .into_iter()
        .find(|p| p.what == "foreign key, named like a program of the app")
        .unwrap()
}

/// A number is four or eight bytes. Text stored under a number's type is text: the type tag of a
/// value is whatever its writer said.
#[test]
fn text_under_a_number_type_is_read_as_text() {
    let command = format!(r#""{TOOL}" --with "{}\x.exe""#, app_dir());
    let place = foreign_key_place();
    // REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_QWORD, and REG_LINK for good measure.
    for ty in [4u32, 5, 11, 6, REG_BINARY] {
        let data = Data::Raw(ty, utf16(&format!("{command}\0")));
        assert_never_safe(&format!("type {ty}"), &place, &data, false);
    }
}

/// Binary data is read for paths that do not start at a drive, and for text of one byte per
/// character.
#[test]
fn binary_text_that_is_a_path_of_any_shape_is_judged() {
    let app = app_dir();
    let place = foreign_key_place();
    let ansi = {
        let mut bytes = format!("{TOOL};{app}\\x.exe").into_bytes();
        bytes.push(0);
        if bytes.len() % 2 == 1 {
            bytes.push(0);
        }
        bytes
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "below a variable",
            utf16(&format!("%USERPROFILE%\\my tool.exe\0{app}\\x.exe\0")),
        ),
        (
            "from the root of the drive",
            utf16(&format!("\\Users\\tester\\my tool.exe\0{app}\\x.exe\0")),
        ),
        ("at a drive", utf16(&format!("{TOOL}\0{app}\\x.exe\0"))),
        (
            "relative",
            utf16(&format!("tools\\my tool.exe\0{app}\\x.exe\0")),
        ),
        (
            "something before the root",
            utf16(&format!("2\\Users\\tester\\my tool.exe\0{app}\\x.exe\0")),
        ),
        (
            "forward slashes",
            utf16(&format!("/Users/tester/my tool.exe\0{app}\\x.exe\0")),
        ),
        (
            "a variable alone",
            utf16(&format!("%MYTOOL%\0{app}\\x.exe\0")),
        ),
        ("one byte per character", ansi),
    ];
    for (what, bytes) in cases {
        assert_never_safe(what, &place, &Data::Raw(REG_BINARY, bytes), false);
    }
}

/// A value that cannot be read is excused by a name of the app's, except where values start
/// programs: there the name decides nothing, read or unread.
#[test]
fn an_unreadable_value_in_a_command_place_is_not_excused_by_its_name() {
    use purge_model::Tier;
    use purge_scan::framework::AppIdentityView;
    let tier_a = |c: &Candidate| c.evidence.iter().any(|e| e.weight > 0 && e.tier == Tier::A);
    let first = places().remove(0);
    let clean = world(&first, &Data::Sz(app_dir()), Record::Value);
    let template = catalog::all_scanners()
        .iter()
        .flat_map(|scanner| clean.scan(scanner.as_ref()))
        .find(|c| touches(c, &first) && tier_a(c))
        .expect("the control is not Tier A");
    for (key, excused) in [
        (r"HKLM\SOFTWARE\Other Vendor\Tool".to_owned(), true),
        (format!(r"HKLM\SOFTWARE\{CV}\Policies\Explorer\Run"), false),
        (format!(r"HKLM\SOFTWARE\{CV}\RunOnceEx\0001"), false),
        (
            r"HKLM\SOFTWARE\Classes\Other.Tool\shell\open\command".to_owned(),
            false,
        ),
    ] {
        let place = place("unreadable", key.clone(), HASH);
        let mut unread = world(&place, &Data::Sz(app_dir()), Record::None);
        assert!(unread.fixture.remove_value(&place.key, place.name));
        unread.fixture.set_values_captured(false);
        let mut candidate = template.clone();
        candidate.target = Target::RegValue {
            path: place.plan_key.clone(),
            name: HASH.to_owned(),
        };
        let scanner = Handmade(vec![candidate]);
        let app = AppIdentityView::from_fingerprint(&unread.fp, &unread.env);
        let sealed = unread.ctx().run(&scanner, &app);
        assert!(!sealed.is_empty(), "{key}");
        assert_eq!(sealed.iter().any(tier_a), excused, "{key}: {sealed:#?}");
    }
}

/// An id of the app somewhere in a value name does not make the value the app's: the name must be
/// the id, with at most something attached. And every place that starts programs at logon is a
/// command place, where the name decides nothing.
#[test]
fn an_id_inside_a_name_does_not_excuse_the_data() {
    let command = format!(r#""{TOOL}" --with "{}\x.exe""#, app_dir());
    let leak = |text: String| -> &'static str { Box::leak(text.into_boxed_str()) };
    let foreign = r"HKLM\SOFTWARE\Other Vendor\Tool";
    let rows: Vec<(String, &'static str)> = vec![
        (foreign.to_owned(), leak(format!("my {HASH} thing"))),
        (
            foreign.to_owned(),
            leak(format!(r"{TOOLS}\{HASH}\notes.txt")),
        ),
        (foreign.to_owned(), leak(format!("{HASH};{TOOL}"))),
        (
            format!(r"HKLM\SOFTWARE\{CV}\Policies\Explorer\Run"),
            leak(format!("my {HASH} thing")),
        ),
        // In a start place not even the id itself as the name excuses the command.
        (format!(r"HKLM\SOFTWARE\{CV}\Policies\Explorer\Run"), HASH),
        (format!(r"HKLM\SOFTWARE\{CV}\RunOnceEx\0001"), HASH),
        (format!(r"HKLM\SOFTWARE\{CV}\RunServices"), HASH),
    ];
    for (key, name) in rows {
        let container = key != foreign;
        let place = place("an id inside the name", key.clone(), name);
        let what = format!("{key} | {name}");
        assert_never_safe(&what, &place, &Data::Sz(command.clone()), container);
    }
}
