//! Fixture tests of the second half of the harvest: the reference snapshot, the subtree baselines, the
//! association journal and the co-product candidates.
//!
//! The fixtures are shaped after the apps the rig measured (VS Code, Git, Firefox) and are built in
//! code, so each test shows the registry it reads. One ignored test replays a real rig snapshot when
//! `PURGE_RUNS_DIR` points at the run directories.

use purge_harvest::refsnap::HarvestCtx;
use purge_harvest::{assoc, coproducts, refsnap, subtree};
use purge_index::baseline::Baseline;
use purge_index::matcher::AnchorSet;
use purge_index::queries::SubtreeLimits;
use purge_model::{
    AnchorKind, InnoRecord, InnoRecordKind, InstallScope, InstallerKind, InventoryEntry, ProgramId,
    RawFlags, RefCarrier, RefSnapEntry, Root, RootKind, RootSource, SourceTrust, SubtreeBaseline,
    Target, View, WritableBy,
};
use purge_source::fixture::{Fixture, FixtureBuilder};
use purge_source::types::KnownFolder;

const SID: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";
const EDITION: &str = "EnterpriseS";
const BUILD: u32 = 26100;
const UBR: u32 = 1742;
const CLASSES: &str = r"HKLM\SOFTWARE\Classes";
const CV: &str = r"Microsoft\Windows\CurrentVersion";

// ---------------------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------------------

/// Everything a [`HarvestCtx`] borrows, owned in one place.
struct World {
    fixture: Fixture,
    anchors: AnchorSet,
    roots: Vec<Root>,
    inno: Vec<InnoRecord>,
    baseline: Option<Baseline>,
    inventory: Vec<InventoryEntry>,
}

impl World {
    /// The context for the first inventory entry.
    fn ctx(&self) -> HarvestCtx<'_> {
        HarvestCtx {
            reg: &self.fixture,
            fs: &self.fixture,
            sys: &self.fixture,
            anchors: &self.anchors,
            roots: &self.roots,
            inno: &self.inno,
            baseline: self.baseline.as_ref(),
            inventory: &self.inventory,
            target: &self.inventory[0],
            cutoff: None,
        }
    }

    fn subtrees(&self) -> Vec<SubtreeBaseline> {
        let ctx = self.ctx();
        let snapshot = refsnap::capture(&ctx);
        subtree::capture(&ctx, &subtree::keys(&ctx, &snapshot))
    }
}

fn builder() -> FixtureBuilder {
    Fixture::builder()
        .os(EDITION, BUILD, UBR)
        .user_sid(SID)
        .known_folder(KnownFolder::ProgramFiles, r"C:\Program Files")
        .known_folder(KnownFolder::ProgramFilesX86, r"C:\Program Files (x86)")
        .key(r"HKLM\SOFTWARE")
        .key(CLASSES)
}

/// A baseline of the test Windows holding `keys`.
fn baseline(keys: &[&str]) -> Baseline {
    let mut text = format!("#purge-baseline 1\tT\tPC\t{EDITION}\t{BUILD}.{UBR}\n");
    for key in keys {
        text.push_str(&format!("K\t{}\t0\t0\t0\n", key.replace('\\', "\\\\")));
    }
    Baseline::from_bytes(text.as_bytes()).expect("the baseline parses")
}

fn install_root(path: &str) -> Root {
    Root {
        path: path.into(),
        kind: RootKind::InstallRoot,
        source: RootSource::ArpInstallLocation,
        trust: SourceTrust::AdminOnly,
        volume_serial: None,
        parent_existed: true,
    }
}

fn entry(
    key_name: &str,
    display: &str,
    publisher: &str,
    dir: &str,
    uninstaller: &str,
) -> InventoryEntry {
    let program_id = ProgramId::machine(View::K64, key_name).unwrap();
    InventoryEntry {
        key_path: program_id.key_path(),
        program_id,
        hive_sid: None,
        view: View::K64,
        display_name: display.into(),
        version: None,
        publisher: Some(publisher.into()),
        flags: RawFlags::default(),
        installer_kind: InstallerKind::Unknown,
        scope: InstallScope::Machine,
        product_code: None,
        upgrade_code: None,
        inno_app_id: None,
        writable_by: WritableBy::Admin,
        install_location: (!dir.is_empty()).then(|| dir.to_owned()),
        uninstall_string: Some(format!("\"{uninstaller}\"")),
        quiet_uninstall_string: None,
        display_icon: None,
        install_time_evidence: Vec::new(),
        msi: None,
    }
}

fn inno_key(kind: InnoRecordKind, path: &str) -> InnoRecord {
    InnoRecord {
        kind,
        target: Target::RegKey { path: path.into() },
        view: Some(View::K64),
        user_hive: false,
        existed_before: false,
        shared: false,
        key_create: true,
    }
}

fn find<'a>(subtrees: &'a [SubtreeBaseline], key: &str) -> Option<&'a SubtreeBaseline> {
    subtrees.iter().find(|s| s.key.eq_ignore_ascii_case(key))
}

fn attributed(subtrees: &[SubtreeBaseline], key: &str) -> bool {
    find(subtrees, key)
        .unwrap_or_else(|| panic!("no subtree for {key}"))
        .fully_attributed
}

fn value_entry<'a>(
    snapshot: &'a [RefSnapEntry],
    key: &str,
    name: &str,
) -> Option<&'a RefSnapEntry> {
    snapshot.iter().find(|e| {
        matches!(&e.target, Target::RegValue { path, name: n }
            if path.eq_ignore_ascii_case(key) && n.eq_ignore_ascii_case(name))
    })
}

fn is_sorted_ci<'a>(keys: impl Iterator<Item = &'a str>) -> bool {
    let folded: Vec<String> = keys.map(str::to_lowercase).collect();
    folded.windows(2).all(|pair| pair[0] < pair[1])
}

// ---------------------------------------------------------------------------------------------------------
// VS Code
// ---------------------------------------------------------------------------------------------------------

const CODE: &str = r"C:\Program Files\Microsoft VS Code";
const CODE_EXTS: [&str; 3] = ["aaa", "txt", "ccc"];

fn file_exts(ext: &str) -> String {
    format!(r"HKU\{SID}\Software\{CV}\Explorer\FileExts\{ext}")
}

fn user_toasts() -> String {
    format!(r"HKU\{SID}\Software\{CV}\ApplicationAssociationToasts")
}

/// A machine-wide VS Code with three extensions:
/// `.aaa` is new to the machine and holds only our `OpenWithProgids` value;
/// `.txt` is part of clean Windows;
/// `.ccc` is not, but another app registered with it too.
fn vscode_registry(reversed: bool) -> Fixture {
    let command = format!("\"{CODE}\\Code.exe\" \"%1\"");
    let mut steps: Vec<Box<dyn FnOnce(FixtureBuilder) -> FixtureBuilder>> = Vec::new();
    for ext in CODE_EXTS {
        let command = command.clone();
        steps.push(Box::new(move |b: FixtureBuilder| {
            let progid = format!(r"{CLASSES}\VSCode.{ext}");
            b.sz(&progid, "", &format!("{ext} source file"))
                .sz(&progid, "AppUserModelID", "Microsoft.VisualStudioCode")
                .sz(
                    &format!(r"{progid}\DefaultIcon"),
                    "",
                    &format!(r"{CODE}\resources\app\resources\win32\default.ico"),
                )
                .sz(&format!(r"{progid}\shell\open\command"), "", &command)
                .sz(
                    &format!(r"{CLASSES}\.{ext}\OpenWithProgids"),
                    &format!("VSCode.{ext}"),
                    "",
                )
        }));
    }
    steps.push(Box::new(|b: FixtureBuilder| {
        b.sz(&format!(r"{CLASSES}\.txt"), "", "txtfile")
            .sz(&format!(r"{CLASSES}\.txt"), "Content Type", "text/plain")
            .sz(&format!(r"{CLASSES}\.txt"), "PerceivedType", "text")
            .sz(&format!(r"{CLASSES}\.txt\OpenWithProgids"), "txtfile", "")
            .sz(
                &format!(r"{CLASSES}\.txt\PersistentHandler"),
                "",
                "{5E941D80-BF96-11CD-B579-08002B30BFEB}",
            )
            .sz(&format!(r"{CLASSES}\txtfile"), "", "Text Document")
    }));
    steps.push(Box::new(|b: FixtureBuilder| {
        b.sz(
            &format!(r"{CLASSES}\.ccc\OpenWithProgids"),
            "OtherApp.ccc",
            "",
        )
    }));
    steps.push(Box::new(|b: FixtureBuilder| {
        b.sz(
            &format!(r"{}\OpenWithProgids", file_exts(".aaa")),
            "VSCode.aaa",
            "",
        )
        .sz(
            &format!(r"{}\OpenWithList", file_exts(".aaa")),
            "a",
            "Code.exe",
        )
        .sz(
            &format!(r"{}\OpenWithList", file_exts(".aaa")),
            "b",
            "notepad.exe",
        )
        .sz(
            &format!(r"{}\OpenWithList", file_exts(".aaa")),
            "MRUList",
            "ab",
        )
        .sz(
            &format!(r"{}\OpenWithList", file_exts(".zzz")),
            "a",
            "notepad.exe",
        )
        .dword(&user_toasts(), "VSCode.txt_.txt", 0)
        .dword(&user_toasts(), "VSCode.ddd_.ddd", 0)
        .dword(&user_toasts(), "txtfile_.txt", 0)
    }));
    steps.push(Box::new(|b: FixtureBuilder| {
        b.sz(
            &format!(r"HKLM\SOFTWARE\{CV}\Run"),
            "CodeHelper",
            &format!("\"{CODE}\\Code.exe\" --tray"),
        )
        .expand_sz(
            &format!(r"HKU\{SID}\Environment"),
            "Path",
            &format!(r"C:\Tools;{CODE}\bin;%USERPROFILE%\bin"),
        )
        .multi_sz(
            r"HKLM\SOFTWARE\Vendor\Lists",
            "Editors",
            &["notepad.exe", &format!(r"{CODE}\Code.exe"), "other"],
        )
    }));
    if reversed {
        steps.reverse();
    }
    steps
        .into_iter()
        .fold(builder(), |b, step| step(b))
        .file(&format!(r"{CODE}\Code.exe"), 1000)
        .build()
}

fn vscode_world(reversed: bool, with_baseline: bool) -> World {
    let mut anchors = AnchorSet::new();
    anchors.add_root(CODE);
    anchors.add_exe_path(&format!(r"{CODE}\Code.exe"));
    anchors.add_exe_name("Code.exe");
    for ext in CODE_EXTS {
        anchors.add_progid(&format!("VSCode.{ext}"));
    }
    // `VSCode.ddd` is in P although the app registered no `.ddd` key: only a toast names it.
    anchors.add_progid("VSCode.ddd");
    let txt = format!(r"{CLASSES}\.txt");
    let txt_progids = format!(r"{CLASSES}\.txt\OpenWithProgids");
    let txt_handler = format!(r"{CLASSES}\.txt\PersistentHandler");
    let txtfile = format!(r"{CLASSES}\txtfile");
    let run = format!(r"HKLM\SOFTWARE\{CV}\Run");
    let user_software = format!(r"HKU\{SID}\Software");
    let user_cv = format!(r"HKU\{SID}\Software\{CV}");
    let user_explorer = format!(r"{user_cv}\Explorer");
    let user_file_exts = format!(r"{user_explorer}\FileExts");
    let known = [
        r"HKLM\SOFTWARE",
        CLASSES,
        txt.as_str(),
        txt_progids.as_str(),
        txt_handler.as_str(),
        txtfile.as_str(),
        run.as_str(),
        user_software.as_str(),
        user_cv.as_str(),
        user_explorer.as_str(),
        user_file_exts.as_str(),
    ];
    World {
        fixture: vscode_registry(reversed),
        anchors,
        roots: vec![install_root(CODE)],
        inno: Vec::new(),
        baseline: with_baseline.then(|| baseline(&known)),
        inventory: vec![entry(
            "{EA457B21-F73E-494C-ACAB-524FDE069978}_is1",
            "Microsoft Visual Studio Code",
            "Microsoft Corporation",
            CODE,
            &format!(r"{CODE}\unins000.exe"),
        )],
    }
}

#[test]
fn vscode_reference_snapshot() {
    let world = vscode_world(false, true);
    let report = refsnap::capture_report(&world.ctx());
    assert!(report.complete, "{:?}", report.warnings);
    let snapshot = &report.entries;

    // An empty-data OpenWithProgids value named in P.
    let own = value_entry(
        snapshot,
        &format!(r"{CLASSES}\.aaa\OpenWithProgids"),
        "VSCode.aaa",
    )
    .expect("the OpenWithProgids value is in the snapshot");
    assert_eq!(own.carrier, RefCarrier::ValueName);
    assert_eq!(own.anchor.kind, AnchorKind::ProgId);
    assert_eq!(own.anchor.text, "VSCode.aaa");
    assert_eq!((own.parent_values, own.parent_subkeys), (1, 0));

    // A command line naming the exe, with the hash of its data.
    let command = value_entry(
        snapshot,
        &format!(r"{CLASSES}\VSCode.txt\shell\open\command"),
        "",
    )
    .expect("the command is in the snapshot");
    assert_eq!(command.carrier, RefCarrier::Data);
    assert_eq!(command.anchor.kind, AnchorKind::Exe);
    assert_eq!(command.data_hash.as_deref().map(str::len), Some(16));

    // Values of other apps are not in it.
    assert!(
        value_entry(
            snapshot,
            &format!(r"{CLASSES}\.ccc\OpenWithProgids"),
            "OtherApp.ccc"
        )
        .is_none()
    );
    assert!(
        value_entry(
            snapshot,
            &format!(r"{CLASSES}\.txt\OpenWithProgids"),
            "txtfile"
        )
        .is_none()
    );

    // A bare exe name proves nothing about the directory: possible reference only.
    let list = format!(r"{}\OpenWithList", file_exts(".aaa"));
    assert!(value_entry(snapshot, &list, "a").is_none());
    assert!(report.weak_hits >= 1);

    // The `;`-separated Path is recorded per segment, never as a whole value.
    let env = format!(r"HKU\{SID}\Environment");
    assert!(value_entry(snapshot, &env, "Path").is_none());
    let segment = snapshot
        .iter()
        .find(|e| matches!(&e.target, Target::RegMultiSzSegment { path, .. } if *path == env))
        .expect("the Path segment is in the snapshot");
    assert_eq!(
        segment.target,
        Target::RegMultiSzSegment {
            path: env,
            name: "Path".into(),
            segment: format!(r"{CODE}\bin"),
            index: Some(1),
        }
    );
    assert_eq!(segment.carrier, RefCarrier::Segment);
    assert_eq!(segment.anchor.kind, AnchorKind::Root);

    // A REG_MULTI_SZ string is recorded with its text and index.
    let multi = snapshot
        .iter()
        .find(|e| matches!(&e.target, Target::RegMultiSzSegment { name, .. } if name == "Editors"))
        .expect("the multi-string segment is in the snapshot");
    assert_eq!(
        multi.target,
        Target::RegMultiSzSegment {
            path: r"HKLM\SOFTWARE\Vendor\Lists".into(),
            name: "Editors".into(),
            segment: format!(r"{CODE}\Code.exe"),
            index: Some(1),
        }
    );
}

#[test]
fn vscode_journal_marks_the_three_extensions_distinctly() {
    let world = vscode_world(false, true);
    let journal = assoc::capture_detailed(&world.ctx());
    assert!(journal.warnings.is_empty(), "{:?}", journal.warnings);
    let keys: Vec<&str> = journal
        .records
        .iter()
        .map(|r| r.entry.key.as_str())
        .collect();
    assert_eq!(
        keys,
        [
            format!(r"{CLASSES}\.aaa"),
            format!(r"{CLASSES}\.ccc"),
            format!(r"{CLASSES}\.ddd"),
            format!(r"{CLASSES}\.txt"),
        ]
    );
    let [new, shared, toast_only, windows] = &journal.records[..] else {
        unreachable!()
    };

    // New to the machine, only our value.
    assert!(new.only_ours());
    assert_eq!(new.entry.openwith_ours, ["VSCode.aaa"]);
    assert_eq!(new.entry.subkey_count, 1);
    assert_eq!(new.entry.default, None);
    assert!(new.entry.other_values.is_empty() && new.entry.other_subkeys.is_empty());
    assert_eq!(new.ext_in_baseline, Some(false));
    assert_eq!(new.openwith_in_baseline, Some(false));
    assert!(!new.entry.ti_owned);
    // The user's FileExts entry: our ProgID and our exe, not notepad.
    assert_eq!(
        new.entry.file_exts_key.as_deref(),
        Some(file_exts(".aaa").as_str())
    );
    let user = new.file_exts.as_ref().unwrap();
    assert_eq!(user.openwith_progids, ["VSCode.aaa"]);
    assert_eq!(
        user.openwith_list,
        [("a".to_owned(), "Code.exe".to_owned())]
    );
    assert_eq!(user.mru_list.as_deref(), Some("ab"));

    // Not part of Windows, but another app is registered too.
    assert!(!shared.only_ours());
    assert_eq!(shared.entry.openwith_ours, ["VSCode.ccc"]);
    assert_eq!(shared.entry.openwith_others, ["OtherApp.ccc"]);
    assert_eq!(shared.ext_in_baseline, Some(false));
    assert_eq!(shared.entry.file_exts_key, None);

    // Part of clean Windows: its own default, values and subkeys are recorded as not ours.
    assert_eq!(windows.entry.openwith_ours, ["VSCode.txt"]);
    assert_eq!(windows.entry.openwith_others, ["txtfile"]);
    assert_eq!(windows.entry.default.as_deref(), Some("txtfile"));
    assert!(!windows.default_is_ours);
    assert_eq!(windows.entry.previous_default, None);
    assert_eq!(
        windows.entry.other_values,
        ["Content Type", "PerceivedType"]
    );
    assert_eq!(windows.entry.other_subkeys, ["PersistentHandler"]);
    assert_eq!(windows.entry.subkey_count, 2);
    assert_eq!(windows.ext_in_baseline, Some(true));
    assert_eq!(windows.openwith_in_baseline, Some(true));
    assert_eq!(windows.entry.toast_values, ["VSCode.txt_.txt"]);

    // Only a toast names `.ddd`: the entry records that the Classes key does not exist.
    assert!(!toast_only.ext_exists);
    assert!(toast_only.entry.openwith_ours.is_empty());
    assert_eq!(toast_only.entry.toast_values, ["VSCode.ddd_.ddd"]);

    // The fingerprint's journal is the same entries.
    let entries = assoc::capture(&world.ctx());
    assert_eq!(
        entries,
        journal
            .records
            .iter()
            .map(|r| r.entry.clone())
            .collect::<Vec<_>>()
    );

    // Without a baseline the membership is unknown, not "absent".
    let journal = assoc::capture_detailed(&vscode_world(false, false).ctx());
    assert!(journal.records.iter().all(|r| r.ext_in_baseline.is_none()));
}

#[test]
fn vscode_subtrees_are_attributed_true_false_false() {
    let world = vscode_world(false, true);
    let subtrees = world.subtrees();

    // New extension, only our value: the key and its OpenWithProgids are wholly ours.
    assert!(attributed(&subtrees, &format!(r"{CLASSES}\.aaa")));
    assert!(attributed(
        &subtrees,
        &format!(r"{CLASSES}\.aaa\OpenWithProgids")
    ));
    // Part of clean Windows: the referencing key is recorded and not attributed, and the climb ends
    // there, so nothing attributes the extension's key either.
    assert!(!attributed(
        &subtrees,
        &format!(r"{CLASSES}\.txt\OpenWithProgids")
    ));
    assert!(!find(&subtrees, &format!(r"{CLASSES}\.txt")).is_some_and(|s| s.fully_attributed));
    // Another app's value next to ours.
    assert!(!attributed(&subtrees, &format!(r"{CLASSES}\.ccc")));
    assert!(!attributed(
        &subtrees,
        &format!(r"{CLASSES}\.ccc\OpenWithProgids")
    ));

    // The ProgIDs of P are covered whole, including values that refer to nothing.
    let progid = find(&subtrees, &format!(r"{CLASSES}\VSCode.aaa")).unwrap();
    assert!(progid.fully_attributed);
    assert_eq!(
        progid.subkeys,
        ["DefaultIcon", "shell", r"shell\open", r"shell\open\command"]
    );
    let names: Vec<(&str, &str)> = progid
        .values
        .iter()
        .map(|v| (v.subkey.as_str(), v.name.as_str()))
        .collect();
    assert_eq!(
        names,
        [
            ("", ""),
            ("", "AppUserModelID"),
            ("DefaultIcon", ""),
            (r"shell\open\command", "")
        ]
    );
    for value in &progid.values {
        let (ty, hash) = subtree::parse_value_hash(&value.hash).unwrap();
        assert_eq!(ty, 1);
        assert!(hash.is_some());
    }

    // A structural container is never recorded, nor the top of a hive.
    assert!(find(&subtrees, &format!(r"HKLM\SOFTWARE\{CV}\Run")).is_none());
    assert!(find(&subtrees, &format!(r"HKU\{SID}\Environment")).is_none());
    assert!(find(&subtrees, CLASSES).is_none());
    assert!(find(&subtrees, r"HKLM\SOFTWARE").is_none());
    // A key that holds a reference among foreign values is recorded and not attributed.
    assert!(!attributed(&subtrees, r"HKLM\SOFTWARE\Vendor\Lists"));
    assert!(!attributed(&subtrees, r"HKLM\SOFTWARE\Vendor"));

    // The user's FileExts key of the new extension holds notepad's entry too.
    assert!(attributed(
        &subtrees,
        &format!(r"{}\OpenWithProgids", file_exts(".aaa"))
    ));
    assert!(!attributed(&subtrees, &file_exts(".aaa")));
    // The climb ended at the baseline key, which is recorded shallowly.
    let stop = find(
        &subtrees,
        &format!(r"HKU\{SID}\Software\{CV}\Explorer\FileExts"),
    )
    .unwrap();
    assert!(!stop.fully_attributed && stop.subkeys.is_empty());
    assert!(find(&subtrees, &format!(r"HKU\{SID}\Software\{CV}\Explorer")).is_none());

    assert!(is_sorted_ci(subtrees.iter().map(|s| s.key.as_str())));
}

#[test]
fn without_a_baseline_only_the_referencing_keys_are_recorded() {
    let world = vscode_world(false, false);
    let subtrees = world.subtrees();
    assert!(find(&subtrees, &format!(r"{CLASSES}\.aaa\OpenWithProgids")).is_some());
    assert!(find(&subtrees, &format!(r"{CLASSES}\.aaa")).is_none());
    assert!(find(&subtrees, r"HKLM\SOFTWARE\Vendor").is_none());
    // ProgIDs do not depend on the climb.
    assert!(attributed(&subtrees, &format!(r"{CLASSES}\VSCode.txt")));

    // A baseline of another build is no baseline.
    let mut other = vscode_world(false, true);
    other.baseline = Some(
        Baseline::from_bytes(
            format!("#purge-baseline 1\tT\tPC\t{EDITION}\t{BUILD}.{}\n", UBR + 1).as_bytes(),
        )
        .unwrap(),
    );
    assert_eq!(other.subtrees(), subtrees);
}

#[test]
fn results_do_not_depend_on_the_order_the_source_lists_things_in() {
    let forward = vscode_world(false, true);
    let backward = vscode_world(true, true);
    let snapshot = refsnap::capture(&forward.ctx());
    assert!(!snapshot.is_empty());
    assert_eq!(snapshot, refsnap::capture(&backward.ctx()));
    assert_eq!(snapshot, refsnap::capture(&forward.ctx()));
    assert_eq!(forward.subtrees(), backward.subtrees());
    assert_eq!(
        assoc::capture(&forward.ctx()),
        assoc::capture(&backward.ctx())
    );

    let ctx = forward.ctx();
    let keys = subtree::keys(&ctx, &snapshot);
    assert!(is_sorted_ci(keys.iter().map(String::as_str)));
    // Keys given twice, in any case and order, are captured once, in key order.
    let mut twice: Vec<String> = keys.iter().rev().cloned().collect();
    twice.extend(keys.iter().map(|k| k.to_uppercase()));
    assert_eq!(
        subtree::capture(&ctx, &twice).len(),
        subtree::capture(&ctx, &keys).len()
    );
}

#[test]
fn vendor_backup_gives_the_previous_default() {
    let npp = r"C:\Program Files\Notepad++";
    let ext = format!(r"{CLASSES}\.log");
    let fixture = builder()
        .sz(&ext, "", "Notepad++_file")
        .sz(&ext, "Notepad++_backup", "txtfile")
        .sz(&ext, "Other_backup", "logfile")
        .sz(&format!(r"{CLASSES}\.ini"), "", "inifile")
        .sz(&format!(r"{CLASSES}\.ini"), "Notepad++_backup", "inifile")
        .sz(
            &format!(r"{CLASSES}\Notepad++_file\shell\open\command"),
            "",
            &format!("\"{npp}\\notepad++.exe\" \"%1\""),
        )
        .build();
    let mut anchors = AnchorSet::new();
    anchors.add_root(npp);
    anchors.add_progid("Notepad++_file");
    let world = World {
        fixture,
        anchors,
        roots: vec![install_root(npp)],
        inno: Vec::new(),
        baseline: None,
        inventory: vec![entry(
            "Notepad++",
            "Notepad++ (64-bit x64)",
            "Notepad++ Team",
            npp,
            &format!(r"{npp}\uninstall.exe"),
        )],
    };
    let journal = assoc::capture_detailed(&world.ctx());
    assert_eq!(journal.records.len(), 2);
    let [ini, log] = &journal.records[..] else {
        unreachable!()
    };

    // The app holds `.log`: the backup names what it replaced.
    assert!(log.default_is_ours);
    assert_eq!(log.entry.default.as_deref(), Some("Notepad++_file"));
    let backup = log.entry.vendor_backup.as_ref().unwrap();
    assert_eq!(
        (backup.name.as_str(), backup.data.as_str()),
        ("Notepad++_backup", "txtfile")
    );
    assert_eq!(log.entry.previous_default.as_deref(), Some("txtfile"));
    // Another vendor's backup value is just another value.
    assert_eq!(log.entry.other_values, ["Other_backup"]);

    // The app left a backup on `.ini` but does not hold the default: nothing was taken.
    assert!(!ini.default_is_ours);
    assert!(ini.entry.vendor_backup.is_some());
    assert_eq!(ini.entry.previous_default, None);
}

// ---------------------------------------------------------------------------------------------------------
// Git
// ---------------------------------------------------------------------------------------------------------

const GIT: &str = r"C:\Program Files\Git";

fn library_shell() -> String {
    format!(r"{CLASSES}\LibraryFolder\background\shell")
}

fn git_builder() -> FixtureBuilder {
    let shell = library_shell();
    let mut b = builder().key(&format!(r"{CLASSES}\LibraryFolder"));
    for (verb, title, exe) in [
        ("git_gui", "Open Git GUI here", "git-gui.exe"),
        ("git_shell", "Open Git Bash here", "git-bash.exe"),
    ] {
        b = b
            .sz(&format!(r"{shell}\{verb}"), "", title)
            .sz(
                &format!(r"{shell}\{verb}"),
                "Icon",
                &format!(r"{GIT}\cmd\{exe}"),
            )
            .sz(
                &format!(r"{shell}\{verb}\command"),
                "",
                &format!("\"{GIT}\\cmd\\{exe}\" \"--cd=%v.\""),
            );
    }
    // `sh_auto_file`: the log names only the command, the parents are implied.
    b.sz(
        &format!(r"{CLASSES}\sh_auto_file\shell\open\command"),
        "",
        &format!("\"{GIT}\\git-bash.exe\" --no-cd \"%L\" %*"),
    )
}

fn git_world(fixture: Fixture) -> World {
    let shell = library_shell();
    let mut anchors = AnchorSet::new();
    anchors.add_root(GIT);
    anchors.add_exe_path(&format!(r"{GIT}\git-bash.exe"));
    let folder = format!(r"{CLASSES}\LibraryFolder");
    World {
        fixture,
        anchors,
        roots: vec![install_root(GIT)],
        inno: vec![
            inno_key(
                InnoRecordKind::RegDeleteEntireKey,
                &format!(r"{shell}\git_gui"),
            ),
            // The log spells the hive as it was written.
            inno_key(
                InnoRecordKind::RegDeleteEntireKey,
                r"HKLM\Software\Classes\LibraryFolder\background\shell\git_shell",
            ),
            inno_key(
                InnoRecordKind::RegDeleteKeyIfEmpty,
                r"HKLM\Software\GitForWindows",
            ),
        ],
        baseline: Some(baseline(&[r"HKLM\SOFTWARE", CLASSES, folder.as_str()])),
        inventory: vec![entry(
            "Git_is1",
            "Git",
            "The Git Development Community",
            GIT,
            &format!(r"{GIT}\unins000.exe"),
        )],
    }
}

#[test]
fn git_library_folder_shell_is_attributed_by_inno_records() {
    let world = git_world(git_builder().build());
    let subtrees = world.subtrees();

    let shell = find(&subtrees, &library_shell()).expect("the shell key is recorded");
    assert_eq!(
        shell.subkeys,
        [
            "git_gui",
            r"git_gui\command",
            "git_shell",
            r"git_shell\command"
        ]
    );
    assert_eq!(shell.values.len(), 6);
    assert!(shell.fully_attributed);
    assert!(!shell.ti_owned);
    // So are the verbs themselves and the implied parent above.
    assert!(attributed(
        &subtrees,
        &format!(r"{}\git_shell", library_shell())
    ));
    assert!(attributed(
        &subtrees,
        &format!(r"{CLASSES}\LibraryFolder\background")
    ));
    // `LibraryFolder` is Windows' own: recorded shallowly, never attributed.
    assert!(!attributed(&subtrees, &format!(r"{CLASSES}\LibraryFolder")));
    // A skeleton whose only content is a command into the root.
    assert!(attributed(&subtrees, &format!(r"{CLASSES}\sh_auto_file")));
    assert!(attributed(
        &subtrees,
        &format!(r"{CLASSES}\sh_auto_file\shell\open")
    ));
    // A key-create record on a key that does not exist yields nothing.
    assert!(find(&subtrees, r"HKLM\Software\GitForWindows").is_none());
}

#[test]
fn git_verb_titles_need_the_inno_records() {
    // Without the log the verbs' titles ("Open Git Bash here") refer to nothing.
    let mut world = git_world(git_builder().build());
    world.inno.clear();
    let subtrees = world.subtrees();
    assert!(!attributed(&subtrees, &library_shell()));
    assert!(!attributed(
        &subtrees,
        &format!(r"{}\git_shell", library_shell())
    ));
    // The command keys below hold only a reference.
    assert!(attributed(
        &subtrees,
        &format!(r"{}\git_shell\command", library_shell())
    ));

    // A record that says the key existed before the install attributes nothing, and vetoes the key.
    let mut world = git_world(git_builder().build());
    world.inno[1].existed_before = true;
    let subtrees = world.subtrees();
    assert!(!attributed(
        &subtrees,
        &format!(r"{}\git_shell", library_shell())
    ));
    assert!(!attributed(&subtrees, &library_shell()));
}

#[test]
fn foreign_content_breaks_the_attribution() {
    let shell = library_shell();
    // Another app's verb next to ours.
    let fixture = git_builder()
        .sz(
            &format!(r"{shell}\other_app\command"),
            "",
            r"C:\Other\other.exe",
        )
        .build();
    let subtrees = git_world(fixture).subtrees();
    assert!(!attributed(&subtrees, &shell));
    assert!(attributed(&subtrees, &format!(r"{shell}\git_shell")));

    // An empty key nobody declares.
    let fixture = git_builder().key(&format!(r"{shell}\orphan")).build();
    assert!(!attributed(&git_world(fixture).subtrees(), &shell));

    // A registry link inside the subtree.
    let fixture = git_builder()
        .link(
            &format!(r"{shell}\git_shell\alias"),
            r"\REGISTRY\MACHINE\SOFTWARE\Elsewhere",
        )
        .build();
    let subtrees = git_world(fixture).subtrees();
    assert!(!attributed(&subtrees, &shell));
    assert!(!attributed(&subtrees, &format!(r"{shell}\git_shell")));

    // A reference to a root that is only inferred is no Tier A fact.
    let mut world = git_world(git_builder().build());
    world.roots[0].kind = RootKind::InferredRoot;
    world.roots[0].source = RootSource::DisplayIcon;
    world.inno.clear();
    let mut anchors = AnchorSet::new();
    anchors.add_root(GIT);
    world.anchors = anchors;
    let subtrees = world.subtrees();
    assert!(!attributed(&subtrees, &format!(r"{CLASSES}\sh_auto_file")));
}

#[test]
fn a_truncated_subtree_is_not_attributed() {
    let world = git_world(git_builder().build());
    let ctx = world.ctx();
    let keys = [library_shell()];
    let full = subtree::capture_with(&ctx, &keys, &subtree::SubtreeOptions::default());
    assert!(full.subtrees[0].fully_attributed);

    for limits in [
        SubtreeLimits {
            max_keys: 3,
            ..SubtreeLimits::default()
        },
        SubtreeLimits {
            max_values: 2,
            ..SubtreeLimits::default()
        },
        SubtreeLimits {
            max_depth: 1,
            ..SubtreeLimits::default()
        },
    ] {
        let options = subtree::SubtreeOptions {
            limits,
            ..subtree::SubtreeOptions::default()
        };
        let cut = subtree::capture_with(&ctx, &keys, &options);
        assert_eq!(cut.subtrees.len(), 1);
        assert!(!cut.subtrees[0].fully_attributed, "{limits:?}");
        assert!(
            cut.warnings.iter().any(|w| w.contains("in part")),
            "{:?}",
            cut.warnings
        );
    }

    // The number of subtrees is capped too.
    let snapshot = refsnap::capture(&ctx);
    let all = subtree::keys(&ctx, &snapshot);
    assert!(all.len() > 2);
    let options = subtree::SubtreeOptions {
        max_subtrees: 2,
        ..subtree::SubtreeOptions::default()
    };
    let capped = subtree::capture_with(&ctx, &all, &options);
    assert_eq!(capped.subtrees.len(), 2);
    assert!(
        capped
            .warnings
            .iter()
            .any(|w| w.contains("only the first 2"))
    );
}

#[test]
fn trusted_installer_ownership_propagates() {
    let shell = library_shell();
    // The key itself.
    let fixture = git_builder().ti_owned(&shell, true).build();
    let subtrees = git_world(fixture).subtrees();
    let top = find(&subtrees, &shell).unwrap();
    assert!(top.ti_owned);
    assert!(!top.fully_attributed);
    // Its parent contains a TrustedInstaller-owned key; its children do not.
    let parent = find(&subtrees, &format!(r"{CLASSES}\LibraryFolder\background")).unwrap();
    assert!(!parent.ti_owned);
    assert!(!parent.fully_attributed);
    assert!(attributed(&subtrees, &format!(r"{shell}\git_shell")));

    // A key below.
    let fixture = git_builder()
        .ti_owned(&format!(r"{shell}\git_gui\command"), true)
        .build();
    let subtrees = git_world(fixture).subtrees();
    assert!(!find(&subtrees, &shell).unwrap().ti_owned);
    assert!(!attributed(&subtrees, &shell));
    assert!(attributed(&subtrees, &format!(r"{shell}\git_shell")));

    // A source that records owners, and says "not TrustedInstaller" everywhere, changes nothing.
    let mut b = git_builder().ti_owned(r"HKLM\SOFTWARE", false);
    for rel in [
        "",
        r"\git_gui",
        r"\git_gui\command",
        r"\git_shell",
        r"\git_shell\command",
    ] {
        b = b.ti_owned(&format!("{shell}{rel}"), false);
    }
    let world = git_world(b.build());
    let ctx = world.ctx();
    let known = subtree::capture_with(
        &ctx,
        std::slice::from_ref(&shell),
        &subtree::SubtreeOptions::default(),
    );
    assert!(known.subtrees[0].fully_attributed);
    assert!(known.warnings.is_empty(), "{:?}", known.warnings);

    // The same source failing to tell for one key: unknown is not "not TrustedInstaller".
    let fixture = git_builder().ti_owned(r"HKLM\SOFTWARE", false).build();
    let world = git_world(fixture);
    let ctx = world.ctx();
    let unknown = subtree::capture_with(&ctx, &[shell], &subtree::SubtreeOptions::default());
    assert!(!unknown.subtrees[0].fully_attributed);
    assert!(
        unknown.warnings.iter().any(|w| w.contains("owner")),
        "{:?}",
        unknown.warnings
    );

    // The journal carries the flag of the extension's key.
    let ext = format!(r"{CLASSES}\.aaa");
    let mut world = vscode_world(false, true);
    world.fixture.set_ti_owned(&ext, true);
    world
        .fixture
        .set_ti_owned(&format!(r"{ext}\OpenWithProgids"), true);
    let journal = assoc::capture_detailed(&world.ctx());
    assert!(journal.records[0].entry.ti_owned && journal.records[0].openwith_ti_owned);
    assert!(!journal.records[1].entry.ti_owned);
    assert!(!attributed(&world.subtrees(), &ext));
}

// ---------------------------------------------------------------------------------------------------------
// Firefox
// ---------------------------------------------------------------------------------------------------------

const FIREFOX: &str = r"C:\Program Files\Mozilla Firefox";
const THUNDERBIRD: &str = r"C:\Program Files\Mozilla Thunderbird";
const MAINTENANCE: &str = r"C:\Program Files (x86)\Mozilla Maintenance Service";

fn firefox_world() -> World {
    let fixture = builder()
        .file(&format!(r"{FIREFOX}\firefox.exe"), 700_000)
        .file(&format!(r"{FIREFOX}\maintenanceservice.exe"), 250_000)
        .file(
            &format!(r"{FIREFOX}\maintenanceservice_installer.exe"),
            200_000,
        )
        .file(&format!(r"{FIREFOX}\updater.exe"), 400_000)
        .file(&format!(r"{FIREFOX}\uninstall\helper.exe"), 1_300_000)
        .file(&format!(r"{THUNDERBIRD}\thunderbird.exe"), 500_000)
        .file(&format!(r"{THUNDERBIRD}\maintenanceservice.exe"), 250_000)
        .file(&format!(r"{MAINTENANCE}\maintenanceservice.exe"), 250_000)
        .file(&format!(r"{MAINTENANCE}\Uninstall.exe"), 100_000)
        .build();
    let mut anchors = AnchorSet::new();
    anchors.add_root(FIREFOX);
    anchors.add_exe_path(&format!(r"{FIREFOX}\firefox.exe"));
    let mut maintenance = entry(
        "MozillaMaintenanceService",
        "Mozilla Maintenance Service",
        "Mozilla",
        "",
        &format!(r"{MAINTENANCE}\uninstall.exe"),
    );
    maintenance.program_id = ProgramId::machine(View::K32, "MozillaMaintenanceService").unwrap();
    maintenance.key_path = maintenance.program_id.key_path();
    maintenance.view = View::K32;
    maintenance.display_icon = Some(format!(r"{MAINTENANCE}\Uninstall.exe,0"));
    World {
        fixture,
        anchors,
        roots: vec![install_root(FIREFOX)],
        inno: Vec::new(),
        baseline: None,
        inventory: vec![
            entry(
                "Mozilla Firefox 160.0 (x64 en-US)",
                "Mozilla Firefox (x64 en-US)",
                "Mozilla",
                FIREFOX,
                &format!(r"{FIREFOX}\uninstall\helper.exe"),
            ),
            entry(
                "Mozilla Thunderbird 140.0 (x64 en-US)",
                "Mozilla Thunderbird (x64 en-US)",
                "Mozilla",
                THUNDERBIRD,
                &format!(r"{THUNDERBIRD}\uninstall\helper.exe"),
            ),
            maintenance,
            // Named like a file of Firefox, but somebody else's.
            entry(
                "UpdaterTool",
                "Updater Tool",
                "Somebody Else",
                r"C:\Program Files\Updater Tool",
                r"C:\Program Files\Updater Tool\uninstall.exe",
            ),
            // The same product once more (another channel) is not a component of this one.
            entry(
                "Mozilla Firefox ESR",
                "Mozilla Firefox (x86 en-US)",
                "Mozilla Corporation",
                r"C:\Program Files (x86)\Mozilla Firefox",
                r"C:\Program Files (x86)\Mozilla Firefox\uninstall\helper.exe",
            ),
        ],
    }
}

#[test]
fn firefox_maintenance_service_is_a_co_product_and_thunderbird_is_not() {
    let world = firefox_world();
    let candidates = coproducts::candidates(&world.ctx());
    assert_eq!(candidates.len(), 1, "{candidates:#?}");
    let service = &candidates[0];
    assert_eq!(service.app.display_name, "Mozilla Maintenance Service");
    assert_eq!(
        service.app.program_id.key_name(),
        "MozillaMaintenanceService"
    );
    assert_eq!(service.key_path, world.inventory[2].key_path);
    assert_eq!(service.roots, [MAINTENANCE]);
    assert!(service.tokens.is_empty());
    assert_eq!(
        service.reasons,
        [coproducts::CoProductReason::NamedInTargetRoot {
            file: format!(r"{FIREFOX}\maintenanceservice.exe")
        }]
    );

    // After the uninstall the runner's diff picks from the candidates.
    let gone = [
        world.inventory[2].program_id.clone(),
        world.inventory[3].program_id.clone(),
    ];
    let removed = coproducts::co_removed(&candidates, &gone);
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].app, service.app);
    assert!(removed[0].fingerprint.is_some());
    assert!(coproducts::co_removed(&candidates, &[]).is_empty());

    // The summary survives a round trip, for the session journal.
    let json = serde_json::to_string(&candidates).unwrap();
    assert_eq!(
        serde_json::from_str::<Vec<coproducts::CoProductPre>>(&json).unwrap(),
        candidates
    );
}

#[test]
fn co_products_by_directory_and_by_inno_log() {
    let suite = r"C:\Program Files\Acme\Suite";
    let fixture = builder().file(&format!(r"{suite}\suite.exe"), 1).build();
    let mut anchors = AnchorSet::new();
    anchors.add_root(suite);
    let mut guid = entry(
        "{11111111-2222-3333-4444-555555555555}",
        "Acme Runtime",
        "Acme Ltd",
        "",
        r"C:\ProgramData\Acme Runtime\uninstall.exe",
    );
    guid.product_code = Some("{11111111-2222-3333-4444-555555555555}".into());
    let world = World {
        fixture,
        anchors,
        roots: vec![install_root(suite)],
        inno: vec![
            InnoRecord {
                kind: InnoRecordKind::RegDeleteValue,
                target: Target::RegValue {
                    path: guid.key_path.replace("SOFTWARE", "Software"),
                    name: "DisplayName".into(),
                },
                view: Some(View::K64),
                user_hive: false,
                existed_before: false,
                shared: false,
                key_create: false,
            },
            InnoRecord {
                kind: InnoRecordKind::DeleteFile,
                target: Target::Path {
                    path: r"C:\Program Files\Acme Helper\helper.dll".into(),
                },
                view: None,
                user_hive: false,
                existed_before: false,
                shared: false,
                key_create: false,
            },
        ],
        baseline: None,
        inventory: vec![
            entry(
                "AcmeSuite",
                "Acme Suite",
                "Acme Inc.",
                suite,
                &format!(r"{suite}\unins000.exe"),
            ),
            // Next to the target in the vendor's folder.
            entry(
                "AcmeTools",
                "Acme Tools",
                "ACME",
                r"C:\Program Files\Acme\Tools",
                r"C:\Program Files\Acme\Tools\u.exe",
            ),
            // Inside the target's root.
            entry(
                "AcmePlugin",
                "Acme Plugin",
                "Acme",
                &format!(r"{suite}\plugins\x"),
                &format!(r"{suite}\plugins\x\u.exe"),
            ),
            // Its ARP key is written by the target's log.
            guid,
            // A file in its directory is deleted by the target's log.
            entry(
                "AcmeHelper",
                "Acme Helper",
                "Acme",
                r"C:\Program Files\Acme Helper",
                r"C:\Program Files\Acme Helper\u.exe",
            ),
            // Same vendor, no tie: both merely sit in Program Files.
            entry(
                "AcmeOther",
                "Acme Other",
                "Acme",
                r"C:\Program Files\Acme Other",
                r"C:\Program Files\Acme Other\u.exe",
            ),
            // Next to the target, but another vendor's.
            entry(
                "Squatter",
                "Squatter",
                "Squatter Co",
                r"C:\Program Files\Acme\Squatter",
                r"C:\Program Files\Acme\Squatter\u.exe",
            ),
        ],
    };
    let candidates = coproducts::candidates(&world.ctx());
    let names: Vec<&str> = candidates
        .iter()
        .map(|c| c.app.display_name.as_str())
        .collect();
    assert_eq!(
        names,
        ["Acme Tools", "Acme Plugin", "Acme Runtime", "Acme Helper"]
    );
    use coproducts::CoProductReason as Reason;
    assert_eq!(
        candidates[0].reasons,
        [Reason::SharedVendorDir {
            dir: r"C:\Program Files\Acme".into()
        }]
    );
    assert_eq!(
        candidates[1].reasons,
        [Reason::InsideTargetRoot {
            dir: format!(r"{suite}\plugins\x")
        }]
    );
    assert!(matches!(
        &candidates[2].reasons[..],
        [Reason::InnoLog { .. }]
    ));
    assert_eq!(
        candidates[2].tokens,
        ["11111111-2222-3333-4444-555555555555"]
    );
    assert_eq!(
        candidates[3].reasons,
        [Reason::InnoLog {
            target: r"C:\Program Files\Acme Helper\helper.dll".into()
        }]
    );

    // An entry without a publisher has no vendor to share.
    let mut world = world;
    world.inventory[0].publisher = None;
    assert!(coproducts::candidates(&world.ctx()).is_empty());
}

// ---------------------------------------------------------------------------------------------------------
// A real rig snapshot
// ---------------------------------------------------------------------------------------------------------

/// With `PURGE_RUNS_DIR` (e.g. `vm/runs`): the reference snapshot, the subtree baselines and the journal
/// of VS Code from its real post-install snapshot, with the time each takes. The harvest budget is 3 s
/// in a release build on the development host (§1.3); the times are reported, not asserted.
#[test]
#[ignore = "needs PURGE_RUNS_DIR with the vscode run"]
fn perf_refsnap_and_subtrees_on_the_vscode_snapshot() {
    let Some(runs) = std::env::var_os("PURGE_RUNS_DIR") else {
        eprintln!("PURGE_RUNS_DIR not set; skipping");
        return;
    };
    let dir = std::path::Path::new(&runs).join("vscode");
    let snap = dir.join("snap-vscode-1.tsv.gz");
    let lists = dir.join("lists-vscode-1.json");
    let t = std::time::Instant::now();
    let fixture =
        Fixture::from_snap(&snap, lists.is_file().then_some(lists.as_path()), None).unwrap();
    eprintln!(
        "fixture loaded in {:?}: {} keys, {} values",
        t.elapsed(),
        fixture.key_count(),
        fixture.value_count()
    );
    use purge_source::registry::RegistrySource;
    use purge_source::system::SystemSource;

    let mut anchors = AnchorSet::new();
    anchors.add_root(CODE);
    anchors.add_exe_path(&format!(r"{CODE}\Code.exe"));
    anchors.add_exe_path(&format!(r"{CODE}\unins000.exe"));
    anchors.add_exe_name("Code.exe");
    let mut progids = 0;
    for name in fixture.subkeys(CLASSES).unwrap() {
        if name.to_ascii_lowercase().starts_with("vscode.") {
            anchors.add_progid(&name);
            progids += 1;
        }
    }
    let os = fixture.os_info().unwrap();
    let kb = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../kb/baselines");
    let baseline = Baseline::select(&kb, &os.edition, os.build, os.ubr);
    eprintln!(
        "{} ProgIDs in P; baseline for {}: {}",
        progids,
        os.baseline_name(),
        if baseline.is_some() { "loaded" } else { "none" }
    );
    let world = World {
        fixture,
        anchors,
        roots: vec![install_root(CODE)],
        inno: Vec::new(),
        baseline,
        inventory: vec![entry(
            "{EA457B21-F73E-494C-ACAB-524FDE069978}_is1",
            "Microsoft Visual Studio Code",
            "Microsoft Corporation",
            CODE,
            &format!(r"{CODE}\unins000.exe"),
        )],
    };
    let ctx = world.ctx();

    let t = std::time::Instant::now();
    let report = refsnap::capture_report(&ctx);
    let refsnap_time = t.elapsed();
    eprintln!(
        "refsnap: {} entries ({} weak hits), {} keys visited, complete={} in {:?}",
        report.entries.len(),
        report.weak_hits,
        report.stats.keys_visited,
        report.complete,
        refsnap_time
    );
    for warning in &report.warnings {
        eprintln!("  warning: {warning}");
    }

    let t = std::time::Instant::now();
    let keys = subtree::keys(&ctx, &report.entries);
    let capture = subtree::capture_with(&ctx, &keys, &subtree::SubtreeOptions::default());
    let subtree_time = t.elapsed();
    let attributed = capture
        .subtrees
        .iter()
        .filter(|s| s.fully_attributed)
        .count();
    eprintln!(
        "subtrees: {} keys, {} recorded, {} fully attributed, {} values in {:?}",
        keys.len(),
        capture.subtrees.len(),
        attributed,
        capture
            .subtrees
            .iter()
            .map(|s| s.values.len())
            .sum::<usize>(),
        subtree_time
    );
    for warning in &capture.warnings {
        eprintln!("  warning: {warning}");
    }
    // The attributed keys that are neither a ProgID of P nor an extension: worth a human look.
    for subtree in capture.subtrees.iter().filter(|s| s.fully_attributed) {
        let lower = subtree.key.to_ascii_lowercase();
        if !lower.contains(r"\classes\vscode.") && !lower.contains(r"\classes\.") {
            eprintln!("  attributed: {}", subtree.key);
        }
    }

    let t = std::time::Instant::now();
    let journal = assoc::capture_detailed(&ctx);
    let only_ours = journal.records.iter().filter(|r| r.only_ours()).count();
    let new_exts = journal
        .records
        .iter()
        .filter(|r| r.ext_in_baseline == Some(false))
        .count();
    eprintln!(
        "journal: {} extensions, {} with only our value, {} absent from the baseline in {:?}",
        journal.records.len(),
        only_ours,
        new_exts,
        t.elapsed()
    );
    eprintln!(
        "refsnap + subtree: {:?} (budget: 3 s for the whole harvest, release build)",
        refsnap_time + subtree_time
    );
    assert!(!report.entries.is_empty());
    assert!(!capture.subtrees.is_empty());
}

// ---------------------------------------------------------------------------------------------------------
// Review regressions
// ---------------------------------------------------------------------------------------------------------

#[test]
fn a_list_hit_that_can_no_longer_be_placed_is_not_recorded_on_the_whole_value() {
    use purge_index::refscan::{self, RefScanOptions, RefWhere};

    let lists = r"HKLM\SOFTWARE\Vendor\Lists";
    let ours = format!(r"{CODE}\Code.exe");
    let world_with = |segments: &[&str]| {
        let mut anchors = AnchorSet::new();
        anchors.add_root(CODE);
        World {
            fixture: builder().multi_sz(lists, "Editors", segments).build(),
            anchors,
            roots: vec![install_root(CODE)],
            inno: Vec::new(),
            baseline: None,
            inventory: vec![entry("Code_is1", "VS Code", "Microsoft", CODE, &ours)],
        }
    };

    // The scan saw our string at index 2 ...
    let before = world_with(&["notepad.exe", r"C:\Other\other.exe", &ours]);
    let ctx = before.ctx();
    let scope = refsnap::scope(&ctx, &mut Vec::new());
    let scan = refscan::scan(
        ctx.reg,
        &ctx.matcher(),
        &scope,
        &RefScanOptions::default(),
        None,
    );
    let hits: Vec<_> = scan
        .hits
        .into_iter()
        .filter(|hit| hit.value_name == "Editors")
        .collect();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].location, RefWhere::Segment(2));
    let (entries, weak) = refsnap::entries_from_hits(&ctx, &hits);
    assert_eq!((entries.len(), weak), (1, 0));

    // ... but by the time the string is read the list is shorter, or holds another app there.
    for now in [
        &["notepad.exe", r"C:\Other\other.exe"][..],
        &["notepad.exe", r"C:\Other\other.exe", r"C:\Third\third.exe"][..],
    ] {
        let after = world_with(now);
        let (entries, weak) = refsnap::entries_from_hits(&after.ctx(), &hits);
        // No entry at all: an entry on the value would attribute the other apps' strings too.
        assert_eq!(entries, [], "{now:?}");
        assert_eq!(weak, 1, "{now:?}");
    }
}

/// Rig run x1-vscode-userstate: the user made empty `.gemspec\OpenWithProgids` and
/// `.edn\OpenWithProgids` keys before the install, the installer wrote its one value into each, and
/// after the uninstall both keys of each pair were preselected as the app's skeletons. The times are
/// the run's: the planted `.ext` key keeps its time from before the install directory existed, its
/// subkey got a new one when the value was written.
#[test]
fn a_key_older_than_the_install_is_not_a_skeleton_of_the_app() {
    const SECOND: u64 = 10_000_000;
    const INSTALL: u64 = 134_000_000_000_000_000;
    let planted = INSTALL - 21 * SECOND;
    let written = INSTALL + 31 * SECOND;
    let command = format!("\"{CODE}\\Code.exe\" \"%1\"");
    let mut b = builder();
    for ext in ["gemspec", "gradle", "ini", "kts"] {
        let progid = format!(r"{CLASSES}\VSCode.{ext}");
        b = b
            .sz(&format!(r"{progid}\shell\open\command"), "", &command)
            .key_lwt(&progid, written)
            .sz(
                &format!(r"{CLASSES}\.{ext}\OpenWithProgids"),
                &format!("VSCode.{ext}"),
                "",
            )
            .key_lwt(&format!(r"{CLASSES}\.{ext}\OpenWithProgids"), written);
    }
    let fixture = b
        // The user's: made before the install, with the subkey already in it.
        .key_lwt(&format!(r"{CLASSES}\.gemspec"), planted)
        // The installer's: the key and the subkey were created by the install.
        .key_lwt(&format!(r"{CLASSES}\.gradle"), written)
        // What the rule cannot see: the key was there, the installer created the subkey in it and so
        // moved the key's own time.
        .key_lwt(&format!(r"{CLASSES}\.ini"), written)
        // A key with a new time whose subkey has an old one (somebody wrote into the key since).
        .key_lwt(&format!(r"{CLASSES}\.kts"), written)
        .key_lwt(&format!(r"{CLASSES}\.kts\OpenWithProgids"), planted)
        // Creating `.gradle` moved the time of the Classes key itself.
        .key_lwt(CLASSES, written)
        .build();
    let mut anchors = AnchorSet::new();
    anchors.add_root(CODE);
    for ext in ["gemspec", "gradle", "ini", "kts"] {
        anchors.add_progid(&format!("VSCode.{ext}"));
    }
    let world = World {
        fixture,
        anchors,
        roots: vec![install_root(CODE)],
        inno: Vec::new(),
        baseline: Some(baseline(&[r"HKLM\SOFTWARE", CLASSES])),
        inventory: vec![entry(
            "{EA457B21-F73E-494C-ACAB-524FDE069978}_is1",
            "Microsoft Visual Studio Code",
            "Microsoft Corporation",
            CODE,
            &format!(r"{CODE}\unins000.exe"),
        )],
    };
    let subtrees = |cutoff: Option<purge_harvest::anchors::ComCutoff>| {
        let mut ctx = world.ctx();
        ctx.cutoff = cutoff;
        let snapshot = refsnap::capture(&ctx);
        subtree::capture(&ctx, &subtree::keys(&ctx, &snapshot))
    };
    let cutoff = |exact: bool| {
        Some(purge_harvest::anchors::ComCutoff {
            time: purge_model::FileTime(INSTALL),
            exact,
        })
    };
    let ext = |name: &str| format!(r"{CLASSES}\.{name}");
    let sub = |name: &str| format!(r"{CLASSES}\.{name}\OpenWithProgids");

    // Without any install time every pair looks like the app's.
    let got = subtrees(None);
    for name in ["gemspec", "gradle", "ini"] {
        assert!(attributed(&got, &ext(name)), "{name}");
        assert!(attributed(&got, &sub(name)), "{name}");
    }

    // With the exact time: the planted key is older than the install, and its subkey existed
    // before the install too (creating it would have moved the planted key's time).
    let got = subtrees(cutoff(true));
    assert!(!attributed(&got, &ext("gemspec")));
    assert!(!attributed(&got, &sub("gemspec")));
    // The installer's own pair is untouched by the rule.
    assert!(attributed(&got, &ext("gradle")));
    assert!(attributed(&got, &sub("gradle")));
    // The known gap: a pre-existing key the installer wrote a subkey into has a new time.
    assert!(attributed(&got, &ext("ini")));
    // An older subkey takes the key above it along.
    assert!(!attributed(&got, &ext("kts")));
    assert!(!attributed(&got, &sub("kts")));

    // The same verdicts as a list for the fingerprint (`older_keys`), for every proof the scan has.
    let older = |cutoff| {
        let mut ctx = world.ctx();
        ctx.cutoff = cutoff;
        let keys = ["gemspec", "gradle", "ini", "kts", "nokey"]
            .into_iter()
            .flat_map(|name| [ext(name), sub(name)]);
        subtree::older_keys(&ctx, keys)
    };
    assert_eq!(
        older(cutoff(true)),
        [ext("gemspec"), sub("gemspec"), sub("kts")]
    );
    assert!(older(cutoff(false)).is_empty());
    assert!(older(None).is_empty());

    // A looser hint concludes nothing here.
    let got = subtrees(cutoff(false));
    assert!(attributed(&got, &ext("gemspec")));
}

/// A registry that refuses to tell about one key (an ACL that denies `KEY_QUERY_VALUE`), over a
/// fixture.
struct Unreadable<'a> {
    inner: &'a Fixture,
    key: String,
}

impl purge_source::registry::RegistrySource for Unreadable<'_> {
    fn key_info(
        &self,
        key: &str,
    ) -> purge_source::types::SourceResult<purge_source::types::KeyInfo> {
        if key.eq_ignore_ascii_case(&self.key) {
            return Err(purge_source::types::SourceError::AccessDenied);
        }
        self.inner.key_info(key)
    }
    fn subkeys(&self, key: &str) -> purge_source::types::SourceResult<Vec<String>> {
        self.inner.subkeys(key)
    }
    fn values(
        &self,
        key: &str,
    ) -> purge_source::types::SourceResult<Vec<purge_source::types::RegValue>> {
        self.inner.values(key)
    }
    fn value(
        &self,
        key: &str,
        name: &str,
    ) -> purge_source::types::SourceResult<purge_source::types::RegData> {
        self.inner.value(key, name)
    }
    fn loaded_user_sids(&self) -> purge_source::types::SourceResult<Vec<String>> {
        self.inner.loaded_user_sids()
    }
    fn current_control_set(&self) -> purge_source::types::SourceResult<u32> {
        self.inner.current_control_set()
    }
}

/// `older_keys` says "this key existed before the install" and a key it does not name can be
/// proven the app's skeleton. Whatever it cannot find out must therefore count as older: a key
/// without a time, a key that cannot be read, a key whose parent has no time or cannot be read.
/// Only a key that is not there, and one that is read with its parent and is newer, are left out.
#[test]
fn older_keys_take_what_they_cannot_tell_for_older() {
    const INSTALL: u64 = 134_000_000_000_000_000;
    let (old, new) = (INSTALL - 10_000_000, INSTALL + 10_000_000);
    let key = |name: &str| format!(r"{CLASSES}\{name}");
    let fixture = builder()
        .key_lwt(CLASSES, new)
        // No time at all (a source that does not report one).
        .key_lwt(&key(".notime"), 0)
        // New, in a parent without a time.
        .key_lwt(&key(".notime\\OpenWithProgids"), new)
        // New, in a new parent: the installer's.
        .key_lwt(&key(".new"), new)
        .key_lwt(&key(".new\\OpenWithProgids"), new)
        // New, in a new parent that cannot be read (see `Unreadable`).
        .key_lwt(&key(".closed"), new)
        .key_lwt(&key(".closed\\OpenWithProgids"), new)
        // New, in an old parent; and old in a new one.
        .key_lwt(&key(".old"), old)
        .key_lwt(&key(".old\\OpenWithProgids"), new)
        .key_lwt(&key(".kts"), new)
        .key_lwt(&key(".kts\\OpenWithProgids"), old)
        // There, and refused: the fixture knows nothing below it.
        .denied(&key(".refused"))
        .build();
    let mut anchors = AnchorSet::new();
    anchors.add_root(CODE);
    let world = World {
        fixture,
        anchors,
        roots: vec![install_root(CODE)],
        inno: Vec::new(),
        baseline: None,
        inventory: vec![entry(
            "{EA457B21-F73E-494C-ACAB-524FDE069978}_is1",
            "Microsoft Visual Studio Code",
            "Microsoft Corporation",
            CODE,
            &format!(r"{CODE}\unins000.exe"),
        )],
    };
    let reg = Unreadable {
        inner: &world.fixture,
        key: key(".closed"),
    };
    let names = [
        ".notime", ".new", ".closed", ".old", ".kts", ".refused", ".absent",
    ];
    let asked = || {
        names
            .into_iter()
            .flat_map(|name| [key(name), key(&format!(r"{name}\OpenWithProgids"))])
    };
    let older = |exact: bool| {
        let mut ctx = world.ctx();
        ctx.reg = &reg;
        ctx.cutoff = Some(purge_harvest::anchors::ComCutoff {
            time: purge_model::FileTime(INSTALL),
            exact,
        });
        subtree::older_keys(&ctx, asked())
    };
    let sub = |name: &str| key(&format!(r"{name}\OpenWithProgids"));
    let mut want = vec![
        // The key cannot be read; its subkey can, but not the key above it.
        key(".closed"),
        sub(".closed"),
        // Older by its own time.
        sub(".kts"),
        // No time; and a parent without one.
        key(".notime"),
        sub(".notime"),
        // Older by its own time, and by its parent's.
        key(".old"),
        sub(".old"),
        // Refused, with whatever is below it.
        key(".refused"),
        sub(".refused"),
    ];
    want.sort();
    assert_eq!(older(true), want);
    // `.new`, its subkey and `.kts` are read and newer; `.absent` is not there.
    assert!(older(false).is_empty());

    // The subtree capture judges with the same clock: a subtree whose key has no time, or whose
    // parent cannot be read, is not attributed under an exact cutoff.
    let mut ctx = world.ctx();
    ctx.reg = &reg;
    ctx.cutoff = Some(purge_harvest::anchors::ComCutoff {
        time: purge_model::FileTime(INSTALL),
        exact: true,
    });
    let got = subtree::capture(&ctx, &asked().collect::<Vec<_>>());
    for name in [".notime", ".closed", ".old", ".kts"] {
        for k in [key(name), sub(name)] {
            if let Some(tree) = find(&got, &k) {
                assert!(!tree.fully_attributed, "{k}");
            }
        }
    }
}

/// The keys `older_keys` is asked about come from four places, and a scanner may start a
/// skeleton proof from a key of any of them: each must be there for itself.
#[test]
fn older_key_candidates_come_from_four_sources() {
    let ext = format!(r"{CLASSES}\.tidy");
    let tree = SubtreeBaseline {
        key: format!(r"{CLASSES}\Tidy.Document"),
        values: Vec::new(),
        subkeys: vec!["shell".into(), r"shell\open".into()],
        lwt: purge_model::FileTime(1),
        ti_owned: false,
        fully_attributed: true,
    };
    let journal = purge_model::ExtJournalEntry {
        ext: ".tidy".into(),
        key: ext.clone(),
        openwith_ours: vec!["Tidy.Document".into()],
        openwith_others: Vec::new(),
        subkey_count: 1,
        default: None,
        previous_default: None,
        other_values: Vec::new(),
        other_subkeys: Vec::new(),
        ti_owned: false,
        vendor_backup: None,
        file_exts_key: None,
        toast_values: Vec::new(),
    };
    let logged = inno_key(
        InnoRecordKind::RegDeleteKeyIfEmpty,
        r"HKLM\SOFTWARE\Acme Tools",
    );
    // A record on a value names no key of its own.
    let mut value_record = logged.clone();
    value_record.target = Target::RegValue {
        path: r"HKLM\SOFTWARE\Other".into(),
        name: "x".into(),
    };
    let from = subtree::older_key_candidates;
    assert_eq!(
        from(std::slice::from_ref(&tree), &[], &[]),
        [
            format!(r"{CLASSES}\Tidy.Document"),
            format!(r"{CLASSES}\Tidy.Document\shell"),
            format!(r"{CLASSES}\Tidy.Document\shell\open"),
        ]
    );
    assert_eq!(
        from(&[], std::slice::from_ref(&journal), &[]),
        [ext.clone(), format!(r"{ext}\OpenWithProgids")]
    );
    assert_eq!(
        from(&[], &[], &[logged.clone(), value_record.clone()]),
        [r"HKLM\SOFTWARE\Acme Tools"]
    );
    assert_eq!(
        from(&[tree], &[journal], &[value_record, logged]).len(),
        3 + 2 + 1
    );
}

/// The harvest and REG-ENV must agree on what an entry of `Path` is and where it stands: both split
/// with `prefix::list_entries`. A `;` inside quotes does not make two entries, an entry written
/// that way is nobody's, and the entry after it keeps its position.
#[test]
fn a_quoted_semicolon_in_path_is_one_entry_for_the_snapshot() {
    let env = format!(r"HKU\{SID}\Environment");
    let fixture = builder()
        .expand_sz(
            &env,
            "Path",
            &format!(r#""{CODE};x\bin";{CODE}\bin;"{CODE}\cmd;C:\Users\tester\tools"#),
        )
        .build();
    let mut anchors = AnchorSet::new();
    anchors.add_root(CODE);
    let world = World {
        fixture,
        anchors,
        roots: vec![install_root(CODE)],
        inno: Vec::new(),
        baseline: None,
        inventory: vec![entry(
            "{EA457B21-F73E-494C-ACAB-524FDE069978}_is1",
            "Microsoft Visual Studio Code",
            "Microsoft Corporation",
            CODE,
            &format!(r"{CODE}\unins000.exe"),
        )],
    };
    let snapshot = refsnap::capture(&world.ctx());
    let segments: Vec<&Target> = snapshot
        .iter()
        .map(|e| &e.target)
        .filter(|t| matches!(t, Target::RegMultiSzSegment { .. }))
        .collect();
    assert_eq!(
        segments,
        [&Target::RegMultiSzSegment {
            path: env,
            name: "Path".into(),
            segment: format!(r"{CODE}\bin"),
            index: Some(1),
        }]
    );
}

/// An entry of `Path` that begins with the app's folder and holds more is not the app's entry:
/// a second path after a quote, a comma or a blank, or a reference to a variable that holds a list.
/// The harvest reads an entry as REG-ENV does (`prefix::ListEntry::read`, as written and
/// expanded), records none of them, and keeps the positions of the entries it does record.
#[test]
fn a_path_entry_that_holds_more_than_one_directory_is_not_in_the_snapshot() {
    let env = format!(r"HKU\{SID}\Environment");
    let tools = r"C:\Users\tester\tools";
    let entries = [
        "%MYDIRS%".to_owned(),
        format!(r#""{CODE}\bin" "{tools}""#),
        format!(r"{CODE}\bin,{tools}"),
        format!(r"{CODE}\bin {tools}"),
        "%QUOTED%".to_owned(),
        r"%MYDIRS%\x".to_owned(),
        // One directory each: recorded.
        "%MYDIR%".to_owned(),
        format!(r"{CODE}\bin,tools"),
        format!(r#""{CODE}\bin\""#),
    ];
    let fixture = builder()
        .expand_sz(&env, "Path", &entries.join(";"))
        .env("MYDIRS", &format!(r"{CODE}\bin;{tools}"))
        .env("QUOTED", &format!(r#"{CODE}\bin" "{tools}"#))
        .env("MYDIR", &format!(r"{CODE}\bin"))
        .build();
    let mut anchors = AnchorSet::new();
    anchors.add_root(CODE);
    let world = World {
        fixture,
        anchors,
        roots: vec![install_root(CODE)],
        inno: Vec::new(),
        baseline: None,
        inventory: vec![entry(
            "{EA457B21-F73E-494C-ACAB-524FDE069978}_is1",
            "Microsoft Visual Studio Code",
            "Microsoft Corporation",
            CODE,
            &format!(r"{CODE}\unins000.exe"),
        )],
    };
    let snapshot = refsnap::capture(&world.ctx());
    let segments: Vec<(u32, &str)> = snapshot
        .iter()
        .filter_map(|e| match &e.target {
            Target::RegMultiSzSegment { segment, index, .. } => {
                Some((index.expect("a position"), segment.as_str()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        segments,
        [
            (6, entries[6].as_str()),
            (7, entries[7].as_str()),
            (8, entries[8].as_str())
        ]
    );
}

#[test]
fn a_subkey_that_existed_before_the_install_vetoes_the_subtree() {
    let shell = library_shell();
    let mut world = git_world(git_builder().build());
    // The verb is deleted entirely, yet the log says its `command` key was there before.
    let mut old = inno_key(
        InnoRecordKind::RegDeleteKeyIfEmpty,
        &format!(r"{shell}\git_gui\command"),
    );
    old.existed_before = true;
    old.key_create = false;
    world.inno.push(old);
    let subtrees = world.subtrees();
    assert!(!attributed(&subtrees, &format!(r"{shell}\git_gui\command")));
    assert!(!attributed(&subtrees, &format!(r"{shell}\git_gui")));
    assert!(!attributed(&subtrees, &shell));
    // The sibling verb is untouched by it.
    assert!(attributed(&subtrees, &format!(r"{shell}\git_shell")));
}

#[test]
fn unbound_hkcu_records_are_bound_to_the_user_the_app_is_installed_for() {
    const OTHER: &str = "S-1-5-21-1004336348-1177238915-682003330-1002";
    let theirs = format!(r"HKU\{OTHER}\Software\Vendor\App");
    let mine = format!(r"HKU\{SID}\Software\Vendor\App");
    let fixture = builder()
        .sz(&theirs, "Setting", "1")
        .sz(&mine, "Setting", "1")
        .build();
    let app = r"C:\Program Files\App";
    let mut anchors = AnchorSet::new();
    anchors.add_root(app);
    let mut target = entry(
        "App_is1",
        "App",
        "Vendor",
        app,
        &format!(r"{app}\unins000.exe"),
    );
    target.hive_sid = Some(OTHER.into());
    let world = World {
        fixture,
        anchors,
        roots: vec![install_root(app)],
        inno: vec![inno_key(
            InnoRecordKind::RegDeleteEntireKey,
            r"HKCU\Software\Vendor\App",
        )],
        baseline: None,
        inventory: vec![target],
    };
    assert_eq!(world.ctx().bind_sid().as_deref(), Some(OTHER));
    let subtrees = world.subtrees();
    assert!(attributed(&subtrees, &theirs));
    // The interactive user's key of the same name is not what the log is about.
    assert!(find(&subtrees, &mine).is_none());
}

#[test]
fn shared_keys_are_never_attributed_even_when_asked_for_directly() {
    let run = format!(r"HKLM\SOFTWARE\{CV}\Run");
    let fixture = builder()
        .sz(&run, "CodeHelper", &format!(r"{CODE}\Code.exe --tray"))
        .sz(r"HKLM\SOFTWARE\Classes\.zzz", "", "VSCode.zzz")
        .build();
    let mut anchors = AnchorSet::new();
    anchors.add_root(CODE);
    anchors.add_progid("VSCode.zzz");
    let world = World {
        fixture,
        anchors,
        roots: vec![install_root(CODE)],
        inno: vec![
            inno_key(InnoRecordKind::RegDeleteEntireKey, &run),
            inno_key(InnoRecordKind::RegDeleteEntireKey, CLASSES),
        ],
        baseline: None,
        inventory: vec![entry("Code_is1", "VS Code", "Microsoft", CODE, CODE)],
    };
    let ctx = world.ctx();
    // The key list leaves them out ...
    let keys = subtree::keys(&ctx, &refsnap::capture(&ctx));
    assert!(!keys.iter().any(|k| k.eq_ignore_ascii_case(&run)));
    assert!(!keys.iter().any(|k| k.eq_ignore_ascii_case(CLASSES)));
    // ... and a caller that passes them anyway gets a record that attributes nothing.
    let subtrees = subtree::capture(&ctx, &[run.as_str(), CLASSES]);
    assert!(!attributed(&subtrees, &run));
    assert!(!attributed(&subtrees, CLASSES));
}
