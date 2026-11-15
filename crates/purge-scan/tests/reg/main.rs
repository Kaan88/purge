//! Tests of the registry scanners REG-SOFTWARE, REG-APPPATHS, REG-RUN, REG-ENV and REF-ANY over
//! fixtures shaped like machines after an uninstall (Firefox with its Maintenance Service, Git,
//! Notepad++).
//!
//! Each scanner has golden files under `tests/reg/golden` (see [`golden`]); the assertions next to them
//! spell out the properties the design depends on.

mod com;
mod golden;
mod hostile;
mod world;

use purge_guard::containers;
use purge_model::{
    Action, AnchorKind, AnchorRef, Blocker, Candidate, EvidenceKind, FileTime, InnoRecordKind,
    ProgramId, RefCarrier, RootSource, Scope, SourceTrust, SubtreeBaseline, SubtreeValue, Target,
    Tier, View,
};
use purge_scan::framework::{OtherApp, OtherApps, Scanner, candidate_id};
use purge_scan::ref_any::RefAny;
use purge_scan::reg_apppaths::RegAppPaths;
use purge_scan::reg_env::RegEnv;
use purge_scan::reg_run::RegRun;
use purge_scan::reg_software::RegSoftware;
use purge_source::fixture::FixtureBuilder;
use purge_source::types::{RegData, ShortcutInfo};

use world::*;

const THUNDERBIRD: &str = r"C:\Program Files\Mozilla Thunderbird";

fn find<'a>(candidates: &'a [Candidate], target: &Target) -> Option<&'a Candidate> {
    let id = candidate_id(target);
    candidates.iter().find(|c| c.id == id)
}

fn expect<'a>(candidates: &'a [Candidate], target: &Target) -> &'a Candidate {
    find(candidates, target).unwrap_or_else(|| {
        panic!(
            "no candidate for {}\n{}",
            golden::target_text(target),
            golden::render(candidates)
        )
    })
}

fn kinds(c: &Candidate) -> Vec<EvidenceKind> {
    c.evidence.iter().map(|e| e.kind).collect()
}

fn has(c: &Candidate, kind: EvidenceKind) -> bool {
    c.evidence.iter().any(|e| e.kind == kind)
}

/// Tier A evidence of the target's own scope: what the Safe band needs first.
fn tier_a_in_scope(c: &Candidate) -> bool {
    let scope = Scope::of(&c.target);
    c.evidence
        .iter()
        .any(|e| e.tier == Tier::A && e.weight > 0 && Some(e.scope) == scope)
}

/// The score as `purge-policy` counts it for candidates without negatives: the highest weight of
/// each kind, plus one for each further source of a kind (two at most).
fn score(c: &Candidate) -> i32 {
    let mut total = 0;
    let mut seen: Vec<EvidenceKind> = Vec::new();
    for e in &c.evidence {
        if seen.contains(&e.kind) {
            continue;
        }
        seen.push(e.kind);
        let same: Vec<_> = c.evidence.iter().filter(|x| x.kind == e.kind).collect();
        let mut sources: Vec<&str> = same.iter().map(|x| x.source.0.as_str()).collect();
        sources.sort_unstable();
        sources.dedup();
        let weight = same.iter().map(|x| i32::from(x.weight)).max().unwrap_or(0);
        total += weight + (sources.len() as i32 - 1).min(2);
    }
    total
}

fn all_scanners() -> [&'static dyn Scanner; 5] {
    [&RegSoftware, &RegAppPaths, &RegRun, &RegEnv, &RefAny]
}

fn thunderbird() -> OtherApps {
    OtherApps::new(vec![OtherApp {
        name: "Mozilla Thunderbird".into(),
        roots: vec![THUNDERBIRD.into()],
        files: vec![format!(r"{THUNDERBIRD}\uninstall\helper.exe")],
        keys: vec![
            r"HKLM\SOFTWARE\Mozilla\Thunderbird".into(),
            r"HKLM\SOFTWARE\Mozilla\Mozilla Thunderbird".into(),
            format!(r"{}\Mozilla\Thunderbird", hkcu()),
        ],
        anchors: vec![AnchorRef {
            kind: AnchorKind::Exe,
            text: "thunderbird.exe".into(),
        }],
    }])
}

fn with_thunderbird(fixture: FixtureBuilder) -> FixtureBuilder {
    fixture
        .dir(THUNDERBIRD)
        .file(&format!(r"{THUNDERBIRD}\thunderbird.exe"), 10)
        .sz(
            r"HKLM\SOFTWARE\Mozilla\Thunderbird\TaskBarIDs",
            THUNDERBIRD,
            "D78BF5DD33499EC2",
        )
        .sz(
            r"HKLM\SOFTWARE\Mozilla\Mozilla Thunderbird\140.0 (en-US)\Main",
            "Install Directory",
            THUNDERBIRD,
        )
        .dword(
            &format!(r"{}\Mozilla\Thunderbird\Launcher", hkcu()),
            &format!(r"{THUNDERBIRD}\thunderbird.exe|Launcher"),
            1,
        )
        .sz(
            &format!(r"HKLM\SOFTWARE\{CV}\App Paths\thunderbird.exe"),
            "",
            &format!(r"{THUNDERBIRD}\thunderbird.exe"),
        )
        .sz(
            &format!(r"HKLM\SOFTWARE\{CV}\Run"),
            "Thunderbird Agent",
            &format!(r#""{THUNDERBIRD}\thunderbird.exe" --background"#),
        )
}

// ---------------------------------------------------------------------------------------------------------
// REG-SOFTWARE
// ---------------------------------------------------------------------------------------------------------

#[test]
fn software_firefox_golden() {
    let world = World::new(firefox_leftovers(), firefox());
    let found = world.scan(&RegSoftware);
    golden::check("reg_software_firefox", &found);

    // The product key, by the app-named-key rule plus its name.
    let product = expect(&found, &key(r"HKLM\SOFTWARE\Mozilla\Firefox"));
    assert_eq!(product.action, Action::DeleteKey);
    assert!(has(product, EvidenceKind::AppNamedKeyWithRootRef));
    assert!(tier_a_in_scope(product) && score(product) >= 8);
    assert!(product.blockers.is_empty(), "{:?}", product.blockers);
    let user_product = expect(&found, &key(format!(r"{}\Mozilla\Firefox", hkcu())));
    assert!(has(user_product, EvidenceKind::AppNamedKeyWithRootRef));

    // The co-removed Maintenance Service's keys, attributed through its own fingerprint.
    for path in [
        r"HKLM\SOFTWARE\Mozilla\MaintenanceService",
        r"HKLM\SOFTWARE\WOW6432Node\Mozilla\MaintenanceService",
    ] {
        let service = expect(&found, &key(path));
        assert_eq!(service.owner.display_name, "Mozilla Maintenance Service");
        assert_eq!(service.action, Action::DeleteKey);
        assert!(has(service, EvidenceKind::ProductSubfolderOfVendor));
        // Nothing in the key names the service's root: listed, not Tier A.
        assert!(!tier_a_in_scope(service) && score(service) >= 4);
    }

    // `mozilla.org`: a vendor container, delete-if-empty, Weak: its name counts once, plus the window.
    let org = expect(&found, &key(r"HKLM\SOFTWARE\mozilla.org"));
    assert_eq!(org.action, Action::RemoveDirIfEmpty);
    assert!(!tier_a_in_scope(org));
    assert_eq!(score(org), 3, "{:?}", org.evidence);
    let marker = &org.evidence[0];
    assert_eq!(marker.kind, EvidenceKind::VendorContainer);
    assert_eq!(marker.detail.get("empty_after_plan"), Some("pending"));
    assert_eq!(marker.detail.get("children"), Some(r#"["Mozilla\\"]"#));

    // The user's vendor key: delete-if-empty with the complete listing.
    let user_vendor = expect(&found, &key(format!(r"{}\Mozilla", hkcu())));
    assert_eq!(user_vendor.action, Action::RemoveDirIfEmpty);
    assert_eq!(
        user_vendor.evidence[0].detail.get("children"),
        Some(r#"["Firefox\\"]"#)
    );
    assert_eq!(kinds(user_vendor), vec![EvidenceKind::VendorContainer]);

    // `HKLM\SOFTWARE\Mozilla` exists on clean Windows and is deny-listed: never a target.
    assert!(find(&found, &key(r"HKLM\SOFTWARE\Mozilla")).is_none());
    assert!(find(&found, &key(r"HKLM\SOFTWARE\Mozilla\NativeMessagingHosts")).is_none());

    // Values that name the root are value targets; the keys holding them are not offered.
    let taskbar = expect(
        &found,
        &value(r"HKLM\SOFTWARE\Mozilla\Firefox\TaskBarIDs", FIREFOX),
    );
    assert_eq!(taskbar.action, Action::DeleteValue);
    assert_eq!(
        kinds(taskbar),
        vec![
            EvidenceKind::InPreUninstallRefSnapshot,
            EvidenceKind::PointsIntoInstallRoot,
            EvidenceKind::DanglingRef
        ]
    );
    let exe = format!(r"{FIREFOX}\firefox.exe");
    for name in [format!("{exe}|Launcher"), format!("{exe}|Browser")] {
        let launcher = expect(&found, &value(launcher_key(), &name));
        assert!(has(launcher, EvidenceKind::InPreUninstallRefSnapshot));
    }
    assert!(find(&found, &key(r"HKLM\SOFTWARE\Mozilla\Firefox\TaskBarIDs")).is_none());
    assert!(find(&found, &key(launcher_key())).is_none());
    // The product key names the value candidates inside it.
    assert!(product.children.contains(&taskbar.id));
}

/// A vendor key under `HKLM\SOFTWARE\WOW6432Node` is a separate key from its 64-bit namesake, so
/// `HKLM\SOFTWARE\Mozilla` on clean Windows (both committed baselines hold it) does not make the 32-bit
/// one Windows' own: it is a delete-if-empty container. Only a baseline that records the 32-bit
/// spelling itself withholds it.
#[test]
fn software_wow_vendor_key_ignores_the_baseline_twin() {
    let wow = key(r"HKLM\SOFTWARE\WOW6432Node\Mozilla");
    for twin_only in [
        baseline(&[
            r"HKLM\SOFTWARE\Mozilla",
            r"HKLM\SOFTWARE\Mozilla\NativeMessagingHosts",
        ]),
        baseline(&[]),
    ] {
        let mut world = World::new(firefox_leftovers(), firefox());
        world.baseline = Some(twin_only);
        let found = world.scan(&RegSoftware);
        let vendor = expect(&found, &wow);
        assert_eq!(vendor.action, Action::RemoveDirIfEmpty);
        let marker = &vendor.evidence[0];
        assert_eq!(marker.kind, EvidenceKind::VendorContainer);
        assert_eq!(marker.detail.get("empty_after_plan"), Some("pending"));
        assert_eq!(
            marker.detail.get("children"),
            Some(r#"["MaintenanceService\\"]"#)
        );
        assert!(vendor.blockers.is_empty(), "{:?}", vendor.blockers);
        // The 64-bit vendor key stays out: the baseline and the deny-list both keep it.
        assert!(find(&found, &key(r"HKLM\SOFTWARE\Mozilla")).is_none());
    }

    // Clean Windows has the 32-bit key itself: never a target.
    let mut world = World::new(firefox_leftovers(), firefox());
    world.baseline = Some(baseline(&[r"HKLM\SOFTWARE\WOW6432Node\Mozilla"]));
    assert!(find(&world.scan(&RegSoftware), &wow).is_none());
}

#[test]
fn software_with_thunderbird_lists_nothing_of_thunderbirds() {
    let mut world = World::new(with_thunderbird(firefox_leftovers()), firefox());
    world.other_apps = thunderbird();
    for scanner in all_scanners() {
        let found = world.scan(scanner);
        for c in &found {
            let text = golden::target_text(&c.target);
            assert!(!text.contains("Thunderbird"), "{}: {text}", scanner.id());
        }
        if scanner.id() == "REG-SOFTWARE" {
            golden::check("reg_software_firefox_with_thunderbird", &found);
            // Firefox's own key is still offered whole.
            let product = expect(&found, &key(r"HKLM\SOFTWARE\Mozilla\Firefox"));
            assert!(has(product, EvidenceKind::AppNamedKeyWithRootRef));
            // The user's vendor key holds Thunderbird's key: it cannot become empty and is not
            // offered.
            assert!(find(&found, &key(format!(r"{}\Mozilla", hkcu()))).is_none());
        }
    }
}

#[test]
fn software_key_referring_to_another_app_is_blocked() {
    let fixture = with_thunderbird(firefox_leftovers()).sz(
        r"HKLM\SOFTWARE\Mozilla\Firefox\Shared",
        "Importer",
        &format!(r"{THUNDERBIRD}\thunderbird.exe"),
    );
    let mut world = World::new(fixture, firefox());
    world.other_apps = thunderbird();
    let found = world.scan(&RegSoftware);
    let product = expect(&found, &key(r"HKLM\SOFTWARE\Mozilla\Firefox"));
    assert!(!has(product, EvidenceKind::AppNamedKeyWithRootRef));
    assert!(!tier_a_in_scope(product));
    assert!(product.blockers.contains(&Blocker::ReferencedByOtherApp {
        app: "Mozilla Thunderbird".into()
    }));
}

#[test]
fn software_notepadpp_golden() {
    let world = World::new(
        machine()
            .sz(r"HKLM\SOFTWARE\WOW6432Node\Notepad++", "", NPP)
            // Windows' own Notepad settings: not this app's.
            .dword(&format!(r"{}\Microsoft\Notepad", hkcu()), "iWindowPosX", 1),
        notepadpp(),
    );
    let found = world.scan(&RegSoftware);
    golden::check("reg_software_notepadpp", &found);
    let product = expect(&found, &key(r"HKLM\SOFTWARE\WOW6432Node\Notepad++"));
    assert_eq!(product.action, Action::DeleteKey);
    assert!(tier_a_in_scope(product) && score(product) >= 8);
    assert_eq!(found.len(), 2, "the key and its default value");
}

#[test]
fn software_microsoft_keys_need_a_manifest_or_a_skeleton() {
    let ms = r"HKLM\SOFTWARE\Microsoft\Git";
    let fixture = || {
        machine().sz(ms, "InstallPath", GIT).sz(
            r"HKLM\SOFTWARE\Microsoft\Windows\Git",
            "InstallPath",
            GIT,
        )
    };
    // Named after the app and pointing into its root, but under SOFTWARE\Microsoft: nothing.
    let world = World::new(fixture(), git());
    let found = world.scan(&RegSoftware);
    assert!(found.is_empty(), "{}", golden::render(&found));

    // With the installer's key-create record the key is offered, on that evidence alone.
    let mut fp = git();
    fp.inno = vec![inno(InnoRecordKind::RegDeleteEntireKey, key(ms))];
    let world = World::new(fixture(), fp);
    let found = world.scan(&RegSoftware);
    assert_eq!(found.len(), 1, "{}", golden::render(&found));
    let c = expect(&found, &key(ms));
    assert_eq!(
        kinds(c),
        vec![EvidenceKind::InstallerManifest(
            purge_model::ManifestKind::Inno
        )]
    );
    assert_eq!(c.action, Action::DeleteKey);
}

#[test]
fn software_inno_key_records() {
    let own = r"HKLM\SOFTWARE\GitForWindows";
    let vendor = r"HKLM\SOFTWARE\Shared Tools Vendor";
    let mut fp = git();
    fp.inno = vec![
        inno(InnoRecordKind::RegDeleteEntireKey, key(own)),
        inno(InnoRecordKind::RegDeleteKeyIfEmpty, key(vendor)),
    ];
    let world = World::new(
        machine()
            .sz(own, "InstallPath", GIT)
            .sz(&format!(r"{vendor}\Other Product"), "x", "y"),
        fp,
    );
    let found = world.scan(&RegSoftware);
    golden::check("reg_software_git_inno", &found);
    assert_eq!(expect(&found, &key(own)).action, Action::DeleteKey);
    // "Delete if empty" in the log is not ownership of what is in the key.
    let shared = expect(&found, &key(vendor));
    assert_eq!(shared.action, Action::RemoveDirIfEmpty);
    assert!(tier_a_in_scope(shared));
}

#[test]
fn software_key_older_than_the_install_is_not_app_named() {
    let path = r"HKLM\SOFTWARE\WOW6432Node\Notepad++";
    let mut fp = notepadpp();
    fp.window.install_time = Some(FileTime(5_000_000_000_000));
    fp.window.t_end = Some(FileTime(5_000_100_000_000));
    let world = World::new(machine().sz(path, "", NPP).key_lwt(path, 1_000), fp);
    let found = world.scan(&RegSoftware);
    let c = expect(&found, &key(path));
    assert!(!has(c, EvidenceKind::AppNamedKeyWithRootRef));
    assert!(c.blockers.contains(&Blocker::OlderThanInstall));
}

// ---------------------------------------------------------------------------------------------------------
// REG-APPPATHS
// ---------------------------------------------------------------------------------------------------------

fn app_paths(base: &str) -> String {
    format!(r"{base}\{CV}\App Paths")
}

#[test]
fn apppaths_golden() {
    let exe = format!(r"{FIREFOX}\firefox.exe");
    let machine_paths = app_paths(r"HKLM\SOFTWARE");
    let fixture = with_thunderbird(machine())
        .sz(&format!(r"{machine_paths}\firefox.exe"), "", &exe)
        .sz(&format!(r"{machine_paths}\firefox.exe"), "Path", FIREFOX)
        // Named like the app's exe but leading elsewhere: someone else's.
        .sz(
            &format!(r"{}\firefox.exe", app_paths(&hkcu())),
            "",
            r"D:\Portable\firefox.exe",
        )
        .sz(
            &format!(r"{machine_paths}\wordpad.exe"),
            "",
            r"C:\Windows\write.exe",
        )
        .sz(
            r"HKLM\SOFTWARE\Classes\Applications\firefox.exe\shell\open\command",
            "",
            &format!(r#""{exe}" -osint -url "%1""#),
        )
        .sz(
            &format!(r"HKU\{SID}_Classes\Applications\notepad.exe\shell\open\command"),
            "",
            r"C:\Windows\notepad.exe %1",
        );
    let mut world = World::new(fixture, firefox());
    world.other_apps = thunderbird();
    let found = world.scan(&RegAppPaths);
    golden::check("reg_apppaths_firefox", &found);

    assert_eq!(found.len(), 2, "{}", golden::render(&found));
    for path in [
        format!(r"{machine_paths}\firefox.exe"),
        r"HKLM\SOFTWARE\Classes\Applications\firefox.exe".to_owned(),
    ] {
        let c = expect(&found, &key(path));
        assert_eq!(c.action, Action::DeleteKey);
        assert!(has(c, EvidenceKind::ChainedRef));
        assert!(has(c, EvidenceKind::AppNamedKeyWithRootRef));
        assert!(tier_a_in_scope(c) && score(c) >= 8);
        assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    }
    // The container is structural.
    assert!(find(&found, &key(machine_paths)).is_none());
}

/// VM run x0-git-toolsdir (`App Paths\rg.exe`): the user's own tool sits in the app's folder, the
/// uninstaller left it there, and its `App Paths` key was preselected because it leads into the root.
#[test]
fn apppaths_key_of_a_file_that_outlived_the_uninstall_is_not_offered() {
    let tool = format!(r"{GIT}\rg.exe");
    let own = format!(r"{GIT}\git-bash.exe");
    let paths = app_paths(r"HKLM\SOFTWARE");
    let fixture = || {
        machine()
            .file(&tool, 5_000)
            .sz(&format!(r"{paths}\rg.exe"), "", &tool)
            .sz(&format!(r"{paths}\git-bash.exe"), "", &own)
    };
    let mut fp = git();
    // The harvest's exe set is every program in the root, the user's tool included.
    fp.exes.push(purge_model::ExeFile {
        path: tool.clone(),
        main: false,
    });
    let world = World::new(fixture(), fp.clone());
    let found = world.scan(&RegAppPaths);
    // The registration of a program that still works, which nothing shows to be the app's.
    assert!(find(&found, &key(format!(r"{paths}\rg.exe"))).is_none());
    // The key of the program the uninstaller removed is the app's as before.
    let gone = expect(&found, &key(format!(r"{paths}\git-bash.exe")));
    assert!(tier_a_in_scope(gone) && score(gone) >= 8);
    // While the app is not verified gone its files are all still there: a file that is present
    // says nothing, and the key is listed (never Tier A) as before.
    let live = World::new(fixture().file(&own, 5_000), fp.clone());
    let ctx = purge_scan::framework::ScanCtx {
        verify_gone: Some(purge_model::VerifyGone::new(false, true, false)),
        ..live.ctx()
    };
    let view = purge_scan::framework::AppIdentityView::from_fingerprint(&live.fp, &live.env);
    let found = ctx.run(&RegAppPaths, &view);
    for exe in ["rg.exe", "git-bash.exe"] {
        let c = expect(&found, &key(format!(r"{paths}\{exe}")));
        assert!(c.evidence.iter().all(|e| e.tier != Tier::A), "{c:?}");
    }
    // The uninstaller removed the programs and left its Uninstall key behind: verify-gone fails as
    // a whole, and the files tell the same story as before.
    let half = World::new(fixture(), fp.clone());
    let ctx = purge_scan::framework::ScanCtx {
        verify_gone: Some(purge_model::VerifyGone::new(false, true, true)),
        ..half.ctx()
    };
    let view = purge_scan::framework::AppIdentityView::from_fingerprint(&half.fp, &half.env);
    let found = ctx.run(&RegAppPaths, &view);
    assert!(find(&found, &key(format!(r"{paths}\rg.exe"))).is_none());
    assert!(find(&found, &key(format!(r"{paths}\git-bash.exe"))).is_some());
    // With no main exe known, "the main exes are gone" holds of nothing: only the whole check
    // counts, and the key is listed as while the app is installed.
    let mut blind = fp.clone();
    for exe in &mut blind.exes {
        exe.main = false;
    }
    let world = World::new(fixture(), blind);
    let ctx = purge_scan::framework::ScanCtx {
        verify_gone: Some(purge_model::VerifyGone::new(false, true, true)),
        ..world.ctx()
    };
    let view = purge_scan::framework::AppIdentityView::from_fingerprint(&world.fp, &world.env);
    let found = ctx.run(&RegAppPaths, &view);
    assert!(find(&found, &key(format!(r"{paths}\rg.exe"))).is_some());

    // A file the installer's log names stays the app's when it survives (it was locked).
    fp.inno = vec![purge_model::InnoRecord {
        kind: InnoRecordKind::DeleteFile,
        target: Target::Path { path: tool.clone() },
        view: None,
        user_hive: false,
        existed_before: false,
        shared: false,
        key_create: false,
    }];
    let world = World::new(fixture(), fp);
    let found = world.scan(&RegAppPaths);
    assert!(tier_a_in_scope(expect(
        &found,
        &key(format!(r"{paths}\rg.exe"))
    )));
}

/// Extended campaign x2, the foreign items offered as Likely: a `Classes\Applications\<exe>` key was
/// listed on the bare file name of a main exe, whatever it held. A portable copy of the same program
/// (x2-npp-userfiles), another install of it (x2-vscode-userstate) and a sibling's `updater.exe`
/// (x2-ff-devedition) carry the name too.
#[test]
fn apppaths_bare_exe_name_is_not_ownership() {
    let user = format!(r"HKU\{SID}_Classes\Applications");
    let named = format!(r"{user}\firefox.exe");
    let generic = r"HKLM\SOFTWARE\Classes\Applications\updater.exe";
    let mut fp = firefox();
    fp.exes.push(purge_model::ExeFile {
        path: format!(r"{FIREFOX}\updater.exe"),
        main: true,
    });
    let scan = |fixture: FixtureBuilder, fp: &purge_model::Fingerprint| {
        World::new(fixture, fp.clone()).scan(&RegAppPaths)
    };

    // The product's own exe name and nothing that points anywhere: offered, on the name alone.
    let found = scan(machine().sz(&named, "FriendlyAppName", "Firefox"), &fp);
    let c = expect(&found, &key(named.clone()));
    assert!(has(c, EvidenceKind::ChainedRef));
    assert!(c.evidence.iter().all(|e| e.tier != Tier::A), "{c:?}");

    // The same key of a portable copy: its command, its icon or a path below a variable leads
    // somewhere else.
    for (sub, name, data) in [
        (
            r"\shell\open\command",
            "",
            r#""C:\Users\tester\Tools\ff-portable\firefox.exe" -osint -url "%1""#,
        ),
        (r"\DefaultIcon", "", r"D:\Portable\firefox.exe,0"),
        ("", "Icon", r"%LOCALAPPDATA%\Portable\firefox.exe"),
        ("", "Share", r"\\server\tools\firefox.exe"),
    ] {
        let fixture = machine().sz(&named, "FriendlyAppName", "Firefox").sz(
            &format!("{named}{sub}"),
            name,
            data,
        );
        assert!(scan(fixture, &fp).is_empty(), "{data}");
    }
    // A path that is binary data is a path all the same.
    let bytes: Vec<u8> = r"D:\Portable\firefox.exe"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert!(scan(machine().binary(&named, "Target", bytes), &fp).is_empty());
    // Data that may hold a path unseen counts as holding one: binary data too large to be read
    // for text, and a string with text after its end.
    let plain = machine().sz(&named, "FriendlyAppName", "Firefox");
    assert_eq!(
        scan(plain.clone().binary(&named, "Small", vec![0x41; 64]), &fp).len(),
        1
    );
    assert!(scan(plain.clone().binary(&named, "Large", vec![0x41; 5000]), &fp).is_empty());
    let after_end: Vec<u8> = "Firefox\0D:\\Portable\\firefox.exe\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let hidden = purge_source::types::RegData {
        ty: purge_source::types::REG_SZ,
        ..purge_source::types::RegData::from_binary(after_end)
    };
    assert!(scan(plain.clone().value(&named, "Note", hidden), &fp).is_empty());
    // So does data that was not read in full.
    let mut cut_short = purge_source::types::RegData::from_sz("Firefox");
    cut_short.truncated = true;
    assert!(scan(plain.clone().value(&named, "Cut", cut_short), &fp).is_empty());
    // And a key that was not read in full (a link below it): the rest may hold a path.
    let linked = plain.link(&format!(r"{named}\shell"), r"HKLM\SOFTWARE\Elsewhere");
    assert!(scan(linked, &fp).is_empty());

    // A sibling install that is known claims the name: the key is listed as kept for it.
    let portable = machine().sz(&named, "FriendlyAppName", "Firefox").sz(
        &format!(r"{named}\DefaultIcon"),
        "",
        r"C:\Program Files\Firefox Developer Edition\firefox.exe,0",
    );
    let mut world = World::new(portable, fp.clone());
    world.other_apps = OtherApps::new(vec![OtherApp {
        name: "Firefox Developer Edition".into(),
        anchors: vec![AnchorRef {
            kind: AnchorKind::Exe,
            text: "firefox.exe".into(),
        }],
        ..OtherApp::default()
    }]);
    let found = world.scan(&RegAppPaths);
    let kept = expect(&found, &key(named.clone()));
    assert!(kept.blockers.contains(&Blocker::ReferencedByOtherApp {
        app: "Firefox Developer Edition".into()
    }));

    // A name any product may use, with nothing to check it against: not offered.
    let flags = || {
        machine()
            .sz(generic, "NoOpenWith", "")
            .dword(generic, "IsHostApp", 1)
    };
    assert!(scan(flags(), &fp).is_empty());
    // The installer's record covers the key: it is the app's whatever its name.
    let mut recorded = fp.clone();
    recorded.inno = vec![inno(InnoRecordKind::RegDeleteEntireKey, key(generic))];
    let found = scan(flags(), &recorded);
    assert!(tier_a_in_scope(expect(&found, &key(generic))));
    // And so does a path in it that leads into the app.
    let command = format!(r#""{FIREFOX}\updater.exe" /bg"#);
    let found = scan(
        flags().sz(&format!(r"{generic}\shell\open\command"), "", &command),
        &fp,
    );
    assert!(tier_a_in_scope(expect(&found, &key(generic))));
}

#[test]
fn apppaths_exe_claimed_by_another_app_is_blocked() {
    let exe = format!(r"{FIREFOX}\firefox.exe");
    let path = format!(r"{}\firefox.exe", app_paths(r"HKLM\SOFTWARE"));
    let mut world = World::new(machine().sz(&path, "", &exe), firefox());
    world.other_apps = OtherApps::new(vec![OtherApp {
        name: "Firefox Developer Edition".into(),
        anchors: vec![AnchorRef {
            kind: AnchorKind::Exe,
            text: "firefox.exe".into(),
        }],
        ..OtherApp::default()
    }]);
    let found = world.scan(&RegAppPaths);
    let c = expect(&found, &key(path));
    assert!(c.blockers.contains(&Blocker::ReferencedByOtherApp {
        app: "Firefox Developer Edition".into()
    }));
}

// ---------------------------------------------------------------------------------------------------------
// REG-RUN
// ---------------------------------------------------------------------------------------------------------

fn run_key(base: &str, list: &str) -> String {
    format!(r"{base}\{CV}\{list}")
}

fn approved(base: &str, list: &str) -> String {
    format!(r"{base}\{CV}\Explorer\StartupApproved\{list}")
}

const ENABLED: [u8; 12] = [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[test]
fn run_golden() {
    let hklm = r"HKLM\SOFTWARE";
    let wow = r"HKLM\SOFTWARE\WOW6432Node";
    let tray = format!(r#""{GIT}\cmd\git-tray.exe" --minimized"#);
    let startup = r"C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup";
    let fixture = with_thunderbird(machine())
        .sz(&run_key(hklm, "Run"), "GitTray", &tray)
        .binary(&approved(hklm, "Run"), "GitTray", ENABLED.to_vec())
        .binary(
            &approved(hklm, "Run"),
            "Thunderbird Agent",
            ENABLED.to_vec(),
        )
        // A 32-bit entry goes with `Run32`, not with the `Run` switch of the same name.
        .sz(
            &run_key(wow, "Run"),
            "GitUpdate",
            &format!(r"{GIT}\update.exe"),
        )
        .binary(&approved(hklm, "Run32"), "GitUpdate", ENABLED.to_vec())
        .binary(&approved(hklm, "Run"), "GitUpdate", ENABLED.to_vec())
        .sz(
            &run_key(&hkcu(), "RunOnce"),
            "GitCleanup",
            &format!(r"{GIT}\cleanup.cmd"),
        )
        .sz(
            &run_key(&hkcu(), "Run"),
            "OneDrive",
            r"C:\Users\tester\OneDrive.exe /background",
        )
        // The uninstaller removed this Run value; its switch stayed behind.
        .binary(&approved(&hkcu(), "Run"), "GitAgent", ENABLED.to_vec())
        // A Startup-folder shortcut into the root, and one of somebody else's.
        .binary(
            &approved(&hkcu(), "StartupFolder"),
            "Git Tray.lnk",
            ENABLED.to_vec(),
        )
        .binary(
            &approved(&hkcu(), "StartupFolder"),
            "Mail.lnk",
            ENABLED.to_vec(),
        )
        // The same, made by the installer: its log names the shortcut.
        .binary(
            &approved(&hkcu(), "StartupFolder"),
            "Git Agent.lnk",
            ENABLED.to_vec(),
        )
        .shortcut(
            &format!(r"{startup}\Git Agent.lnk"),
            ShortcutInfo {
                raw_path: Some(format!(r"{GIT}\cmd\git-agent.exe")),
                ..ShortcutInfo::default()
            },
        )
        .shortcut(
            &format!(r"{startup}\Git Tray.lnk"),
            ShortcutInfo {
                raw_path: Some(format!(r"{GIT}\cmd\git-tray.exe")),
                ..ShortcutInfo::default()
            },
        )
        .shortcut(
            &format!(r"{startup}\Mail.lnk"),
            ShortcutInfo {
                raw_path: Some(format!(r"{THUNDERBIRD}\thunderbird.exe")),
                ..ShortcutInfo::default()
            },
        );
    let mut fp = git();
    fp.anchors.run_entries = vec![purge_model::RunEntry {
        key: run_key(&hkcu(), "Run"),
        name: "GitAgent".into(),
        data: format!(r"{GIT}\agent.exe"),
    }];
    fp.ref_snapshot = vec![snap(
        value(run_key(hklm, "Run"), "GitTray"),
        RefCarrier::Data,
        AnchorKind::Root,
        GIT,
    )];
    // The installer's log records one of the start entries; nothing shows who made the others.
    fp.inno = vec![
        inno(
            InnoRecordKind::RegDeleteValue,
            value(run_key(hklm, "Run"), "GitTray"),
        ),
        inno(
            InnoRecordKind::DeleteFile,
            Target::Path {
                path: format!(r"{startup}\Git Agent.lnk"),
            },
        ),
    ];
    let mut world = World::new(fixture, fp);
    world.other_apps = thunderbird();
    let found = world.scan(&RegRun);
    golden::check("reg_run_git", &found);

    let targets = [
        value(run_key(hklm, "Run"), "GitTray"),
        value(approved(hklm, "Run"), "GitTray"),
        value(run_key(wow, "Run"), "GitUpdate"),
        value(approved(hklm, "Run32"), "GitUpdate"),
        value(run_key(&hkcu(), "RunOnce"), "GitCleanup"),
        value(approved(&hkcu(), "Run"), "GitAgent"),
        value(approved(&hkcu(), "StartupFolder"), "Git Tray.lnk"),
        value(approved(&hkcu(), "StartupFolder"), "Git Agent.lnk"),
    ];
    assert_eq!(found.len(), targets.len(), "{}", golden::render(&found));
    for (n, target) in targets.iter().enumerate() {
        let c = expect(&found, target);
        // Value targets only.
        assert_eq!(c.action, Action::DeleteValue);
        assert!(c.blockers.is_empty());
        // `Run` is written by every program and by the user (VM run x0-git-userstate: the user's own
        // `GitAutoFetch` entry was preselected). Tier A only for the entry the installer recorded and
        // its switch, and for the switch of a Startup shortcut the installer's log names. A Startup
        // shortcut into the app's folder that nobody recorded (index 6) is the user's as likely as
        // the app's: its switch is listed and never preselected.
        let owned = n < 2 || n == 7;
        assert_eq!(tier_a_in_scope(c), owned, "{}", golden::target_text(target));
    }
    let run = expect(&found, &targets[0]);
    assert!(has(run, EvidenceKind::InPreUninstallRefSnapshot));
    assert!(has(run, EvidenceKind::PointsIntoInstallRoot));
    assert!(has(run, EvidenceKind::DanglingRef));
    assert!(
        run.evidence
            .iter()
            .any(|e| matches!(e.kind, EvidenceKind::InstallerManifest(_)))
    );
    // Not recorded: the same evidence, capped at Tier B and marked as found in a shared place.
    let unrecorded = expect(&found, &targets[2]);
    assert!(unrecorded.evidence.iter().all(|e| e.tier != Tier::A));
    let switch = expect(&found, &targets[1]);
    assert!(has(switch, EvidenceKind::ChainedRef) && score(switch) >= 8);
    assert!(find(&found, &value(approved(hklm, "Run"), "GitUpdate")).is_none());
}

/// Rule T: evidence that rests on a per-user registration is tagged `UserWritable`, also on a
/// machine-wide target, so that the policy can downgrade it there.
#[test]
fn run_rule_t_user_sourced_evidence_on_an_hklm_target() {
    let root = r"C:\Users\tester\AppData\Local\Programs\Acme";
    let mut fp = git();
    fp.app.program_id = ProgramId::user(SID, View::K64, "Acme").expect("a valid program id");
    fp.roots[0].path = root.into();
    fp.roots[0].trust = SourceTrust::UserWritable;
    fp.roots[0].source = RootSource::ArpInstallLocation;
    fp.exes[0].path = format!(r"{root}\acme.exe");
    let machine_run = run_key(r"HKLM\SOFTWARE", "Run");
    let user_run = run_key(&hkcu(), "Run");
    let command = format!(r"{root}\acme.exe --tray");
    let world = World::new(
        machine()
            .dir(r"C:\Users\tester\AppData\Local\Programs")
            .sz(&machine_run, "Acme", &command)
            .sz(&user_run, "Acme", &command),
        fp,
    );
    let found = world.scan(&RegRun);
    assert_eq!(found.len(), 2, "{}", golden::render(&found));
    for path in [machine_run, user_run] {
        let c = expect(&found, &value(path, "Acme"));
        assert!(!c.evidence.is_empty());
        assert!(
            c.evidence
                .iter()
                .all(|e| e.trust == SourceTrust::UserWritable),
            "{:?}",
            c.evidence
        );
    }
}

// ---------------------------------------------------------------------------------------------------------
// REG-ENV
// ---------------------------------------------------------------------------------------------------------

fn git_cmd() -> String {
    format!(r"{GIT}\cmd")
}

fn path_value(entries: &[&str]) -> FixtureBuilder {
    machine().expand_sz(MACHINE_ENV, "Path", &entries.join(";"))
}

fn git_with_path_snapshot() -> purge_model::Fingerprint {
    let mut fp = git();
    fp.ref_snapshot = vec![snap(
        Target::RegMultiSzSegment {
            path: MACHINE_ENV.into(),
            name: "Path".into(),
            segment: git_cmd(),
            index: Some(2),
        },
        RefCarrier::Segment,
        AnchorKind::Root,
        GIT,
    )];
    fp
}

#[test]
fn env_git_path_segment_golden() {
    let cmd = git_cmd();
    let fixture = path_value(&[
        r"%SystemRoot%\system32",
        r"C:\Windows",
        &cmd,
        r"C:\Tools\bin",
    ])
    .sz(MACHINE_ENV, "OS", "Windows_NT")
    .expand_sz(
        &format!(r"HKU\{SID}\Environment"),
        "Path",
        r"%USERPROFILE%\AppData\Local\Microsoft\WindowsApps;",
    );
    let world = World::new(fixture, git_with_path_snapshot());
    let found = world.scan(&RegEnv);
    golden::check("reg_env_git_path", &found);

    assert_eq!(found.len(), 1, "{}", golden::render(&found));
    let c = &found[0];
    // Spelled the way the rig canonicalises and a plan must name it.
    assert_eq!(c.target, segment(MACHINE_ENV_PLAN, "Path", &cmd));
    assert_eq!(c.action, Action::EditSegment);
    assert_eq!(
        kinds(c),
        vec![
            EvidenceKind::InPreUninstallRefSnapshot,
            EvidenceKind::PointsIntoInstallRoot,
            EvidenceKind::DanglingRef
        ]
    );
    assert!(c.evidence.iter().all(|e| e.scope == Scope::Value));
    assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    // REF-ANY leaves the Environment keys to this scanner.
    assert!(world.scan(&RefAny).is_empty());
}

#[test]
fn env_segment_that_was_not_the_apps_at_harvest_yields_nothing() {
    let cmd = git_cmd();
    // Not in the snapshot: the entry was added by someone else, or after the harvest.
    let world = World::new(path_value(&[r"C:\Windows", &cmd]), git());
    assert!(world.scan(&RegEnv).is_empty());

    // The Inno log says the value existed before the install.
    let mut fp = git_with_path_snapshot();
    let mut record = inno(InnoRecordKind::RegDeleteValue, value(MACHINE_ENV, "Path"));
    record.existed_before = true;
    fp.inno = vec![record];
    let world = World::new(path_value(&[r"C:\Windows", &cmd]), fp);
    assert!(world.scan(&RegEnv).is_empty());

    // The directory is still there: the entry still works for whatever is in it.
    let world = World::new(
        path_value(&[r"C:\Windows", &cmd]).dir(&cmd),
        git_with_path_snapshot(),
    );
    assert!(world.scan(&RegEnv).is_empty());
}

#[test]
fn env_user_path_is_compared_expanded_and_snapshot_may_name_the_value() {
    let user_env = format!(r"HKU\{SID}\Environment");
    let written = r"%ProgramFiles%\Git\cmd\";
    let mut fp = git();
    // A harvest that recorded the value as a whole.
    fp.ref_snapshot = vec![snap(
        value(user_env.clone(), "Path"),
        RefCarrier::Data,
        AnchorKind::Root,
        GIT,
    )];
    let world = World::new(
        machine().expand_sz(
            &user_env,
            "Path",
            &format!(r"C:\Users\tester\bin;{written};{written}"),
        ),
        fp,
    );
    let found = world.scan(&RegEnv);
    assert_eq!(found.len(), 2, "{}", golden::render(&found));
    assert_eq!(found[0].target, segment(user_env.clone(), "Path", written));
    // The repeated entry is told apart by its position.
    assert_eq!(
        found[1].target,
        Target::RegMultiSzSegment {
            path: user_env,
            name: "Path".into(),
            segment: written.into(),
            index: Some(2),
        }
    );
    for c in &found {
        assert!(has(c, EvidenceKind::PointsIntoInstallRoot));
        assert!(has(c, EvidenceKind::DanglingRef));
    }
}

/// A directory name may hold a `;` when the entry is quoted. Cut at that `;`, the first half of
/// `"C:\Program Files\Git;x\bin"` reads as Git's folder and was offered as an entry to take out.
#[test]
fn env_semicolon_inside_quotes_does_not_split_an_entry() {
    let user_env = format!(r"HKU\{SID}\Environment");
    let mut fp = git();
    fp.ref_snapshot = vec![snap(
        value(user_env.clone(), "Path"),
        RefCarrier::Data,
        AnchorKind::Root,
        GIT,
    )];
    let theirs = format!(r#""{GIT};x\bin""#);
    let world = World::new(
        machine().expand_sz(
            &user_env,
            "Path",
            &format!(r"C:\Users\tester\bin;{theirs};C:\Tools"),
        ),
        fp.clone(),
    );
    let found = world.scan(&RegEnv);
    assert!(found.is_empty(), "{}", golden::render(&found));

    // A quote that is never closed runs to the end of the list, over the user's later entries:
    // nothing from the quote on is offered, with or without the installer's record on the value.
    let unclosed = format!(r#"C:\Users\tester\bin;"{GIT}\cmd;C:\Users\tester\tools;C:\Other"#);
    let mut recorded = fp.clone();
    recorded.inno = vec![inno(
        InnoRecordKind::RegDeleteValue,
        value(user_env.clone(), "Path"),
    )];
    for fp in [fp.clone(), recorded] {
        let world = World::new(machine().expand_sz(&user_env, "Path", &unclosed), fp);
        let found = world.scan(&RegEnv);
        assert!(found.is_empty(), "{}", golden::render(&found));
    }

    // The app's own quoted entry is still found, whole.
    let own = format!(r#""{GIT}\cmd""#);
    let world = World::new(
        machine().expand_sz(&user_env, "Path", &format!(r"{theirs};{own}")),
        fp,
    );
    let found = world.scan(&RegEnv);
    assert_eq!(found.len(), 1, "{}", golden::render(&found));
    assert_eq!(found[0].target, segment(user_env, "Path", &own));
}

/// The installer recorded `GIT_LIBS`; it now holds the app's directory and one of the user's inside
/// one pair of quotes. That is not "a variable that leads into the app's folder": it is listed and
/// the policy never ticks it.
#[test]
fn env_recorded_variable_with_a_quoted_list_is_not_preselected() {
    use purge_policy::band::{PolicyCtx, TargetScope, decide};
    let mut fp = git();
    fp.ref_snapshot = vec![snap(
        value(MACHINE_ENV, "GIT_LIBS"),
        RefCarrier::Data,
        AnchorKind::Root,
        GIT,
    )];
    fp.inno = vec![inno(
        InnoRecordKind::RegDeleteValue,
        value(MACHINE_ENV, "GIT_LIBS"),
    )];
    let decided = |data: &str| {
        let world = World::new(machine().sz(MACHINE_ENV, "GIT_LIBS", data), fp.clone());
        let found = world.scan(&RegEnv);
        assert_eq!(found.len(), 1, "{}", golden::render(&found));
        let decision = decide(
            &found[0],
            &PolicyCtx {
                mode: purge_model::ScanMode::Post,
                verify_gone: purge_model::VerifyGone::new(true, true, true),
                target_scope: TargetScope::Machine,
            },
        );
        (
            tier_a_in_scope(&found[0]),
            decision.band,
            decision.preselected,
        )
    };
    let (tier_a, band, ticked) = decided(&format!(r#""{GIT}\lib;C:\Users\tester\mylibs""#));
    assert!(!tier_a);
    assert_ne!(band, purge_model::Band::Safe);
    assert!(!ticked);
    // The same variable holding the app's directory alone is the installer's, and Safe.
    let (tier_a, band, ticked) = decided(&format!(r"{GIT}\lib"));
    assert!(tier_a);
    assert_eq!((band, ticked), (purge_model::Band::Safe, true));

    // One install run of the log found the variable in place: not the installer's alone, although
    // another run recorded it plainly.
    let mut found_in_place = inno(
        InnoRecordKind::RegDeleteValue,
        value(MACHINE_ENV, "GIT_LIBS"),
    );
    found_in_place.existed_before = true;
    fp.inno.push(found_in_place);
    let world = World::new(
        machine().sz(MACHINE_ENV, "GIT_LIBS", &format!(r"{GIT}\lib")),
        fp,
    );
    let found = world.scan(&RegEnv);
    assert!(
        found.iter().all(|c| !tier_a_in_scope(c)),
        "{}",
        golden::render(&found)
    );
}

/// An entry edit takes one entry's whole text out of the list. With the installer's record on the
/// user's `Path` and a fingerprint that names the value, an entry that begins with the app's folder
/// and holds more (through a variable that is a list, as a second quoted path, after a comma or a
/// blank) was offered Safe and ticked: the user's directory went with the app's. Such an entry is
/// not one directory and is not offered at all; one that is a bare reference to another variable
/// or has a comma in its name is one directory, listed and never ticked. Through the policy
/// (`purge_policy::band::decide`), whatever the fingerprint says.
#[test]
fn env_entry_that_holds_more_than_the_apps_directory_is_never_preselected() {
    use purge_model::Band;
    use purge_policy::band::{PolicyCtx, TargetScope, decide};
    let user_env = format!(r"HKU\{SID}\Environment");
    let cmd = git_cmd();
    let tools = r"C:\Users\tester\tools";
    let mut fp = git();
    // The broadest record a harvest can leave: the value as a whole, referring to the root.
    fp.ref_snapshot = vec![snap(
        value(user_env.clone(), "Path"),
        RefCarrier::Data,
        AnchorKind::Root,
        GIT,
    )];
    fp.inno = vec![inno(
        InnoRecordKind::RegDeleteValue,
        value(user_env.clone(), "Path"),
    )];
    let decided = |entry: &str, variable: Option<(&str, String)>| -> Vec<(Target, Band, bool)> {
        let mut fixture =
            machine().expand_sz(&user_env, "Path", &format!(r"C:\Users\tester\bin;{entry}"));
        if let Some((name, holds)) = &variable {
            fixture = fixture.sz(&user_env, name, holds);
        }
        let mut world = World::new(fixture, fp.clone());
        if let Some((name, holds)) = variable {
            world.env.insert(name.to_uppercase(), holds);
        }
        world
            .scan(&RegEnv)
            .iter()
            .map(|c| {
                let decision = decide(
                    c,
                    &PolicyCtx {
                        mode: purge_model::ScanMode::Post,
                        verify_gone: purge_model::VerifyGone::new(true, true, true),
                        target_scope: TargetScope::Machine,
                    },
                );
                assert_eq!(
                    decision.preselected,
                    decision.band == Band::Safe,
                    "{}",
                    golden::render(std::slice::from_ref(c))
                );
                (c.target.clone(), decision.band, decision.preselected)
            })
            .collect()
    };
    let entry_of = |text: &str, band: Band| {
        vec![(
            segment(user_env.clone(), "Path", text),
            band,
            band == Band::Safe,
        )]
    };

    // The control: the app's own entry, plain or quoted, is the installer's and Safe.
    assert_eq!(decided(&cmd, None), entry_of(&cmd, Band::Safe));
    let quoted = format!(r#""{cmd}\""#);
    assert_eq!(decided(&quoted, None), entry_of(&quoted, Band::Safe));
    let through = r"%ProgramFiles%\Git\cmd";
    assert_eq!(decided(through, None), entry_of(through, Band::Safe));

    // Not one directory: nothing is offered.
    for (entry, variable) in [
        (
            "%MYDIRS%".to_owned(),
            Some(("MYDIRS", format!("{cmd};{tools}"))),
        ),
        (format!(r#""{cmd}" "{tools}""#), None),
        (format!("{cmd},{tools}"), None),
        (format!("{cmd} {tools}"), None),
        // No second drive path: the quote left inside decides.
        (format!(r#""{cmd}" "tools""#), None),
        (format!(r#""{cmd}"\bin"#), None),
        // A tab or a line break separates two things.
        (format!("{cmd}\ttools"), None),
        (format!("{cmd}\r\n{tools}"), None),
        // `..` is not resolved by anything here: the entry starts with the app's folder and
        // leads out of it, as written or through a variable.
        (format!(r"{cmd}\..\..\..\Users\tester\tools"), None),
        (format!(r"{cmd}\.\x"), None),
        (
            format!(r"{cmd}\%UP%"),
            Some(("UP", r"..\..\..\Users\tester\tools".to_owned())),
        ),
        (format!(r#"{cmd}" "{tools}"#), None),
        (
            "%MYDIRS%".to_owned(),
            Some(("MYDIRS", format!(r#"{cmd}" "{tools}"#))),
        ),
        (
            "%MYDIRS%".to_owned(),
            Some(("MYDIRS", format!("{cmd},{tools}"))),
        ),
        (
            r"%MYDIRS%\bin".to_owned(),
            Some(("MYDIRS", format!("{cmd};{tools}"))),
        ),
    ] {
        assert_eq!(
            decided(&entry, variable.clone()),
            [],
            "{entry} {variable:?}"
        );
    }

    // One directory that is not provably the installer's entry: listed, not ticked.
    assert_eq!(
        decided("%MYDIR%", Some(("MYDIR", cmd.clone()))),
        entry_of("%MYDIR%", Band::Likely)
    );
    for unsure in [
        format!("{cmd},tools"),
        format!(r"{cmd},\\server\tools"),
        format!(r"{cmd} \\server\tools"),
        // A blank before what starts a second path.
        format!(r"{cmd} \Users\tester\tools"),
        format!(r"{cmd} /Users/tester/tools"),
        format!(r"{cmd} %NOPE%\tools"),
    ] {
        assert_eq!(decided(&unsure, None), entry_of(&unsure, Band::Likely));
    }
    // What a reference expands to is read as well: a comma or a second path start behind it.
    for (name, holds) in [("TAIL", "cmd,x"), ("TAIL", r"cmd \Users\tester\tools")] {
        let entry = format!(r"{GIT}\%{name}%");
        assert_eq!(
            decided(&entry, Some((name, holds.to_owned()))),
            entry_of(&entry, Band::Likely),
            "{holds}"
        );
    }
    let plain_tail = format!(r"{GIT}\%TAIL%");
    assert_eq!(
        decided(&plain_tail, Some(("TAIL", "cmd".to_owned()))),
        entry_of(&plain_tail, Band::Safe)
    );
    // References only, however they are put together.
    for evasion in ["%MYDIR%%EMPTY%", r"%MYDIR%\%EMPTY%"] {
        assert_eq!(
            decided(evasion, Some(("MYDIR", cmd.clone()))),
            entry_of(evasion, Band::Likely)
        );
    }
    let two = r"%ProgramFiles%\%MYREL%";
    assert_eq!(
        decided(two, Some(("MYREL", r"Git\cmd".to_owned()))),
        entry_of(two, Band::Likely)
    );
}

/// A reference is expanded with the interactive user's environment. Windows expands only
/// `REG_EXPAND_SZ` values, and the machine's `Path` is read by everybody: an entry there that
/// refers to a variable a user sets for themselves leads to the app's folder for that user only.
#[test]
fn env_reference_is_expanded_as_windows_does_and_for_whom_the_key_is() {
    use purge_model::Band;
    use purge_policy::band::{PolicyCtx, TargetScope, decide};
    let user_env = format!(r"HKU\{SID}\Environment");
    let closed = std::cell::Cell::new(false);
    let band = |key: &str, plan_key: &str, expand: bool, entry: &str, user_root: bool| {
        let mut fp = git();
        fp.ref_snapshot = vec![snap(
            value(plan_key, "Path"),
            RefCarrier::Data,
            AnchorKind::Root,
            GIT,
        )];
        fp.inno = vec![inno(
            InnoRecordKind::RegDeleteValue,
            value(plan_key, "Path"),
        )];
        let text = format!(r"C:\Windows;{entry}");
        let mut fixture = if expand {
            machine().expand_sz(key, "Path", &text)
        } else {
            machine().sz(key, "Path", &text)
        };
        if user_root {
            fixture = fixture.sz(&user_env, "ROOT", GIT);
        }
        if closed.get() {
            fixture = fixture.denied(&format!(r"HKU\{SID}\Volatile Environment"));
        }
        let mut world = World::new(fixture, fp);
        world.env.insert("ROOT".into(), GIT.into());
        world.env.insert("TEMP".into(), GIT.into());
        let found = world.scan(&RegEnv);
        assert!(found.len() <= 1, "{}", golden::render(&found));
        found.first().map(|c| {
            decide(
                c,
                &PolicyCtx {
                    mode: purge_model::ScanMode::Post,
                    verify_gone: purge_model::VerifyGone::new(true, true, true),
                    target_scope: TargetScope::Machine,
                },
            )
            .band
        })
    };
    let machine_path = |expand, entry: &str, user_root| {
        band(MACHINE_ENV, MACHINE_ENV_PLAN, expand, entry, user_root)
    };
    // A machine variable in the machine's list: the installer's entry.
    assert_eq!(machine_path(true, r"%ROOT%\cmd", false), Some(Band::Safe));
    assert_eq!(
        machine_path(true, r"%ProgramFiles%\Git\cmd", false),
        Some(Band::Safe)
    );
    // The user sets `ROOT` for themselves: what the machine's entry leads to is not known.
    assert_eq!(machine_path(true, r"%ROOT%\cmd", true), Some(Band::Likely));
    // A variable Windows sets per user, whatever it holds for this one.
    assert_eq!(machine_path(true, r"%TEMP%\cmd", false), Some(Band::Likely));
    // In the user's own list the user's variable is the one that counts.
    assert_eq!(
        band(&user_env, &user_env, true, r"%ROOT%\cmd", true),
        Some(Band::Safe)
    );
    // A user key that cannot be read may set it.
    closed.set(true);
    assert_eq!(machine_path(true, r"%ROOT%\cmd", false), Some(Band::Likely));
    assert_eq!(machine_path(true, &git_cmd(), false), Some(Band::Safe));
    closed.set(false);
    // `REG_SZ`: `%ROOT%` is text, and the entry names nothing of the app.
    assert_eq!(machine_path(false, r"%ROOT%\cmd", false), None);
    assert_eq!(machine_path(false, &git_cmd(), false), Some(Band::Safe));
}

/// The caps of an entry (`prefix::ListEntry`) hold for a variable the installer recorded and that
/// is offered whole: `GIT_HOME` = `%MYDIR%` leads to the app's folder through a variable of the
/// user's, and `<app>\lib,x` may be two things. Listed, never ticked.
#[test]
fn env_recorded_variable_that_leads_there_indirectly_is_not_preselected() {
    use purge_model::Band;
    use purge_policy::band::{PolicyCtx, TargetScope, decide};
    let mut fp = git();
    fp.ref_snapshot = vec![snap(
        value(MACHINE_ENV_PLAN, "GIT_HOME"),
        RefCarrier::Data,
        AnchorKind::Root,
        GIT,
    )];
    fp.inno = vec![inno(
        InnoRecordKind::RegDeleteValue,
        value(MACHINE_ENV_PLAN, "GIT_HOME"),
    )];
    let decided = |data: &str| {
        let mut world = World::new(
            machine().expand_sz(MACHINE_ENV, "GIT_HOME", data),
            fp.clone(),
        );
        world.env.insert("MYDIR".into(), format!(r"{GIT}\lib"));
        let found = world.scan(&RegEnv);
        assert_eq!(found.len(), 1, "{}", golden::render(&found));
        assert_eq!(found[0].target, value(MACHINE_ENV_PLAN, "GIT_HOME"));
        let decision = decide(
            &found[0],
            &PolicyCtx {
                mode: purge_model::ScanMode::Post,
                verify_gone: purge_model::VerifyGone::new(true, true, true),
                target_scope: TargetScope::Machine,
            },
        );
        (
            tier_a_in_scope(&found[0]),
            decision.band,
            decision.preselected,
        )
    };
    assert_eq!(decided(&format!(r"{GIT}\lib")), (true, Band::Safe, true));
    assert_eq!(decided(r"%ProgramFiles%\Git\lib"), (true, Band::Safe, true));
    for data in [
        "%MYDIR%".to_owned(),
        format!(r"{GIT}\lib,x"),
        format!(r"{GIT}\lib \\server\x"),
    ] {
        assert_eq!(decided(&data), (false, Band::Likely, false), "{data}");
    }
}

/// A `;`-list outside the `Environment` keys (another product's search path). The installer's log
/// has a record on the value, the app's folder is gone, and an entry begins with the app's
/// folder. An entry edit takes the entry's whole text: an entry that holds more than one path is
/// not offered, and no entry is the app's on the strength of the record, which names the list and
/// not its entries. Only in a list that is the app's by where it is can an entry be Safe.
#[test]
fn list_entry_outside_environment_is_read_like_a_path_entry() {
    use purge_model::Band;
    use purge_policy::band::{PolicyCtx, TargetScope, decide};
    let cmd = git_cmd();
    let tools = r"C:\Users\tester\tools";
    let theirs = r"HKLM\SOFTWARE\Other Vendor\Tool";
    let own = r"HKLM\SOFTWARE\Git\Settings";
    let decided = |key: &str, entry: &str, variable: Option<(&str, String)>| {
        let mut fp = git();
        fp.ref_snapshot = vec![snap(
            value(key, "SearchPath"),
            RefCarrier::Data,
            AnchorKind::Root,
            GIT,
        )];
        fp.inno = vec![inno(
            InnoRecordKind::RegDeleteValue,
            value(key, "SearchPath"),
        )];
        let fixture = machine().sz(key, "SearchPath", &format!(r"C:\Users\tester\bin;{entry}"));
        let mut world = World::new(fixture, fp);
        if let Some((name, holds)) = variable {
            world.env.insert(name.to_uppercase(), holds);
        }
        let mut out: Vec<(Target, Band, bool)> = Vec::new();
        for scanner in [&RefAny as &dyn Scanner, &RegSoftware] {
            for c in world.scan(scanner) {
                let decision = decide(
                    &c,
                    &PolicyCtx {
                        mode: purge_model::ScanMode::Post,
                        verify_gone: purge_model::VerifyGone::new(true, true, true),
                        target_scope: TargetScope::Machine,
                    },
                );
                let row = (c.target.clone(), decision.band, decision.preselected);
                if matches!(c.target, Target::RegMultiSzSegment { .. }) && !out.contains(&row) {
                    out.push(row);
                }
            }
        }
        out
    };
    let entry_of = |key: &str, text: &str, band: Band| {
        vec![(segment(key, "SearchPath", text), band, band == Band::Safe)]
    };
    // More than one path in the entry: nothing is offered, in either place.
    for key in [theirs, own] {
        for (entry, variable) in [
            (format!(r#""{cmd}" "{tools}""#), None),
            (format!("{cmd},{tools}"), None),
            (format!("{cmd} {tools}"), None),
            (
                "%MYDIRS%".to_owned(),
                Some(("MYDIRS", format!("{tools};{cmd}"))),
            ),
            // Another program's command line with a file of the app as an argument.
            (
                format!(r#""C:\Users\tester\my tool.exe" --with "{cmd}\x.exe""#),
                None,
            ),
            (format!(r"{cmd}\..\..\..\Users\tester\tools"), None),
        ] {
            assert_eq!(decided(key, &entry, variable.clone()), [], "{key}: {entry}");
        }
    }
    // A plain entry in another product's list: the record on the value does not make it the
    // app's. Listed, not ticked.
    assert_eq!(
        decided(theirs, &cmd, None),
        entry_of(theirs, &cmd, Band::Likely)
    );
    // The same in a list of the app's own key: Safe; with a comma or behind a reference, listed.
    assert_eq!(decided(own, &cmd, None), entry_of(own, &cmd, Band::Safe));
    let file = format!(r"{cmd}\git.exe");
    assert_eq!(decided(own, &file, None), entry_of(own, &file, Band::Safe));
    let comma = format!("{cmd},tools");
    assert_eq!(
        decided(own, &comma, None),
        entry_of(own, &comma, Band::Likely)
    );
    let argument = format!(r"{cmd}\git.exe /quiet");
    assert_eq!(
        decided(own, &argument, None),
        entry_of(own, &argument, Band::Likely)
    );
    assert_eq!(
        decided(own, "%MYDIR%", Some(("MYDIR", cmd.clone()))),
        entry_of(own, "%MYDIR%", Band::Likely)
    );

    // A key the installer's log deletes whole is the app's place as well (with a baseline that
    // does not have it): the record on the key, unlike one on the value, covers what is in it.
    let logged = r"HKLM\SOFTWARE\Contoso\Bridge";
    let mut fp = git();
    fp.inno = vec![inno(InnoRecordKind::RegDeleteEntireKey, key(logged))];
    let world = World::new(
        machine().sz(logged, "SearchPath", &format!(r"C:\Users\tester\bin;{cmd}")),
        fp,
    );
    let found = world.scan(&RefAny);
    assert!(tier_a_in_scope(expect(
        &found,
        &segment(logged, "SearchPath", &cmd)
    )));

    // A list offered whole because every entry refers to the app: an entry that is more than a
    // path of the app keeps the value from being the app's alone, record or no record.
    let whole = |data: String| {
        let mut fp = git();
        fp.inno = vec![inno(
            InnoRecordKind::RegDeleteValue,
            value(theirs, "SearchPath"),
        )];
        let world = World::new(machine().sz(theirs, "SearchPath", &data), fp);
        let found = world.scan(&RefAny);
        tier_a_in_scope(expect(&found, &value(theirs, "SearchPath")))
    };
    assert!(whole(format!(r"{cmd};{GIT}\bin")));
    assert!(!whole(format!(r#"{GIT}\bin;"{cmd}" "{tools}""#)));
    assert!(!whole(format!(r"{GIT}\bin;{cmd},tools")));

    // An entry that names the app without being a path of the app (a folder of somebody else's
    // that carries the app's token, recorded by the harvest) is not the app's entry, even in
    // the app's own key.
    let own_list = r"HKLM\SOFTWARE\Mozilla\Firefox\Extensions";
    let named = format!(r"D:\Other\{HASH}\x.dll");
    let inside = format!(r"{FIREFOX}\browser\y.dll");
    let mut fp = firefox();
    for (index, text) in [(1u32, &named), (2, &inside)] {
        fp.ref_snapshot.push(snap(
            Target::RegMultiSzSegment {
                path: own_list.into(),
                name: "Load".into(),
                segment: text.clone(),
                index: Some(index),
            },
            RefCarrier::Segment,
            AnchorKind::Token,
            HASH,
        ));
    }
    let world = World::new(
        machine().multi_sz(
            own_list,
            "Load",
            &[r"C:\Users\tester\a.dll", &named, &inside],
        ),
        fp,
    );
    let found = world.scan(&RefAny);
    assert!(!tier_a_in_scope(expect(
        &found,
        &segment(own_list, "Load", &named)
    )));
    assert!(tier_a_in_scope(expect(
        &found,
        &segment(own_list, "Load", &inside)
    )));

    // A sibling product's key below the vendor's key is not the app's place for an entry
    // (Thunderbird next to Firefox), whether or not that product is in the inventory: the
    // inventory gives another app its Uninstall key, roots and anchors, never its settings
    // key. Listed, not ticked. The same list in the product's own key is the app's.
    let entry = format!(r"{FIREFOX}\browser");
    let in_key = |key: &str| {
        let world = World::new(
            machine().sz(key, "SearchPath", &format!(r"C:\Users\tester\bin;{entry}")),
            firefox(),
        );
        let mut bands: Vec<(Band, bool)> = Vec::new();
        for scanner in [&RefAny as &dyn Scanner, &RegSoftware] {
            for c in world.scan(scanner) {
                if c.target != segment(key, "SearchPath", &entry) {
                    continue;
                }
                let decision = decide(
                    &c,
                    &PolicyCtx {
                        mode: purge_model::ScanMode::Post,
                        verify_gone: purge_model::VerifyGone::new(true, true, true),
                        target_scope: TargetScope::Machine,
                    },
                );
                bands.push((decision.band, decision.preselected));
            }
        }
        bands.dedup();
        bands
    };
    assert_eq!(
        in_key(r"HKLM\SOFTWARE\Mozilla\Thunderbird\Paths"),
        [(Band::Likely, false)]
    );
    assert_eq!(
        in_key(r"HKLM\SOFTWARE\Mozilla\Firefox\Paths"),
        [(Band::Safe, true)]
    );

    // `..` is refused wherever a path is tested against the roots.
    let world = World::new(machine(), git());
    let ctx = world.ctx();
    assert!(ctx.inside_install_root(&cmd).is_some());
    assert!(
        ctx.inside_install_root(&format!(r"{GIT}\..\..\Users\tester\tools"))
            .is_none()
    );
}

/// The `Environment` key counts as the app's own place when the installer's log deletes the key
/// whole and the baseline does not have it (a per-user key, a baseline without the key). A
/// variable without a record of its own is then Tier A through the key, and the caps of an entry
/// must hold on that branch too: a bare reference, a comma, a variable Windows sets per user.
#[test]
fn env_single_value_in_a_key_the_log_deletes_whole_keeps_the_entry_caps() {
    use purge_model::Band;
    use purge_policy::band::{PolicyCtx, TargetScope, decide};
    let decided = |data: &str| {
        let mut fp = git();
        fp.ref_snapshot = vec![snap(
            value(MACHINE_ENV_PLAN, "GIT_HOME"),
            RefCarrier::Data,
            AnchorKind::Root,
            GIT,
        )];
        fp.inno = vec![inno(
            InnoRecordKind::RegDeleteEntireKey,
            key(MACHINE_ENV_PLAN),
        )];
        let mut world = World::new(machine().expand_sz(MACHINE_ENV, "GIT_HOME", data), fp);
        world.env.insert("MYDIR".into(), format!(r"{GIT}\lib"));
        world.env.insert("USERPROFILE".into(), GIT.into());
        let found = world.scan(&RegEnv);
        assert_eq!(found.len(), 1, "{}", golden::render(&found));
        let decision = decide(
            &found[0],
            &PolicyCtx {
                mode: purge_model::ScanMode::Post,
                verify_gone: purge_model::VerifyGone::new(true, true, true),
                target_scope: TargetScope::Machine,
            },
        );
        (
            tier_a_in_scope(&found[0]),
            decision.band,
            decision.preselected,
        )
    };
    // The construction does make the place the app's: a plain value is Safe.
    assert_eq!(decided(&format!(r"{GIT}\lib")), (true, Band::Safe, true));
    for data in [
        "%MYDIR%".to_owned(),
        format!(r"{GIT}\lib,x"),
        r"%USERPROFILE%\x".to_owned(),
    ] {
        assert_eq!(decided(&data), (false, Band::Likely, false), "{data}");
    }
}

/// The other half of `per_user_reference`: another user's `Environment` key (the user the app is
/// installed for, who is not the interactive one). An entry there that refers to a variable a
/// user sets was expanded with the wrong user's environment.
#[test]
fn env_reference_in_another_users_key_is_not_proven() {
    use purge_model::Band;
    use purge_policy::band::{PolicyCtx, TargetScope, decide};
    const OTHER: &str = "S-1-5-21-1004336348-1177238915-682003330-1002";
    let other_env = format!(r"HKU\{OTHER}\Environment");
    let band = |entry: &str| {
        let mut fp = git();
        fp.app.program_id =
            purge_model::ProgramId::user(OTHER, purge_model::View::K64, "Git_is1").unwrap();
        fp.ref_snapshot = vec![snap(
            value(other_env.clone(), "Path"),
            RefCarrier::Data,
            AnchorKind::Root,
            GIT,
        )];
        fp.inno = vec![inno(
            InnoRecordKind::RegDeleteValue,
            value(other_env.clone(), "Path"),
        )];
        let fixture = machine()
            .expand_sz(&other_env, "Path", &format!(r"C:\Users\other\bin;{entry}"))
            .sz(&other_env, "ROOT", r"D:\Elsewhere");
        let mut world = World::new(fixture, fp);
        world.env.insert("ROOT".into(), GIT.into());
        let found = world.scan(&RegEnv);
        let rows: Vec<Band> = found
            .iter()
            .filter(|c| matches!(c.target, Target::RegMultiSzSegment { .. }))
            .map(|c| {
                decide(
                    c,
                    &PolicyCtx {
                        mode: purge_model::ScanMode::Post,
                        verify_gone: purge_model::VerifyGone::new(true, true, true),
                        target_scope: TargetScope::PerUser,
                    },
                )
                .band
            })
            .collect();
        assert!(rows.len() <= 1, "{}", golden::render(&found));
        (rows.first().copied(), found.iter().any(tier_a_in_scope))
    };
    // Written out, the entry is the installer's in that user's list as in any other.
    let (plain_band, plain_tier_a) = band(&git_cmd());
    assert!(plain_tier_a, "{plain_band:?}");
    // Through a variable that user sets (to something else than the interactive user's).
    let (_, tier_a) = band(r"%ROOT%\cmd");
    assert!(!tier_a);
    assert_ne!(band(r"%ROOT%\cmd").0, Some(Band::Safe));
}

/// A root that is not the app's alone (the installer was pointed at a folder that held other
/// things: `shared_root` demotes it to an InferredRoot) proves nothing about a `Path` entry that
/// lies under it, whatever the log says about `Path`: another tool's stale entry looks the same
/// (rig run x0-git-toolsdir). No entry is offered from such a root.
#[test]
fn env_entry_under_a_root_that_is_not_the_apps_alone_is_not_offered() {
    let mut fp = git();
    fp.ref_snapshot = vec![snap(
        value(MACHINE_ENV_PLAN, "Path"),
        RefCarrier::Data,
        AnchorKind::Root,
        GIT,
    )];
    fp.inno = vec![inno(
        InnoRecordKind::RegDeleteValue,
        value(MACHINE_ENV_PLAN, "Path"),
    )];
    let fixture = || path_value(&[r"C:\Windows", &git_cmd(), &format!(r"{GIT}\rg")]);
    // The control: an InstallRoot.
    let found = World::new(fixture(), fp.clone()).scan(&RegEnv);
    assert_eq!(found.len(), 2, "{}", golden::render(&found));
    assert!(found.iter().all(tier_a_in_scope));
    fp.roots[0].kind = purge_model::RootKind::InferredRoot;
    let found = World::new(fixture(), fp).scan(&RegEnv);
    assert!(
        found.iter().all(|c| !tier_a_in_scope(c)),
        "{}",
        golden::render(&found)
    );
}

/// A value offered whole (`DeleteValue`) in another product's key, with the installer's record on
/// it: the record says who made the value, not what it holds now. Data that holds more than one
/// path of the app (the tool rewrote its search path; another program's command line) is listed
/// and never ticked, whether or not the data splits as a list of paths and whatever its type.
#[test]
fn recorded_value_of_another_product_that_holds_more_than_the_apps_path_is_not_preselected() {
    use purge_model::Band;
    use purge_policy::band::{PolicyCtx, TargetScope, decide};
    let cmd = git_cmd();
    let tools = r"C:\Users\tester\tools";
    let theirs = r"HKLM\SOFTWARE\Other Vendor\Tool";
    let own = r"HKLM\SOFTWARE\Git\Settings";
    let decided = |key: &str, fixture: FixtureBuilder| {
        let mut fp = git();
        fp.ref_snapshot = vec![snap(
            value(key, "SearchPath"),
            RefCarrier::Data,
            AnchorKind::Root,
            GIT,
        )];
        fp.inno = vec![inno(
            InnoRecordKind::RegDeleteValue,
            value(key, "SearchPath"),
        )];
        let world = World::new(fixture, fp);
        let mut out: Vec<(Band, bool)> = Vec::new();
        for scanner in [&RefAny as &dyn Scanner, &RegSoftware] {
            for c in world.scan(scanner) {
                if c.target != value(key, "SearchPath") {
                    continue;
                }
                let decision = decide(
                    &c,
                    &PolicyCtx {
                        mode: purge_model::ScanMode::Post,
                        verify_gone: purge_model::VerifyGone::new(true, true, true),
                        target_scope: TargetScope::Machine,
                    },
                );
                out.push((decision.band, decision.preselected));
            }
        }
        out.dedup();
        out
    };
    let sz = |key: &str, data: String| decided(key, machine().sz(key, "SearchPath", &data));
    let multi = |key: &str, strings: &[String]| {
        let strings: Vec<&str> = strings.iter().map(String::as_str).collect();
        decided(key, machine().multi_sz(key, "SearchPath", &strings))
    };
    let command = format!(r#""C:\Users\tester\my tool.exe" --with "{cmd}\x.exe""#);
    let listed = [(Band::Likely, false)];
    let safe = [(Band::Safe, true)];
    // The control: the value still holds what the installer wrote, one path of the app.
    assert_eq!(sz(theirs, cmd.clone()), safe);
    assert_eq!(sz(theirs, format!(r#""{cmd}\""#)), safe);
    assert_eq!(sz(theirs, format!(r"{cmd};{GIT}\bin")), safe);
    assert_eq!(multi(theirs, &[cmd.clone(), format!(r"{GIT}\bin")]), safe);
    for data in [
        format!(r#"C:\Users\tester\bin;"{cmd}" "{tools}";relative"#),
        format!(r#"bin;"{cmd}" "{tools}""#),
        format!(r"C:\Users\tester\bin;{cmd};relative"),
        format!(r"C:\Users\tester\bin {cmd}"),
        format!("{tools},{cmd}"),
        // One string that is a command line of somebody else's, or of the app's.
        command.clone(),
        format!(r#""{cmd}\git.exe" --with "{tools}""#),
    ] {
        assert_eq!(sz(theirs, data.clone()), listed, "{data}");
    }
    assert_eq!(multi(theirs, &[cmd.clone(), command.clone()]), listed);
    assert_eq!(multi(theirs, &[format!("{tools};{cmd}")]), listed);
    // A value that is the app's by its name (a path of the app) is not judged by data that
    // does not refer to the app at all.
    let named = format!(r"{cmd}\git.exe");
    let mut fp = git();
    fp.inno = vec![inno(InnoRecordKind::RegDeleteValue, value(theirs, &named))];
    let world = World::new(machine().sz(theirs, &named, "RUNASADMIN"), fp);
    assert!(tier_a_in_scope(expect(
        &world.scan(&RefAny),
        &value(theirs, &named)
    )));
    // In the app's own key a single string and a `REG_MULTI_SZ` value stay the app's; a `;`-list
    // with somebody else's entry does not.
    assert_eq!(
        sz(own, format!(r#""{cmd}\git.exe" --with "{tools}""#)),
        safe
    );
    assert_eq!(
        multi(own, &[cmd.clone(), format!(r#""{cmd}\git.exe" --flag"#)]),
        safe
    );
    assert_eq!(
        sz(own, format!(r#"{GIT}\bin;"{cmd}" "{tools}";relative"#)),
        listed
    );
}

#[test]
fn env_whole_variable_needs_an_inno_value_record() {
    let home = format!(r"{GIT}\home");
    let fixture = || {
        machine()
            .sz(MACHINE_ENV, "GIT_INSTALL_ROOT", &home)
            .sz(MACHINE_ENV, "GIT_SSH", "plink.exe")
    };
    // Without a record the variable is not offered whole (and it is no list entry either).
    let world = World::new(fixture(), git());
    assert!(world.scan(&RegEnv).is_empty());

    let mut fp = git();
    fp.inno = vec![
        inno(
            InnoRecordKind::RegDeleteValue,
            value(MACHINE_ENV, "GIT_INSTALL_ROOT"),
        ),
        inno(
            InnoRecordKind::RegDeleteValue,
            value(MACHINE_ENV, "GIT_SSH"),
        ),
    ];
    let world = World::new(fixture(), fp);
    let found = world.scan(&RegEnv);
    golden::check("reg_env_git_variables", &found);
    assert_eq!(found.len(), 2);
    let root_var = expect(&found, &value(MACHINE_ENV_PLAN, "GIT_INSTALL_ROOT"));
    assert_eq!(root_var.action, Action::DeleteValue);
    assert!(has(root_var, EvidenceKind::PointsIntoInstallRoot));
    assert!(tier_a_in_scope(root_var));
    // The record names the variable, not what it holds: the installer logged `GIT_SSH`, and a
    // `GIT_SSH` that does not lead into the app's folder may as well be one the user set again for
    // a copy of their own after an uninstall. Listed, never preselected.
    let elsewhere = expect(&found, &value(MACHINE_ENV_PLAN, "GIT_SSH"));
    assert!(!tier_a_in_scope(elsewhere));
    assert!(
        elsewhere
            .evidence
            .iter()
            .all(|e| e.detail.get("unproven").is_some())
    );
}

/// VM run x0-git-userstate: the user set `GIT_SSH` to Git's ssh and put Git's `cmd` on their own
/// `Path`. `GIT_SSH` is one value, not a list: it was offered as an entry edit (which leaves an empty
/// variable behind) and preselected.
#[test]
fn env_single_value_variable_is_the_value_and_a_users_entry_is_not_tier_a() {
    let user_env = format!(r"HKU\{SID}\Environment");
    let ssh = format!(r"{GIT}\usr\bin\ssh.exe");
    let cmd = git_cmd();
    let mut fp = git();
    fp.ref_snapshot = vec![
        snap(
            value(user_env.clone(), "GIT_SSH"),
            RefCarrier::Data,
            AnchorKind::Root,
            GIT,
        ),
        snap(
            value(user_env.clone(), "Path"),
            RefCarrier::Data,
            AnchorKind::Root,
            GIT,
        ),
    ];
    let fixture = machine()
        .sz(&user_env, "GIT_SSH", &ssh)
        .expand_sz(&user_env, "Path", &cmd);
    let world = World::new(fixture, fp);
    let found = world.scan(&RegEnv);
    assert_eq!(found.len(), 2, "{}", golden::render(&found));

    // One value: offered as the value, never as an entry of it.
    let var = expect(&found, &value(user_env.clone(), "GIT_SSH"));
    assert_eq!(var.action, Action::DeleteValue);
    assert!(
        !found.iter().any(|c| matches!(
            &c.target,
            Target::RegMultiSzSegment { name, .. } if name == "GIT_SSH"
        )),
        "{}",
        golden::render(&found)
    );
    // `Path` is a list even with one entry in it.
    let entry = expect(&found, &segment(user_env.clone(), "Path", &cmd));
    assert_eq!(entry.action, Action::EditSegment);

    // Nothing shows that Git wrote either: the references are there, at Tier B.
    assert!(has(var, EvidenceKind::InPreUninstallRefSnapshot));
    for c in [var, entry] {
        assert!(has(c, EvidenceKind::PointsIntoInstallRoot));
        assert!(has(c, EvidenceKind::DanglingRef));
        assert!(c.evidence.iter().all(|e| e.tier == Tier::B), "{c:?}");
        assert!(!tier_a_in_scope(c));
    }
}

/// The same variable when the installer's log records it: the app's own, Tier A.
#[test]
fn env_single_value_variable_the_installer_recorded_is_tier_a() {
    let ssh = format!(r"{GIT}\usr\bin\ssh.exe");
    let mut fp = git();
    fp.ref_snapshot = vec![snap(
        value(MACHINE_ENV, "GIT_SSH"),
        RefCarrier::Data,
        AnchorKind::Root,
        GIT,
    )];
    fp.inno = vec![inno(
        InnoRecordKind::RegDeleteValue,
        value(MACHINE_ENV, "GIT_SSH"),
    )];
    let world = World::new(machine().sz(MACHINE_ENV, "GIT_SSH", &ssh), fp);
    let found = world.scan(&RegEnv);
    assert_eq!(found.len(), 1, "{}", golden::render(&found));
    assert_eq!(found[0].action, Action::DeleteValue);
    assert!(tier_a_in_scope(&found[0]));
}

// ---------------------------------------------------------------------------------------------------------
// REF-ANY
// ---------------------------------------------------------------------------------------------------------

/// VM runs x0-git-userstate and x0-git-toolsdir: a setting of another program
/// (`TortoiseGit|MSysGit`, `ContosoTools\Settings|GitExecutable`) that holds a path into the app was
/// preselected. It is in the reference snapshot and it dangles, and it is still not the app's.
#[test]
fn ref_any_setting_of_another_program_is_not_tier_a() {
    let exe = format!(r"{FIREFOX}\firefox.exe");
    let tortoise = format!(r"HKU\{SID}\Software\TortoiseGit");
    let contoso = format!(r"HKU\{SID}\Software\ContosoTools\Settings");
    let own = format!(r"HKU\{SID}\Software\Mozilla\Firefox\Launcher");
    let mut fp = firefox();
    fp.ref_snapshot = vec![
        snap(
            value(tortoise.clone(), "Browser"),
            RefCarrier::Data,
            AnchorKind::Exe,
            &exe,
        ),
        snap(
            value(contoso.clone(), "BrowserExecutable"),
            RefCarrier::Data,
            AnchorKind::Exe,
            &exe,
        ),
        snap(
            value(own.clone(), "Path"),
            RefCarrier::Data,
            AnchorKind::Exe,
            &exe,
        ),
    ];
    let fixture = machine()
        .sz(&tortoise, "Browser", &exe)
        .sz(&contoso, "BrowserExecutable", &exe)
        .sz(&own, "Path", &exe);
    let world = World::new(fixture, fp);
    let found = world.scan(&RefAny);
    for target in [
        value(tortoise, "Browser"),
        value(contoso, "BrowserExecutable"),
    ] {
        let c = expect(&found, &target);
        assert!(has(c, EvidenceKind::InPreUninstallRefSnapshot));
        assert!(has(c, EvidenceKind::DanglingRef));
        assert!(
            c.evidence.iter().all(|e| e.tier != Tier::A),
            "{}",
            golden::target_text(&target)
        );
        assert!(
            c.evidence
                .iter()
                .all(|e| e.detail.get("place") == Some("shared"))
        );
    }
    // The same reference in the app's own key keeps its tier.
    assert!(tier_a_in_scope(expect(&found, &value(own, "Path"))));
}

/// VM runs x0-vscode-userstate and x0-git-upgrade: the Restart Manager's session values (the files
/// the uninstaller asked about) were preselected. They are Windows' own short-lived state.
#[test]
fn ref_any_restart_manager_sessions_are_not_read() {
    let session = format!(r"HKU\{SID}\Software\Microsoft\RestartManager\Session0000");
    let fixture = machine()
        .multi_sz(
            &session,
            "RegFiles0000",
            &[
                &format!(r"{GIT}\cmd\git.exe"),
                &format!(r"{GIT}\git-bash.exe"),
            ],
        )
        .sz(&session, "SessionHash", "00")
        .sz(
            &format!(r"HKU\{SID}\Software\Vendor\Tool"),
            "Git",
            &format!(r"{GIT}\cmd\git.exe"),
        );
    let world = World::new(fixture, git());
    let found = world.scan(&RefAny);
    // The control: the other value that points at Git is found.
    assert_eq!(found.len(), 1, "{}", golden::render(&found));
    assert_eq!(
        found[0].target,
        value(format!(r"HKU\{SID}\Software\Vendor\Tool"), "Git")
    );
}

fn subtree(key_path: &str, values: &[(&str, &str)], subkeys: &[&str]) -> SubtreeBaseline {
    SubtreeBaseline {
        key: key_path.into(),
        values: values
            .iter()
            .map(|(subkey, name)| SubtreeValue {
                subkey: (*subkey).into(),
                name: (*name).into(),
                hash: "0".into(),
            })
            .collect(),
        subkeys: subkeys.iter().map(|s| (*s).to_owned()).collect(),
        lwt: FileTime(1),
        ti_owned: false,
        fully_attributed: true,
    }
}

#[test]
fn ref_any_firefox_golden() {
    let exe = format!(r"{FIREFOX}\firefox.exe");
    let client = format!(r"HKLM\SOFTWARE\Clients\StartMenuInternet\Firefox-{HASH}");
    let badge = format!(r"{}\{CV}\Explorer\FeatureUsage\AppBadgeUpdated", hkcu());
    let other_key = r"HKLM\SOFTWARE\Acme\Editor";
    let truncated = {
        let mut data = RegData::from_sz(FIREFOX);
        data.truncated = true;
        data.len += 64;
        data
    };
    let fixture = firefox_leftovers()
        .sz(
            &format!(r"{client}\shell\open\command"),
            "",
            &format!(r#""{exe}""#),
        )
        .sz(&format!(r"{client}\DefaultIcon"), "", &format!("{exe},0"))
        // A harvested token as the value's own name.
        .dword(&badge, HASH, 3)
        // A list in which one entry is the app's.
        .multi_sz(
            r"HKLM\SOFTWARE\Vendor\Indexer",
            "Folders",
            &[r"C:\Data", &format!(r"{FIREFOX}\browser"), r"D:\Media"],
        )
        // Another app's own settings mentioning the root.
        .sz(other_key, "LastBrowser", &exe)
        // Data the source could not read in full proves nothing.
        .value(r"HKLM\SOFTWARE\Vendor\Cut", "Dir", truncated)
        // Mentions that are not references into the app.
        .sz(
            r"HKLM\SOFTWARE\Vendor\Other",
            "Dir",
            r"C:\Program Files\Mozilla Firefox Nightly",
        )
        // The Environment keys are REG-ENV's.
        .expand_sz(MACHINE_ENV, "Path", &format!(r"C:\Windows;{FIREFOX}"));
    let mut fp = firefox();
    fp.ref_snapshot.push(snap(
        value(badge.clone(), HASH),
        RefCarrier::ValueName,
        AnchorKind::Token,
        HASH,
    ));
    fp.subtrees = vec![
        subtree(
            &client,
            &[(r"shell\open\command", ""), ("DefaultIcon", "")],
            &["shell", r"shell\open", r"shell\open\command", "DefaultIcon"],
        ),
        // A structural container never goes as a key, whatever the harvest attributed.
        subtree(&run_key(r"HKLM\SOFTWARE", "Run"), &[], &[]),
    ];
    let mut world = World::new(fixture.key(&run_key(r"HKLM\SOFTWARE", "Run")), fp);
    world.other_apps = OtherApps::new(vec![OtherApp {
        name: "Acme Editor".into(),
        keys: vec![other_key.into()],
        ..OtherApp::default()
    }]);
    let found = world.scan(&RefAny);
    golden::check("ref_any_firefox", &found);

    // Value level, Tier A from the snapshot or from the dangling reference.
    let taskbar = expect(
        &found,
        &value(r"HKLM\SOFTWARE\Mozilla\Firefox\TaskBarIDs", FIREFOX),
    );
    assert!(has(taskbar, EvidenceKind::InPreUninstallRefSnapshot));
    let command = expect(&found, &value(format!(r"{client}\shell\open\command"), ""));
    assert!(has(command, EvidenceKind::DanglingRef) && score(command) >= 8);
    let token = expect(&found, &value(badge, HASH));
    assert_eq!(
        kinds(token),
        vec![
            EvidenceKind::InPreUninstallRefSnapshot,
            EvidenceKind::HarvestedToken
        ]
    );
    // One entry of a list is edited out; the value stays.
    let entry = expect(
        &found,
        &segment(
            r"HKLM\SOFTWARE\Vendor\Indexer",
            "Folders",
            &format!(r"{FIREFOX}\browser"),
        ),
    );
    assert_eq!(entry.action, Action::EditSegment);
    assert!(find(&found, &value(r"HKLM\SOFTWARE\Vendor\Indexer", "Folders")).is_none());
    // Inside another app's own key: listed, blocked.
    let foreign = expect(&found, &value(other_key, "LastBrowser"));
    assert!(foreign.blockers.contains(&Blocker::InsideOtherApp {
        app: "Acme Editor".into()
    }));
    assert!(find(&found, &value(r"HKLM\SOFTWARE\Vendor\Cut", "Dir")).is_none());
    assert!(find(&found, &value(r"HKLM\SOFTWARE\Vendor\Other", "Dir")).is_none());
    assert!(
        !found
            .iter()
            .any(|c| golden::target_text(&c.target).contains("Environment"))
    );

    // Keys: only the fully attributed, still fully covered one with evidence of its own.
    let keys: Vec<&Candidate> = found
        .iter()
        .filter(|c| matches!(c.target, Target::RegKey { .. }))
        .collect();
    assert_eq!(keys.len(), 1, "{}", golden::render(&found));
    assert_eq!(keys[0].target, key(client));
    assert_eq!(kinds(keys[0]), vec![EvidenceKind::HarvestedToken]);
    assert!(find(&found, &key(r"HKLM\SOFTWARE\Mozilla\Firefox\TaskBarIDs")).is_none());
}

#[test]
fn ref_any_key_with_something_new_in_it_is_not_offered() {
    let exe = format!(r"{FIREFOX}\firefox.exe");
    let client = format!(r"HKLM\SOFTWARE\Clients\StartMenuInternet\Firefox-{HASH}");
    let mut fp = firefox();
    fp.subtrees = vec![subtree(&client, &[("DefaultIcon", "")], &["DefaultIcon"])];
    let fixture = firefox_leftovers()
        .sz(&format!(r"{client}\DefaultIcon"), "", &format!("{exe},0"))
        .sz(&client, "AddedLater", "by someone");
    let world = World::new(fixture, fp);
    let found = world.scan(&RefAny);
    assert!(find(&found, &key(client.clone())).is_none());
    // The value that refers to the app is still offered.
    assert!(find(&found, &value(format!(r"{client}\DefaultIcon"), "")).is_some());
}

#[test]
fn ref_any_git_skeleton_key() {
    let auto = r"HKLM\SOFTWARE\Classes\sh_auto_file";
    let mut fp = git();
    fp.subtrees = vec![subtree(
        auto,
        &[(r"shell\open\command", "")],
        &["shell", r"shell\open", r"shell\open\command"],
    )];
    // The uninstaller removed the command; the value-free parents stayed.
    let left = || {
        machine()
            .key(&format!(r"{auto}\shell\open"))
            .ti_owned(auto, false)
            .ti_owned(&format!(r"{auto}\shell"), false)
            .ti_owned(&format!(r"{auto}\shell\open"), false)
    };
    let world = World::new(left(), fp);
    let found = world.scan(&RefAny);
    golden::check("ref_any_git_skeleton", &found);
    assert_eq!(found.len(), 1, "{}", golden::render(&found));
    assert_eq!(found[0].target, key(auto));
    assert_eq!(kinds(&found[0]), vec![EvidenceKind::ProvenOwnedSkeleton]);

    // Without a baseline nothing proves the key is not Windows' own.
    let mut fp = git();
    fp.subtrees = vec![subtree(auto, &[], &["shell", r"shell\open"])];
    let mut world = World::new(left(), fp);
    world.baseline = None;
    assert!(world.scan(&RefAny).is_empty());
}

// ---------------------------------------------------------------------------------------------------------
// All five
// ---------------------------------------------------------------------------------------------------------

/// No scanner of this package ever offers a structural container as a key, and none decides a band.
#[test]
fn no_key_candidate_is_a_structural_container() {
    let hklm = r"HKLM\SOFTWARE";
    let exe = format!(r"{GIT}\git-bash.exe");
    let containers_of = |base: &str| {
        vec![
            run_key(base, "Run"),
            run_key(base, "RunOnce"),
            approved(base, "Run"),
            approved(base, "Run32"),
            approved(base, "StartupFolder"),
            app_paths(base),
            format!(r"{base}\RegisteredApplications"),
            format!(r"{base}\{CV}\ApplicationAssociationToasts"),
        ]
    };
    let mut keys = containers_of(hklm);
    keys.extend(containers_of(&hkcu()));
    keys.push(MACHINE_ENV.to_owned());
    keys.push(format!(r"HKU\{SID}\Environment"));
    keys.push(r"HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList".to_owned());

    // Every container holds a value that refers to the app, was fully attributed at harvest and is
    // named by an Inno key-create record: the strongest case anyone could make for the key.
    let mut fixture = machine();
    let mut fp = git();
    for container in &keys {
        fixture = fixture.sz(container, "Git", &exe);
        fp.subtrees.push(subtree(container, &[("", "Git")], &[]));
        fp.inno.push(inno(
            InnoRecordKind::RegDeleteEntireKey,
            key(container.clone()),
        ));
    }
    fixture = fixture
        .sz(&format!(r"{}\git-bash.exe", app_paths(hklm)), "", &exe)
        .sz(r"HKLM\SOFTWARE\Git", "InstallPath", GIT);
    let world = World::new(fixture, fp);
    let mut key_targets = 0;
    for scanner in all_scanners() {
        for c in world.scan(scanner) {
            assert!(c.decision.is_none());
            if let Target::RegKey { path } = &c.target {
                key_targets += 1;
                assert!(
                    !containers::is_value_container(path, &world.guard),
                    "{}: {path}",
                    scanner.id()
                );
            }
        }
    }
    assert!(key_targets >= 2, "the app's own keys are still offered");
}

/// A scan over a machine the app left nothing on finds nothing.
#[test]
fn clean_machine_yields_nothing() {
    let fixture =
        || with_thunderbird(machine()).expand_sz(MACHINE_ENV, "Path", r"C:\Windows;C:\Tools");
    for fp in [firefox(), git(), notepadpp()] {
        let mut world = World::new(fixture(), fp);
        world.other_apps = thunderbird();
        for scanner in all_scanners() {
            let found = world.scan(scanner);
            assert!(
                found.is_empty(),
                "{}:\n{}",
                scanner.id(),
                golden::render(&found)
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// Review regressions
// ---------------------------------------------------------------------------------------------------------

/// Another app's `Run` command that only passes a file of this app as an argument is that app's
/// entry: it is listed blocked, and its `StartupApproved` switch is not offered at all.
#[test]
fn run_command_of_another_app_naming_this_app_is_blocked() {
    let hklm = r"HKLM\SOFTWARE";
    let command = format!(r#""{THUNDERBIRD}\thunderbird.exe" -open "{GIT}\cmd\git-tray.exe""#);
    let fixture = with_thunderbird(machine())
        .sz(&run_key(hklm, "Run"), "MailHelper", &command)
        .binary(&approved(hklm, "Run"), "MailHelper", ENABLED.to_vec());
    let mut world = World::new(fixture, git());
    world.other_apps = thunderbird();
    let found = world.scan(&RegRun);
    assert_eq!(found.len(), 1, "{}", golden::render(&found));
    let run = expect(&found, &value(run_key(hklm, "Run"), "MailHelper"));
    assert!(run.blockers.contains(&Blocker::ReferencedByOtherApp {
        app: "Mozilla Thunderbird".into()
    }));
    assert!(find(&found, &value(approved(hklm, "Run"), "MailHelper")).is_none());
}

/// The same for the values REG-SOFTWARE and REF-ANY offer: a value that names another installed app
/// next to this one carries `ReferencedByOtherApp`; one entry of a list is judged by itself.
#[test]
fn value_naming_another_app_as_well_is_blocked() {
    let exe = format!(r"{FIREFOX}\firefox.exe");
    let other = format!(r"{THUNDERBIRD}\thunderbird.exe");
    let fixture = with_thunderbird(firefox_leftovers())
        .sz(
            r"HKLM\SOFTWARE\Mozilla\Firefox\Handoff",
            "Command",
            &format!(r#""{other}" --import "{exe}""#),
        )
        .sz(
            r"HKLM\SOFTWARE\Vendor\Tool",
            "Browsers",
            &format!(r"{THUNDERBIRD};{FIREFOX}\browser"),
        );
    let mut world = World::new(fixture, firefox());
    world.other_apps = thunderbird();
    let blocked = Blocker::ReferencedByOtherApp {
        app: "Mozilla Thunderbird".into(),
    };
    for scanner in [&RegSoftware as &dyn Scanner, &RefAny] {
        let found = world.scan(scanner);
        let command = expect(
            &found,
            &value(r"HKLM\SOFTWARE\Mozilla\Firefox\Handoff", "Command"),
        );
        assert!(command.blockers.contains(&blocked), "{}", scanner.id());
        // A value that names this app only is not touched by the rule.
        let own = expect(
            &found,
            &value(r"HKLM\SOFTWARE\Mozilla\Firefox\TaskBarIDs", FIREFOX),
        );
        assert!(own.blockers.is_empty(), "{}", scanner.id());
    }
    let found = world.scan(&RefAny);
    let entry = expect(
        &found,
        &segment(
            r"HKLM\SOFTWARE\Vendor\Tool",
            "Browsers",
            &format!(r"{FIREFOX}\browser"),
        ),
    );
    assert_eq!(entry.action, Action::EditSegment);
    assert!(entry.blockers.is_empty());
}

/// `Path` and the other variables of Windows itself are never offered whole, even when the Inno log
/// has a delete record on the value and the value holds one entry only.
#[test]
fn env_windows_variables_are_never_offered_whole() {
    let user_env = format!(r"HKU\{SID}\Environment");
    let record = |fp: &mut purge_model::Fingerprint| {
        fp.inno = vec![
            inno(InnoRecordKind::RegDeleteValue, value(MACHINE_ENV, "Path")),
            inno(
                InnoRecordKind::RegDeleteValue,
                value(user_env.clone(), "PATH"),
            ),
            inno(InnoRecordKind::RegDeleteValue, value(MACHINE_ENV, "TEMP")),
        ];
    };
    // One foreign entry each: nothing is the app's.
    let mut fp = git();
    record(&mut fp);
    let fixture = machine()
        .expand_sz(MACHINE_ENV, "Path", r"C:\Tools")
        .expand_sz(&user_env, "Path", r"C:\Users\tester\bin")
        .expand_sz(MACHINE_ENV, "TEMP", r"C:\Windows\TEMP");
    let found = World::new(fixture, fp).scan(&RegEnv);
    assert!(found.is_empty(), "{}", golden::render(&found));

    // The app's entry as the only one: an entry edit, never the variable.
    let mut fp = git_with_path_snapshot();
    record(&mut fp);
    let found = World::new(path_value(&[&git_cmd()]), fp).scan(&RegEnv);
    assert_eq!(found.len(), 1, "{}", golden::render(&found));
    assert_eq!(found[0].action, Action::EditSegment);
    assert_eq!(
        found[0].target,
        segment(MACHINE_ENV_PLAN, "Path", &git_cmd())
    );
}

/// A key that is a vendor alias and matches the app by tokens only is not taken whole on a root
/// reference somewhere below it: it may hold products that are no installed apps of their own.
#[test]
fn software_vendor_alias_key_is_not_taken_whole_on_a_token_match() {
    let root = r"C:\Program Files\Acmeworks Zenith\Acmeworks";
    let mut fp = git();
    fp.app.display_name = "Acmeworks".into();
    fp.identity.names = vec!["Acmeworks".into()];
    fp.identity.vendors = vec!["Acmeworks Zenith".into()];
    fp.identity.tokens = vec!["acmeworks".into()];
    fp.roots[0].path = root.into();
    fp.roots[0].source = RootSource::ArpInstallLocation;
    fp.exes[0].path = format!(r"{root}\acmeworks.exe");
    let vendor = r"HKLM\SOFTWARE\Acmeworks Zenith";
    let fixture = machine()
        .dir(r"C:\Program Files\Acmeworks Zenith")
        .sz(&format!(r"{vendor}\Settings"), "InstallDir", root)
        // A product the launcher installed: not an installed app, invisible to the other-app test.
        .sz(&format!(r"{vendor}\Engine 5"), "Licence", "ABCD-1234");
    let world = World::new(fixture, fp);
    {
        // The case under test: a vendor alias that is a name-token match but not the full name.
        let app = purge_scan::framework::AppIdentityView::from_fingerprint(&world.fp, &world.env);
        assert!(app.identity.matches_vendor("Acmeworks Zenith").is_some());
        assert!(app.identity.matches_name("Acmeworks Zenith").is_some());
        assert!(app.identity.matches_full_name("Acmeworks Zenith").is_none());
    }
    let found = world.scan(&RegSoftware);
    let key_candidate = expect(&found, &key(vendor));
    assert_eq!(
        key_candidate.action,
        Action::RemoveDirIfEmpty,
        "{}",
        golden::render(&found)
    );
    assert!(!has(key_candidate, EvidenceKind::AppNamedKeyWithRootRef));
    assert!(!tier_a_in_scope(key_candidate));
    assert!(find(&found, &key(format!(r"{vendor}\Engine 5"))).is_none());
    // The value that names the root is still a value target.
    assert!(find(&found, &value(format!(r"{vendor}\Settings"), "InstallDir")).is_some());
}

/// A value of a service's registration is listed as system integration (never preselected) and named
/// through `CurrentControlSet`.
#[test]
fn ref_any_service_values_are_system_and_spelled_current_control_set() {
    let fixture = machine().expand_sz(
        r"HKLM\SYSTEM\ControlSet001\Services\GitDaemon",
        "ImagePath",
        &format!(r#""{GIT}\cmd\git-daemon.exe" --service"#),
    );
    let world = World::new(fixture, git());
    let found = world.scan(&RefAny);
    assert_eq!(found.len(), 1, "{}", golden::render(&found));
    assert_eq!(
        found[0].target,
        value(
            r"HKLM\SYSTEM\CurrentControlSet\Services\GitDaemon",
            "ImagePath"
        )
    );
    assert_eq!(found[0].category, purge_model::Category::System);
    assert_eq!(found[0].action, Action::DeleteValue);
}

/// Under `SOFTWARE\Microsoft` a harvested token in a key's name does not make the key a candidate,
/// even when everything in it was attributed at harvest; elsewhere it does.
#[test]
fn ref_any_token_named_key_under_microsoft_is_not_offered() {
    let exe = format!(r"{FIREFOX}\firefox.exe");
    let inside = format!(r"HKLM\SOFTWARE\{CV}\Uninstall\Firefox-{HASH}");
    let outside = format!(r"HKLM\SOFTWARE\Clients\StartMenuInternet\Firefox-{HASH}");
    let mut fp = firefox();
    fp.subtrees = vec![
        subtree(&inside, &[("", "DisplayIcon")], &[]),
        subtree(&outside, &[("", "DisplayIcon")], &[]),
    ];
    let fixture =
        firefox_leftovers()
            .sz(&inside, "DisplayIcon", &exe)
            .sz(&outside, "DisplayIcon", &exe);
    let world = World::new(fixture, fp);
    let found = world.scan(&RefAny);
    assert!(find(&found, &key(inside.clone())).is_none());
    assert!(find(&found, &key(outside)).is_some());
    // The value itself is still a value target.
    assert!(find(&found, &value(inside, "DisplayIcon")).is_some());
}

/// The M1a campaign case (r0-npp): `Software\WOW6432Node\Notepad++` is named like the product, and the
/// product's name is also one of its vendor aliases. It holds one value that names nothing of the
/// app. As a vendor container it could never be emptied; it is the product's own key and is offered
/// whole on its name: no Tier A evidence, so listed and never ticked. With another installed app that
/// carries the name in its own, the key may be shared and stays a delete-if-empty container.
#[test]
fn software_key_named_like_the_product_is_a_product_key_not_a_vendor_container() {
    let npp_key = r"HKLM\SOFTWARE\WOW6432Node\Notepad++";
    let world = |other: Option<&str>| {
        let mut fp = notepadpp();
        fp.identity = identity(
            &["Notepad++ (64-bit x64)", "Notepad++"],
            &["Notepad++ Team", "NOTEPAD++"],
            &["notepad++"],
        );
        let mut world = World::new(machine().dword(npp_key, "InstallerLanguage", 1033), fp);
        if let Some(name) = other {
            world.other_apps = OtherApps::new(vec![OtherApp {
                name: name.into(),
                ..OtherApp::default()
            }]);
        }
        world
    };
    let found = world(None).scan(&RegSoftware);
    assert_eq!(found.len(), 1, "{}", golden::render(&found));
    let product = expect(&found, &key(npp_key));
    assert_eq!(product.action, Action::DeleteKey);
    assert!(has(product, EvidenceKind::ExactFullName));
    assert!(!has(product, EvidenceKind::VendorContainer));
    assert!(!tier_a_in_scope(product), "{product:?}");
    assert!(product.blockers.is_empty());

    // An unrelated app changes nothing; one that carries the product's name does.
    let found = world(Some("Acme Editor")).scan(&RegSoftware);
    assert_eq!(expect(&found, &key(npp_key)).action, Action::DeleteKey);
    let found = world(Some("Notepad++ Plugin Manager")).scan(&RegSoftware);
    let shared = expect(&found, &key(npp_key));
    assert_eq!(shared.action, Action::RemoveDirIfEmpty);
    assert_eq!(kinds(shared), vec![EvidenceKind::VendorContainer]);
}
