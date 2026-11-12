//! Tests of the registry scanners REG-SOFTWARE, REG-APPPATHS, REG-RUN, REG-ENV and REF-ANY over
//! fixtures shaped like machines after an uninstall (Firefox with its Maintenance Service, Git,
//! Notepad++).
//!
//! Each scanner has golden files under `tests/reg/golden` (see [`golden`]); the assertions next to them
//! spell out the properties the design depends on.

mod golden;
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

    // `mozilla.org`: a vendor container, delete-if-empty, Likely by its score.
    let org = expect(&found, &key(r"HKLM\SOFTWARE\mozilla.org"));
    assert_eq!(org.action, Action::RemoveDirIfEmpty);
    assert!(!tier_a_in_scope(org));
    assert_eq!(score(org), 4, "{:?}", org.evidence);
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
    ];
    assert_eq!(found.len(), targets.len(), "{}", golden::render(&found));
    for target in &targets {
        let c = expect(&found, target);
        // Value targets only, all with Value-scope Tier A evidence.
        assert_eq!(c.action, Action::DeleteValue);
        assert!(tier_a_in_scope(c), "{}", golden::target_text(target));
        assert!(c.blockers.is_empty());
    }
    let run = expect(&found, &targets[0]);
    assert_eq!(
        kinds(run),
        vec![
            EvidenceKind::InPreUninstallRefSnapshot,
            EvidenceKind::PointsIntoInstallRoot,
            EvidenceKind::DanglingRef
        ]
    );
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
    assert!(tier_a_in_scope(expect(
        &found,
        &value(MACHINE_ENV_PLAN, "GIT_SSH")
    )));
}

// ---------------------------------------------------------------------------------------------------------
// REF-ANY
// ---------------------------------------------------------------------------------------------------------

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
