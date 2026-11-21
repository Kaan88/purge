//! An NSIS app (Fennec Browser) whose uninstaller also removes a co-product (Fennec Maintenance
//! Service), while a sibling product of the same vendor (Fennec Mail) stays installed. Driven through the
//! pipeline functions.

use purge_engine::cli::output::json_text;
use purge_engine::pipeline::{self, Settings};
use purge_identity::kbdata::Kb;
use purge_inventory::runner::RunOptions;
use purge_model::{Band, Plan, RunOutcome, ScanMode, Target};

use crate::common::{FakeHost, Switch, golden, machine, rig};

const KEY_NAME: &str = "Fennec Browser 9.0 (x64 en-US)";

/// The Fennec machine.
pub fn fennec() -> Switch {
    Switch::new(machine("nsis", |_| {}))
}

fn mentions(target: &Target, needle: &str) -> bool {
    format!("{target:?}")
        .to_lowercase()
        .contains(&needle.to_lowercase())
}

#[test]
fn nsis_app_with_a_co_product_through_the_pipeline() {
    let machine = fennec();
    let sources = machine.sources();
    let settings = Settings::default();
    let mut lines: Vec<String> = Vec::new();
    let mut progress = |l: &str| lines.push(l.to_owned());

    // Harvest: the maintenance service is a co-product candidate, the mail client is not.
    let harvested =
        pipeline::harvest(sources, KEY_NAME, Kb::shipped(), &settings, &mut progress).unwrap();
    let names: Vec<&str> = harvested
        .report
        .co_candidates
        .iter()
        .map(|c| c.app.display_name.as_str())
        .collect();
    assert_eq!(names, ["Fennec Maintenance Service"]);
    let mut fp = harvested.report.fingerprint;

    // Uninstall: the co-product disappears with the app.
    let mut host = FakeHost::new(&machine, Some(0), true);
    let done = pipeline::uninstall(
        sources,
        &mut host,
        KEY_NAME,
        Some(&mut fp),
        &RunOptions::default(),
        &mut progress,
    )
    .unwrap();
    assert!(!done.failed());
    assert_eq!(done.report.doc.outcome, RunOutcome::Success);
    assert_eq!(
        host.spawned,
        [r#""C:\Program Files\Fennec Browser\uninstall\helper.exe" /S"#]
    );
    let co: Vec<&str> = fp
        .co_removed
        .iter()
        .map(|c| c.app.display_name.as_str())
        .collect();
    assert_eq!(co, ["Fennec Maintenance Service"]);
    assert!(fp.verify_gone.is_some_and(|v| v.is_passed()));

    // Scan.
    let scanned =
        pipeline::scan(sources, &fp, ScanMode::Post, None, &settings, &mut progress).unwrap();
    let plan: &Plan = &scanned.built.plan;
    assert_eq!(plan.app, "fennec browser 9.0 (x64 en-us)");
    assert_eq!(
        scanned.per_scanner.len(),
        purge_scan::catalog::SCANNER_IDS.len()
    );
    let text = json_text(plan);
    golden("nsis.plan.json", &text);
    serde_json::from_str::<rig::Plan>(&text).expect("the rig reads the plan");

    // The sibling product stays untouched: never Safe, never ticked.
    for i in &plan.items {
        if mentions(&i.target, "Fennec Mail") || mentions(&i.target, "fennecmail") {
            assert!(
                i.band != Band::Safe && !i.preselected,
                "the still-installed mail client: {i:?}"
            );
        }
    }
    // The vendor's key and folder that still hold the mail client's own are not offered at all, not
    // even delete-if-empty: nothing the plan lists could empty them (M1a gate, `Software\Mozilla`
    // with `Thunderbird` in it).
    for kept in [
        Target::RegKey {
            path: r"HKLM\SOFTWARE\Fennec".into(),
        },
        Target::Path {
            path: r"C:\Users\tester\AppData\Roaming\Fennec".into(),
        },
    ] {
        assert!(
            plan.items.iter().all(|i| i.target != kept),
            "a vendor container holding the mail client's data is listed: {kept:?}"
        );
    }
    // The browser's own leftovers are found.
    assert!(
        plan.items.iter().any(|i| i.target
            == Target::Path {
                path: r"C:\Program Files\Fennec Browser".into()
            }),
        "{plan:#?}"
    );
    // Progress went out, first line before any work.
    assert!(
        lines[0].starts_with("harvest: reading the inventory"),
        "{lines:?}"
    );

    // The same inputs give the same plan.
    let again = pipeline::scan(sources, &fp, ScanMode::Post, None, &settings, &mut |_| {}).unwrap();
    assert_eq!(again.built, scanned.built);
}

#[test]
fn external_and_forced_scans_check_verify_gone_afresh() {
    let machine = fennec();
    let settings = Settings::default();
    let fp = pipeline::harvest(
        machine.sources(),
        KEY_NAME,
        Kb::shipped(),
        &settings,
        &mut |_| {},
    )
    .unwrap()
    .report
    .fingerprint;
    // Still installed: verify-gone fails, nothing is Safe in either mode.
    for mode in [ScanMode::External, ScanMode::Forced] {
        let scanned = pipeline::scan(
            machine.sources(),
            &fp,
            mode,
            Some("fennec"),
            &settings,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(scanned.built.plan.mode, mode);
        assert!(
            scanned
                .built
                .plan
                .items
                .iter()
                .all(|i| i.band != Band::Safe && !i.preselected),
            "{mode:?}"
        );
        if mode == ScanMode::External {
            assert!(
                scanned
                    .warnings
                    .iter()
                    .any(|w| w.message.contains("verify-gone failed")),
                "{:?}",
                scanned.warnings
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// A COM class shared with the sibling product (M1a gate, r0-firefox-tb)
// ---------------------------------------------------------------------------------------------------------

const CLASS: &str = "{1814CEEB-49E2-407F-AF99-FA755A7D2607}";
const INTERFACES: [&str; 3] = [
    "{0D68D6D0-D93D-4D08-A30D-F00DD1F45B24}",
    "{1814CEEB-49E2-407F-AF99-FA755A7D2607}",
    "{4E747BE5-2052-4265-8AF0-8ECAD7AAD1C0}",
];
/// The last-write time of the browser's Uninstall key in `nsis.before.json`: its install time.
const BROWSER_INSTALLED: u64 = 134_390_000_000_000_000;
const SECOND: u64 = 10_000_000;

/// How the accessibility class got onto the machine.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ClassStory {
    /// The mail client registered it 45 seconds before the browser was installed and ships the same
    /// DLL; the browser's installer only rewrote the server path. The gate case.
    MailFirstSameDll,
    /// The mail client registered it 45 seconds before the browser's install directory was created,
    /// and nothing else is known: it ships no DLL of that name. Only the exact age shows it.
    MailFirstNothingShared,
    /// The class key is a month older than the browser's install; nobody else ships the DLL.
    OlderThanTheInstall,
    /// The browser registered it itself.
    BrowsersOwn,
}

fn with_class(story: ClassStory) -> Switch {
    use purge_model::FileTime;
    use purge_source::types::RegData;
    Switch::new(machine("nsis", |f| {
        let class_key = format!(r"HKLM\SOFTWARE\Classes\CLSID\{CLASS}");
        let server = format!(r"{class_key}\InProcServer32");
        let registered = match story {
            ClassStory::MailFirstSameDll | ClassStory::MailFirstNothingShared => {
                BROWSER_INSTALLED - 45 * SECOND
            }
            ClassStory::OlderThanTheInstall => BROWSER_INSTALLED - 30 * 86_400 * SECOND,
            ClassStory::BrowsersOwn => BROWSER_INSTALLED + 5 * SECOND,
        };
        f.add_file(
            r"C:\Program Files\Fennec Browser\AccessibleMarshal.dll",
            30_000,
        );
        if story == ClassStory::MailFirstNothingShared {
            // The inventory reads the install directory's creation time: the exact start of the
            // install, two seconds before the Uninstall key was written.
            let created = FileTime(BROWSER_INSTALLED - 2 * SECOND);
            f.set_times(
                r"C:\Program Files\Fennec Browser",
                purge_source::types::FileTimes {
                    created: Some(created),
                    modified: Some(created),
                    accessed: None,
                },
            );
        }
        if story == ClassStory::MailFirstSameDll {
            f.add_file(
                r"C:\Program Files\Fennec Mail\AccessibleMarshal.dll",
                30_000,
            );
        }
        f.set_value(
            &server,
            "",
            RegData::from_sz(r"C:\Program Files\Fennec Browser\AccessibleMarshal.dll"),
        );
        f.set_key_lwt(&class_key, FileTime(registered));
        // The browser's installer wrote the server path in every story.
        f.set_key_lwt(&server, FileTime(BROWSER_INSTALLED + 5 * SECOND));
        for iid in INTERFACES {
            let proxy = format!(r"HKLM\SOFTWARE\Classes\Interface\{iid}\ProxyStubClsid32");
            f.set_value(&proxy, "", RegData::from_sz(CLASS));
            f.set_key_lwt(&proxy, FileTime(registered));
            f.set_key_lwt(
                &format!(r"HKLM\SOFTWARE\Classes\Interface\{iid}"),
                FileTime(registered),
            );
        }
    }))
}

/// Harvest, uninstall and scan; returns whether the class is an anchor and every listed target (top
/// level and absorbed) that names the class or an interface key.
fn class_items(story: ClassStory) -> (bool, Vec<String>) {
    let machine = with_class(story);
    let sources = machine.sources();
    let settings = Settings::default();
    let harvested =
        pipeline::harvest(sources, KEY_NAME, Kb::shipped(), &settings, &mut |_| {}).unwrap();
    let demoted = harvested
        .report
        .modified_clsids
        .iter()
        .any(|m| m.id.eq_ignore_ascii_case(CLASS));
    let mut fp = harvested.report.fingerprint;
    let anchor = fp
        .anchors
        .clsids
        .iter()
        .any(|c| c.eq_ignore_ascii_case(CLASS));
    assert_ne!(anchor, demoted, "{story:?}");
    let mut host = FakeHost::new(&machine, Some(0), true);
    pipeline::uninstall(
        sources,
        &mut host,
        KEY_NAME,
        Some(&mut fp),
        &RunOptions::default(),
        &mut |_| {},
    )
    .unwrap();
    let scanned =
        pipeline::scan(sources, &fp, ScanMode::Post, None, &settings, &mut |_| {}).unwrap();
    let sidecar = json_text(&scanned.built.scan).to_uppercase();
    let plan = &scanned.built.plan;
    let listed: Vec<String> = plan
        .items
        .iter()
        .filter(|i| mentions(&i.target, CLASS) || mentions(&i.target, r"\Interface\\"))
        .map(|i| format!("{:?} {:?} {}", i.target, i.band, i.preselected))
        .collect();
    if listed.is_empty() {
        // Nothing absorbed or explained either: the class does not appear in the sidecar at all.
        assert!(!sidecar.contains(CLASS), "{story:?}");
    }
    (anchor, listed)
}

/// Removing the browser must leave the mail client's COM class alone: neither the three
/// `Interface\…\ProxyStubClsid32` values nor the `InProcServer32` value the browser overwrote are
/// offered, in any band.
#[test]
fn com_class_shared_with_the_sibling_product_is_not_offered() {
    let (anchor, listed) = class_items(ClassStory::MailFirstSameDll);
    assert!(
        !anchor,
        "a class another app ships the server of is not an anchor"
    );
    assert_eq!(listed, Vec::<String>::new());
}

/// The same with nothing known about the mail client's files: the class key is 45 seconds older than
/// the browser's install directory, so the browser cannot have registered it.
#[test]
fn com_class_registered_seconds_before_the_install_directory_existed_is_not_offered() {
    let (anchor, listed) = class_items(ClassStory::MailFirstNothingShared);
    assert!(!anchor);
    assert_eq!(listed, Vec::<String>::new());
}

/// The same without the second copy of the DLL: a class key that is older than the app's install is
/// not the app's registration.
#[test]
fn com_class_older_than_the_install_is_not_offered() {
    let (anchor, listed) = class_items(ClassStory::OlderThanTheInstall);
    assert!(!anchor);
    assert_eq!(listed, Vec::<String>::new());
}

/// The control: the browser's own class is an anchor. Its server value is offered, and the interface
/// values, known only through the class id, are never Safe or ticked. The class is the shared Gecko
/// proxy of `kb/shared-iids.json` and the interfaces are shared IIDs, but the values' data was the
/// browser's, so `com.shared-proxy` and `com.shared-iid` are lifted for these values only (R2a S10):
/// the bands are M1a's. The shared keys themselves stay denied.
#[test]
fn com_class_of_the_app_itself_is_offered_with_unticked_interface_values() {
    let (anchor, listed) = class_items(ClassStory::BrowsersOwn);
    assert!(anchor);
    assert!(
        listed.iter().any(|l| l.contains("InProcServer32")),
        "{listed:#?}"
    );
    let interfaces: Vec<&String> = listed.iter().filter(|l| l.contains("Interface")).collect();
    assert_eq!(interfaces.len(), 3, "{listed:#?}");
    for line in interfaces {
        assert!(line.ends_with("Likely false"), "{line}");
    }
}
