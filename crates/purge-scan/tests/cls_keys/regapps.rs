//! CLS-REGAPPS: `RegisteredApplications` values, `Capabilities` keys and `Clients` entries.

use purge_model::{Blocker, Category};
use purge_scan::cls_regapps::ClsRegApps;
use purge_scan::framework::{OtherApp, OtherApps, Scanner};
use purge_source::fixture::Fixture;
use purge_source::types::RegData;

use crate::common::*;

const ROOT: &str = r"C:\Program Files\Acme Mail";
const OPEN: &str = r#""C:\Program Files\Acme Mail\mail.exe" -mail"#;
const REGISTERED: &str = r"HKLM\SOFTWARE\RegisteredApplications";
const CLIENT: &str = r"HKLM\SOFTWARE\Clients\Mail\Acme Mail";
const CAPABILITIES: &str = r"HKLM\SOFTWARE\Acme\Mail\Capabilities";

fn user_registered() -> String {
    format!(r"HKU\{SID}\Software\RegisteredApplications")
}

fn registry() -> Fixture {
    machine()
        // A mail client entry by command.
        .sz(CLIENT, "", "Acme Mail")
        .sz(&format!(r"{CLIENT}\shell\open\command"), "", OPEN)
        // Capabilities outside Clients, naming a ProgID of P; registered in HKLM.
        .sz(CAPABILITIES, "ApplicationName", "Acme Mail")
        .sz(
            &format!(r"{CAPABILITIES}\FileAssociations"),
            ".eml",
            "AcmeMail.Message",
        )
        .sz(REGISTERED, "Acme Mail", r"SOFTWARE\Acme\Mail\Capabilities")
        // A registration whose Capabilities key is already gone.
        .sz(
            REGISTERED,
            "Acme Mail (old)",
            r"Software\Acme\Old\Capabilities",
        )
        // The user's hive: a registration recorded by the Inno log.
        .sz(
            &user_registered(),
            "Acme Mail User",
            r"Software\Acme\Mail\Capabilities",
        )
        // Others.
        .sz(
            r"HKLM\SOFTWARE\Clients\Mail\Other Mail\shell\open\command",
            "",
            r#""C:\Program Files\Other Mail\other.exe""#,
        )
        .sz(
            r"HKLM\SOFTWARE\Other\Capabilities",
            "ApplicationIcon",
            r"C:\Program Files\Other Mail\other.exe,0",
        )
        .sz(REGISTERED, "Other Mail", r"Software\Other\Capabilities")
        .sz(
            REGISTERED,
            "Paint",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Paint\Capabilities",
        )
        .sz(REGISTERED, "Odd", r"..\..\SYSTEM\Setup")
        .build()
}

fn world() -> World {
    let mut fp = machine_fp("AcmeMail", "Acme Mail", ROOT);
    fp.exes = vec![exe(&format!(r"{ROOT}\mail.exe"))];
    fp.anchors.progids = vec!["AcmeMail.Message".into()];
    let mut world = World::new(registry(), fp);
    world.baseline = Some(baseline(&[
        r"HKLM\SOFTWARE\Clients",
        r"HKLM\SOFTWARE\Clients\Mail",
        REGISTERED,
    ]));
    world
}

#[test]
fn registration_capabilities_and_client_are_offered() {
    let world = world();
    let candidates = world.run(&ClsRegApps);
    assert_golden(
        render(&candidates),
        &[
            r"key HKLM\SOFTWARE\Clients\Mail\Acme Mail DeleteKey [ChainedRef/A/Key]",
            r"key HKLM\SOFTWARE\Acme\Mail\Capabilities DeleteKey [ChainedRef/A/Key]",
            r"value HKLM\SOFTWARE\RegisteredApplications|Acme Mail DeleteValue [ChainedRef/A/Value]",
        ],
    );
    assert!(
        candidates
            .iter()
            .all(|c| c.category == Category::Registration)
    );
    let capabilities = on_key(&candidates, CAPABILITIES).unwrap();
    let chain = &capabilities.evidence[0];
    assert_eq!(chain.detail.get("anchor"), Some("AcmeMail.Message"));
    // Not nested in the client key: nobody's child.
    assert!(on_key(&candidates, CLIENT).unwrap().children.is_empty());
    assert_eq!(
        ClsRegApps.value_containers(),
        [r"*\SOFTWARE\RegisteredApplications"]
    );
}

#[test]
fn recorded_registrations_are_offered_without_their_capabilities_key() {
    let mut world = world();
    world.fp.inno = vec![purge_model::InnoRecord {
        kind: purge_model::InnoRecordKind::RegDeleteValue,
        target: purge_model::Target::RegValue {
            path: user_registered(),
            name: "Acme Mail User".into(),
        },
        view: Some(purge_model::View::K64),
        user_hive: true,
        existed_before: false,
        shared: false,
        key_create: false,
    }];
    world.fp.ref_snapshot = vec![snap_progid_value(REGISTERED, "Acme Mail (old)")];
    let lines = world.golden(&ClsRegApps);
    assert!(lines.contains(&format!(
        "value {}|Acme Mail User DeleteValue [InstallerManifest/A/Value]",
        user_registered()
    )));
    // Known only from the snapshot, through a ProgID: Tier B, so it cannot be Safe on that alone.
    assert!(lines.contains(
        &r"value HKLM\SOFTWARE\RegisteredApplications|Acme Mail (old) DeleteValue [InPreUninstallRefSnapshot/B/Value]"
            .to_owned()
    ));
    assert_eq!(lines.len(), 5, "{lines:?}");
}

#[test]
fn without_a_baseline_keys_are_not_offered() {
    // Every view below Exact takes the no-baseline path (presence-only, design L5).
    for below in 0..purge_index::baseline_view::fixture::BELOW_EXACT {
        let mut world = world();
        world.baseline = purge_index::baseline_view::fixture::below_exact(below, &world.fp.os);
        // The client key carries the app's name: its values are the app's registration.
        world.fp.identity.tokens = vec!["acme".into(), "mail".into()];
        assert_golden(
            world.golden(&ClsRegApps),
            &[
                r"value HKLM\SOFTWARE\Clients\Mail\Acme Mail\shell\open\command| DeleteValue [DanglingRef/A/Value, PointsIntoInstallRoot/A/Value]",
                r"value HKLM\SOFTWARE\RegisteredApplications|Acme Mail DeleteValue [ChainedRef/A/Value]",
            ],
        );
    }
}

#[test]
fn capabilities_inside_another_apps_key_prove_nothing() {
    let mut world = world();
    world.other_apps = OtherApps::new(vec![OtherApp {
        name: "Acme Suite".into(),
        keys: vec![r"HKLM\SOFTWARE\Acme\Mail".into()],
        ..OtherApp::default()
    }]);
    let candidates = world.run(&ClsRegApps);
    assert_golden(
        render(&candidates),
        &[r"key HKLM\SOFTWARE\Clients\Mail\Acme Mail DeleteKey [ChainedRef/A/Key]"],
    );
}

#[test]
fn a_client_whose_command_launches_something_else_is_not_the_apps() {
    let mut world = world();
    world.fixture.set_value(
        &format!(r"{CLIENT}\shell\open\command"),
        "",
        RegData::from_sz(r#""C:\Program Files\Other Mail\other.exe""#),
    );
    assert!(on_key(&world.run(&ClsRegApps), CLIENT).is_none());
}

#[test]
fn blockers_reach_the_candidates() {
    let mut world = world();
    world.fixture.set_ti_owned(CLIENT, true);
    world.baseline = Some(baseline(&[
        r"HKLM\SOFTWARE\Clients",
        r"HKLM\SOFTWARE\Clients\Mail",
        REGISTERED,
        CAPABILITIES,
    ]));
    let candidates = world.run(&ClsRegApps);
    assert_eq!(
        on_key(&candidates, CLIENT).unwrap().blockers,
        vec![Blocker::TrustedInstallerOwned]
    );
    // Windows ships the Capabilities key: values only, and none of them points into the app.
    assert!(on_key(&candidates, CAPABILITIES).is_none());
}

/// Invariant L5 over this world: a view below Exact only takes away (`tests/shared/l5.rs`).
#[test]
fn l5_a_view_below_exact_only_takes_away() {
    let offered = crate::l5_check("regapps", &world, &["CLS-REGAPPS"]);
    assert!(offered > 0, "the world offers something without a baseline");
}
