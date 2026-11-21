//! CLS-VERBS: verbs under the shell objects, attributed by their command.

use purge_model::{Category, HarvestedToken, SourceId};
use purge_scan::cls_verbs::ClsVerbs;
use purge_source::fixture::Fixture;
use purge_source::types::RegData;

use crate::common::*;

const ROOT: &str = r"C:\Program Files\Acme Editor";
const OPEN: &str = r#""C:\Program Files\Acme Editor\editor.exe" "%1""#;

fn verb(object: &str, name: &str) -> String {
    format!(r"{HKLM_CLASSES}\{object}\shell\{name}")
}

fn registry() -> Fixture {
    machine()
        // The app's verbs on five of the shell objects, one of them in the user's hive.
        .sz(&format!(r"{}\command", verb("*", "AcmeEdit")), "", OPEN)
        .sz(
            &verb("*", "AcmeEdit"),
            "Icon",
            r"C:\Program Files\Acme Editor\editor.exe",
        )
        .sz(
            &format!(r"{}\command", verb("Directory", "AcmeEdit")),
            "",
            OPEN,
        )
        .sz(
            &format!(r"{}\command", verb(r"Directory\Background", "AcmeEdit")),
            "",
            OPEN,
        )
        .sz(&format!(r"{}\command", verb("Drive", "AcmeEdit")), "", OPEN)
        .sz(
            &format!(r"{}\Folder\shell\AcmeEdit\command", user_classes()),
            "",
            OPEN,
        )
        // Windows' and another app's verbs.
        .sz(
            &format!(r"{}\command", verb("Directory", "cmd")),
            "",
            r#"cmd.exe /s /k pushd "%V""#,
        )
        .sz(
            &format!(r"{}\command", verb("*", "OtherTool")),
            "",
            r#""C:\Program Files\Other\other.exe" "%1""#,
        )
        // A verb in a place this scanner does not read.
        .sz(
            &format!(r"{HKLM_CLASSES}\txtfile\shell\AcmeEdit\command"),
            "",
            OPEN,
        )
        .build()
}

fn world() -> World {
    let mut fp = machine_fp("AcmeEditor", "Acme Editor", ROOT);
    fp.exes = vec![exe(&format!(r"{ROOT}\editor.exe"))];
    let mut world = World::new(registry(), fp);
    world.baseline = Some(baseline(&[
        HKLM_CLASSES,
        r"HKLM\SOFTWARE\Classes\*",
        r"HKLM\SOFTWARE\Classes\*\shell",
        r"HKLM\SOFTWARE\Classes\Directory",
        r"HKLM\SOFTWARE\Classes\Directory\shell",
        r"HKLM\SOFTWARE\Classes\Directory\shell\cmd",
        r"HKLM\SOFTWARE\Classes\Directory\shell\cmd\command",
        r"HKLM\SOFTWARE\Classes\Directory\Background",
        r"HKLM\SOFTWARE\Classes\Directory\Background\shell",
        r"HKLM\SOFTWARE\Classes\Drive",
        r"HKLM\SOFTWARE\Classes\Drive\shell",
    ]));
    world
}

#[test]
fn verbs_whose_command_launches_the_app_are_offered() {
    let world = world();
    let candidates = world.run(&ClsVerbs);
    assert_golden(
        render(&candidates),
        &[
            r"key HKLM\SOFTWARE\Classes\*\shell\AcmeEdit DeleteKey [ChainedRef/A/Key]",
            r"key HKLM\SOFTWARE\Classes\Directory\Background\shell\AcmeEdit DeleteKey [ChainedRef/A/Key]",
            r"key HKLM\SOFTWARE\Classes\Directory\shell\AcmeEdit DeleteKey [ChainedRef/A/Key]",
            r"key HKLM\SOFTWARE\Classes\Drive\shell\AcmeEdit DeleteKey [ChainedRef/A/Key]",
            &format!(
                r"key {}\Folder\shell\AcmeEdit DeleteKey [ChainedRef/A/Key]",
                user_classes()
            ),
        ],
    );
    assert!(candidates.iter().all(|c| c.category == Category::ShellCom));
    // The user's `Folder\shell` exists only because of the app, but nothing proves it: not offered.
    assert!(on_key(&candidates, &format!(r"{}\Folder\shell", user_classes())).is_none());
}

#[test]
fn a_verb_named_by_a_harvested_token_carries_it() {
    let mut world = world();
    let token = "0A1B2C3D4E5F6071";
    world.fp.tokens = vec![HarvestedToken {
        token: token.into(),
        source: SourceId("arp:key".into()),
    }];
    let key = verb("AllFilesystemObjects", &format!("Acme-{token}"));
    world
        .fixture
        .set_value(&format!(r"{key}\command"), "", RegData::from_sz(OPEN));
    let candidates = world.run(&ClsVerbs);
    let c = on_key(&candidates, &key).unwrap();
    assert_eq!(
        render(std::slice::from_ref(c)),
        [format!(
            "key {key} DeleteKey [ChainedRef/A/Key, HarvestedToken/A/Key]"
        )]
    );
}

#[test]
fn without_a_baseline_only_the_values_are_offered() {
    // Every view below Exact takes the no-baseline path (presence-only, design L5).
    for below in 0..purge_index::baseline_view::fixture::BELOW_EXACT {
        let mut world = world();
        world.baseline = purge_index::baseline_view::fixture::below_exact(below, &world.fp.os);
        let lines = world.golden(&ClsVerbs);
        assert_eq!(lines.len(), 6, "{lines:?}");
        // `*\shell`, `Directory\shell` and the like are places every program and the user add verbs to:
        // without an installer record a value that points at the app is Tier B.
        assert!(lines.iter().all(|l| l.starts_with("value ")
            && l.ends_with("DeleteValue [DanglingRef/B/Value, PointsIntoInstallRoot/B/Value]")));
        assert!(lines.contains(&format!(
            "value {}|Icon DeleteValue [DanglingRef/B/Value, PointsIntoInstallRoot/B/Value]",
            verb("*", "AcmeEdit")
        )));
    }
}

#[test]
fn a_verb_windows_ships_is_never_a_key_candidate() {
    // The app redirected Windows' own `cmd` verb to itself.
    let mut world = world();
    let command = format!(r"{}\command", verb("Directory", "cmd"));
    world
        .fixture
        .set_value(&command, "", RegData::from_sz(OPEN));
    let candidates = world.run(&ClsVerbs);
    assert!(on_key(&candidates, &verb("Directory", "cmd")).is_none());
    assert!(render(&candidates).contains(&format!(
        "value {command}| DeleteValue [DanglingRef/B/Value, PointsIntoInstallRoot/B/Value]"
    )));
}

#[test]
fn trusted_installer_owned_verb_carries_the_blocker() {
    let mut world = world();
    world.fixture.set_ti_owned(&verb("Drive", "AcmeEdit"), true);
    let lines = world.golden(&ClsVerbs);
    assert!(lines.contains(
        &r"key HKLM\SOFTWARE\Classes\Drive\shell\AcmeEdit DeleteKey [ChainedRef/A/Key] !TrustedInstallerOwned"
            .to_owned()
    ));
}

/// Invariant L5 over this world: a view below Exact only takes away (`tests/shared/l5.rs`).
#[test]
fn l5_a_view_below_exact_only_takes_away() {
    let offered = crate::l5_check("verbs", &world, &["CLS-VERBS"]);
    assert!(offered > 0, "the world offers something without a baseline");
}
