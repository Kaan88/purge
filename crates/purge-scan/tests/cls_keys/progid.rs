//! CLS-PROGID: keys of the set P, `*_auto_file` keys, and the blockers that keep a key.

use purge_model::{
    AnchorKind, Blocker, EvidenceKind, ExtJournalEntry, InnoRecord, InnoRecordKind, Target, Tier,
    View,
};
use purge_scan::cls_progid::ClsProgId;
use purge_scan::framework::{OtherApp, OtherApps};
use purge_source::fixture::Fixture;
use purge_source::types::RegData;

use crate::common::*;

const ROOT: &str = r"C:\Program Files\Acme Editor";
const OPEN: &str = r#""C:\Program Files\Acme Editor\editor.exe" "%1""#;
const DOC: &str = r"HKLM\SOFTWARE\Classes\Acme.Document";
const DOC_COMMAND: &str = r"HKLM\SOFTWARE\Classes\Acme.Document\shell\open\command";

/// The editor is uninstalled (its directory is gone) and its ProgID is still registered.
fn registry() -> Fixture {
    machine()
        .sz(DOC, "", "Acme document")
        .sz(DOC_COMMAND, "", OPEN)
        .build()
}

fn world() -> World {
    let mut fp = machine_fp("AcmeEditor", "Acme Editor", ROOT);
    fp.exes = vec![exe(&format!(r"{ROOT}\editor.exe"))];
    fp.anchors.progids = vec!["Acme.Document".into()];
    World::new(registry(), fp)
}

#[test]
fn progid_in_p_is_offered_as_a_key() {
    let world = world();
    let candidates = world.run(&ClsProgId);
    assert_golden(
        render(&candidates),
        &[r"key HKLM\SOFTWARE\Classes\Acme.Document DeleteKey [ChainedRef/A/Key]"],
    );
    let c = &candidates[0];
    assert_eq!(c.category, purge_model::Category::Association);
    assert_eq!(c.child_count, Some(5));
}

#[test]
fn inno_key_create_record_adds_the_manifest() {
    let mut world = world();
    world.fp.inno = vec![inno_key(DOC)];
    assert_golden(
        world.golden(&ClsProgId),
        &[
            r"key HKLM\SOFTWARE\Classes\Acme.Document DeleteKey [ChainedRef/A/Key, InstallerManifest/A/Key]",
        ],
    );
}

#[test]
fn progid_in_p_on_the_harvests_word_alone_is_chained_at_tier_b() {
    // The uninstaller removed the command; nothing in the key points anywhere now.
    let mut world = world();
    world.fixture.remove_key(&format!(r"{DOC}\shell"));
    assert_golden(
        world.golden(&ClsProgId),
        &[r"key HKLM\SOFTWARE\Classes\Acme.Document DeleteKey [ChainedRef/B/Key]"],
    );
    // With the harvest's record of the command it is Tier A again.
    world.fp.ref_snapshot = vec![snap_data_value(
        DOC_COMMAND,
        "",
        AnchorKind::Exe,
        &format!(r"{ROOT}\editor.exe"),
    )];
    let candidates = world.run(&ClsProgId);
    let chain = candidates[0]
        .evidence
        .iter()
        .find(|e| e.kind == EvidenceKind::ChainedRef)
        .unwrap();
    assert_eq!(chain.tier, Tier::A);
    assert_eq!(chain.detail.get("anchor"), Some("Acme.Document"));
}

#[test]
fn without_a_baseline_the_key_is_not_offered_only_its_values() {
    // Every view below Exact takes the no-baseline path (presence-only, design L5).
    for below in 0..purge_index::baseline_view::fixture::BELOW_EXACT {
        let mut world = world();
        world.baseline = purge_index::baseline_view::fixture::below_exact(below, &world.fp.os);
        assert_golden(
            world.golden(&ClsProgId),
            &[
                r"value HKLM\SOFTWARE\Classes\Acme.Document\shell\open\command| DeleteValue [DanglingRef/A/Value, PointsIntoInstallRoot/A/Value]",
            ],
        );
        // The harvest's record of the value counts as well.
        world.fp.ref_snapshot = vec![snap_data_value(
            DOC_COMMAND,
            "",
            AnchorKind::Exe,
            &format!(r"{ROOT}\editor.exe"),
        )];
        assert_golden(
            world.golden(&ClsProgId),
            &[
                r"value HKLM\SOFTWARE\Classes\Acme.Document\shell\open\command| DeleteValue [DanglingRef/A/Value, InPreUninstallRefSnapshot/A/Value, PointsIntoInstallRoot/A/Value]",
            ],
        );
    }
}

#[test]
fn pre_existing_progid_never_yields_a_key() {
    // Windows ships the key: the app only modified it.
    let mut world = world();
    world.baseline = Some(baseline(&[HKLM_CLASSES, DOC]));
    let lines = world.golden(&ClsProgId);
    assert_golden(
        lines,
        &[
            r"value HKLM\SOFTWARE\Classes\Acme.Document\shell\open\command| DeleteValue [DanglingRef/A/Value, PointsIntoInstallRoot/A/Value]",
        ],
    );
    // The Inno log says the key existed before the install.
    let mut world = self::world();
    world.fp.inno = vec![InnoRecord {
        existed_before: true,
        ..inno_key(DOC)
    }];
    assert!(on_key(&world.run(&ClsProgId), DOC).is_none());
}

#[test]
fn trusted_installer_owned_key_carries_the_blocker() {
    let mut world = world();
    world.fixture.set_ti_owned(DOC, true);
    assert_golden(
        world.golden(&ClsProgId),
        &[
            r"key HKLM\SOFTWARE\Classes\Acme.Document DeleteKey [ChainedRef/A/Key] !TrustedInstallerOwned",
        ],
    );
}

#[test]
fn progid_claimed_by_another_app_is_blocked() {
    let mut world = world();
    world.other_apps = OtherApps::new(vec![other_app(
        "Acme Viewer",
        r"C:\Program Files\Acme Viewer",
        &[(AnchorKind::ProgId, "acme.document")],
    )]);
    assert_golden(
        world.golden(&ClsProgId),
        &[
            r"key HKLM\SOFTWARE\Classes\Acme.Document DeleteKey [ChainedRef/A/Key] !ReferencedByOtherApp(Acme Viewer)",
        ],
    );
}

#[test]
fn progid_referenced_by_another_apps_association_is_blocked() {
    // Another app made the ProgID the default of its own extension, in the user's hive, and added it
    // to an OpenWithProgids list. Neither was there (as the app's) at harvest.
    let mut world = world();
    let ext = format!(r"{}\.acmeview", user_classes());
    world
        .fixture
        .set_value(&ext, "", RegData::from_sz("Acme.Document"));
    world.fixture.set_value(
        &format!(r"{HKLM_CLASSES}\.txt\OpenWithProgids"),
        "Acme.Document",
        RegData::from_sz(""),
    );
    world.other_apps = OtherApps::new(vec![OtherApp {
        name: "Acme Viewer".into(),
        keys: vec![ext.clone()],
        ..OtherApp::default()
    }]);
    let candidates = world.run(&ClsProgId);
    let c = on_key(&candidates, DOC).unwrap();
    assert_eq!(
        c.blockers,
        vec![
            Blocker::ReferencedByOtherApp {
                app: r"unrecorded association HKLM\SOFTWARE\Classes\.txt\OpenWithProgids|Acme.Document"
                    .into()
            },
            Blocker::ReferencedByOtherApp {
                app: "Acme Viewer".into()
            },
        ]
    );
    assert!(c.blockers.iter().all(Blocker::is_hard));
}

#[test]
fn the_apps_own_recorded_associations_do_not_block() {
    let mut world = world();
    let ext = format!(r"{HKLM_CLASSES}\.acme");
    let open_with = format!(r"{HKLM_CLASSES}\.txt\OpenWithProgids");
    let user_open_with = format!(r"{}\.md\OpenWithProgids", user_classes());
    world
        .fixture
        .set_value(&ext, "", RegData::from_sz("Acme.Document"));
    for key in [&open_with, &user_open_with] {
        world
            .fixture
            .set_value(key, "Acme.Document", RegData::from_sz(""));
    }
    // `.acme` through the extension journal, `.txt` through the reference snapshot, and the user's
    // `.md` through an Inno value record spelled the way the log spells the user's Classes.
    world.fp.ext_journal = vec![ExtJournalEntry {
        ext: ".acme".into(),
        key: ext.clone(),
        openwith_ours: Vec::new(),
        openwith_others: Vec::new(),
        subkey_count: 0,
        default: Some("Acme.Document".into()),
        previous_default: None,
        other_values: Vec::new(),
        other_subkeys: Vec::new(),
        ti_owned: false,
        vendor_backup: None,
        file_exts_key: None,
        toast_values: Vec::new(),
    }];
    world.fp.ref_snapshot = vec![snap_progid_value(&open_with, "Acme.Document")];
    world.fp.inno = vec![InnoRecord {
        kind: InnoRecordKind::RegDeleteValue,
        target: Target::RegValue {
            path: format!(r"HKU\{SID}\Software\Classes\.md\OpenWithProgids"),
            name: "Acme.Document".into(),
        },
        view: Some(View::K64),
        user_hive: true,
        existed_before: false,
        shared: false,
        key_create: false,
    }];
    assert_golden(
        world.golden(&ClsProgId),
        &[r"key HKLM\SOFTWARE\Classes\Acme.Document DeleteKey [ChainedRef/A/Key]"],
    );
}

#[test]
fn progid_taken_over_by_another_program_is_not_offered() {
    // The key is in P, but its command now launches something else.
    let mut world = world();
    world.fixture.set_value(
        DOC_COMMAND,
        "",
        RegData::from_sz(r#""C:\Program Files\Other\other.exe" "%1""#),
    );
    assert_golden(world.golden(&ClsProgId), &[]);
    // A command that only mentions the app's file as an argument launches something else too; the
    // value is still offered, the key is not.
    world.fixture.set_value(
        DOC_COMMAND,
        "",
        RegData::from_sz(
            r#"C:\Windows\System32\cmd.exe /c "C:\Program Files\Acme Editor\editor.exe" "%1""#,
        ),
    );
    let lines = world.golden(&ClsProgId);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].starts_with(&format!("value {DOC_COMMAND}| DeleteValue")));
}

#[test]
fn auto_file_key_needs_a_command_into_the_roots() {
    let auto = r"HKLM\SOFTWARE\Classes\acme_auto_file";
    let mut world = world();
    world.fp.anchors.progids.clear();
    // Not in P any more: the plain ProgID is not looked at.
    world.fixture.set_value(
        &format!(r"{auto}\shell\open\command"),
        "",
        RegData::from_sz(OPEN),
    );
    assert_golden(
        world.golden(&ClsProgId),
        &[r"key HKLM\SOFTWARE\Classes\acme_auto_file DeleteKey [ChainedRef/A/Key]"],
    );
    // An unquoted command with an environment variable resolves the same way.
    world
        .env
        .insert("PROGRAMFILES".into(), r"C:\Program Files".into());
    world.fixture.set_value(
        &format!(r"{auto}\shell\open\command"),
        "",
        RegData::from_expand_sz(r"%ProgramFiles%\Acme Editor\editor.exe %1"),
    );
    assert_golden(
        world.golden(&ClsProgId),
        &[r"key HKLM\SOFTWARE\Classes\acme_auto_file DeleteKey [ChainedRef/A/Key]"],
    );
    // Someone else's auto-file key, and one without any command, are not offered.
    world.fixture.set_value(
        &format!(r"{auto}\shell\open\command"),
        "",
        RegData::from_sz(r#""C:\Windows\notepad.exe" "%1""#),
    );
    world
        .fixture
        .add_key(r"HKLM\SOFTWARE\Classes\xyz_auto_file\shell");
    assert_golden(world.golden(&ClsProgId), &[]);
    // A path that steps out of the root is not a path into it.
    world.fixture.set_value(
        &format!(r"{auto}\shell\open\command"),
        "",
        RegData::from_sz(r#""C:\Program Files\Acme Editor\..\Other\other.exe" "%1""#),
    );
    assert_golden(world.golden(&ClsProgId), &[]);
}

#[test]
fn user_hive_progid_is_found_in_the_physical_classes_hive() {
    let mut world = world();
    world.fixture.remove_key(DOC);
    let key = format!(r"{}\Acme.Document", user_classes());
    world.fixture.set_value(
        &format!(r"{key}\shell\open\command"),
        "",
        RegData::from_sz(OPEN),
    );
    assert_golden(
        world.golden(&ClsProgId),
        &[&format!("key {key} DeleteKey [ChainedRef/A/Key]")],
    );
}

#[test]
fn incomplete_subtree_is_not_offered_as_a_key() {
    let world = world();
    let mut ctx = world.ctx();
    ctx.limits.max_key_children = 1;
    let app = purge_scan::framework::AppIdentityView::from_fingerprint(&world.fp, &world.env);
    let candidates = purge_scan::framework::Scanner::scan(&ClsProgId, &ctx, &app);
    assert!(on_key(&candidates, DOC).is_none());
}

/// Invariant L5 over this world: a view below Exact only takes away (`tests/shared/l5.rs`).
#[test]
fn l5_a_view_below_exact_only_takes_away() {
    let offered = crate::l5_check("progid", &world, &["CLS-PROGID"]);
    assert!(offered > 0, "the world offers something without a baseline");
}
