//! CLS-AUMID: `Classes\AppUserModelId\<AUMID>` keys of the anchor set.

use purge_model::{AnchorKind, Category};
use purge_scan::cls_aumid::ClsAumid;
use purge_scan::framework::OtherApps;
use purge_source::fixture::Fixture;

use crate::common::*;

const ROOT: &str = r"C:\Program Files\Acme Editor";
const CONTAINER: &str = r"HKLM\SOFTWARE\Classes\AppUserModelId";

fn registry() -> Fixture {
    machine()
        .sz(
            &format!(r"{CONTAINER}\Acme.Editor"),
            "DisplayName",
            "Acme Editor",
        )
        .sz(
            &format!(r"{CONTAINER}\Acme.Editor"),
            "IconUri",
            r"C:\Program Files\Acme Editor\editor.ico",
        )
        // In the user's hive, with nothing that points anywhere.
        .sz(
            &format!(r"{}\AppUserModelId\Acme.Editor.Toast", user_classes()),
            "DisplayName",
            "Acme Editor",
        )
        // Not in the anchor set.
        .sz(
            &format!(r"{CONTAINER}\Other.App"),
            "IconUri",
            r"C:\Program Files\Other\other.ico",
        )
        .sz(
            &format!(r"{CONTAINER}\Microsoft.Windows.Explorer"),
            "DisplayName",
            "Explorer",
        )
        .build()
}

fn world() -> World {
    let mut fp = machine_fp("AcmeEditor", "Acme Editor", ROOT);
    fp.anchors.aumids = vec![
        "acme.editor".into(),
        "Acme.Editor".into(),
        "Acme.Editor.Toast".into(),
        "Acme.Missing".into(),
    ];
    let mut world = World::new(registry(), fp);
    world.baseline = Some(baseline(&[
        HKLM_CLASSES,
        CONTAINER,
        r"HKLM\SOFTWARE\Classes\AppUserModelId\Microsoft.Windows.Explorer",
    ]));
    world
}

#[test]
fn aumid_keys_of_the_anchor_set_are_offered() {
    let world = world();
    let candidates = world.run(&ClsAumid);
    assert_golden(
        render(&candidates),
        &[
            r"key HKLM\SOFTWARE\Classes\AppUserModelId\Acme.Editor DeleteKey [ChainedRef/A/Key]",
            // On the harvest's word alone.
            &format!(
                r"key {}\AppUserModelId\Acme.Editor.Toast DeleteKey [ChainedRef/B/Key]",
                user_classes()
            ),
        ],
    );
    assert!(
        candidates
            .iter()
            .all(|c| c.category == Category::Registration)
    );
    assert!(on_key(&candidates, CONTAINER).is_none());
}

#[test]
fn without_a_baseline_only_values_are_offered() {
    // Every view below Exact takes the no-baseline path (presence-only, design L5).
    for below in 0..purge_index::baseline_view::fixture::BELOW_EXACT {
        let mut world = world();
        world.baseline = purge_index::baseline_view::fixture::below_exact(below, &world.fp.os);
        assert_golden(
            world.golden(&ClsAumid),
            &[
                r"value HKLM\SOFTWARE\Classes\AppUserModelId\Acme.Editor|IconUri DeleteValue [DanglingRef/A/Value, PointsIntoInstallRoot/A/Value]",
            ],
        );
    }
}

#[test]
fn an_aumid_windows_ships_is_not_offered() {
    let mut world = world();
    world.fp.anchors.aumids = vec!["Microsoft.Windows.Explorer".into()];
    assert_golden(world.golden(&ClsAumid), &[]);
}

#[test]
fn an_aumid_another_app_shares_is_blocked() {
    let mut world = world();
    world.fp.anchors.aumids = vec!["Acme.Editor".into()];
    world.other_apps = OtherApps::new(vec![other_app(
        "Acme Viewer",
        r"C:\Program Files\Acme Viewer",
        &[(AnchorKind::Aumid, "Acme.Editor")],
    )]);
    world
        .fixture
        .set_ti_owned(&format!(r"{CONTAINER}\Acme.Editor"), true);
    assert_golden(
        world.golden(&ClsAumid),
        &[
            r"key HKLM\SOFTWARE\Classes\AppUserModelId\Acme.Editor DeleteKey [ChainedRef/A/Key] !TrustedInstallerOwned !ReferencedByOtherApp(Acme Viewer)",
        ],
    );
}

/// Invariant L5 over this world: a view below Exact only takes away (`tests/shared/l5.rs`).
#[test]
fn l5_a_view_below_exact_only_takes_away() {
    let offered = crate::l5_check("aumid", &world, &["CLS-AUMID"]);
    assert!(offered > 0, "the world offers something without a baseline");
}
