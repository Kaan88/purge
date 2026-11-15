//! Regression tests from the adversarial review of the Classes key scanners: other users' hives, the
//! environment of the wrong user, commands that cannot be read, and `Capabilities` keys inside another
//! program's client key.

use purge_model::{HarvestedToken, SourceId};
use purge_scan::cls_aumid::ClsAumid;
use purge_scan::cls_progid::ClsProgId;
use purge_scan::cls_protocol::ClsProtocol;
use purge_scan::cls_regapps::ClsRegApps;
use purge_scan::cls_verbs::ClsVerbs;
use purge_scan::framework::Scanner;
use purge_source::fixture::FixtureBuilder;
use purge_source::types::RegData;

use crate::common::*;

/// A second user whose hive is loaded.
const OTHER_SID: &str = "S-1-5-21-1004336348-1177238915-682003330-1002";
const TOKEN: &str = "0A1B2C3D4E5F6071";

fn other_classes() -> String {
    format!(r"HKU\{OTHER_SID}_Classes")
}

fn token() -> HarvestedToken {
    HarvestedToken {
        token: TOKEN.into(),
        source: SourceId("arp:key".into()),
    }
}

fn all_scanners() -> [&'static dyn Scanner; 5] {
    [&ClsProgId, &ClsVerbs, &ClsProtocol, &ClsAumid, &ClsRegApps]
}

fn run_all(world: &World) -> Vec<String> {
    let mut lines = Vec::new();
    for scanner in all_scanners() {
        lines.extend(world.golden(scanner));
    }
    lines
}

// ---- a per-user app and the hive of another user -------------------------------------------------------

const USER_ROOT: &str = r"C:\Users\tester\AppData\Local\Programs\Acme";
const USER_OPEN: &str = r#""C:\Users\tester\AppData\Local\Programs\Acme\acme.exe" "%1""#;

/// The same registrations in the hive `classes` / `software` of one user: a ProgID of P named by the
/// token, a toast AUMID named by the token, a URL scheme, a verb and a client key.
fn per_user_registrations(builder: FixtureBuilder, hive: &str, classes: &str) -> FixtureBuilder {
    builder
        .key(hive)
        .sz(&format!(r"{classes}\Acme.Doc-{TOKEN}"), "", "Acme Document")
        .sz(
            &format!(r"{classes}\AppUserModelId\Acme.Toast-{TOKEN}"),
            "DisplayName",
            "Acme",
        )
        .sz(&format!(r"{classes}\acme"), "URL Protocol", "")
        .sz(
            &format!(r"{classes}\acme\shell\open\command"),
            "",
            USER_OPEN,
        )
        .sz(
            &format!(r"{classes}\*\shell\Acme-{TOKEN}\command"),
            "",
            USER_OPEN,
        )
        .sz(
            &format!(r"{hive}\Software\Clients\StartMenuInternet\Acme-{TOKEN}"),
            "",
            "Acme",
        )
        .sz(
            &format!(r"{hive}\Software\RegisteredApplications"),
            &format!("Acme-{TOKEN}"),
            &format!(r"Software\Clients\StartMenuInternet\Acme-{TOKEN}\Capabilities"),
        )
}

fn per_user_world(own: bool, other: bool) -> World {
    let mut builder = machine().dir(r"C:\Users\tester\AppData\Local\Programs");
    if own {
        builder = per_user_registrations(builder, &format!(r"HKU\{SID}"), &user_classes());
    }
    if other {
        builder = per_user_registrations(builder, &format!(r"HKU\{OTHER_SID}"), &other_classes());
    }
    let mut fp = user_fp("Acme", "Acme", USER_ROOT);
    fp.exes = vec![exe(&format!(r"{USER_ROOT}\acme.exe"))];
    fp.tokens = vec![token()];
    fp.anchors.progids = vec![format!("Acme.Doc-{TOKEN}")];
    fp.anchors.aumids = vec![format!("Acme.Toast-{TOKEN}")];
    World::new(builder.build(), fp)
}

#[test]
fn a_per_user_app_owns_nothing_in_another_users_hive() {
    // Only the other user has the registrations (an install of their own, same ProgIDs and tokens).
    let lines = run_all(&per_user_world(false, true));
    assert!(lines.is_empty(), "{lines:#?}");

    // With both, exactly the app's own user's are listed.
    let lines = run_all(&per_user_world(true, true));
    assert!(!lines.is_empty());
    for line in &lines {
        assert!(!line.contains(OTHER_SID), "{line}");
        assert!(line.contains(SID), "{line}");
    }
    assert_eq!(lines, run_all(&per_user_world(true, false)));
}

#[test]
fn a_machine_wide_app_is_still_followed_into_other_loaded_hives() {
    // The same fixture, but the app is installed for all users: its per-user registrations in any
    // loaded hive are its own.
    let mut world = per_user_world(false, true);
    let mut fp = machine_fp("Acme", "Acme", USER_ROOT);
    fp.exes = world.fp.exes.clone();
    fp.tokens = world.fp.tokens.clone();
    fp.anchors = world.fp.anchors.clone();
    world.fp = fp;
    let lines = run_all(&world);
    assert!(
        lines.contains(&format!(
            r"key {}\acme DeleteKey [ChainedRef/A/Key]",
            other_classes()
        )),
        "{lines:#?}"
    );
    assert!(lines.iter().all(|l| l.contains(OTHER_SID)));
}

// ---- the environment of the wrong user ------------------------------------------------------------------

#[test]
fn the_interactive_users_environment_is_not_applied_to_another_users_hive() {
    // A machine-wide registration whose InstallRoot lies in the interactive user's profile. Both users
    // have a verb written with `%LOCALAPPDATA%`: the other user's expands to that user's own profile,
    // which is not the app's root.
    const OPEN: &str = r#""%LOCALAPPDATA%\Programs\Acme\acme.exe" "%1""#;
    let own = format!(r"{}\*\shell\Acme\command", user_classes());
    let theirs = format!(r"{}\*\shell\Acme\command", other_classes());
    let fixture = machine()
        .dir(r"C:\Users\tester\AppData\Local\Programs")
        .key(&format!(r"HKU\{SID}"))
        .key(&format!(r"HKU\{OTHER_SID}"))
        .expand_sz(&own, "", OPEN)
        .expand_sz(&theirs, "", OPEN)
        .expand_sz(
            &format!(r"{}\*\shell\Acme", other_classes()),
            "Icon",
            r"%LOCALAPPDATA%\Programs\Acme\acme.exe",
        )
        .build();
    let mut fp = machine_fp("Acme", "Acme", USER_ROOT);
    fp.exes = vec![exe(&format!(r"{USER_ROOT}\acme.exe"))];
    let mut world = World::new(fixture, fp);
    world.env.insert(
        "LOCALAPPDATA".into(),
        r"C:\Users\tester\AppData\Local".into(),
    );

    // With a baseline: the key in the own hive only.
    assert_golden(
        world.golden(&ClsVerbs),
        &[&format!(
            r"key {}\*\shell\Acme DeleteKey [ChainedRef/A/Key]",
            user_classes()
        )],
    );
    // Without one: the value in the own hive only.
    world.baseline = None;
    assert_golden(
        world.golden(&ClsVerbs),
        &[&format!(
            "value {own}| DeleteValue [DanglingRef/B/Value, PointsIntoInstallRoot/B/Value]"
        )],
    );
}

// ---- a command that is not a string ---------------------------------------------------------------------

#[test]
fn a_key_with_a_command_that_is_not_a_string_is_not_offered() {
    let root = r"C:\Program Files\Acme";
    let verb = format!(r"{HKLM_CLASSES}\*\shell\Acme-{TOKEN}");
    let fixture = machine()
        .sz(
            &format!(r"{verb}\command"),
            "",
            r#""C:\Program Files\Acme\acme.exe" "%1""#,
        )
        .build();
    let mut fp = machine_fp("Acme", "Acme", root);
    fp.tokens = vec![token()];
    let mut world = World::new(fixture, fp);
    assert!(on_key(&world.run(&ClsVerbs), &verb).is_some());

    world.fixture.set_value(
        &format!(r"{verb}\command"),
        "",
        RegData {
            ty: purge_source::types::REG_BINARY,
            ..RegData::from_sz("x")
        },
    );
    let candidates = world.run(&ClsVerbs);
    assert!(candidates.is_empty(), "{:#?}", render(&candidates));
}

// ---- Capabilities inside another program's client key ---------------------------------------------------

#[test]
fn capabilities_inside_a_client_key_that_launches_something_else_prove_nothing() {
    let root = r"C:\Program Files\Acme";
    let client = r"HKLM\SOFTWARE\Clients\StartMenuInternet\Other Browser";
    let fixture = machine()
        .dir(r"C:\Program Files\Other")
        .file(r"C:\Program Files\Other\other.exe", 10)
        .sz(
            &format!(r"{client}\shell\open\command"),
            "",
            r#""C:\Program Files\Other\other.exe""#,
        )
        // The other browser lists a ProgID of this app among its associations.
        .sz(
            &format!(r"{client}\Capabilities\FileAssociations"),
            ".acme",
            "Acme.Doc",
        )
        .sz(
            r"HKLM\SOFTWARE\RegisteredApplications",
            "Other Browser",
            r"Software\Clients\StartMenuInternet\Other Browser\Capabilities",
        )
        .build();
    let mut fp = machine_fp("Acme", "Acme", root);
    fp.anchors.progids = vec!["Acme.Doc".into()];
    let world = World::new(fixture, fp);
    let lines = world.golden(&ClsRegApps);
    assert!(lines.is_empty(), "{lines:#?}");
}
