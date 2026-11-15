//! CLS-PROTOCOL: URL scheme keys, on a VS Code user-install shaped fixture (ENGINE_PLAN.md §1.4).

use purge_model::{AnchorKind, Category, EvidenceKind, SourceTrust};
use purge_scan::cls_protocol::ClsProtocol;
use purge_scan::framework::OtherApps;
use purge_source::fixture::Fixture;
use purge_source::types::RegData;

use crate::common::*;

const ROOT: &str = r"C:\Users\tester\AppData\Local\Programs\Microsoft VS Code";
const OPEN_URL: &str =
    r#""C:\Users\tester\AppData\Local\Programs\Microsoft VS Code\Code.exe" --open-url -- "%1""#;

fn vscode() -> String {
    format!(r"{}\vscode", user_classes())
}

/// After the per-user uninstall: the scheme key is left in the user's Classes hive.
fn registry() -> Fixture {
    let classes = user_classes();
    machine()
        .dir(r"C:\Users\tester\AppData\Local\Programs")
        .sz(&vscode(), "", "URL:vscode")
        .sz(&vscode(), "URL Protocol", "")
        .sz(&format!(r"{}\shell\open\command", vscode()), "", OPEN_URL)
        // Another app's scheme, a scheme of Windows, and a key that is not a scheme.
        .sz(&format!(r"{classes}\zoommtg"), "URL Protocol", "")
        .sz(
            &format!(r"{classes}\zoommtg\shell\open\command"),
            "",
            r#""C:\Users\tester\AppData\Roaming\Zoom\bin\Zoom.exe" "--url=%1""#,
        )
        .sz(&format!(r"{HKLM_CLASSES}\mailto"), "URL Protocol", "")
        .sz(
            &format!(r"{HKLM_CLASSES}\mailto\shell\open\command"),
            "",
            r#""C:\Windows\System32\rundll32.exe" url.dll,MailToProtocolHandler %l"#,
        )
        .sz(
            &format!(r"{classes}\VSCode.notascheme\shell\open\command"),
            "",
            OPEN_URL,
        )
        .build()
}

fn world() -> World {
    let mut fp = user_fp(
        "{771FD6B0-FA20-440A-A002-3B3BAC16DC50}_is1",
        "Microsoft Visual Studio Code (User)",
        ROOT,
    );
    fp.roots[0].source = purge_model::RootSource::InnoApp;
    fp.exes = vec![exe(&format!(r"{ROOT}\Code.exe"))];
    let mut world = World::new(registry(), fp);
    world.baseline = Some(baseline(&[
        HKLM_CLASSES,
        r"HKLM\SOFTWARE\Classes\mailto",
        r"HKLM\SOFTWARE\Classes\mailto\shell\open\command",
    ]));
    world
}

#[test]
fn vscode_user_protocol_key_is_offered() {
    let world = world();
    let candidates = world.run(&ClsProtocol);
    assert_golden(
        render(&candidates),
        &[&format!("key {} DeleteKey [ChainedRef/A/Key]", vscode())],
    );
    let c = &candidates[0];
    assert_eq!(c.category, Category::Association);
    assert!(c.blockers.is_empty());
    // A per-user registration: the evidence is marked user-writable (Rule T input for the policy).
    assert_eq!(c.evidence[0].trust, SourceTrust::UserWritable);
    assert_eq!(
        c.evidence[0].detail.get("anchor"),
        Some(r"c:\users\tester\appdata\local\programs\microsoft vs code\code.exe")
    );
}

#[test]
fn the_inno_key_record_adds_the_manifest() {
    let mut world = world();
    world.fp.inno = vec![inno_key(&vscode())];
    let candidates = world.run(&ClsProtocol);
    assert_golden(
        render(&candidates),
        &[&format!(
            "key {} DeleteKey [ChainedRef/A/Key, InstallerManifest/A/Key]",
            vscode()
        )],
    );
    assert!(
        candidates[0]
            .evidence
            .iter()
            .any(|e| matches!(e.kind, EvidenceKind::InstallerManifest(_)))
    );
}

#[test]
fn without_a_baseline_only_the_command_value_is_offered() {
    let mut world = world();
    world.baseline = None;
    // The harvest found the scheme to be the app's own registration.
    world.fp.anchors.progids = vec!["vscode".into()];
    assert_golden(
        world.golden(&ClsProtocol),
        &[&format!(
            r"value {}\shell\open\command| DeleteValue [DanglingRef/A/Value, PointsIntoInstallRoot/A/Value]",
            vscode()
        )],
    );
}

/// VM run x0-vscode-zipcopy: the scheme key was made by a portable copy before the install, which
/// only rewrote the command. The harvest does not take such a scheme as the app's, and a command
/// that points at the app does not make the key the app's: Tier B, listed and not preselected.
#[test]
fn the_command_of_a_scheme_that_is_not_the_apps_is_not_tier_a() {
    let mut world = world();
    world.baseline = None;
    assert!(world.fp.anchors.progids.is_empty());
    assert_golden(
        world.golden(&ClsProtocol),
        &[&format!(
            r"value {}\shell\open\command| DeleteValue [DanglingRef/B/Value, PointsIntoInstallRoot/B/Value]",
            vscode()
        )],
    );
}

#[test]
fn a_scheme_windows_ships_is_never_a_key_candidate() {
    // The app took over `mailto`.
    let mut world = world();
    let command = format!(r"{HKLM_CLASSES}\mailto\shell\open\command");
    world
        .fixture
        .set_value(&command, "", RegData::from_sz(OPEN_URL));
    let candidates = world.run(&ClsProtocol);
    assert!(on_key(&candidates, &format!(r"{HKLM_CLASSES}\mailto")).is_none());
    // The key is Windows': the reference alone is Tier B.
    assert!(render(&candidates).contains(&format!(
        "value {command}| DeleteValue [DanglingRef/B/Value, PointsIntoInstallRoot/B/Value]"
    )));
}

#[test]
fn a_scheme_another_app_also_claims_is_blocked() {
    let mut world = world();
    world.other_apps = OtherApps::new(vec![other_app(
        "VS Code Insiders",
        r"C:\Users\tester\AppData\Local\Programs\Microsoft VS Code Insiders",
        &[(AnchorKind::ProgId, "vscode")],
    )]);
    assert_golden(
        world.golden(&ClsProtocol),
        &[&format!(
            "key {} DeleteKey [ChainedRef/A/Key] !ReferencedByOtherApp(VS Code Insiders)",
            vscode()
        )],
    );
}
