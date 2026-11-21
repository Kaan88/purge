//! A Firefox-shaped machine install whose install directory is gone but whose registrations are all
//! still there (the pre-uninstall state, simulated as leftovers), next to an installed Thunderbird
//! (ENGINE_PLAN.md §1.4: "With Thunderbird present, nothing of Thunderbird's is listed").

use purge_model::{AnchorKind, Candidate, EvidenceKind, HarvestedToken, Scope, SourceId, Tier};
use purge_scan::cls_aumid::ClsAumid;
use purge_scan::cls_progid::ClsProgId;
use purge_scan::cls_protocol::ClsProtocol;
use purge_scan::cls_regapps::ClsRegApps;
use purge_scan::cls_verbs::ClsVerbs;
use purge_scan::framework::{OtherApps, Scanner};
use purge_source::fixture::Fixture;

use crate::common::*;

const HASH: &str = "308046B0AF4A39CB";
const FX_ROOT: &str = r"C:\Program Files\Mozilla Firefox";
const TB_ROOT: &str = r"C:\Program Files\Mozilla Thunderbird";
const FX_OPEN: &str = r#""C:\Program Files\Mozilla Firefox\firefox.exe" -osint -url "%1""#;
const TB_OPEN: &str = r#""C:\Program Files\Mozilla Thunderbird\thunderbird.exe" "%1""#;
const REGISTERED: &str = r"HKLM\SOFTWARE\RegisteredApplications";

fn fx_html() -> String {
    format!(r"{HKLM_CLASSES}\FirefoxHTML-{HASH}")
}
fn fx_url() -> String {
    format!(r"{HKLM_CLASSES}\FirefoxURL-{HASH}")
}
fn fx_toast() -> String {
    format!(r"{HKLM_CLASSES}\AppUserModelId\FirefoxToast-{HASH}")
}
fn fx_client() -> String {
    format!(r"HKLM\SOFTWARE\Clients\StartMenuInternet\Firefox-{HASH}")
}
fn html_open_with() -> String {
    format!(r"{HKLM_CLASSES}\.html\OpenWithProgids")
}

fn registry() -> Fixture {
    let tb_client = r"HKLM\SOFTWARE\Clients\Mail\Mozilla Thunderbird";
    machine()
        .dir(TB_ROOT)
        .file(&format!(r"{TB_ROOT}\thunderbird.exe"), 1024)
        // Firefox: ProgIDs.
        .sz(&fx_html(), "", "Firefox HTML Document")
        .sz(
            &format!(r"{}\DefaultIcon", fx_html()),
            "",
            r"C:\Program Files\Mozilla Firefox\firefox.exe,1",
        )
        .sz(&format!(r"{}\shell\open\command", fx_html()), "", FX_OPEN)
        .sz(&fx_url(), "", "Firefox URL")
        .sz(&fx_url(), "URL Protocol", "")
        .sz(&format!(r"{}\shell\open\command", fx_url()), "", FX_OPEN)
        // Firefox: its own association value, recorded by the harvest.
        .sz(&format!(r"{HKLM_CLASSES}\.html"), "", "htmlfile")
        .sz(&html_open_with(), &format!("FirefoxHTML-{HASH}"), "")
        // Firefox: toast AUMID.
        .sz(&fx_toast(), "DisplayName", "Firefox")
        .sz(
            &fx_toast(),
            "IconUri",
            r"C:\Program Files\Mozilla Firefox\browser\VisualElements\VisualElements_70.png",
        )
        // Firefox: default-programs registration.
        .sz(&fx_client(), "", "Firefox")
        .sz(&format!(r"{}\shell\open\command", fx_client()), "", FX_OPEN)
        .sz(
            &format!(r"{}\Capabilities", fx_client()),
            "ApplicationDescription",
            "Firefox delivers safe, easy web browsing.",
        )
        .sz(
            &format!(r"{}\Capabilities\FileAssociations", fx_client()),
            ".html",
            &format!("FirefoxHTML-{HASH}"),
        )
        .sz(
            REGISTERED,
            &format!("Firefox-{HASH}"),
            &format!(r"Software\Clients\StartMenuInternet\Firefox-{HASH}\Capabilities"),
        )
        // Thunderbird, installed.
        .sz(
            &format!(r"{HKLM_CLASSES}\ThunderbirdEML"),
            "",
            "Thunderbird Document",
        )
        .sz(
            &format!(r"{HKLM_CLASSES}\ThunderbirdEML\shell\open\command"),
            "",
            TB_OPEN,
        )
        .sz(&format!(r"{HKLM_CLASSES}\.eml"), "", "ThunderbirdEML")
        .sz(
            &format!(r"{HKLM_CLASSES}\Thunderbird.Url.mailto"),
            "URL Protocol",
            "",
        )
        .sz(
            &format!(r"{HKLM_CLASSES}\Thunderbird.Url.mailto\shell\open\command"),
            "",
            TB_OPEN,
        )
        .sz(
            &format!(r"{HKLM_CLASSES}\AppUserModelId\ThunderbirdToast-D78BF5DD33499EC2"),
            "DisplayName",
            "Thunderbird",
        )
        .sz(tb_client, "", "Mozilla Thunderbird")
        .sz(&format!(r"{tb_client}\shell\open\command"), "", TB_OPEN)
        .sz(
            &format!(r"{tb_client}\Capabilities\FileAssociations"),
            ".eml",
            "ThunderbirdEML",
        )
        .sz(
            REGISTERED,
            "Thunderbird",
            r"Software\Clients\Mail\Mozilla Thunderbird\Capabilities",
        )
        // Windows' own.
        .sz(
            r"HKLM\SOFTWARE\Clients\StartMenuInternet\IEXPLORE.EXE\shell\open\command",
            "",
            r#""C:\Program Files\Internet Explorer\iexplore.exe""#,
        )
        .sz(
            REGISTERED,
            "Internet Explorer",
            r"SOFTWARE\Microsoft\Internet Explorer\Capabilities",
        )
        .key(&format!(r"{HKLM_CLASSES}\*\shell"))
        .build()
}

fn world() -> World {
    let mut fp = machine_fp(
        "Mozilla Firefox 130.0 (x64 en-US)",
        "Mozilla Firefox (x64 en-US)",
        FX_ROOT,
    );
    fp.exes = vec![exe(&format!(r"{FX_ROOT}\firefox.exe"))];
    fp.anchors.progids = ["HTML", "URL", "PDF"]
        .iter()
        .map(|kind| format!("Firefox{kind}-{HASH}"))
        .collect();
    fp.anchors.aumids = vec![format!("FirefoxToast-{HASH}")];
    fp.tokens = vec![HarvestedToken {
        token: HASH.into(),
        source: SourceId("progid".into()),
    }];
    fp.ref_snapshot = vec![snap_progid_value(
        &html_open_with(),
        &format!("FirefoxHTML-{HASH}"),
    )];
    let mut world = World::new(registry(), fp);
    world.baseline = Some(baseline(&[
        HKLM_CLASSES,
        r"HKLM\SOFTWARE\Classes\*",
        r"HKLM\SOFTWARE\Classes\*\shell",
        r"HKLM\SOFTWARE\Classes\.html",
        r"HKLM\SOFTWARE\Classes\.html\OpenWithProgids",
        r"HKLM\SOFTWARE\Classes\AppUserModelId",
        r"HKLM\SOFTWARE\Clients",
        r"HKLM\SOFTWARE\Clients\Mail",
        r"HKLM\SOFTWARE\Clients\StartMenuInternet",
        r"HKLM\SOFTWARE\Clients\StartMenuInternet\IEXPLORE.EXE",
        r"HKLM\SOFTWARE\RegisteredApplications",
    ]));
    world.other_apps = OtherApps::new(vec![other_app(
        "Mozilla Thunderbird (x64 en-US)",
        TB_ROOT,
        &[
            (AnchorKind::ProgId, "ThunderbirdEML"),
            (AnchorKind::ProgId, "Thunderbird.Url.mailto"),
            (AnchorKind::Aumid, "ThunderbirdToast-D78BF5DD33499EC2"),
        ],
    )]);
    world
}

fn all(world: &World) -> Vec<Candidate> {
    let scanners: [&dyn Scanner; 5] = [&ClsProgId, &ClsVerbs, &ClsProtocol, &ClsAumid, &ClsRegApps];
    scanners.iter().flat_map(|s| world.run(*s)).collect()
}

#[test]
fn firefox_registrations_are_offered_per_scanner() {
    let world = world();
    assert_golden(
        world.golden(&ClsProgId),
        &[
            &format!(
                "key {} DeleteKey [ChainedRef/A/Key, HarvestedToken/A/Key]",
                fx_html()
            ),
            &format!(
                "key {} DeleteKey [ChainedRef/A/Key, HarvestedToken/A/Key]",
                fx_url()
            ),
        ],
    );
    assert_golden(
        world.golden(&ClsProtocol),
        &[&format!(
            "key {} DeleteKey [ChainedRef/A/Key, HarvestedToken/A/Key]",
            fx_url()
        )],
    );
    assert_golden(
        world.golden(&ClsAumid),
        &[&format!(
            "key {} DeleteKey [ChainedRef/A/Key, HarvestedToken/A/Key]",
            fx_toast()
        )],
    );
    assert_golden(
        world.golden(&ClsRegApps),
        &[
            &format!(
                "key {} DeleteKey [ChainedRef/A/Key, HarvestedToken/A/Key]",
                fx_client()
            ),
            &format!(
                r"key {}\Capabilities DeleteKey [ChainedRef/A/Key]",
                fx_client()
            ),
            &format!(
                "value {REGISTERED}|Firefox-{HASH} DeleteValue [ChainedRef/A/Value, HarvestedToken/A/Value]"
            ),
        ],
    );
    assert_golden(world.golden(&ClsVerbs), &[]);
}

#[test]
fn evidence_details_and_nesting() {
    let world = world();
    let progids = world.run(&ClsProgId);
    let html = on_key(&progids, &fx_html()).unwrap();
    let chain = html
        .evidence
        .iter()
        .find(|e| e.kind == EvidenceKind::ChainedRef)
        .unwrap();
    assert_eq!(
        (chain.tier, chain.weight, chain.scope),
        (Tier::A, 5, Scope::Key)
    );
    assert_eq!(
        chain.detail.get("anchor"),
        Some(r"c:\program files\mozilla firefox\firefox.exe")
    );
    let token = html
        .evidence
        .iter()
        .find(|e| e.kind == EvidenceKind::HarvestedToken)
        .unwrap();
    assert_eq!(token.detail.get("token"), Some(HASH));
    // The deletion takes four subkeys (DefaultIcon, shell, open, command) and three values with it.
    assert_eq!(html.child_count, Some(7));
    assert!(html.blockers.is_empty());

    // The Capabilities key is recorded as nested in the client key.
    let regapps = world.run(&ClsRegApps);
    let client = on_key(&regapps, &fx_client()).unwrap();
    let capabilities = on_key(&regapps, &format!(r"{}\Capabilities", fx_client())).unwrap();
    assert_eq!(client.children, vec![capabilities.id.clone()]);
}

#[test]
fn nothing_of_thunderbird_or_windows_is_listed() {
    let world = world();
    let candidates = all(&world);
    assert!(!candidates.is_empty());
    for c in &candidates {
        let line = target(c);
        assert!(!line.contains("Thunderbird"), "{line}");
        assert!(!line.contains(".eml"), "{line}");
        assert!(!line.contains("IEXPLORE"), "{line}");
        assert!(!line.contains("Internet Explorer"), "{line}");
    }
    // Structural roots are never targets.
    for structural in [
        HKLM_CLASSES.to_owned(),
        format!(r"{HKLM_CLASSES}\*"),
        format!(r"{HKLM_CLASSES}\*\shell"),
        format!(r"{HKLM_CLASSES}\AppUserModelId"),
        r"HKLM\SOFTWARE\Clients".to_owned(),
        r"HKLM\SOFTWARE\Clients\StartMenuInternet".to_owned(),
        r"HKLM\SOFTWARE\Clients\Mail".to_owned(),
        REGISTERED.to_owned(),
    ] {
        assert!(on_key(&candidates, &structural).is_none(), "{structural}");
    }
}

#[test]
fn the_same_holds_while_the_install_directory_still_exists() {
    // Leftovers found before the uninstaller removed the files: the commands point into the root
    // instead of dangling, which attributes the keys just the same.
    let mut world = world();
    world.fixture.add_dir(FX_ROOT);
    world
        .fixture
        .add_file(&format!(r"{FX_ROOT}\firefox.exe"), 4096);
    let candidates = all(&world);
    for key in [fx_html(), fx_url(), fx_toast(), fx_client()] {
        assert!(on_key(&candidates, &key).is_some(), "{key}");
    }
}

#[test]
fn without_a_baseline_only_values_are_offered() {
    // Every view below Exact takes the no-baseline path (presence-only, design L5).
    for below in 0..purge_index::baseline_view::fixture::BELOW_EXACT {
        let mut world = world();
        world.baseline = purge_index::baseline_view::fixture::below_exact(below, &world.fp.os);
        let candidates = all(&world);
        assert!(
            candidates.iter().all(|c| target(c).starts_with("value ")),
            "{:?}",
            render(&candidates)
        );
        assert_golden(
            world.golden(&ClsProgId),
            &[
                &format!(
                    r"value {}\DefaultIcon| DeleteValue [DanglingRef/A/Value, PointsIntoInstallRoot/A/Value]",
                    fx_html()
                ),
                &format!(
                    r"value {}\shell\open\command| DeleteValue [DanglingRef/A/Value, PointsIntoInstallRoot/A/Value]",
                    fx_html()
                ),
                &format!(
                    r"value {}\shell\open\command| DeleteValue [DanglingRef/A/Value, PointsIntoInstallRoot/A/Value]",
                    fx_url()
                ),
            ],
        );
        assert_golden(
            world.golden(&ClsAumid),
            &[&format!(
                "value {}|IconUri DeleteValue [DanglingRef/A/Value, PointsIntoInstallRoot/A/Value]",
                fx_toast()
            )],
        );
        // The RegisteredApplications value is a value either way.
        let regapps = world.golden(&ClsRegApps);
        assert!(regapps.contains(&format!(
            "value {REGISTERED}|Firefox-{HASH} DeleteValue [ChainedRef/A/Value, HarvestedToken/A/Value]"
        )));
    }
}

/// Invariant L5 over this world: a view below Exact only takes away (`tests/shared/l5.rs`).
#[test]
fn l5_a_view_below_exact_only_takes_away() {
    let offered = crate::l5_check(
        "firefox",
        &world,
        &["CLS-PROGID", "CLS-PROTOCOL", "CLS-AUMID", "CLS-REGAPPS"],
    );
    assert!(offered > 0, "the world offers something without a baseline");
}
