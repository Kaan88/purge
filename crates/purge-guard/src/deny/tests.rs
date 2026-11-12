//! Deny-list tests: one positive and one negative table per bullet of ENGINE_PLAN.md §5.10, the
//! annotation semantics, the exemptions, the fail-closed cases, the rig's `vm/truth/deny.json`, and a
//! property test that a verdict does not depend on how the location is spelled.

use std::sync::LazyLock;

use purge_model::{Blocker, Target, View};

use super::*;
use crate::canon::tests::{Rng, respell_path};
use crate::canon::{GuardEnv, OtherAppRoot};

const SID: &str = GuardEnv::SAMPLE_SID;
const CV: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion";
const NT: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const ROAMING: &str = r"C:\Users\tester\AppData\Roaming";
const LOCAL: &str = r"C:\Users\tester\AppData\Local";
const PD_PROGRAMS: &str = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs";

fn env() -> GuardEnv {
    let mut env = GuardEnv::sample();
    env.sync_roots = vec![r"C:\Users\tester\OneDrive - Corp".into()];
    env.other_app_roots = vec![
        OtherAppRoot {
            app: "Other Game".into(),
            path: r"D:\Games\Other".into(),
        },
        OtherAppRoot {
            app: "OtherApp".into(),
            path: r"C:\Program Files\Vendor\OtherApp".into(),
        },
    ];
    env.protected_dirs = vec![r"D:\SteamLibrary".into()];
    env.profiles[0].known_folders = vec![r"E:\Docs".into()];
    env.profiles[0].user_content_folders = vec![r"E:\Docs".into()];
    env
}

static LIST: LazyLock<DenyList> = LazyLock::new(|| DenyList::compile(&env()));

fn p(path: impl Into<String>) -> Target {
    Target::Path { path: path.into() }
}

fn k(path: impl Into<String>) -> Target {
    Target::RegKey { path: path.into() }
}

fn v(path: impl Into<String>, name: &str) -> Target {
    Target::RegValue {
        path: path.into(),
        name: name.into(),
    }
}

fn seg(path: impl Into<String>) -> Target {
    Target::RegMultiSzSegment {
        path: path.into(),
        name: "Path".into(),
        segment: r"C:\Program Files\Git\cmd".into(),
        index: None,
    }
}

fn hku(rest: &str) -> String {
    format!(r"HKU\{SID}\{rest}")
}

fn none() -> Exemptions {
    Exemptions::default()
}

fn rule(target: &Target) -> Option<String> {
    LIST.denying_rule(target, &none())
}

#[track_caller]
fn all_denied(targets: &[Target], rule_prefix: &str) {
    for target in targets {
        let got = rule(target);
        assert!(
            got.as_deref().is_some_and(|r| r.starts_with(rule_prefix)),
            "{target:?}: expected a `{rule_prefix}*` denial, got {got:?}"
        );
    }
}

#[track_caller]
fn all_allowed(targets: &[Target]) {
    for target in targets {
        assert_eq!(rule(target), None, "{target:?}");
    }
}

#[test]
fn the_embedded_lists_compile() {
    assert_eq!(LIST.invalid(), None);
    let data = kb_rules().unwrap();
    assert!(!data.is_empty());
    for rule in &data {
        assert!(!rule.id.is_empty() && !rule.why.is_empty(), "{rule:?}");
    }
    assert!(
        LIST.rules()
            .iter()
            .any(|r| r.id() == "kb.mozilla-vendor-key")
    );
    assert!(LIST.rules().iter().any(|r| r.is_registry()));
    for rule in LIST.rules() {
        assert!(!rule.id().is_empty() && !rule.pattern().is_empty() && !rule.why().is_empty());
        assert!(["S", "E", "E+A"].contains(&rule.annotation().as_str()));
    }
    assert_eq!(LIST.env(), &env());
}

#[test]
fn annotation_wire_names() {
    for (annotation, name) in [
        (Annotation::Subtree, "\"S\""),
        (Annotation::Exact, "\"E\""),
        (Annotation::ExactAndAncestors, "\"E+A\""),
    ] {
        assert_eq!(serde_json::to_string(&annotation).unwrap(), name);
        assert_eq!(
            serde_json::from_str::<Annotation>(name).unwrap(),
            annotation
        );
    }
}

#[test]
fn check_returns_the_deny_listed_blocker() {
    let got = check(&p(r"C:\Windows\System32\kernel32.dll"), &env(), &none());
    assert_eq!(
        got,
        Some(Blocker::DenyListed {
            rule: "fs.windir".into()
        })
    );
    assert_eq!(check(&p(r"C:\Program Files\Git"), &env(), &none()), None);
}

// ---------------------------------------------------------------------------------------------------
// Annotation semantics, with data rules on neutral locations.

fn data(id: &str, kind: DataRuleKind, annotation: Annotation, pattern: &str) -> DataRule {
    DataRule {
        id: id.into(),
        kind,
        annotation,
        pattern: pattern.into(),
        values: false,
        view: None,
        why: "test".into(),
    }
}

fn zone_list() -> DenyList {
    use Annotation::*;
    use DataRuleKind::*;
    let mut values = data("kev", Key, Exact, r"HKLM\SOFTWARE\Zone\EV\item");
    values.values = true;
    let mut view32 = data("k32", Key, Exact, r"HKLM\SOFTWARE\Zone\V32");
    view32.view = Some(View::K32);
    let rules = vec![
        data("s", Path, Subtree, r"D:\Zone\S\item"),
        data("e", Path, Exact, r"D:\Zone\E\item"),
        data("ea", Path, ExactAndAncestors, r"D:\Zone\EA\item"),
        data("wild", Path, Subtree, r"D:\Wild\*\secret"),
        data("ks", Key, Subtree, r"HKLM\SOFTWARE\Zone\S\item"),
        data("ke", Key, Exact, r"HKLM\SOFTWARE\Zone\E\item"),
        data("kea", Key, ExactAndAncestors, r"HKLM\SOFTWARE\Zone\EA\item"),
        values,
        view32,
    ];
    let list = DenyList::with_data(&env(), &rules);
    assert_eq!(list.invalid(), None);
    list
}

#[test]
fn annotation_semantics_for_paths() {
    let list = zone_list();
    let rule = |path: &str| list.denying_rule(&p(path), &none());
    let rows: &[(&str, Option<&str>)] = &[
        // [S]: the item, its subtree, and (removing them removes it) its ancestors.
        (r"D:\Zone\S\item", Some("kb.s")),
        (r"D:\Zone\S\item\child\leaf.txt", Some("kb.s")),
        (r"D:\Zone\S", Some("kb.s")),
        (r"D:\Zone", Some("kb.s")),
        (r"D:\Zone\S\other", None),
        (r"D:\Zone\S\itemX", None),
        // [E]: the item only.
        (r"D:\Zone\E\item", Some("kb.e")),
        (r"D:\Zone\E\item\child", None),
        (r"D:\Zone\E", None),
        // [E+A]: the item and its ancestors; children are allowed.
        (r"D:\Zone\EA\item", Some("kb.ea")),
        (r"D:\Zone\EA", Some("kb.ea")),
        (r"D:\Zone\EA\item\child", None),
        (r"D:\Zone\EA\sibling", None),
        // [S] with a wildcard: ancestors only above the wildcard.
        (r"D:\Wild\a\secret", Some("kb.wild")),
        (r"D:\Wild\a\secret\x", Some("kb.wild")),
        (r"D:\Wild", Some("kb.wild")),
        (r"D:\Wild\a", None),
        (r"D:\Wild\a\public", None),
    ];
    for (path, want) in rows {
        assert_eq!(rule(path).as_deref(), *want, "{path}");
    }
}

#[test]
fn annotation_semantics_for_keys_and_values() {
    let list = zone_list();
    let rule = |target: &Target| list.denying_rule(target, &none());
    let z = r"HKLM\SOFTWARE\Zone";
    let rows: Vec<(Target, Option<&str>)> = vec![
        (k(format!(r"{z}\S\item")), Some("kb.ks")),
        (k(format!(r"{z}\S\item\child")), Some("kb.ks")),
        (k(format!(r"{z}\S")), Some("kb.ks")),
        (k(format!(r"{z}\S\other")), None),
        (v(format!(r"{z}\S\item"), "x"), Some("kb.ks")),
        (v(format!(r"{z}\S\item\child"), ""), Some("kb.ks")),
        (seg(format!(r"{z}\S\item")), Some("kb.ks")),
        (v(format!(r"{z}\S"), "x"), None),
        (k(format!(r"{z}\E\item")), Some("kb.ke")),
        (k(format!(r"{z}\E\item\child")), None),
        (k(format!(r"{z}\E")), None),
        (v(format!(r"{z}\E\item"), "x"), None),
        (k(format!(r"{z}\EA\item")), Some("kb.kea")),
        (k(format!(r"{z}\EA")), Some("kb.kea")),
        (k(format!(r"{z}\EA\item\child")), None),
        (v(format!(r"{z}\EA\item"), "x"), None),
        (v(format!(r"{z}\EA"), "x"), None),
        // `values: true` protects the values directly in the key, not those below it.
        (k(format!(r"{z}\EV\item")), Some("kb.kev")),
        (v(format!(r"{z}\EV\item"), "x"), Some("kb.kev")),
        (v(format!(r"{z}\EV\item\child"), "x"), None),
        // A rule restricted to one view.
        (k(r"HKLM\SOFTWARE\WOW6432Node\Zone\V32"), Some("kb.k32")),
        (k(format!(r"{z}\V32")), None),
        // An unrestricted rule covers both views.
        (k(r"HKLM\SOFTWARE\WOW6432Node\Zone\E\item"), Some("kb.ke")),
    ];
    for (target, want) in &rows {
        assert_eq!(rule(target).as_deref(), *want, "{target:?}");
    }
}

// ---------------------------------------------------------------------------------------------------
// §5.10 Filesystem, bullet by bullet.

#[test]
fn fs_windir_subtree_and_the_prefetch_exception() {
    all_denied(
        &[
            p(r"C:\Windows"),
            p(r"c:\windows\"),
            p(r"%WINDIR%\explorer.exe"),
            p(r"C:\Windows\System32\drivers\x.sys"),
            p(r"C:\Windows\SysWOW64\x.dll"),
            p(r"C:\Windows\WinSxS\amd64_x"),
            p(r"C:\Windows\Fonts\app.ttf"),
            p(r"C:\Windows\Installer\1a2b.msi"),
            p(r"C:\Windows\servicing"),
            p(r"C:\Windows\assembly\GAC_MSIL\x"),
            // Never the Prefetch folder, a nested file, or another file type.
            p(r"C:\Windows\Prefetch"),
            p(r"C:\Windows\Prefetch\sub\APP.EXE-1A2B3C4D.pf"),
            p(r"C:\Windows\Prefetch\Layout.ini"),
        ],
        "fs.windir",
    );
    all_allowed(&[
        p(r"C:\Windows\Prefetch\APP.EXE-1A2B3C4D.pf"),
        p(r"C:\WindowsOld\x"),
        p(r"C:\Windows.old\x"),
    ]);
}

#[test]
fn fs_shared_engine_dirs() {
    all_denied(
        &[
            p(r"C:\Program Files\Common Files\Microsoft Shared"),
            p(r"C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe"),
            p(r"C:\Program Files (x86)\Common Files\microsoft shared\VC\msdia80.dll"),
            p(r"C:\Program Files (x86)\Common Files\InstallShield\Engine\6\x.exe"),
            p(r"C:\Program Files\Common Files\InstallShield"),
        ],
        "fs.common-files.",
    );
    all_allowed(&[
        p(r"C:\Program Files\Common Files\Vendor\x.dll"),
        p(r"C:\Program Files\Common Files\Microsoft Shared Stuff"),
        p(r"C:\Program Files\Common Files\InstallShieldX\y"),
    ]);
}

#[test]
fn fs_programdata_microsoft_and_the_start_menu_carve_out() {
    let app_lnk = p(format!(r"{PD_PROGRAMS}\App\App.lnk"));
    let app_dir = p(format!(r"{PD_PROGRAMS}\App"));
    let top_lnk = p(format!(r"{PD_PROGRAMS}\App.lnk"));
    all_denied(
        &[
            p(r"C:\ProgramData\Microsoft"),
            p(r"C:\ProgramData\Microsoft\Windows\Caches\x.db"),
            p(r"C:\ProgramData\Microsoft\Windows Defender\x"),
            app_lnk.clone(),
            app_dir.clone(),
            top_lnk.clone(),
        ],
        "fs.",
    );
    assert_eq!(rule(&app_lnk).as_deref(), Some("fs.programdata.microsoft"));
    all_allowed(&[
        p(r"C:\ProgramData\Vendor\x"),
        p(r"C:\ProgramData\MicrosoftX"),
    ]);

    // With Tier A, an app's own shortcut or folder below Programs is allowed ...
    let tier_a = Exemptions {
        tier_a_start_menu_entry: true,
        ..none()
    };
    for target in [&app_lnk, &app_dir, &top_lnk] {
        assert_eq!(LIST.denying_rule(target, &tier_a), None, "{target:?}");
    }
    // ... and nothing else is.
    for (path, want) in [
        (PD_PROGRAMS.to_owned(), "fs.known-folder"),
        (
            r"C:\ProgramData\Microsoft\Windows\Start Menu".to_owned(),
            "fs.known-folder",
        ),
        (format!(r"{PD_PROGRAMS}\Startup"), "fs.known-folder"),
        (
            format!(r"{PD_PROGRAMS}\Accessories"),
            "fs.start-menu.windows-folder",
        ),
        (
            format!(r"{PD_PROGRAMS}\Administrative Tools"),
            "fs.start-menu.windows-folder",
        ),
        (
            format!(r"{PD_PROGRAMS}\Notepad.lnk"),
            "kb.windows-notepad-shortcut",
        ),
        (
            format!(r"{PD_PROGRAMS}\Accessories\Notepad.lnk"),
            "kb.windows-notepad-shortcut",
        ),
        (
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Other.lnk".to_owned(),
            "fs.programdata.microsoft",
        ),
        (
            r"C:\ProgramData\Microsoft\Windows\Caches\x.db".to_owned(),
            "fs.programdata.microsoft",
        ),
        (
            r"C:\ProgramData\Microsoft".to_owned(),
            "fs.programdata.microsoft",
        ),
    ] {
        assert_eq!(
            LIST.denying_rule(&p(&*path), &tier_a).as_deref(),
            Some(want),
            "{path}"
        );
    }
}

#[test]
fn notepad_shortcut_is_always_denied() {
    let every = Exemptions {
        proven_owned_skeleton: true,
        environment_segment_edit: true,
        tier_a_start_menu_entry: true,
        long_names_resolved: true,
    };
    for path in [
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk".to_owned(),
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad.lnk".to_owned(),
        format!(r"{ROAMING}\Microsoft\Windows\Start Menu\Programs\Accessories\notepad.LNK"),
        format!(r"{ROAMING}\Microsoft\Windows\Start Menu\Programs\Notepad.lnk"),
        r"C:\Users\someone-else\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Notepad.lnk"
            .to_owned(),
    ] {
        for ex in [none(), every] {
            assert!(LIST.check(&p(&*path), &ex).is_some(), "{path} with {ex:?}");
        }
    }
    // Notepad++'s own shortcut is a different name.
    assert_eq!(
        rule(&p(format!(
            r"{ROAMING}\Microsoft\Windows\Start Menu\Programs\Notepad++.lnk"
        ))),
        None
    );
}

#[test]
fn fs_package_stores() {
    all_denied(
        &[
            p(r"C:\Program Files\WindowsApps"),
            p(r"C:\Program Files\WindowsApps\Vendor.App_1.0.0.0_x64__abc\App.exe"),
            p(format!(r"{LOCAL}\Packages")),
            p(format!(r"{LOCAL}\Packages\Vendor.App_abc\LocalState\x.db")),
            p(r"C:\Users\someone-else\AppData\Local\Packages\Vendor.App_abc"),
            p(format!(r"{LOCAL}\Microsoft\WindowsApps\app.exe")),
            p(r"C:\ProgramData\Packages\Vendor.App_abc"),
        ],
        "",
    );
    all_allowed(&[
        p(format!(r"{LOCAL}\PackagesX\y")),
        p(format!(r"{LOCAL}\Vendor\Packages")),
        p(r"C:\Program Files\WindowsAppsX\y"),
    ]);
}

#[test]
fn fs_dotnet() {
    all_denied(
        &[
            p(r"C:\Program Files\dotnet"),
            p(r"C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.0\x.dll"),
            p(r"C:\Program Files (x86)\Reference Assemblies\Microsoft\Framework"),
            p(r"C:\Program Files\Microsoft.NET\x"),
            p(r"C:\Program Files\microsoft.net"),
        ],
        "fs.dotnet",
    );
    all_denied(
        &[p(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319")],
        "fs.windir",
    );
    // `Microsoft.NET` is a whole segment: a longer name is another directory.
    all_allowed(&[
        p(r"C:\Program Files\Microsoft.NET Hosting\x"),
        p(r"C:\Program Files\.NET Hosting\x"),
        p(r"C:\Program Files\Microsoft.NETCore\x"),
        p(r"C:\Program Files\dotnet-tools\x"),
        p(r"C:\Program Files\Reference Assemblies2\x"),
    ]);
}

#[test]
fn fs_secrets() {
    all_denied(
        &[
            p(format!(r"{ROAMING}\Microsoft\Protect\{SID}\key")),
            p(format!(r"{ROAMING}\Microsoft\Credentials")),
            p(format!(r"{ROAMING}\Microsoft\Crypto\RSA\x")),
            p(format!(
                r"{ROAMING}\Microsoft\SystemCertificates\My\Certificates\x"
            )),
            p(format!(r"{ROAMING}\Microsoft\Vault")),
            p(format!(r"{LOCAL}\Microsoft\Credentials\x")),
            p(format!(r"{LOCAL}\Microsoft\Vault\x")),
            p(r"C:\Users\someone-else\AppData\Roaming\Microsoft\Vault\x"),
            // Removing the parent would remove them.
            p(format!(r"{ROAMING}\Microsoft")),
            p(format!(r"{LOCAL}\Microsoft")),
        ],
        "fs.",
    );
    assert_eq!(
        rule(&p(format!(r"{ROAMING}\Microsoft\Protect\x"))).as_deref(),
        Some("fs.secrets")
    );
    all_allowed(&[
        p(format!(r"{ROAMING}\Microsoft\Teams\x")),
        p(format!(r"{ROAMING}\Vendor\Credentials")),
        p(format!(r"{LOCAL}\Microsoft\VaultX")),
        p(format!(r"{LOCAL}\Vendor\Vault")),
    ]);
}

#[test]
fn fs_dotfiles() {
    let home = r"C:\Users\tester";
    let denied: Vec<Target> = [
        ".ssh",
        r".ssh\id_ed25519",
        r".gnupg\pubring.kbx",
        r".aws\credentials",
        ".azure",
        r".kube\config",
        r".docker\config.json",
        ".gitconfig",
        ".git-credentials",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".SSH",
    ]
    .iter()
    .map(|name| p(format!(r"{home}\{name}")))
    .chain([p(r"C:\Users\someone-else\.ssh\known_hosts")])
    .collect();
    all_denied(&denied, "fs.dotfiles");
    all_allowed(&[
        p(format!(r"{home}\.vscode\extensions")),
        p(format!(r"{home}\.config\app")),
        p(format!(r"{home}\.sshx")),
        p(format!(r"{home}\.gitconfig.bak")),
        // Only at the profile root.
        p(format!(r"{LOCAL}\App\.ssh")),
    ]);
}

#[test]
fn fs_sync_roots() {
    all_denied(
        &[
            p(r"C:\Users\tester\OneDrive - Corp"),
            p(r"C:\Users\tester\OneDrive - Corp\Apps\Tool\tool.exe"),
        ],
        "fs.sync-root",
    );
    all_allowed(&[
        p(r"C:\Users\tester\OneDriveX\y"),
        p(r"C:\Users\tester\OneDrive - Corp2\y"),
    ]);
}

#[test]
fn fs_volume_system_folders() {
    all_denied(
        &[
            p(r"C:\System Volume Information"),
            p(r"C:\System Volume Information\x"),
            p(r"D:\$Recycle.Bin\S-1-5-21-1\$R1.exe"),
            p(r"C:\Recovery"),
            p(r"E:\Boot\BCD"),
        ],
        "fs.volume-system",
    );
    all_allowed(&[
        p(r"C:\Bootstrap\x"),
        p(r"D:\Recovery Tools\x"),
        p(r"D:\Data\Boot"),
    ]);
}

#[test]
fn fs_purge_own_dirs() {
    all_denied(
        &[
            p(r"C:\Program Files\Purge"),
            p(r"C:\Program Files\Purge\purge-engine.exe"),
            p(r"C:\ProgramData\Purge\fp\x.json"),
            p(r"D:\.purge-q\0001\x"),
            p(r"C:\.purge-q"),
        ],
        "fs.purge",
    );
    all_allowed(&[
        p(r"C:\ProgramData\Purgery\x"),
        p(r"C:\Program Files\PurgeX\x"),
        p(r"D:\.purge-queue\x"),
    ]);
}

#[test]
fn fs_exact_and_ancestor_containers() {
    let denied = [
        (r"C:\", "fs.drive-root"),
        (r"D:\", "fs.drive-root"),
        (r"C:\Program Files", "fs.program-files"),
        // Regression: an ARP InstallLocation of `C:\Program Files\`.
        (r"C:\Program Files\", "fs.program-files"),
        (r"C:\Program Files (x86)", "fs.program-files"),
        (r"C:\ProgramData", "fs.programdata"),
        (r"C:\Program Files\Common Files", "fs.common-files"),
        (r"C:\ProgramData\Package Cache", "fs.package-cache"),
        (
            r"C:\Users\tester\AppData\Local\Package Cache",
            "fs.package-cache",
        ),
        (
            r"C:\Users\tester\AppData\Local\Programs",
            "fs.local-programs",
        ),
        (
            r"C:\Program Files\InstallShield Installation Information",
            "fs.installshield-info",
        ),
        (r"D:\SteamLibrary\steamapps", "fs.steamapps"),
        (r"D:\SteamLibrary\SteamApps\common", "fs.steamapps"),
        (r"C:\Program Files (x86)\Steam\steamapps", "fs.steamapps"),
        (r"D:\SteamLibrary", "fs.protected-dir"),
        (r"C:\Program Files\Java", "kb.java-root"),
        (r"C:\Program Files\Eclipse Adoptium", "kb.java-root"),
        (r"C:\Users", "fs.profiles-dir"),
        (r"C:\Users\tester", "fs.profile-root"),
        (r"C:\Users\someone-else", "fs.profile-root"),
        (r"C:\Users\Public", "fs.profile-root"),
        (r"C:\Users\tester\AppData", "fs.known-folder"),
        (r"C:\Users\tester\AppData\Roaming", "fs.known-folder"),
        (r"C:\Users\tester\AppData\Local", "fs.known-folder"),
        (r"C:\Users\tester\AppData\LocalLow", "fs.known-folder"),
        (r"C:\Users\tester\AppData\Local\Temp", "fs.known-folder"),
        (r"C:\Users\tester\Desktop", "fs.known-folder"),
        (r"C:\Users\tester\Documents", "fs.known-folder"),
        (r"C:\Users\tester\Downloads", "fs.known-folder"),
        (r"C:\Users\tester\Pictures", "fs.known-folder"),
        (r"C:\Users\tester\Videos", "fs.known-folder"),
        (r"C:\Users\tester\Music", "fs.known-folder"),
        (r"C:\Users\tester\Saved Games", "fs.known-folder"),
        (r"C:\Users\Public\Desktop", "fs.known-folder"),
        (
            r"C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu",
            "fs.known-folder",
        ),
        (
            r"C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu\Programs",
            "fs.known-folder",
        ),
        (
            r"C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
            "fs.known-folder",
        ),
        (
            r"C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories",
            "fs.start-menu.windows-folder",
        ),
        // A redirected known folder from the GuardEnv.
        (r"E:\Docs", "fs.known-folder"),
    ];
    for (path, want) in denied {
        assert_eq!(rule(&p(path)).as_deref(), Some(want), "{path}");
    }
    // Children of an [E+A] item are allowed.
    all_allowed(&[
        p(r"C:\Program Files\Git"),
        p(r"C:\Program Files (x86)\Notepad++\notepad++.exe"),
        p(r"C:\ProgramData\Vendor"),
        p(r"C:\Program Files\Common Files\Vendor"),
        p(r"C:\ProgramData\Package Cache\{0A1B2C3D-0000-1111-2222-333344445555}v1.0\app.msi"),
        p(r"C:\Users\tester\AppData\Local\Programs\Microsoft VS Code"),
        p(
            r"C:\Program Files\InstallShield Installation Information\{0A1B2C3D-0000-1111-2222-333344445555}",
        ),
        p(r"D:\SteamLibrary\steamapps\common\Game"),
        p(r"D:\Games\steamapps2"),
        p(r"D:\SteamLibrary\tools"),
        p(r"C:\Program Files\Java\jdk-21"),
        p(r"C:\Users\tester\Desktop\App.lnk"),
        p(r"C:\Users\tester\Documents\App"),
        p(r"C:\Users\tester\AppData\Roaming\Code"),
        p(r"C:\Users\tester\AppData\Local\Temp\app-update"),
        p(r"C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\App\App.lnk"),
        p(r"C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\App.lnk"),
        p(r"E:\Docs\App"),
        p(r"D:\Apps\Tool"),
    ]);
}

#[test]
fn fs_other_apps_roots() {
    assert_eq!(
        rule(&p(r"D:\Games\Other")).as_deref(),
        Some("fs.other-app-root:Other Game")
    );
    all_denied(
        &[
            p(r"D:\Games\Other\bin\game.exe"),
            // Ancestors of another app's root.
            p(r"D:\Games"),
            p(r"C:\Program Files\Vendor"),
            p(r"C:\Program Files\Vendor\OtherApp\x.dll"),
        ],
        "fs.other-app-root:",
    );
    all_allowed(&[
        p(r"C:\Program Files\Vendor\Mine"),
        p(r"D:\Games2"),
        p(r"D:\Games\OtherX"),
    ]);
}

// ---------------------------------------------------------------------------------------------------
// §5.10 Registry, bullet by bullet.

#[test]
fn reg_structural_roots() {
    all_denied(
        &[
            k("HKLM"),
            k(format!(r"HKU\{SID}")),
            k(r"HKLM\SOFTWARE"),
            k(r"HKLM\SOFTWARE\WOW6432Node"),
            k(hku("Software")),
            k(hku(r"Software\WOW6432Node")),
            k(r"HKLM\SOFTWARE\Microsoft"),
            k(format!(r"HKLM\{CV}")),
            k(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion"),
            k(hku(CV)),
            k(format!(r"HKLM\{NT}")),
            k(hku(r"Software\Microsoft\Windows NT")),
            // Their own values are as structural as the keys.
            v(format!(r"HKLM\{CV}"), "ProgramFilesDir"),
            v(format!(r"HKLM\{NT}"), "CurrentBuild"),
            v(r"HKLM\SOFTWARE", ""),
            // Other top-level keys of a user hive.
            k(hku("Environment")),
            k(hku("Control Panel")),
        ],
        "reg.",
    );
    // An ancestor of protected keys: denied, under whichever rule protects something below it.
    assert!(rule(&k(r"HKLM\SOFTWARE\Microsoft\Windows")).is_some());
    all_allowed(&[
        k(r"HKLM\SOFTWARE\Vendor"),
        k(r"HKLM\SOFTWARE\Vendor\App"),
        k(r"HKLM\SOFTWARE\WOW6432Node\Vendor\App"),
        k(hku(r"Software\Vendor")),
        k(hku(r"Software\WOW6432Node\Vendor")),
        k(r"HKLM\SOFTWARE\Microsoft\VendorApp"),
        v(r"HKLM\SOFTWARE\Microsoft", "x"),
        v(r"HKLM\SOFTWARE\Vendor\App", "InstallDir"),
        k(format!(r"HKLM\{CV}Extra")),
        k(hku(r"AppEvents\Schemes\Apps\MyApp")),
        seg(hku("Environment")),
    ]);
}

#[test]
fn reg_policies() {
    all_denied(
        &[
            k(r"HKLM\SOFTWARE\Policies"),
            k(r"HKLM\SOFTWARE\Policies\Vendor\App"),
            v(r"HKLM\SOFTWARE\WOW6432Node\Policies\Vendor\App", "Setting"),
            k(hku(r"Software\Policies\Vendor")),
            v(
                format!(r"HKLM\{CV}\Policies\Explorer"),
                "NoDriveTypeAutoRun",
            ),
            k(hku(&format!(r"{CV}\Policies\System"))),
            k(format!(r"HKLM\{NT}\Policies")),
        ],
        "reg.policies",
    );
    all_allowed(&[
        k(r"HKLM\SOFTWARE\Vendor\Policies"),
        k(r"HKLM\SOFTWARE\PoliciesX\Vendor"),
    ]);
}

#[test]
fn reg_classes_roots() {
    let classes = r"HKLM\SOFTWARE\Classes";
    let mut denied = vec![
        k(classes),
        k(format!(r"HKU\{SID}_Classes")),
        k(hku(r"Software\Classes")),
        k(r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID"),
        k(r"HKLM\SOFTWARE\Classes\WOW6432Node\Interface"),
        k(format!(r"HKU\{SID}_Classes\CLSID")),
        k(hku(r"Software\Classes\Directory\Background\shell")),
    ];
    for name in [
        "CLSID",
        "Interface",
        "TypeLib",
        "AppID",
        "*",
        "AllFilesystemObjects",
        "Folder",
        "Directory",
        r"Directory\Background",
        "Drive",
        "DesktopBackground",
        "LibraryFolder",
        "SystemFileAssociations",
        "Applications",
        "AppUserModelId",
    ] {
        denied.push(k(format!(r"{classes}\{name}")));
    }
    for root in [
        r"*\shell",
        r"*\shellex",
        r"*\shellex\ContextMenuHandlers",
        r"Directory\shell",
        r"Directory\Background\shell",
        r"Directory\shellex\ContextMenuHandlers",
        r"Folder\shellex",
        r"Drive\shell",
        r"AllFilesystemObjects\shellex\PropertySheetHandlers",
        r"LibraryFolder\Background\shell",
        r"DesktopBackground\Shell",
    ] {
        denied.push(k(format!(r"{classes}\{root}")));
    }
    all_denied(&denied, "reg.classes");
    all_allowed(&[
        k(format!(
            r"{classes}\CLSID\{{0A1B2C3D-0000-1111-2222-333344445555}}"
        )),
        k(format!(
            r"{classes}\Interface\{{0A1B2C3D-0000-1111-2222-333344445555}}"
        )),
        k(format!(r"{classes}\*\shell\MyVerb")),
        k(format!(
            r"{classes}\*\shellex\ContextMenuHandlers\MyHandler"
        )),
        k(format!(r"{classes}\Directory\Background\shell\git_shell")),
        k(format!(r"{classes}\Applications\app.exe")),
        k(format!(r"{classes}\AppUserModelId\Vendor.App")),
        k(format!(r"{classes}\MyApp.Document")),
        k(format!(r"{classes}\.myext")),
        k(format!(r"HKU\{SID}_Classes\sh_auto_file")),
        v(format!(r"{classes}\.txt\OpenWithProgids"), "MyApp.txt"),
        k(format!(r"{classes}\CLSIDX")),
    ]);
}

#[test]
fn reg_shell_roots_yield_to_a_proven_owned_skeleton() {
    let skeleton = Exemptions {
        proven_owned_skeleton: true,
        ..none()
    };
    let classes = r"HKLM\SOFTWARE\Classes";
    for path in [
        format!(r"{classes}\LibraryFolder\Background\shell"),
        format!(r"{classes}\Directory\shellex\ContextMenuHandlers"),
        format!(r"HKU\{SID}_Classes\*\shell"),
    ] {
        assert_eq!(
            rule(&k(&*path)).as_deref(),
            Some("reg.classes.shell-root"),
            "{path}"
        );
        assert_eq!(LIST.denying_rule(&k(&*path), &skeleton), None, "{path}");
    }
    // The exemption reaches the shell roots only.
    for path in [
        classes.to_owned(),
        format!(r"{classes}\CLSID"),
        format!(r"{classes}\Directory"),
        format!(r"{classes}\LibraryFolder\Background"),
        format!(r"HKLM\{CV}\Run"),
        r"HKLM\SOFTWARE\Policies\Vendor".to_owned(),
    ] {
        assert!(LIST.denying_rule(&k(&*path), &skeleton).is_some(), "{path}");
    }
}

#[test]
fn reg_subtree_rules() {
    let system = r"HKLM\SYSTEM\CurrentControlSet";
    all_denied(
        &[
            v(
                hku(&format!(r"{CV}\Explorer\User Shell Folders")),
                "Personal",
            ),
            k(format!(r"HKLM\{CV}\Explorer\Shell Folders")),
            v(hku(&format!(r"{CV}\Explorer\Shell Folders")), "Desktop"),
            k(format!(r"{system}\Control\Session Manager")),
            v(
                format!(r"{system}\Control\Session Manager\Environment"),
                "Path",
            ),
            seg(format!(r"{system}\Control\Session Manager\Environment")),
            v(format!(r"HKLM\{NT}\Winlogon"), "Shell"),
            k(hku(
                r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            )),
            k(format!(r"HKLM\{NT}\ProfileList\{SID}")),
            k(format!(r"HKLM\{NT}\Image File Execution Options\app.exe")),
            v(format!(r"HKLM\{NT}\Fonts"), "App Font (TrueType)"),
            k(r"HKLM\SOFTWARE\Microsoft\Cryptography\Providers"),
            k(r"HKLM\SYSTEM\Setup"),
            k(format!(r"{system}\Services\bam\State\UserSettings\{SID}")),
            k(format!(r"HKLM\{NT}\Schedule\TaskCache\Tree\Vendor\Task")),
            k(format!(r"HKLM\{CV}\AppModel\Lookaside\user")),
            k(format!(r"HKLM\{CV}\Appx\AppxAllUserStore")),
            k(r"HKLM\SOFTWARE\Classes\PackagedCom\Package\Vendor.App"),
            k(format!(r"HKU\{SID}_Classes\PackagedCom")),
            k(format!(
                r"HKU\{SID}_Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository"
            )),
            k(format!(r"HKLM\{CV}\Component Based Servicing\Packages")),
            k(format!(r"HKLM\{CV}\SideBySide\Winners")),
            k(format!(r"HKLM\{CV}\WindowsUpdate\Auto Update")),
            // The parent of a subtree rule cannot go either.
            k(format!(r"HKLM\{NT}\Schedule")),
        ],
        "reg.",
    );
    all_allowed(&[
        k(r"HKLM\SOFTWARE\Vendor\Winlogon"),
        k(format!(r"HKLM\{NT}\FontsX")),
        k(format!(r"HKLM\{CV}\AppHost")),
        k(format!(r"HKLM\{CV}\Explorer\Shell FoldersX")),
        k(r"HKLM\SOFTWARE\Microsoft\CryptographyX"),
        k(r"HKLM\SOFTWARE\Classes\PackagedComX"),
    ]);
}

#[test]
fn reg_environment_segment_edit() {
    let edit = Exemptions {
        environment_segment_edit: true,
        ..none()
    };
    let environment = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
    assert_eq!(rule(&seg(environment)).as_deref(), Some("reg.hklm.system"));
    assert_eq!(LIST.denying_rule(&seg(environment), &edit), None);
    assert_eq!(
        LIST.denying_rule(
            &seg(r"HKEY_LOCAL_MACHINE\System\ControlSet001\Control\Session Manager\Environment"),
            &edit
        ),
        None
    );
    // Only the segment edit, only that key, only the current control set.
    for target in [
        v(environment, "Path"),
        k(environment),
        seg(format!(r"{environment}\Sub")),
        seg(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager"),
        seg(r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"),
        seg(r"HKLM\SYSTEM\ControlSet002\Control\Session Manager\Environment"),
    ] {
        assert_eq!(
            LIST.denying_rule(&target, &edit).as_deref(),
            Some("reg.hklm.system"),
            "{target:?}"
        );
    }
    // The per-user Environment key needs no exemption for a value or a segment.
    all_allowed(&[
        seg(hku("Environment")),
        v(hku("Environment"), "MY_APP_HOME"),
    ]);
}

#[test]
fn reg_hklm_system_and_other_hives() {
    let services = r"HKLM\SYSTEM\CurrentControlSet\Services";
    all_denied(
        &[
            k(r"HKLM\SYSTEM"),
            k(r"HKLM\SYSTEM\CurrentControlSet"),
            k(format!(r"{services}\MyService")),
            v(format!(r"{services}\MyService"), "ImagePath"),
            k(format!(r"{services}\WinSock2\Parameters")),
            k(format!(r"{services}\EventLog")),
            k(format!(r"{services}\EventLog\Application")),
            v(format!(r"{services}\EventLog\Application"), "MaxSize"),
            k(r"HKLM\SYSTEM\ControlSet002\Services\MyService"),
            k(r"HKLM\SYSTEM\MountedDevices"),
        ],
        "reg.hklm.system",
    );
    all_denied(
        &[
            k(r"HKLM\SAM\SAM"),
            k(r"HKLM\SECURITY"),
            k(r"HKLM\HARDWARE\DESCRIPTION"),
            k(r"HKLM\BCD00000000"),
        ],
        "reg.hklm.non-software",
    );
    // Event sources are the one registry shape under SYSTEM that may be offered; services go through
    // the SCM as `Target::Service`.
    all_allowed(&[
        k(format!(r"{services}\EventLog\Application\MyApp")),
        v(
            format!(r"{services}\EventLog\Application\MyApp"),
            "EventMessageFile",
        ),
        k(r"HKLM\SYSTEM\ControlSet001\Services\EventLog\Vendor Log\MyApp"),
        Target::Service {
            name: "MyService".into(),
        },
    ]);
}

#[test]
fn reg_registration_containers() {
    all_denied(
        &[
            k(format!(r"HKLM\{CV}\Uninstall")),
            k(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            k(hku(&format!(r"{CV}\Uninstall"))),
            k(format!(r"HKLM\{CV}\Run")),
            k(hku(&format!(r"{CV}\RunOnce"))),
            k(format!(r"HKLM\{CV}\RunOnceEx")),
            k(format!(r"HKLM\{CV}\App Paths")),
            k(format!(r"HKLM\{CV}\Installer")),
            k(format!(r"HKLM\{CV}\Installer\Folders")),
            k(format!(r"HKLM\{CV}\Installer\UserData")),
            k(format!(r"HKLM\{CV}\Installer\UserData\S-1-5-18")),
            k(format!(r"HKLM\{CV}\Installer\UserData\S-1-5-18\Products")),
            k(r"HKLM\SOFTWARE\Classes\Installer"),
            k(r"HKLM\SOFTWARE\Classes\Installer\Products"),
            k(r"HKLM\SOFTWARE\Classes\Installer\Dependencies"),
            k(hku(r"Software\Microsoft\Installer\Products")),
            k(r"HKLM\SOFTWARE\RegisteredApplications"),
            k(hku(r"Software\RegisteredApplications")),
            k(format!(r"HKLM\{CV}\Explorer")),
            k(hku(&format!(r"{CV}\Explorer"))),
            k(hku(&format!(r"{CV}\Explorer\FileExts"))),
            k(hku(&format!(r"{CV}\Explorer\Advanced"))),
            k(hku(&format!(r"{CV}\Explorer\StartupApproved\Run"))),
            k(format!(r"HKLM\{CV}\Shell Extensions\Approved")),
        ],
        "reg.",
    );
    all_allowed(&[
        k(format!(
            r"HKLM\{CV}\Uninstall\{{0A1B2C3D-0000-1111-2222-333344445555}}"
        )),
        k(hku(&format!(r"{CV}\Uninstall\MyApp"))),
        v(format!(r"HKLM\{CV}\Run"), "MyApp"),
        v(hku(&format!(r"{CV}\Explorer\StartupApproved\Run")), "MyApp"),
        k(format!(r"HKLM\{CV}\App Paths\myapp.exe")),
        k(format!(
            r"HKLM\{CV}\Installer\UserData\S-1-5-18\Products\0A1B2C3D"
        )),
        v(
            format!(r"HKLM\{CV}\Installer\Folders"),
            r"C:\Program Files\MyApp\",
        ),
        k(r"HKLM\SOFTWARE\Classes\Installer\Products\0A1B2C3D"),
        v(r"HKLM\SOFTWARE\RegisteredApplications", "MyApp"),
        k(hku(&format!(r"{CV}\Explorer\FileExts\.myext"))),
        k(hku(&format!(
            r"{CV}\Explorer\FileExts\.myext\OpenWithProgids"
        ))),
        v(
            format!(r"HKLM\{CV}\Shell Extensions\Approved"),
            "{0A1B2C3D-0000-1111-2222-333344445555}",
        ),
        k(format!(r"HKLM\{CV}\RunX")),
    ]);
}

#[test]
fn reg_user_choice() {
    let ext = hku(&format!(r"{CV}\Explorer\FileExts\.txt"));
    all_denied(
        &[
            k(format!(r"{ext}\UserChoice")),
            v(format!(r"{ext}\UserChoice"), "ProgId"),
            v(format!(r"{ext}\UserChoice"), "Hash"),
            k(format!(r"{ext}\UserChoiceLatest\ProgId")),
            k(hku(
                r"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice",
            )),
        ],
        "reg.userchoice",
    );
    all_allowed(&[
        v(format!(r"{ext}\OpenWithList"), "a"),
        v(format!(r"{ext}\OpenWithProgids"), "MyApp.txt"),
        k(format!(r"{ext}\UserChoiceX")),
        k(ext),
    ]);
}

#[test]
fn reg_system_accounts_and_unloaded_hives() {
    for (path, want) in [
        (r"HKU\.DEFAULT\Software\Vendor", "reg.hku.system-account"),
        (r"HKU\S-1-5-18\Software\Vendor", "reg.hku.system-account"),
        (r"HKU\S-1-5-19\Software\Vendor", "reg.hku.system-account"),
        (r"HKU\S-1-5-20\Software\Vendor", "reg.hku.system-account"),
        (r"HKU\S-1-5-18_Classes\Vendor.Doc", "reg.hku.system-account"),
        (
            r"HKU\S-1-5-21-1-2-3-1002\Software\Vendor",
            "reg.hku.not-loaded",
        ),
        (
            r"HKU\S-1-5-21-1-2-3-1002_Classes\Vendor.Doc",
            "reg.hku.not-loaded",
        ),
    ] {
        assert_eq!(rule(&k(path)).as_deref(), Some(want), "{path}");
        assert_eq!(rule(&v(path, "x")).as_deref(), Some(want), "{path}");
    }
    all_allowed(&[
        k(hku(r"Software\Vendor")),
        k(format!(r"HKU\{SID}_Classes\Vendor.Doc")),
    ]);
}

#[test]
fn kb_mozilla_and_shim_inclusion_list() {
    assert_eq!(
        rule(&k(r"HKLM\SOFTWARE\Mozilla")).as_deref(),
        Some("kb.mozilla-vendor-key")
    );
    assert_eq!(
        rule(&k(r"hkey_local_machine\software\mozilla\")).as_deref(),
        Some("kb.mozilla-vendor-key")
    );
    all_denied(
        &[
            k(r"HKLM\SOFTWARE\Mozilla\NativeMessagingHosts"),
            k(
                r"HKLM\SOFTWARE\Mozilla\NativeMessagingHosts\com.microsoft.defender.browser_extension.native_message_host",
            ),
            v(r"HKLM\SOFTWARE\Mozilla\NativeMessagingHosts\x", ""),
        ],
        "kb.mozilla-native-messaging-hosts",
    );
    all_denied(
        &[
            k(r"HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList"),
            k(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\MediaPlayer\ShimInclusionList"),
        ],
        "kb.mediaplayer-shim-inclusion-list",
    );
    all_denied(
        &[k(
            r"HKLM\SOFTWARE\Classes\CLSID\{042d2b7d-308b-4032-a569-466a8e0de728}\InprocServer32",
        )],
        "kb.security-health-agent-clsid",
    );
    all_allowed(&[
        k(r"HKLM\SOFTWARE\Mozilla\Firefox"),
        k(r"HKLM\SOFTWARE\Mozilla\Mozilla Firefox\131.0 (x64 en-US)"),
        k(r"HKLM\SOFTWARE\MozillaPlugins"),
        k(r"HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\myapp.exe"),
        v(
            r"HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList",
            "myapp.exe",
        ),
        // The rig's truth names the 64-bit vendor key only.
        k(r"HKLM\SOFTWARE\WOW6432Node\Mozilla"),
    ]);
}

// ---------------------------------------------------------------------------------------------------
// Fail-closed behaviour.

#[test]
fn targets_that_are_not_locations_pass() {
    for list in [&*LIST, &DenyList::compile(&GuardEnv::default())] {
        for target in [
            Target::Service {
                name: "MyService".into(),
            },
            Target::Task {
                path: r"\Vendor\Task".into(),
            },
            Target::FirewallRule {
                id: "{0A1B}".into(),
            },
            Target::AppxPackage {
                full_name: "Vendor.App_1.0.0.0_x64__abc".into(),
            },
        ] {
            assert_eq!(list.check(&target, &none()), None, "{target:?}");
        }
    }
}

#[test]
fn an_incomplete_env_or_a_bad_rule_denies_every_location() {
    let mut no_windir = env();
    no_windir.windir.clear();
    let bad_rule = [data(
        "bad",
        DataRuleKind::Path,
        Annotation::Exact,
        r"relative\x",
    )];
    let bad_key = [data(
        "bad",
        DataRuleKind::Key,
        Annotation::Exact,
        r"HKCU\Software\X",
    )];
    let broken = [
        DenyList::compile(&GuardEnv::default()),
        DenyList::compile(&no_windir),
        DenyList::with_data(&env(), &bad_rule),
        DenyList::with_data(&env(), &bad_key),
    ];
    for list in &broken {
        assert!(list.invalid().is_some());
        for target in [
            p(r"D:\Apps\Tool"),
            k(r"HKLM\SOFTWARE\Vendor"),
            v(hku(r"Software\Vendor"), "x"),
        ] {
            assert_eq!(
                list.check(&target, &none()),
                Some(Blocker::DenyListed {
                    rule: "guard.unavailable".into()
                }),
                "{target:?}"
            );
        }
        assert_eq!(
            list.root_rejection(r"D:\Apps\Tool", true).as_deref(),
            Some("guard.unavailable")
        );
    }
    assert_eq!(
        check(&p(r"D:\Apps\Tool"), &GuardEnv::default(), &none()),
        Some(Blocker::DenyListed {
            rule: "guard.unavailable".into()
        })
    );
}

#[test]
fn targets_that_do_not_canonicalise_are_denied() {
    for (target, want) in [
        (p(r"C:\Apps\..\Windows"), "canon.dot-segment"),
        (p(r"Apps\Tool"), "canon.relative"),
        (p(r"\\server\share\Tool"), "canon.unc"),
        (
            p(r"\\?\GLOBALROOT\Device\HarddiskVolume3\Apps"),
            "canon.globalroot",
        ),
        (p(r"\\.\C:\Apps"), "canon.device-namespace"),
        (p(r"D:\Apps\Tool\file.txt:Zone.Identifier"), "canon.ads"),
        (p(r"D:\Apps\Tool\NUL"), "canon.device-name"),
        (p(r"D:\Apps\Tool."), "canon.trailing-dot-or-space"),
        (p(r"%TEMP%\Tool"), "canon.env-token"),
        // Per-user tokens are not accepted in a target: it must name the profile's real path.
        (p(r"%APPDATA%\Tool"), "canon.no-profile"),
        (p(""), "canon.empty"),
        (k(r"HKCR\MyApp.Document"), "canon.hkcr"),
        (k(r"HKCU\Software\Vendor"), "canon.no-profile"),
        (
            v(r"HKEY_CURRENT_USER\Software\Vendor", "x"),
            "canon.no-profile",
        ),
        (k(r"HKCC\Software"), "canon.unknown-root"),
        (k("HKU"), "canon.missing-sid"),
        (k(r"HKU\Software\Vendor"), "canon.bad-sid"),
    ] {
        assert_eq!(rule(&target).as_deref(), Some(want), "{target:?}");
    }
    let mut unknown_set = env();
    unknown_set.current_control_set = 0;
    assert_eq!(
        DenyList::compile(&unknown_set)
            .denying_rule(
                &k(r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\MyApp"),
                &none()
            )
            .as_deref(),
        Some("canon.no-control-set")
    );
}

#[test]
fn short_names_are_denied_until_resolved() {
    let resolved = Exemptions {
        long_names_resolved: true,
        ..none()
    };
    // `PROGRA~1` may alias `Program Files`: the lexical rules cannot tell.
    for path in [r"C:\PROGRA~1", r"C:\PROGRA~1\Git", r"D:\Apps\MYTOOL~1\bin"] {
        assert_eq!(
            rule(&p(path)).as_deref(),
            Some("canon.short-name-unresolved"),
            "{path}"
        );
    }
    assert_eq!(
        LIST.denying_rule(&p(r"D:\Apps\MYTOOL~1\bin"), &resolved),
        None
    );
    // Resolution does not lift any rule.
    assert_eq!(
        LIST.denying_rule(&p(r"C:\Windows\SYSTEM~1"), &resolved)
            .as_deref(),
        Some("fs.windir")
    );
}

// ---------------------------------------------------------------------------------------------------
// validate_root inputs.

#[test]
fn root_rejection_cases() {
    let rejected = [
        (r"C:\Program Files\", "fs.program-files"),
        (r"C:\", "fs.drive-root"),
        (r"C:\Windows\System32\MyApp", "fs.windir"),
        (r"C:\Program Files\Common Files", "fs.common-files"),
        (
            r"C:\Program Files\Common Files\Microsoft Shared\MyApp",
            "fs.common-files.microsoft-shared",
        ),
        (r"C:\ProgramData", "fs.programdata"),
        (
            r"C:\Users\tester\AppData\Local\Programs",
            "fs.local-programs",
        ),
        (r"C:\Users\tester\Documents", "fs.known-folder"),
        (r"C:\Users\tester\Documents\MyApp", "root.user-content"),
        (r"C:\Users\tester\Desktop\Tools\MyApp", "root.user-content"),
        (
            r"C:\Users\someone-else\Downloads\MyApp",
            "root.user-content",
        ),
        (r"C:\Users\tester\Saved Games\MyGame", "root.user-content"),
        (r"E:\Docs\MyApp", "root.user-content"),
        (r"C:\Users\tester\OneDrive - Corp\MyApp", "fs.sync-root"),
        (
            r"C:\ProgramData\Package Cache\{0A1B}v1",
            "root.package-cache",
        ),
        (
            r"C:\Users\tester\AppData\Local\Package Cache\{0A1B}",
            "root.package-cache",
        ),
        (r"C:\Windows\Installer\{0A1B}", "fs.windir"),
        (
            r"C:\Program Files (x86)\InstallShield Installation Information\{0A1B}",
            "root.installshield-info",
        ),
        (r"C:\Program Files\Vendor", "fs.other-app-root:OtherApp"),
        (r"D:\Games\Other\mods", "fs.other-app-root:Other Game"),
        (r"C:\Apps\..\Windows", "canon.dot-segment"),
    ];
    for (path, want) in rejected {
        assert_eq!(
            LIST.root_rejection(path, true).as_deref(),
            Some(want),
            "{path}"
        );
    }
    for path in [
        r"C:\Program Files\Git",
        r"C:\Program Files (x86)\Notepad++",
        r"C:\Users\tester\AppData\Local\Programs\Microsoft VS Code",
        r"C:\Users\tester\AppData\Roaming\MyApp",
        r"C:\Program Files\Vendor\Mine",
        r"D:\Apps\Tool",
    ] {
        assert_eq!(LIST.root_rejection(path, true), None, "{path}");
    }
    assert_eq!(
        LIST.root_rejection(r"C:\PROGRA~1\Git", false).as_deref(),
        Some("canon.short-name-unresolved")
    );
}

// ---------------------------------------------------------------------------------------------------
// Shared components.

#[test]
fn shared_components_lookup() {
    let shared = SharedComponents::compile(&env()).unwrap();
    let ids: Vec<&str> = shared.components().iter().map(|c| c.id.as_str()).collect();
    for id in [
        "vcredist",
        "dotnet",
        "webview2",
        "directx",
        "vclibs",
        "windowsappruntime",
        "ui-xaml",
        "edge",
    ] {
        assert!(ids.contains(&id), "{id} is seeded");
    }
    let appx = |name: &str| Target::AppxPackage {
        full_name: name.into(),
    };
    let webview_client =
        r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
    let rows: Vec<(Target, Option<&str>)> = vec![
        (
            p(r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\131.0\msedgewebview2.exe"),
            Some("webview2"),
        ),
        (
            p(r"C:\Program Files (x86)\Microsoft\Edge\Application"),
            Some("edge"),
        ),
        (
            p(r"c:\program files (x86)\microsoft\edgeupdate\MicrosoftEdgeUpdate.exe"),
            Some("edge"),
        ),
        (
            k(
                r"HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}",
            ),
            Some("webview2"),
        ),
        (v(hku(webview_client), "pv"), Some("webview2")),
        (
            k(
                r"HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}",
            ),
            Some("edge"),
        ),
        (
            k(r"HKLM\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"),
            Some("vcredist"),
        ),
        (
            k(r"HKLM\SOFTWARE\Classes\Installer\Dependencies\VC,redist.x64,amd64,14.38,bundle"),
            Some("vcredist"),
        ),
        (
            k(
                r"HKLM\SOFTWARE\Classes\Installer\Dependencies\Microsoft.VS.VC_RuntimeMinimumVSU_amd64,v14",
            ),
            Some("vcredist"),
        ),
        (
            p(r"C:\Program Files\dotnet\shared\Microsoft.NETCore.App"),
            Some("dotnet"),
        ),
        (p(r"C:\Windows\Microsoft.NET\Framework64"), Some("dotnet")),
        (
            k(r"HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full"),
            Some("dotnet"),
        ),
        (k(r"HKLM\SOFTWARE\Microsoft\DirectX"), Some("directx")),
        (
            appx("Microsoft.VCLibs.140.00_14.0.33519.0_x64__8wekyb3d8bbwe"),
            Some("vclibs"),
        ),
        (
            appx("Microsoft.UI.Xaml.2.8_8.2310.30001.0_x64__8wekyb3d8bbwe"),
            Some("ui-xaml"),
        ),
        (
            appx("microsoft.windowsappruntime.1.4_4000.1082.2259.0_x64__8wekyb3d8bbwe"),
            Some("windowsappruntime"),
        ),
        (
            appx("Microsoft.DirectXRuntime_9.29.1974.0_x64__8wekyb3d8bbwe"),
            Some("directx"),
        ),
        (appx("Vendor.App_1.0.0.0_x64__abc"), None),
        (p(r"C:\Program Files\Git"), None),
        (p(r"C:\Program Files (x86)\Microsoft\EdgeWebViewX"), None),
        (p(r"C:\Program Files (x86)\Microsoft"), None),
        (k(r"HKLM\SOFTWARE\Vendor"), None),
        (k(r"HKLM\SOFTWARE\Microsoft\EdgeUpdateX"), None),
        (k(r"HKCR\MSEdgeHTM"), None),
        (
            Target::Service {
                name: "edgeupdate".into(),
            },
            None,
        ),
    ];
    for (target, want) in &rows {
        assert_eq!(
            shared.find(target).map(|c| c.id.as_str()),
            *want,
            "{target:?}"
        );
    }
    assert!(
        SharedComponents::with_data(
            &env(),
            vec![SharedComponent {
                id: "bad".into(),
                name: "Bad".into(),
                paths: vec![r"relative\x".into()],
                keys: Vec::new(),
                packages: Vec::new(),
            }]
        )
        .is_err()
    );
}

// ---------------------------------------------------------------------------------------------------
// The rig's truth file: every target its patterns describe is denied.

#[derive(Debug, Clone)]
enum Node {
    Lit(char),
    /// `[...]`: negated?, members.
    Class(bool, Vec<char>),
    Any,
    Group(Vec<Vec<Node>>),
    Optional(Box<Node>),
    Star(Box<Node>),
    Plus(Box<Node>),
}

/// Parses the regex subset `vm/truth/deny.json` uses: literals, escapes, groups with alternation,
/// classes, `.`, and the `? * +` quantifiers. Anchors are dropped (every pattern is anchored).
fn parse_alternatives(chars: &[char], pos: &mut usize) -> Vec<Vec<Node>> {
    let mut alternatives = vec![Vec::new()];
    while *pos < chars.len() {
        let c = chars[*pos];
        *pos += 1;
        let node = match c {
            ')' => {
                *pos -= 1;
                break;
            }
            '|' => {
                alternatives.push(Vec::new());
                continue;
            }
            '^' | '$' => continue,
            '\\' => {
                *pos += 1;
                Node::Lit(chars[*pos - 1])
            }
            '(' => {
                let inner = parse_alternatives(chars, pos);
                assert_eq!(chars[*pos], ')', "unbalanced group");
                *pos += 1;
                Node::Group(inner)
            }
            '[' => {
                let negated = chars[*pos] == '^';
                if negated {
                    *pos += 1;
                }
                let mut members = Vec::new();
                while chars[*pos] != ']' {
                    if chars[*pos] == '\\' {
                        *pos += 1;
                    }
                    members.push(chars[*pos]);
                    *pos += 1;
                }
                *pos += 1;
                Node::Class(negated, members)
            }
            '.' => Node::Any,
            other => {
                assert!(
                    !"{}+*?".contains(other),
                    "unsupported regex syntax {other:?}"
                );
                Node::Lit(other)
            }
        };
        let node = match chars.get(*pos) {
            Some('?') => {
                *pos += 1;
                Node::Optional(Box::new(node))
            }
            Some('*') => {
                *pos += 1;
                Node::Star(Box::new(node))
            }
            Some('+') => {
                *pos += 1;
                Node::Plus(Box::new(node))
            }
            _ => node,
        };
        alternatives.last_mut().unwrap().push(node);
    }
    alternatives
}

/// Strings the node matches: every branch of every alternation, and fixed fillers for open classes.
fn samples(node: &Node) -> Vec<String> {
    match node {
        Node::Lit(c) => vec![c.to_string()],
        Node::Any => vec!["a".into()],
        // `[0-9-]`: the tail of the sample profile's SID.
        Node::Class(false, members) if members.contains(&'0') => {
            vec![SID.trim_start_matches("S-1-5-21-").to_owned()]
        }
        Node::Class(false, members) => members.iter().map(|c| c.to_string()).collect(),
        // One segment (the class excludes the separator), or any run of segments.
        Node::Class(true, members) if members.contains(&'\\') => vec!["alice".into()],
        Node::Class(true, _) => vec![r"Sub\Leaf".into()],
        Node::Group(alternatives) => alternatives.iter().flat_map(|seq| sequence(seq)).collect(),
        Node::Optional(inner) => std::iter::once(String::new())
            .chain(samples(inner))
            .collect(),
        Node::Star(inner) => {
            let mut out = vec![String::new()];
            out.extend(samples(inner).into_iter().map(|s| repeat_filler(inner, s)));
            out
        }
        Node::Plus(inner) => samples(inner)
            .into_iter()
            .map(|s| repeat_filler(inner, s))
            .collect(),
    }
}

/// `.*` and `.+` stand for a longer tail than one character.
fn repeat_filler(inner: &Node, sample: String) -> String {
    if matches!(inner, Node::Any) {
        r"a\b.txt".into()
    } else {
        sample
    }
}

fn sequence(nodes: &[Node]) -> Vec<String> {
    nodes.iter().fold(vec![String::new()], |acc, node| {
        let options = samples(node);
        acc.iter()
            .flat_map(|prefix| options.iter().map(move |s| format!("{prefix}{s}")))
            .collect()
    })
}

/// A rigtool canonical target string (`P:path`, `K:key`, `V:key|name`, `C:key|name`) as a target.
fn truth_target(sample: &str) -> Option<Target> {
    let (kind, rest) = sample.split_once(':')?;
    let (location, name) = match rest.split_once('|') {
        Some((location, name)) => (location, Some(name)),
        None => (rest, None),
    };
    Some(match (kind, name) {
        ("P", None) => p(location),
        ("K", None) => k(location),
        ("V", name) => v(location, name.unwrap_or("")),
        ("C", name) => Target::RegValueChanged {
            path: location.into(),
            name: name.unwrap_or("").into(),
            before: String::new(),
            after: String::new(),
        },
        // A key or path with a value name is not a target the scorer can produce.
        _ => return None,
    })
}

#[test]
fn every_target_of_the_rig_deny_file_is_denied() {
    let file = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vm/truth/deny.json");
    let text = std::fs::read_to_string(file).expect("vm/truth/deny.json is part of the repository");
    let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
    let rules = doc["rules"].as_array().expect("rules array");
    assert!(rules.len() >= 20, "the truth file has its rules");

    let every = Exemptions {
        proven_owned_skeleton: true,
        environment_segment_edit: true,
        tier_a_start_menu_entry: true,
        long_names_resolved: true,
    };
    let mut checked = 0;
    for rule in rules {
        let pattern = rule["match"].as_str().expect("match");
        let chars: Vec<char> = pattern.chars().collect();
        let mut pos = 0;
        let alternatives = parse_alternatives(&chars, &mut pos);
        assert_eq!(pos, chars.len(), "parsed all of {pattern}");
        let mut for_rule = 0;
        for sample in alternatives.iter().flat_map(|seq| sequence(seq)) {
            let Some(target) = truth_target(&sample) else {
                continue;
            };
            // No exemption a candidate can earn opens any of them.
            for ex in [none(), every] {
                assert!(
                    LIST.check(&target, &ex).is_some(),
                    "{sample:?} (from {pattern}) is not denied with {ex:?}"
                );
            }
            for_rule += 1;
        }
        assert!(for_rule > 0, "no target sampled from {pattern}");
        checked += for_rule;
    }
    assert!(checked > 150, "sampled {checked} targets");
}

#[test]
fn the_truth_sampler_expands_what_it_should() {
    let expand = |pattern: &str| -> Vec<String> {
        let chars: Vec<char> = pattern.chars().collect();
        let mut pos = 0;
        let alternatives = parse_alternatives(&chars, &mut pos);
        alternatives.iter().flat_map(|seq| sequence(seq)).collect()
    };
    assert_eq!(
        expand(r"^P:C:\\(Windows|Users\\[^\\]+)\\x(\\y)?$"),
        [
            r"P:C:\Windows\x",
            r"P:C:\Windows\x\y",
            r"P:C:\Users\alice\x",
            r"P:C:\Users\alice\x\y"
        ]
    );
    assert_eq!(
        expand(r"^[KV]:HKLM\\A\.b(\\[^|]*)?(\|.*)?$"),
        [
            r"K:HKLM\A.b",
            r"K:HKLM\A.b|",
            r"K:HKLM\A.b|a\b.txt",
            r"K:HKLM\A.b\",
            r"K:HKLM\A.b\|",
            r"K:HKLM\A.b\|a\b.txt",
            r"K:HKLM\A.b\Sub\Leaf",
            r"K:HKLM\A.b\Sub\Leaf|",
            r"K:HKLM\A.b\Sub\Leaf|a\b.txt",
            r"V:HKLM\A.b",
            r"V:HKLM\A.b|",
            r"V:HKLM\A.b|a\b.txt",
            r"V:HKLM\A.b\",
            r"V:HKLM\A.b\|",
            r"V:HKLM\A.b\|a\b.txt",
            r"V:HKLM\A.b\Sub\Leaf",
            r"V:HKLM\A.b\Sub\Leaf|",
            r"V:HKLM\A.b\Sub\Leaf|a\b.txt",
        ]
    );
    assert_eq!(
        expand(r"^K:HKU\\S-1-5-21-[0-9-]+\\X$|^K:HKLM\\X$"),
        [format!(r"K:HKU\{SID}\X"), r"K:HKLM\X".to_owned()]
    );
}

// ---------------------------------------------------------------------------------------------------
// The verdict does not depend on the spelling.

#[test]
fn property_verdicts_survive_respelling() {
    let mut rng = Rng::new(0x5EED_0003);
    let paths: &[&str] = &[
        r"C:\Windows\System32\drivers",
        r"C:\Program Files",
        r"C:\Program Files\Common Files\Microsoft Shared\ClickToRun",
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk",
        r"C:\Users\tester\.ssh\id_rsa",
        r"C:\Users\tester\AppData\Local\Packages\Vendor.App",
        r"C:\Users\tester\AppData\Roaming\Microsoft\Protect",
        r"D:\SteamLibrary\steamapps",
        r"D:\Games\Other\bin",
        r"C:\Users\tester",
        r"C:\",
        // Allowed.
        r"C:\Program Files\Git\bin",
        r"C:\Users\tester\AppData\Roaming\Code",
        r"C:\ProgramData\Vendor\App",
        r"D:\Apps\Tool",
        r"C:\Windows\Prefetch\APP.EXE-1A2B3C4D.pf",
        r"C:\Program Files\Microsoft.NET Hosting",
    ];
    let keys: &[&str] = &[
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        r"HKLM\SOFTWARE\Classes\CLSID",
        r"HKLM\SOFTWARE\Mozilla",
        r"HKLM\SOFTWARE\Policies\Vendor",
        r"HKLM\SYSTEM\ControlSet001\Services\MyService",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
        // Allowed.
        r"HKLM\SOFTWARE\Vendor\App",
        r"HKLM\SOFTWARE\Mozilla\Firefox",
        r"HKLM\SOFTWARE\WOW6432Node\Vendor",
        r"HKLM\SOFTWARE\Classes\CLSID\{0A1B2C3D-0000-1111-2222-333344445555}",
        r"HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\MyApp",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MyApp",
    ];
    for _ in 0..400 {
        for canonical in paths {
            let want = rule(&p(*canonical));
            // File names compare case-insensitively, so the case may change too.
            let respelled = respell_path(&mut rng, canonical);
            let spelled = rng.recase(&respelled);
            assert_eq!(rule(&p(&*spelled)), want, "{spelled:?} vs {canonical}");
        }
        for canonical in keys {
            let want = rule(&k(*canonical));
            let rest = canonical.strip_prefix("HKLM").unwrap();
            let rest = rest.replace(
                "ControlSet001",
                if rng.coin() {
                    "CurrentControlSet"
                } else {
                    "ControlSet001"
                },
            );
            let root = *rng.pick(&[
                "HKLM",
                "HKEY_LOCAL_MACHINE",
                r"Computer\HKEY_LOCAL_MACHINE",
                r"\Registry\Machine",
            ]);
            let mut spelled = format!("{root}{}", rng.recase(&rest));
            if rng.coin() {
                spelled.push('\\');
            }
            assert_eq!(rule(&k(&*spelled)), want, "{spelled:?} vs {canonical}");
            assert_eq!(
                rule(&v(&*spelled, "x")),
                rule(&v(*canonical, "x")),
                "value in {spelled:?}"
            );
        }
    }
    // A user key reads the same through every root spelling that names the SID.
    for (a, b) in [
        (
            hku(r"Software\Classes\Directory\shell"),
            format!(r"HKU\{SID}_Classes\Directory\shell"),
        ),
        (
            hku(r"Software\Classes\MyApp.Doc"),
            format!(r"HKEY_USERS\{}_classes\MyApp.Doc", SID.to_lowercase()),
        ),
    ] {
        assert_eq!(rule(&k(&*a)), rule(&k(&*b)), "{a} vs {b}");
    }
}

// Review regressions.

/// The facts in a `GuardEnv` protect the same directories however they are spelled; compared raw, a
/// `C:/Windows` would have compiled into a rule that matches nothing.
#[test]
fn env_directories_are_canonicalised_before_rules_are_compiled() {
    let mut odd = env();
    odd.system_drive = r"c:\".into();
    odd.windir = "c:/windows/".into();
    odd.program_files = r"\\?\C:\Program Files".into();
    odd.program_files_x86 = Some(r"C:\\Program Files (x86)\".into());
    odd.program_data = "C:/ProgramData".into();
    odd.profiles_dir = r"c:\users\".into();
    odd.profiles[0].root = "C:/Users/tester".into();
    odd.profiles[0].appdata = "C:/Users/tester/AppData/Roaming".into();
    odd.profiles[0].local_appdata = r"\\?\C:\Users\tester\AppData\Local".into();
    odd.profiles[0].known_folders = vec!["E:/Docs".into(), String::new()];
    odd.sync_roots = vec!["C:/Users/tester/OneDrive - Corp/".into()];
    odd.other_app_roots[0].path = "d:/Games/Other".into();
    odd.protected_dirs = vec![r"\\?\D:\SteamLibrary".into()];
    odd.purge_dirs = vec!["C:/Program Files/Purge".into()];
    let list = DenyList::compile(&odd);
    assert_eq!(list.invalid(), None);
    let ex = none();
    for (path, want) in [
        (r"C:\Windows\System32\kernel32.dll", Some("fs.windir")),
        (r"C:\Program Files", Some("fs.program-files")),
        (r"C:\Program Files (x86)", Some("fs.program-files")),
        (r"C:\Program Files\Common Files", Some("fs.common-files")),
        (r"C:\ProgramData", Some("fs.programdata")),
        (
            r"C:\ProgramData\Microsoft\Crypto",
            Some("fs.programdata.microsoft"),
        ),
        (r"C:\Users\tester", Some("fs.profile-root")),
        (
            r"C:\Users\tester\AppData\Roaming\Microsoft\Protect\x",
            Some("fs.secrets"),
        ),
        (r"E:\Docs", Some("fs.known-folder")),
        (
            r"C:\Users\tester\OneDrive - Corp\notes.txt",
            Some("fs.sync-root"),
        ),
        (r"D:\Games\Other\data", Some("fs.other-app-root:Other Game")),
        (r"D:\Games", Some("fs.other-app-root:Other Game")),
        (r"D:\SteamLibrary", Some("fs.protected-dir")),
        (r"C:\Program Files\Purge\purge.exe", Some("fs.purge")),
        (r"C:\Program Files\Git", None),
        (r"C:\Users\tester\AppData\Roaming\Vendor", None),
    ] {
        assert_eq!(list.denying_rule(&p(path), &ex).as_deref(), want, "{path}");
        // And the same verdicts as the plainly spelled environment gives.
        assert_eq!(LIST.denying_rule(&p(path), &ex).as_deref(), want, "{path}");
    }
    // Tokens in targets expand from the canonical facts too.
    assert_eq!(
        list.denying_rule(&p(r"%WINDIR%\System32"), &ex).as_deref(),
        Some("fs.windir")
    );
    let dotnet = p(r"C:\Program Files\dotnet\shared");
    let plain = SharedComponents::compile(&env()).unwrap();
    let shared = SharedComponents::compile(&odd).unwrap();
    assert!(plain.find(&dotnet).is_some());
    assert_eq!(
        shared.find(&dotnet).map(|c| c.id.as_str()),
        plain.find(&dotnet).map(|c| c.id.as_str())
    );
}

/// A fact that cannot be made canonical means the guard cannot be trusted: everything is denied.
#[test]
fn an_env_directory_that_does_not_canonicalise_denies_every_location() {
    type Break = fn(&mut GuardEnv);
    let cases: &[Break] = &[
        |e| e.windir = r"Windows".into(),
        |e| e.windir = r"C:\".into(),
        |e| e.windir = r"%SystemRoot%".into(),
        |e| e.windir = r"\\server\share\Windows".into(),
        |e| e.program_files = r"C:\Program Files\..\Windows".into(),
        |e| e.program_files_x86 = Some(r"Program Files (x86)".into()),
        |e| e.system_drive = "C".into(),
        |e| e.system_drive = r"C:\Windows".into(),
        |e| e.sync_roots = vec![r"\\?\Volume{0000}\OneDrive".into()],
        |e| e.other_app_roots[0].path = r"Games\Other".into(),
        |e| e.protected_dirs = vec![r"D:\Steam\..".into()],
        |e| e.profiles[0].root = r"tester".into(),
        |e| e.profiles[0].known_folders = vec![r"E:\Docs:stream".into()],
        |e| e.purge_dirs = vec![r"\\.\C:\Purge".into()],
    ];
    for (i, break_it) in cases.iter().enumerate() {
        let mut bad = env();
        break_it(&mut bad);
        let list = DenyList::compile(&bad);
        assert!(list.invalid().is_some(), "case {i}");
        for target in [p(r"C:\Program Files\Git"), k(r"HKLM\SOFTWARE\Vendor\App")] {
            assert_eq!(
                list.denying_rule(&target, &none()).as_deref(),
                Some("guard.unavailable"),
                "case {i}: {target:?}"
            );
        }
    }
}

/// A folder redirected to a share needs no rule (UNC targets never canonicalise), so it must not take
/// the whole guard down.
#[test]
fn unc_and_blank_optional_directories_are_skipped() {
    let mut e = env();
    e.profiles[0].appdata = r"\\server\profiles\tester\AppData\Roaming".into();
    e.profiles[0].known_folders = vec![r"\\server\home\tester\Documents".into(), "  ".into()];
    e.sync_roots.push(String::new());
    e.program_files_x86 = Some(String::new());
    let list = DenyList::compile(&e);
    assert_eq!(list.invalid(), None);
    assert_eq!(
        list.denying_rule(&p(r"\\server\home\tester\Documents\x"), &none())
            .as_deref(),
        Some("canon.unc")
    );
    assert_eq!(
        list.denying_rule(&p(r"C:\Users\tester\AppData\Roaming"), &none())
            .as_deref(),
        Some("fs.known-folder"),
        "the default layout is still protected"
    );
    assert_eq!(
        list.denying_rule(&p(r"C:\Program Files\Git"), &none()),
        None
    );
}

#[test]
fn only_prefetch_traces_leave_the_windir_rule() {
    all_allowed(&[
        p(r"C:\Windows\Prefetch\NOTEPAD++.EXE-1A2B3C4D.pf"),
        p(r"c:\windows\prefetch\app-setup.exe-00ff00ff.PF"),
    ]);
    all_denied(
        &[
            p(r"C:\Windows\Prefetch"),
            p(r"C:\Windows\Prefetch\evil.pf"),
            p(r"C:\Windows\Prefetch\.pf"),
            p(r"C:\Windows\Prefetch\-1A2B3C4D.pf"),
            p(r"C:\Windows\Prefetch\APP.EXE-1A2B3C4.pf"),
            p(r"C:\Windows\Prefetch\APP.EXE-1A2B3C4G.pf"),
            p(r"C:\Windows\Prefetch\APP.EXE-1A2B3C4D5.pf"),
            p(r"C:\Windows\Prefetch\Layout.ini"),
            p(r"C:\Windows\Prefetch\AgAppLaunch.db"),
            p(r"C:\Windows\Prefetch\ReadyBoot\Trace1.fx"),
            p(r"C:\Windows\Prefetch\ReadyBoot\APP.EXE-1A2B3C4D.pf"),
            p(r"C:\Windows\System32\APP.EXE-1A2B3C4D.pf"),
        ],
        "fs.windir",
    );
}

#[test]
fn event_sources_only_in_the_current_control_set() {
    let source = r"Services\EventLog\Application\MyApp";
    all_allowed(&[
        k(format!(r"HKLM\SYSTEM\CurrentControlSet\{source}")),
        k(format!(r"HKLM\SYSTEM\ControlSet001\{source}")),
        v(
            format!(r"HKLM\SYSTEM\ControlSet001\{source}"),
            "EventMessageFile",
        ),
    ]);
    all_denied(
        &[
            k(format!(r"HKLM\SYSTEM\ControlSet002\{source}")),
            k(format!(r"HKLM\SYSTEM\ControlSetBackup\{source}")),
            k(format!(r"HKLM\SYSTEM\{source}")),
            k(r"HKLM\SYSTEM\ControlSet001\Services\EventLog\Application"),
            k(r"HKLM\SYSTEM\ControlSet001\Services\EventLog"),
            v(
                r"HKLM\SYSTEM\ControlSet001\Services\EventLog\Application",
                "File",
            ),
        ],
        "reg.hklm.system",
    );
}

#[test]
fn core_user_environment_values_are_never_deleted_whole() {
    for name in ["Path", "PATH", "pathext", "TEMP", "Tmp"] {
        assert_eq!(
            rule(&v(hku("Environment"), name)).as_deref(),
            Some("reg.environment.core-value"),
            "{name}"
        );
    }
    // An app's own variable, and a segment of PATH, are still offered.
    all_allowed(&[
        v(hku("Environment"), "JAVA_HOME"),
        v(hku("Environment"), "PathFoo"),
        seg(hku("Environment")),
        // A vendor key that happens to be called Environment is not the container.
        v(hku(r"Software\Vendor\Environment"), "Path"),
    ]);
    // The machine container admits nothing but the exempted segment edit.
    let all = Exemptions {
        proven_owned_skeleton: true,
        environment_segment_edit: true,
        tier_a_start_menu_entry: true,
        long_names_resolved: true,
    };
    for name in ["Path", "JAVA_HOME"] {
        let target = v(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            name,
        );
        assert_eq!(
            LIST.denying_rule(&target, &all).as_deref(),
            Some("reg.hklm.system"),
            "{name}"
        );
    }
}

#[test]
fn user_hive_files_are_denied() {
    all_denied(
        &[
            p(r"C:\Users\tester\NTUSER.DAT"),
            p(r"C:\Users\tester\ntuser.dat.LOG1"),
            p(r"C:\Users\tester\ntuser.ini"),
            p(r"C:\Users\Default\NTUSER.DAT"),
            p(r"C:\Users\someone-else\NTUSER.DAT{53b39e88-18c4-11ea-a811-000d3aa4692b}.TM.blf"),
            p(format!(r"{LOCAL}\Microsoft\Windows\UsrClass.dat")),
            p(format!(r"{LOCAL}\Microsoft\Windows\UsrClass.dat.LOG2")),
        ],
        "fs.user-hive",
    );
    all_allowed(&[
        p(r"C:\Users\tester\.vendor-app"),
        p(format!(r"{LOCAL}\Microsoft\Windows\Vendor.dat")),
    ]);
}

#[test]
fn package_stores_and_boot_files_on_any_volume() {
    all_denied(
        &[
            p(r"D:\WindowsApps"),
            p(r"D:\WindowsApps\Vendor.App_1.0.0.0_x64__abc"),
            p(r"E:\WpSystem\S-1-5-21-1\AppData"),
        ],
        "kb.package-store-other-volume",
    );
    all_denied(
        &[
            p(r"C:\bootmgr"),
            p(r"C:\BOOTNXT"),
            p(r"C:\EFI\Microsoft\Boot\BCD"),
            p(r"C:\pagefile.sys"),
            p(r"D:\pagefile.sys"),
            p(r"C:\hiberfil.sys"),
            p(r"C:\swapfile.sys"),
        ],
        "kb.volume-boot-file",
    );
    all_allowed(&[
        p(r"D:\WindowsAppsTool"),
        p(r"D:\Tools\EFI"),
        p(r"D:\Games\pagefile.sys"),
    ]);
}

#[test]
fn windows_start_menu_folders_are_denied_with_their_entries() {
    let all = Exemptions {
        proven_owned_skeleton: true,
        environment_segment_edit: true,
        tier_a_start_menu_entry: true,
        long_names_resolved: true,
    };
    for base in [
        PD_PROGRAMS.to_owned(),
        format!(r"{ROAMING}\Microsoft\Windows\Start Menu\Programs"),
    ] {
        for rest in [
            r"Accessories",
            r"Accessories\Paint.lnk",
            r"Accessories\System Tools",
            r"Administrative Tools\Services.lnk",
            r"System Tools\Command Prompt.lnk",
            r"Windows PowerShell\Windows PowerShell.lnk",
            r"Accessibility\Narrator.lnk",
        ] {
            let target = p(format!(r"{base}\{rest}"));
            for ex in [none(), all] {
                assert_eq!(
                    LIST.denying_rule(&target, &ex).as_deref(),
                    Some("fs.start-menu.windows-folder"),
                    "{target:?}"
                );
            }
        }
        // An app's own folder and shortcut directly under Programs are unaffected.
        for rest in [
            r"Vendor App",
            r"Vendor App\App.lnk",
            r"App.lnk",
            r"Accessories2\App.lnk",
        ] {
            let target = p(format!(r"{base}\{rest}"));
            assert_eq!(LIST.denying_rule(&target, &all), None, "{target:?}");
        }
    }
}
