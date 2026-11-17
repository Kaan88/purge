//! M1b deny-list tests (M1B-GUARD, C-GUARD): the Installer database and Package Cache exemptions, the
//! object rules of `check_object`, the new registry and file rules, and the M1b value containers.

use std::sync::LazyLock;

use purge_guard::canon::GuardEnv;
use purge_guard::containers::{self, M1B_VALUE_CONTAINERS, VALUE_CONTAINERS};
use purge_guard::deny::{DenyList, Exemptions, ObjectGuardFacts, check_object, shared_iids};
use purge_model::{Blocker, ObjectKind, Target};

const SID: &str = GuardEnv::SAMPLE_SID;
const CV: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion";
/// A packed product code of a gone product.
const P: &str = "1A2B3C4D5E6F708192A3B4C5D6E7F801";
/// Another product, still installed.
const OTHER: &str = "9F8E7D6C5B4A39281706F5E4D3C2B1A0";
const U: &str = "0123456789ABCDEF0123456789ABCDEF";
const C: &str = "FEDCBA9876543210FEDCBA9876543210";

static LIST: LazyLock<DenyList> = LazyLock::new(|| DenyList::compile(&GuardEnv::sample()));

fn k(path: impl Into<String>) -> Target {
    Target::RegKey { path: path.into() }
}

fn v(path: impl Into<String>, name: &str) -> Target {
    Target::RegValue {
        path: path.into(),
        name: name.into(),
    }
}

fn p(path: impl Into<String>) -> Target {
    Target::Path { path: path.into() }
}

fn rule_with(target: &Target, ex: &Exemptions<'_>) -> Option<String> {
    LIST.denying_rule(target, ex)
}

fn rule(target: &Target) -> Option<String> {
    rule_with(target, &Exemptions::default())
}

fn list(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| (*s).to_owned()).collect()
}

fn gone_msi(products: &[String]) -> Exemptions<'_> {
    Exemptions {
        gone_msi_products: products,
        ..Exemptions::default()
    }
}

/// The eight shapes of C-GUARD for product `code`.
fn eight_shapes(code: &str) -> Vec<Target> {
    vec![
        k(format!(r"{CV}\Installer\UserData\S-1-5-18\Products\{code}")),
        k(format!(r"HKLM\SOFTWARE\Classes\Installer\Products\{code}")),
        k(format!(
            r"HKU\{SID}\Software\Microsoft\Installer\Products\{code}"
        )),
        v(format!(r"{CV}\Installer\UpgradeCodes\{U}"), code),
        v(
            format!(r"HKLM\SOFTWARE\Classes\Installer\UpgradeCodes\{U}"),
            code,
        ),
        v(
            format!(r"{CV}\Installer\UserData\S-1-5-18\Components\{C}"),
            code,
        ),
        k(format!(r"HKLM\SOFTWARE\Classes\Installer\Features\{code}")),
        v(format!(r"{CV}\Installer\Folders"), r"C:\Program Files\App\"),
    ]
}

// ---------------------------------------------------------------------------------------------------
// reg.installer
// ---------------------------------------------------------------------------------------------------

#[test]
fn exemption_closed_by_default() {
    assert_eq!(Exemptions::default().gone_msi_products.len(), 0);
    assert_eq!(Exemptions::default().gone_cache_dirs.len(), 0);
    assert_eq!(Exemptions::default().gone_burn.len(), 0);
    for target in eight_shapes(P) {
        assert_eq!(
            rule(&target).as_deref(),
            Some("reg.installer"),
            "{target:?}"
        );
    }
    // An empty list is the same as the default.
    let empty: Vec<String> = Vec::new();
    for target in eight_shapes(P) {
        assert_eq!(
            rule_with(&target, &gone_msi(&empty)).as_deref(),
            Some("reg.installer"),
            "{target:?}"
        );
    }
    // The Package Cache and Burn shapes are closed too.
    assert_eq!(
        rule(&p(r"C:\ProgramData\Package Cache\{0A1B}v1\app.msi")).as_deref(),
        Some("fs.package-cache")
    );
    assert_eq!(
        rule(&k(
            r"HKLM\SOFTWARE\Classes\Installer\Dependencies\Vendor.App"
        ))
        .as_deref(),
        Some("reg.installer")
    );
}

#[test]
fn exemption_allows_exact_eight_shapes() {
    let gone = list(&[P]);
    let ex = gone_msi(&gone);
    for target in eight_shapes(P) {
        assert_eq!(rule_with(&target, &ex), None, "{target:?}");
    }
    // Each shape needs its own target kind: a value shape as a key and a key shape as a value stay
    // denied.
    let swapped = [
        v(
            format!(r"{CV}\Installer\UserData\S-1-5-18\Products\{P}"),
            "x",
        ),
        v(r"HKLM\SOFTWARE\Classes\Installer", P),
        k(format!(r"{CV}\Installer\UpgradeCodes\{U}\{P}")),
        k(format!(r"{CV}\Installer\Folders\x")),
        Target::RegValueChanged {
            path: format!(r"{CV}\Installer\UpgradeCodes\{U}"),
            name: P.into(),
            before: String::new(),
            after: String::new(),
        },
    ];
    for target in &swapped {
        assert!(rule_with(target, &ex).is_some(), "{target:?}");
    }
}

#[test]
fn exemption_denies_products_parent_child_and_sibling() {
    let gone = list(&[P]);
    let ex = gone_msi(&gone);
    let denied = [
        // One level above.
        k(format!(r"{CV}\Installer\UserData\S-1-5-18\Products")),
        k(r"HKLM\SOFTWARE\Classes\Installer\Products"),
        k(format!(r"HKU\{SID}\Software\Microsoft\Installer\Products")),
        k(r"HKLM\SOFTWARE\Classes\Installer\Features"),
        k(format!(r"{CV}\Installer\UserData\S-1-5-18")),
        k(format!(r"{CV}\Installer")),
        // One level below, as its own target.
        k(format!(
            r"{CV}\Installer\UserData\S-1-5-18\Products\{P}\InstallProperties"
        )),
        k(format!(
            r"HKLM\SOFTWARE\Classes\Installer\Products\{P}\SourceList"
        )),
        v(
            format!(r"{CV}\Installer\UserData\S-1-5-18\Products\{P}\InstallProperties"),
            "DisplayName",
        ),
        v(
            format!(r"HKLM\SOFTWARE\Classes\Installer\Products\{P}"),
            "ProductName",
        ),
        // A sibling: a product that is not gone.
        k(format!(
            r"{CV}\Installer\UserData\S-1-5-18\Products\{OTHER}"
        )),
        k(format!(r"HKLM\SOFTWARE\Classes\Installer\Products\{OTHER}")),
        k(format!(
            r"HKU\{SID}\Software\Microsoft\Installer\Products\{OTHER}"
        )),
        v(format!(r"{CV}\Installer\UpgradeCodes\{U}"), OTHER),
        v(
            format!(r"{CV}\Installer\UserData\S-1-5-18\Components\{C}"),
            OTHER,
        ),
        // The keys holding the values stay denied: only the value is ever offered.
        k(format!(r"{CV}\Installer\UpgradeCodes\{U}")),
        k(format!(r"HKLM\SOFTWARE\Classes\Installer\UpgradeCodes\{U}")),
        k(format!(r"{CV}\Installer\Folders")),
        // Other parts of the database, even named by the product.
        k(format!(r"{CV}\Installer\UserData\S-1-5-18\Patches\{P}")),
        k(format!(r"HKLM\SOFTWARE\Classes\Installer\Patches\{P}")),
        k(format!(
            r"HKU\{SID}\Software\Microsoft\Installer\Features\{P}"
        )),
        k(format!(
            r"HKU\{SID}\Software\Microsoft\Installer\UpgradeCodes\{U}"
        )),
        v(
            format!(r"HKU\{SID}\Software\Microsoft\Installer\UpgradeCodes\{U}"),
            P,
        ),
        k(format!(r"{CV}\Installer\Products\{P}")),
        k(format!(r"HKU\{SID}_Classes\Installer\Products\{P}")),
        k(format!(r"HKLM\SOFTWARE\Classes\Installer\Components\{C}")),
    ];
    for target in &denied {
        assert!(rule_with(target, &ex).is_some(), "{target:?}");
    }
}

#[test]
fn exemption_denies_packed_code_as_substring() {
    let gone = list(&[P]);
    let ex = gone_msi(&gone);
    for code in [
        format!("{P}X"),
        format!("X{P}"),
        P[..31].to_owned(),
        format!("{P} "),
        format!("{P}.bak"),
    ] {
        for target in eight_shapes(&code).into_iter().take(7) {
            assert_eq!(
                rule_with(&target, &ex).as_deref(),
                Some("reg.installer"),
                "{target:?}"
            );
        }
    }
    // A listed entry that is not a packed code opens nothing, not even the path-keyed Folders store.
    for bad in [
        list(&[""]),
        list(&["*"]),
        list(&[&format!("{P}X")]),
        list(&["Products"]),
    ] {
        let ex = gone_msi(&bad);
        for target in eight_shapes(P)
            .into_iter()
            .chain([k(r"HKLM\SOFTWARE\Classes\Installer\Products\Products")])
        {
            assert!(rule_with(&target, &ex).is_some(), "{bad:?} {target:?}");
        }
    }
}

#[test]
fn exemption_denies_gone_code_under_components_key_target() {
    let gone = list(&[P]);
    let ex = gone_msi(&gone);
    let component = format!(r"{CV}\Installer\UserData\S-1-5-18\Components\{C}");
    assert_eq!(rule_with(&v(&component, P), &ex), None);
    assert_eq!(
        rule_with(&k(&component), &ex).as_deref(),
        Some("msi.component-foreign")
    );
    assert_eq!(
        rule(&k(&component)).as_deref(),
        Some("msi.component-foreign")
    );
    // A component key named like the gone product is still a component key.
    let named = format!(r"{CV}\Installer\UserData\S-1-5-18\Components\{P}");
    assert_eq!(
        rule_with(&k(&named), &ex).as_deref(),
        Some("msi.component-foreign")
    );
    assert!(rule_with(&k(format!(r"{component}\Sub")), &ex).is_some());
}

#[test]
fn exemption_case_insensitive_whole_segment() {
    let gone = list(&[&P.to_ascii_lowercase()]);
    let ex = gone_msi(&gone);
    for target in eight_shapes(P) {
        assert_eq!(rule_with(&target, &ex), None, "{target:?}");
    }
    let upper = list(&[P]);
    let ex = gone_msi(&upper);
    for target in eight_shapes(&P.to_ascii_lowercase()) {
        assert_eq!(rule_with(&target, &ex), None, "{target:?}");
    }
    // Mixed case in the fixed segments of the shape.
    let mixed = k(format!(
        r"hklm\software\MICROSOFT\windows\currentversion\INSTALLER\userdata\s-1-5-18\PRODUCTS\{P}"
    ));
    assert_eq!(rule_with(&mixed, &ex), None);
}

#[test]
fn exemption_through_wow6432_and_hkcr_alias_same_answer() {
    let gone = list(&[P]);
    let ex = gone_msi(&gone);
    for code in [P, OTHER] {
        let spellings = [
            format!(r"HKLM\SOFTWARE\Classes\Installer\Products\{code}"),
            format!(r"HKLM\SOFTWARE\WOW6432Node\Classes\Installer\Products\{code}"),
            format!(r"HKLM\SOFTWARE\Classes\WOW6432Node\Installer\Products\{code}"),
            format!(r"HKEY_LOCAL_MACHINE\Software\Classes\Installer\Products\{code}"),
        ];
        let want = rule_with(&k(&spellings[0]), &ex);
        for spelled in &spellings {
            assert_eq!(rule_with(&k(spelled), &ex), want, "{spelled}");
        }
        let userdata = [
            format!(r"{CV}\Installer\UserData\S-1-5-18\Products\{code}"),
            format!(
                r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\{code}"
            ),
        ];
        let want = rule_with(&k(&userdata[0]), &ex);
        for spelled in &userdata {
            assert_eq!(rule_with(&k(spelled), &ex), want, "{spelled}");
        }
    }
    // The merged view is never a location, exempt or not.
    assert_eq!(
        rule_with(&k(format!(r"HKCR\Installer\Products\{P}")), &ex).as_deref(),
        Some("canon.hkcr")
    );
    // A user's Classes in both spellings, for the Burn shapes.
    let burn = list(&["Vendor.App,v1"]);
    let ex = Exemptions {
        gone_burn: &burn,
        ..Exemptions::default()
    };
    let a = k(format!(
        r"HKU\{SID}\Software\Classes\Installer\Dependencies\Vendor.App,v1"
    ));
    let b = k(format!(
        r"HKU\{SID}_Classes\Installer\Dependencies\Vendor.App,v1"
    ));
    assert_eq!(rule_with(&a, &ex), None);
    assert_eq!(rule_with(&b, &ex), None);
}

// ---------------------------------------------------------------------------------------------------
// gone_burn
// ---------------------------------------------------------------------------------------------------

#[test]
fn burn_exemption_two_shapes_only() {
    let burn = list(&[
        "{B0B0B0B0-0000-1111-2222-333344445555}",
        "VC,redist.x64,amd64,14.38,bundle",
    ]);
    let ex = Exemptions {
        gone_burn: &burn,
        ..Exemptions::default()
    };
    let deps = r"HKLM\SOFTWARE\Classes\Installer\Dependencies";
    let allowed = [
        k(format!(r"{deps}\VC,redist.x64,amd64,14.38,bundle")),
        k(format!(r"{deps}\vc,REDIST.x64,amd64,14.38,BUNDLE")),
        k(format!(
            r"{deps}\Some.Provider\Dependents\{{B0B0B0B0-0000-1111-2222-333344445555}}"
        )),
        k(
            r"HKLM\SOFTWARE\Classes\WOW6432Node\Installer\Dependencies\VC,redist.x64,amd64,14.38,bundle",
        ),
    ];
    for target in &allowed {
        assert_eq!(rule_with(target, &ex), None, "{target:?}");
    }
    let denied = [
        // Values of the shapes: keys only.
        v(
            format!(r"{deps}\VC,redist.x64,amd64,14.38,bundle"),
            "Version",
        ),
        // Below the shapes.
        k(format!(
            r"{deps}\VC,redist.x64,amd64,14.38,bundle\Dependents"
        )),
        k(format!(
            r"{deps}\Some.Provider\Dependents\{{B0B0B0B0-0000-1111-2222-333344445555}}\Sub"
        )),
        // A listed name in another position.
        k(format!(
            r"{deps}\{{B0B0B0B0-0000-1111-2222-333344445555}}x\Dependents"
        )),
        k(format!(
            r"{deps}\Some.Provider\Other\{{B0B0B0B0-0000-1111-2222-333344445555}}"
        )),
        k(r"HKLM\SOFTWARE\Classes\Installer\Products\{B0B0B0B0-0000-1111-2222-333344445555}"),
        // A Burn name does not open an MSI shape.
        k(format!(r"{CV}\Installer\UserData\S-1-5-18\Products\{P}")),
    ];
    for target in &denied {
        assert!(rule_with(target, &ex).is_some(), "{target:?}");
    }
}

#[test]
fn burn_exemption_denies_dependencies_root_and_unlisted_provider() {
    let burn = list(&["Vendor.App,v1", "", "*", r"a\b"]);
    let ex = Exemptions {
        gone_burn: &burn,
        ..Exemptions::default()
    };
    let deps = r"HKLM\SOFTWARE\Classes\Installer\Dependencies";
    for target in [
        k(deps),
        k(format!(r"HKU\{SID}_Classes\Installer\Dependencies")),
        k(r"HKLM\SOFTWARE\Classes\Installer"),
        k(format!(r"{deps}\Other.App,v1")),
        k(format!(r"{deps}\Vendor.App,v1x")),
        k(format!(r"{deps}\xVendor.App,v1")),
        k(format!(r"{deps}\Other.App,v1\Dependents\Someone.Else")),
        k(format!(r"{deps}\Vendor.App,v1\Dependents")),
        k(format!(r"{deps}\*")),
        k(format!(r"{deps}\a\b")),
    ] {
        assert_eq!(
            rule_with(&target, &ex).as_deref(),
            Some("reg.installer"),
            "{target:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------------
// fs.package-cache
// ---------------------------------------------------------------------------------------------------

fn cache(dirs: &[String]) -> Exemptions<'_> {
    Exemptions {
        gone_cache_dirs: dirs,
        long_names_resolved: true,
        ..Exemptions::default()
    }
}

#[test]
fn pkgcache_exemption_only_direct_child_of_cache_root() {
    let dirs = list(&[
        r"C:\ProgramData\Package Cache\{0A1B2C3D-0000-1111-2222-333344445555}v1.0",
        r"c:/users/tester/appdata/local/package cache/{B0B0}",
    ]);
    let ex = cache(&dirs);
    for target in [
        p(r"C:\ProgramData\Package Cache\{0A1B2C3D-0000-1111-2222-333344445555}v1.0"),
        p(r"C:\ProgramData\Package Cache\{0A1B2C3D-0000-1111-2222-333344445555}v1.0\app.msi"),
        p(r"C:\PROGRAMDATA\PACKAGE CACHE\{0a1b2c3d-0000-1111-2222-333344445555}V1.0\x\y"),
        p(r"C:\Users\tester\AppData\Local\Package Cache\{B0B0}\bundle.exe"),
    ] {
        assert_eq!(rule_with(&target, &ex), None, "{target:?}");
    }
    for target in [
        p(r"C:\ProgramData\Package Cache\{0A1B2C3D-0000-1111-2222-333344445555}v1.1"),
        p(r"C:\ProgramData\Package Cache\{0A1B2C3D-0000-1111-2222-333344445555}v1.0x"),
        p(r"C:\ProgramData\Package Cache\Other\app.msi"),
        p(r"C:\Users\tester\AppData\Local\Package Cache\{B0B0}x"),
    ] {
        assert_eq!(
            rule_with(&target, &ex).as_deref(),
            Some("fs.package-cache"),
            "{target:?}"
        );
    }
    // A deeper entry is not a direct child: it opens nothing, not even itself.
    let deeper = list(&[r"C:\ProgramData\Package Cache\{0A1B}v1\sub"]);
    assert_eq!(
        rule_with(
            &p(r"C:\ProgramData\Package Cache\{0A1B}v1\sub\x.msi"),
            &cache(&deeper)
        )
        .as_deref(),
        Some("fs.package-cache")
    );
    // An entry with a short-name-like segment is ignored.
    let short = list(&[r"C:\ProgramData\PACKAG~1\{0A1B}v1"]);
    assert!(
        rule_with(
            &p(r"C:\ProgramData\Package Cache\{0A1B}v1\x"),
            &cache(&short)
        )
        .is_some()
    );
}

#[test]
fn pkgcache_exemption_ignores_listed_root_itself() {
    let dirs = list(&[
        r"C:\ProgramData\Package Cache",
        r"C:\ProgramData\Package Cache\",
        r"C:\Users\tester\AppData\Local\Package Cache",
    ]);
    let ex = cache(&dirs);
    for target in [
        p(r"C:\ProgramData\Package Cache"),
        p(r"C:\ProgramData\Package Cache\{0A1B}v1"),
        p(r"C:\ProgramData\Package Cache\{0A1B}v1\app.msi"),
        p(r"C:\Users\tester\AppData\Local\Package Cache"),
        p(r"C:\Users\tester\AppData\Local\Package Cache\{B0B0}"),
    ] {
        assert_eq!(
            rule_with(&target, &ex).as_deref(),
            Some("fs.package-cache"),
            "{target:?}"
        );
    }
    // The ancestors stay denied by their own rules.
    assert_eq!(
        rule_with(&p(r"C:\ProgramData"), &ex).as_deref(),
        Some("fs.programdata")
    );
}

#[test]
fn pkgcache_exemption_ignores_listed_dir_outside_cache() {
    let dirs = list(&[
        r"C:\Program Files",
        r"C:\Program Files\App",
        r"C:\ProgramData\Vendor",
        r"C:\ProgramData\Package Cache Old\{0A1B}v1",
        r"D:\Package Cache\{0A1B}v1",
        r"C:\Windows\Installer",
    ]);
    let ex = cache(&dirs);
    for (target, want) in [
        (r"C:\Program Files", "fs.program-files"),
        (r"C:\Windows\Installer\1a2b.msi", "fs.windir"),
    ] {
        assert_eq!(
            rule_with(&p(target), &ex).as_deref(),
            Some(want),
            "{target}"
        );
    }
    // Nothing listed outside a cache opens a cache entry.
    assert_eq!(
        rule_with(&p(r"C:\ProgramData\Package Cache\{0A1B}v1"), &ex).as_deref(),
        Some("fs.package-cache")
    );
    // Items outside any cache are judged exactly as without the list.
    for target in [
        r"C:\Program Files\App\app.exe",
        r"C:\ProgramData\Vendor\x",
        r"D:\Package Cache\{0A1B}v1\x",
    ] {
        assert_eq!(
            rule_with(&p(target), &ex),
            rule_with(&p(target), &cache(&[])),
            "{target}"
        );
    }
}

#[test]
fn pkgcache_root_rejection_unchanged() {
    assert_eq!(
        LIST.root_rejection(r"C:\ProgramData\Package Cache\{0A1B}v1", true)
            .as_deref(),
        Some("root.package-cache")
    );
    assert_eq!(
        LIST.root_rejection(r"C:\ProgramData\Package Cache", true)
            .as_deref(),
        Some("fs.package-cache")
    );
}

// ---------------------------------------------------------------------------------------------------
// check_object
// ---------------------------------------------------------------------------------------------------

fn denied(rule: &str) -> Option<Blocker> {
    Some(Blocker::DenyListed { rule: rule.into() })
}

fn service<'a>(program: Option<&'a str>, ty: u32) -> ObjectGuardFacts<'a> {
    ObjectGuardFacts {
        name_or_path_or_id: "VendorSvc",
        program,
        service_type: Some(ty),
        ..ObjectGuardFacts::default()
    }
}

const APP_EXE: &str = r"C:\Program Files\Vendor\svc.exe";

#[test]
fn check_object_driver() {
    for ty in [0x1, 0x2, 0x4, 0x8, 0x1 | 0x10, 0x2 | 0x100] {
        assert_eq!(
            check_object(ObjectKind::Service, &service(Some(APP_EXE), ty)),
            denied("sys.driver"),
            "{ty:#x}"
        );
    }
    // An unknown type is not trusted to be a plain service.
    let unknown = ObjectGuardFacts {
        service_type: None,
        ..service(Some(APP_EXE), 0x10)
    };
    assert_eq!(
        check_object(ObjectKind::Service, &unknown),
        denied("sys.driver")
    );
    for ty in [0x10, 0x20, 0x110] {
        assert_eq!(
            check_object(ObjectKind::Service, &service(Some(APP_EXE), ty)),
            None
        );
    }
}

#[test]
fn check_object_peruser_template_and_instance() {
    // Template (USER_SERVICE | OWN_PROCESS), instance (| USERSERVICE_INSTANCE), and the flag alone.
    for facts in [
        service(Some(APP_EXE), 0x50),
        service(Some(APP_EXE), 0x60),
        service(Some(APP_EXE), 0xd0),
        service(Some(APP_EXE), 0xe0),
        ObjectGuardFacts {
            per_user_template: true,
            ..service(Some(APP_EXE), 0x10)
        },
    ] {
        assert_eq!(
            check_object(ObjectKind::Service, &facts),
            denied("sys.service.peruser"),
            "{facts:?}"
        );
    }
}

#[test]
fn check_object_marked() {
    let marked = ObjectGuardFacts {
        delete_flag: true,
        ..service(Some(APP_EXE), 0x10)
    };
    assert_eq!(
        check_object(ObjectKind::Service, &marked),
        denied("sys.service.marked")
    );
}

#[test]
fn check_object_program_under_systemroot_any_depth() {
    for program in [
        r"C:\Windows\System32\svchost.exe",
        r"C:\Windows\vendor.exe",
        r"C:\Windows\System32\drivers\etc\deep\a\b\c.exe",
        r"c:\windows\syswow64\x.exe",
        r"%SystemRoot%\System32\vendorsvc.exe",
        r"\SystemRoot\System32\vendor.exe",
        r"System32\vendor.exe",
    ] {
        assert_eq!(
            check_object(ObjectKind::Service, &service(Some(program), 0x10)),
            denied("sys.service.windows"),
            "{program}"
        );
        let task = ObjectGuardFacts {
            name_or_path_or_id: r"\Vendor\Updater",
            program: Some(program),
            ..ObjectGuardFacts::default()
        };
        assert_eq!(
            check_object(ObjectKind::Task, &task),
            denied("sys.task.windows"),
            "{program}"
        );
    }
    for program in [APP_EXE, r"C:\WindowsApps\x.exe", r"D:\Tools\Windows\x.exe"] {
        assert_eq!(
            check_object(ObjectKind::Service, &service(Some(program), 0x10)),
            None,
            "{program}"
        );
    }
    // No resolved program: no program rule.
    assert_eq!(
        check_object(ObjectKind::Service, &service(None, 0x10)),
        None
    );
    // Task folders of Windows, Office and the Edge updater.
    for path in [
        r"\Microsoft\Windows\Defrag\ScheduledDefrag",
        r"\Microsoft\Office\OfficeTelemetryAgentLogOn",
        r"\Microsoft\EdgeUpdate\Task",
        r"\MICROSOFT\WINDOWS\x",
    ] {
        let task = ObjectGuardFacts {
            name_or_path_or_id: path,
            program: Some(APP_EXE),
            ..ObjectGuardFacts::default()
        };
        assert_eq!(
            check_object(ObjectKind::Task, &task),
            denied("sys.task.windows"),
            "{path}"
        );
    }
    let own = ObjectGuardFacts {
        name_or_path_or_id: r"\Vendor\Updater",
        program: Some(APP_EXE),
        ..ObjectGuardFacts::default()
    };
    assert_eq!(check_object(ObjectKind::Task, &own), None);
    // The DenyList form also knows a Windows directory outside the default place.
    let mut env = GuardEnv::sample();
    env.windir = r"D:\WinNT".into();
    let list = DenyList::compile(&env);
    let elsewhere = service(Some(r"D:\WinNT\System32\x.exe"), 0x10);
    assert_eq!(check_object(ObjectKind::Service, &elsewhere), None);
    assert_eq!(
        list.check_object(ObjectKind::Service, &elsewhere),
        denied("sys.service.windows")
    );
    assert_eq!(
        LIST.check_object(ObjectKind::Service, &service(Some(APP_EXE), 0x10)),
        None
    );
}

#[test]
fn check_object_firewall_package_bound_and_resource_name() {
    let rule = |package_bound, resource_name| ObjectGuardFacts {
        name_or_path_or_id: "{E943ED23-4F49-4790-988F-428CC1C396F4}",
        program: Some(APP_EXE),
        package_bound,
        resource_name,
        ..ObjectGuardFacts::default()
    };
    assert_eq!(
        check_object(ObjectKind::FirewallRule, &rule(true, false)),
        denied("fw.package-bound")
    );
    assert_eq!(
        check_object(ObjectKind::FirewallRule, &rule(false, true)),
        denied("fw.resource-name")
    );
    assert_eq!(
        check_object(ObjectKind::FirewallRule, &rule(true, true)),
        denied("fw.package-bound")
    );
    assert_eq!(
        check_object(ObjectKind::FirewallRule, &rule(false, false)),
        None
    );
}

#[test]
fn check_object_precedence_order() {
    // Every fact set at once, removed one by one in the contract's order.
    let mut facts = ObjectGuardFacts {
        name_or_path_or_id: r"\Microsoft\Windows\X",
        program: Some(r"C:\Windows\System32\x.exe"),
        service_type: Some(0x1 | 0x40),
        delete_flag: true,
        per_user_template: true,
        package_bound: true,
        resource_name: true,
        in_baseline: true,
    };
    assert_eq!(
        check_object(ObjectKind::Service, &facts),
        denied("sys.driver")
    );
    facts.service_type = Some(0x50);
    assert_eq!(
        check_object(ObjectKind::Service, &facts),
        denied("sys.service.peruser")
    );
    facts.service_type = Some(0x10);
    facts.per_user_template = false;
    assert_eq!(
        check_object(ObjectKind::Service, &facts),
        denied("sys.service.marked")
    );
    facts.delete_flag = false;
    assert_eq!(
        check_object(ObjectKind::Service, &facts),
        Some(Blocker::WindowsBaseline)
    );
    assert_eq!(
        check_object(ObjectKind::Task, &facts),
        Some(Blocker::WindowsBaseline)
    );
    assert_eq!(
        check_object(ObjectKind::FirewallRule, &facts),
        Some(Blocker::WindowsBaseline)
    );
    facts.in_baseline = false;
    assert_eq!(
        check_object(ObjectKind::Service, &facts),
        denied("sys.service.windows")
    );
    assert_eq!(
        check_object(ObjectKind::Task, &facts),
        denied("sys.task.windows")
    );
    assert_eq!(
        check_object(ObjectKind::FirewallRule, &facts),
        denied("fw.package-bound")
    );
    facts.package_bound = false;
    assert_eq!(
        check_object(ObjectKind::FirewallRule, &facts),
        denied("fw.resource-name")
    );
    facts.resource_name = false;
    facts.program = Some(APP_EXE);
    facts.name_or_path_or_id = r"\Vendor\X";
    for kind in [
        ObjectKind::Service,
        ObjectKind::Task,
        ObjectKind::FirewallRule,
    ] {
        assert_eq!(check_object(kind, &facts), None, "{kind:?}");
    }
    // Service-only facts do not block a task or a firewall rule.
    facts.service_type = Some(0x1);
    facts.delete_flag = true;
    assert_eq!(check_object(ObjectKind::Task, &facts), None);
    assert_eq!(check_object(ObjectKind::FirewallRule, &facts), None);
}

// ---------------------------------------------------------------------------------------------------
// Registry and file rules
// ---------------------------------------------------------------------------------------------------

#[test]
fn svc_registry_direct_blocks_key_not_values() {
    let services = r"HKLM\SYSTEM\CurrentControlSet\Services";
    for key in [
        format!(r"{services}\VendorSvc"),
        format!(r"{services}\VendorSvc\Parameters"),
        format!(r"{services}\VendorSvc\Security"),
        format!(r"{services}\VendorSvc\TriggerInfo"),
        format!(r"{services}\VendorSvc\Enum"),
    ] {
        assert_eq!(
            rule(&k(&key)).as_deref(),
            Some("svc.registry-direct"),
            "{key}"
        );
    }
    // Values under Services are untouched by this rule: the M1a rule still denies them.
    for (key, name) in [
        (format!(r"{services}\VendorSvc"), "ImagePath"),
        (format!(r"{services}\VendorSvc\Parameters"), "ServiceDll"),
    ] {
        assert_eq!(rule(&v(&key, name)).as_deref(), Some("reg.hklm.system"));
    }
    // Other subkeys are not the service's own structure.
    assert_eq!(
        rule(&k(format!(r"{services}\VendorSvc\Performance"))).as_deref(),
        Some("reg.hklm.system")
    );
    // Event sources stay offerable.
    assert_eq!(
        rule(&k(format!(r"{services}\EventLog\Application\VendorApp"))),
        None
    );
    assert_eq!(
        rule(&k(format!(r"{services}\EventLog\Application"))).as_deref(),
        Some("reg.eventlog-log")
    );
}

#[test]
fn svc_registry_direct_controlset001_spelling() {
    for key in [
        r"HKLM\SYSTEM\CurrentControlSet\Services\VendorSvc",
        r"HKLM\SYSTEM\ControlSet001\Services\VendorSvc",
        r"HKLM\System\controlset001\services\vendorsvc",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Services\VendorSvc\Parameters",
    ] {
        assert_eq!(
            rule(&k(key)).as_deref(),
            Some("svc.registry-direct"),
            "{key}"
        );
    }
    for key in [
        r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Vendor Log",
        r"HKLM\SYSTEM\ControlSet001\Services\EventLog\Vendor Log",
    ] {
        assert_eq!(rule(&k(key)).as_deref(), Some("reg.eventlog-log"), "{key}");
    }
}

#[test]
fn fw_registry_direct_blocks_value_and_key() {
    let store = r"Services\SharedAccess\Parameters\FirewallPolicy";
    for set in ["CurrentControlSet", "ControlSet001"] {
        let base = format!(r"HKLM\SYSTEM\{set}\{store}");
        for target in [
            k(&base),
            k(format!(r"{base}\FirewallRules")),
            v(
                format!(r"{base}\FirewallRules"),
                "{E943ED23-4F49-4790-988F-428CC1C396F4}",
            ),
            k(format!(r"{base}\StandardProfile")),
            v(format!(r"{base}\StandardProfile"), "EnableFirewall"),
        ] {
            assert_eq!(
                rule(&target).as_deref(),
                Some("fw.registry-direct"),
                "{target:?}"
            );
        }
    }
    for target in [
        k(r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall"),
        k(r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules"),
        v(
            r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules",
            "Rule1",
        ),
        k(r"HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\WindowsFirewall"),
    ] {
        assert_eq!(
            rule(&target).as_deref(),
            Some("fw.policy-store"),
            "{target:?}"
        );
    }
}

#[test]
fn task_registry_direct_blocks_taskcache_and_tasks_dir() {
    let cache = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache";
    for target in [
        k(cache),
        k(format!(r"{cache}\Tree\Vendor\Updater")),
        v(format!(r"{cache}\Tree\Vendor\Updater"), "Id"),
        k(format!(
            r"{cache}\Tasks\{{0A1B2C3D-0000-1111-2222-333344445555}}"
        )),
        p(r"C:\Windows\System32\Tasks"),
        p(r"C:\Windows\System32\Tasks\Vendor\Updater"),
        p(r"C:\WINDOWS\system32\tasks\Vendor"),
        p(r"C:\Windows\Tasks"),
        p(r"C:\Windows\Tasks\Vendor Updater.job"),
    ] {
        assert_eq!(
            rule(&target).as_deref(),
            Some("task.registry-direct"),
            "{target:?}"
        );
    }
}

#[test]
fn shared_iid_blocked_in_all_three_class_views() {
    let data = shared_iids().unwrap();
    assert!(!data.iids.is_empty());
    for entry in &data.iids {
        let iid = &entry.iid;
        for base in [
            r"HKLM\SOFTWARE\Classes".to_owned(),
            r"HKLM\SOFTWARE\Classes\WOW6432Node".to_owned(),
            r"HKLM\SOFTWARE\WOW6432Node\Classes".to_owned(),
            format!(r"HKU\{SID}\Software\Classes"),
            format!(r"HKU\{SID}_Classes"),
        ] {
            let key = format!(r"{base}\Interface\{iid}");
            for target in [
                k(&key),
                k(key.to_ascii_lowercase()),
                v(&key, ""),
                k(format!(r"{key}\ProxyStubClsid32")),
                v(format!(r"{key}\ProxyStubClsid32"), ""),
                v(format!(r"{key}\TypeLib"), "Version"),
            ] {
                assert_eq!(
                    rule(&target).as_deref(),
                    Some("com.shared-iid"),
                    "{target:?}"
                );
            }
        }
    }
    // Both IIDs registered under one name are listed; the rule does not depend on the name.
    assert!(data.is_shared_iid("{C48C7FCF-4AB5-4056-AFA6-902D6E1D1149}"));
    assert!(data.is_shared_iid("{b70d9f59-3b5a-4dba-ab9e-22012f607df5}"));
    // An unlisted interface is not affected.
    assert_eq!(
        rule(&k(
            r"HKLM\SOFTWARE\Classes\Interface\{0A1B2C3D-0000-1111-2222-333344445555}"
        )),
        None
    );
}

#[test]
fn shared_proxy_clsid_never_owner() {
    let data = shared_iids().unwrap();
    for clsid in [
        "{00020424-0000-0000-C000-000000000046}",
        "{00020420-0000-0000-C000-000000000046}",
        "{00020421-0000-0000-C000-000000000046}",
        "{00020422-0000-0000-C000-000000000046}",
        "{00020423-0000-0000-C000-000000000046}",
        "{00020425-0000-0000-C000-000000000046}",
    ] {
        assert!(data.is_shared_proxy_clsid(clsid), "{clsid}");
        assert!(
            data.is_shared_proxy_clsid(&clsid.to_ascii_lowercase()),
            "{clsid}"
        );
    }
    for entry in &data.shared_proxy_clsids {
        for base in [
            r"HKLM\SOFTWARE\Classes".to_owned(),
            r"HKLM\SOFTWARE\Classes\WOW6432Node".to_owned(),
            format!(r"HKU\{SID}_Classes"),
        ] {
            let key = format!(r"{base}\CLSID\{}", entry.clsid);
            for target in [
                k(&key),
                k(format!(r"{key}\InprocServer32")),
                v(format!(r"{key}\InprocServer32"), ""),
            ] {
                assert_eq!(
                    rule(&target).as_deref(),
                    Some("com.shared-proxy"),
                    "{target:?}"
                );
            }
        }
    }
    assert!(!data.is_shared_proxy_clsid("{0A1B2C3D-0000-1111-2222-333344445555}"));
}

#[test]
fn other_m1b_roots_are_denied_but_their_children_are_not() {
    let shared = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs";
    assert_eq!(rule(&k(shared)).as_deref(), Some("reg.shareddlls"));
    assert_eq!(
        rule(&k(
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs"
        ))
        .as_deref(),
        Some("reg.shareddlls")
    );
    assert_eq!(rule(&v(shared, r"C:\Program Files\App\x.dll")), None);
    let tracing = r"HKLM\SOFTWARE\Microsoft\Tracing";
    assert_eq!(rule(&k(tracing)).as_deref(), Some("reg.tracing-root"));
    assert_eq!(rule(&v(tracing, "x")).as_deref(), Some("reg.tracing-root"));
    assert_eq!(rule(&k(format!(r"{tracing}\app_RASAPI32"))), None);
    for root in ["ReportArchive", "ReportQueue", "Temp"] {
        let user = format!(r"C:\Users\tester\AppData\Local\Microsoft\Windows\WER\{root}");
        assert_eq!(rule(&p(&user)).as_deref(), Some("fs.wer-root"), "{user}");
        assert_eq!(rule(&p(format!(r"{user}\AppCrash_app.exe_1"))), None);
        let machine = format!(r"C:\ProgramData\Microsoft\Windows\WER\{root}");
        assert_eq!(
            rule(&p(&machine)).as_deref(),
            Some("fs.wer-root"),
            "{machine}"
        );
    }
    assert_eq!(
        rule(&p(r"C:\Users\tester\AppData\Local\Microsoft\Windows\WER")).as_deref(),
        Some("fs.wer-root")
    );
}

// ---------------------------------------------------------------------------------------------------
// Value containers
// ---------------------------------------------------------------------------------------------------

#[test]
fn value_containers_m1a_entries_unchanged_in_place() {
    let m1a = [
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\*",
        r"HKU\*\Environment",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
        r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\*\OpenWithList",
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts",
        r"*\SOFTWARE\RegisteredApplications",
        r"HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList",
        r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
    ];
    assert_eq!(&VALUE_CONTAINERS[..m1a.len()], &m1a[..]);
    let all: Vec<&str> = containers::all_value_containers().collect();
    assert_eq!(&all[..m1a.len()], &m1a[..]);
    assert_eq!(&all[m1a.len()..], M1B_VALUE_CONTAINERS);
}

#[test]
fn value_containers_include_every_path_store() {
    let env = GuardEnv::sample();
    let u = format!(r"HKU\{SID}");
    let stores = [
        // SharedDlls, both views.
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs".to_owned(),
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs".to_owned(),
        // InstallerFolders.
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders".to_owned(),
        // AppCompatLayers, machine and user.
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers".to_owned(),
        format!(r"{u}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"),
        // PcaStore, PcaPersisted.
        format!(
            r"{u}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
        ),
        format!(
            r"{u}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted"
        ),
        // MuiCache, both spellings of the user's Classes.
        format!(r"{u}\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"),
        format!(r"{u}_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"),
        // UserAssist.
        format!(
            r"{u}\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}}\Count"
        ),
        // FeatureUsage.
        format!(
            r"{u}\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated"
        ),
        format!(r"{u}\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch"),
        format!(r"{u}\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"),
        format!(
            r"{u}\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView"
        ),
        // Shell Extensions\Approved: both views, machine and user.
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved".to_owned(),
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"
            .to_owned(),
        format!(r"{u}\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved"),
        // MSI upgrade codes and component client lists.
        format!(r"{CV}\Installer\UpgradeCodes\{U}"),
        format!(r"{CV}\Installer\UserData\S-1-5-18\Components\{C}"),
        format!(r"HKLM\SOFTWARE\Classes\Installer\UpgradeCodes\{U}"),
    ];
    for store in &stores {
        assert!(containers::is_value_container(store, &env), "{store}");
        assert_eq!(
            containers::check(&k(store), &env),
            Some(Blocker::StructuralContainer),
            "{store}"
        );
        assert_eq!(containers::check(&v(store, r"C:\App\x.exe"), &env), None);
    }
    // Neighbours are not containers.
    for neighbour in [
        format!(r"{u}\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{{X}}"),
        format!(r"{u}\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage"),
        format!(r"{CV}\Installer\UpgradeCodes"),
        format!(r"{CV}\Installer\UserData\S-1-5-18\Products\{P}"),
    ] {
        assert!(
            !containers::is_value_container(&neighbour, &env),
            "{neighbour}"
        );
    }
}
