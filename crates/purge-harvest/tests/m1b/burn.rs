//! Burn bundle facts: packages through their dependents, the cache folder, children and their roots.

use purge_model::{RootSource, SourceTrust};
use purge_source::fixture::FixtureBuilder;

use super::*;

const DEPS: &str = r"HKLM\SOFTWARE\Classes\Installer\Dependencies";

/// A bundle id.
const BUNDLE: &str = "{B0000000-0000-0000-0000-000000000001}";
/// Its package.
const CORE: &str = "{C0000000-0000-0000-0000-000000000001}";

/// A Burn bundle entry with its provider key and cache path.
fn bundle(
    b: FixtureBuilder,
    id: &str,
    name: &str,
    provider: &str,
    cache_path: &str,
) -> FixtureBuilder {
    bundle_in(b, UNINSTALL, id, name, provider, cache_path)
}

/// The Uninstall key of the user `SID`.
fn user_uninstall() -> String {
    format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Uninstall")
}

/// The dependency records of the user `SID` (`HKCU\Software\Classes` is the user's Classes hive).
fn user_deps() -> String {
    format!(r"HKU\{SID}_Classes\Installer\Dependencies")
}

/// A Burn bundle entry under the Uninstall key `uninstall`.
fn bundle_in(
    b: FixtureBuilder,
    uninstall: &str,
    id: &str,
    name: &str,
    provider: &str,
    cache_path: &str,
) -> FixtureBuilder {
    let key = format!(r"{uninstall}\{id}");
    b.sz(&key, "DisplayName", name)
        .sz(&key, "BundleProviderKey", provider)
        .sz(&key, "BundleCachePath", cache_path)
        .sz(
            &key,
            "BundleUpgradeCode",
            "{B1111111-0000-0000-0000-000000000001}",
        )
        .sz(
            &key,
            "UninstallString",
            &format!(r#""{cache_path}" /uninstall"#),
        )
        .file(cache_path, 1_000)
        // The bundle's own provider key, as Burn writes it.
        .key(&format!(r"{DEPS}\{provider}\Dependents"))
}

/// Registers `dependent` as a dependent of provider key `provider`.
fn depends(b: FixtureBuilder, provider: &str, dependent: &str) -> FixtureBuilder {
    b.key(&format!(r"{DEPS}\{provider}\Dependents\{dependent}"))
}

/// A package of a bundle: an MSI product (hidden from ARP) with two key-path files in `dir`.
fn package(b: FixtureBuilder, code: &str, name: &str, dir: &str, first: u32) -> FixtureBuilder {
    let b =
        msi_app(b, code, name, None).dword(&format!(r"{UNINSTALL}\{code}"), "SystemComponent", 1);
    files(
        b,
        code,
        first,
        &[&format!(r"{dir}\main.exe"), &format!(r"{dir}\main.dll")],
    )
}

fn cache(id: &str) -> String {
    format!(r"C:\ProgramData\Package Cache\{id}\setup.exe")
}

#[test]
fn burn_children_via_dependents() {
    let b = bundle(machine(), BUNDLE, "Tool Suite", "ToolSuite", &cache(BUNDLE));
    let b = package(
        b,
        CORE,
        "Tool Suite Core",
        r"C:\Program Files\Tool Suite",
        1,
    );
    let b = depends(b, CORE, BUNDLE);
    // Windows Installer installed the package from Burn's cache.
    let b = b.sz(
        &format!(
            r"HKLM\SOFTWARE\Classes\Installer\Products\{}\SourceList",
            packed(CORE)
        ),
        "LastUsedSource",
        &format!(r"n;1;C:\ProgramData\Package Cache\{CORE}v1.0.0\"),
    );
    let report = harvest_of(&b.build(), "Tool Suite");
    let fp = &report.fingerprint;

    let burn = fp.burn.as_ref().expect("burn facts");
    assert_eq!(burn.bundle_id, BUNDLE);
    assert_eq!(burn.provider_key.as_deref(), Some("ToolSuite"));
    assert_eq!(
        burn.cache_path.as_deref(),
        Some(format!(r"C:\ProgramData\Package Cache\{BUNDLE}").as_str())
    );
    assert_eq!(burn.packages.len(), 1, "{:?}", burn.packages);
    let p = &burn.packages[0];
    assert_eq!(p.provider_key, CORE);
    assert_eq!(p.product_code.as_deref(), Some(CORE));
    assert!(p.other_dependents.is_empty());
    assert_eq!(
        p.cache_dir.as_deref(),
        Some(format!(r"C:\ProgramData\Package Cache\{CORE}v1.0.0").as_str())
    );
    assert!(burn.dependents_at_harvest.is_empty());

    // The package is the bundle's alone: its MSI facts, and its folder as the bundle's root.
    assert_eq!(fp.msi.len(), 1);
    assert_eq!(fp.msi[0].product_code, CORE);
    assert_eq!(
        roots(&report),
        [(
            r"C:\Program Files\Tool Suite".to_owned(),
            RootSource::MsiComponent
        )]
    );
    assert_eq!(fp.roots[0].trust, SourceTrust::AdminOnly);
}

#[test]
fn burn_child_with_other_dependent_not_harvested() {
    const B312: &str = "{B0000000-0000-0000-0000-000000000312}";
    const B313: &str = "{B0000000-0000-0000-0000-000000000313}";
    const CORE312: &str = "{C0000000-0000-0000-0000-000000000312}";
    const LAUNCHER: &str = "{D0000000-0000-0000-0000-000000000001}";
    let b = bundle(
        machine(),
        B312,
        "Python 3.12.10 (64-bit)",
        "CPython-3.12",
        &cache(B312),
    );
    let b = bundle(
        b,
        B313,
        "Python 3.13.3 (64-bit)",
        "CPython-3.13",
        &cache(B313),
    );
    let b = package(
        b,
        CORE312,
        "Python 3.12.10 Core Interpreter (64-bit)",
        r"C:\Program Files\Python312",
        1,
    );
    let b = package(
        b,
        LAUNCHER,
        "Python Launcher",
        r"C:\Program Files\Python Launcher",
        10,
    );
    let b = depends(b, CORE312, B312);
    // The launcher is shared by both Pythons.
    let b = depends(depends(b, LAUNCHER, B312), LAUNCHER, B313);
    let report = harvest_of(&b.build(), "Python 3.12.10 (64-bit)");
    let fp = &report.fingerprint;

    let burn = fp.burn.as_ref().unwrap();
    let launcher = burn
        .packages
        .iter()
        .find(|p| p.product_code.as_deref() == Some(LAUNCHER))
        .expect("the launcher is a package of the bundle");
    assert_eq!(launcher.other_dependents, [B313]);
    // Only the core is harvested; the launcher contributes nothing.
    assert_eq!(
        fp.msi
            .iter()
            .map(|m| m.product_code.as_str())
            .collect::<Vec<_>>(),
        [CORE312]
    );
    assert_eq!(
        roots(&report),
        [(
            r"C:\Program Files\Python312".to_owned(),
            RootSource::MsiComponent
        )]
    );
    assert!(
        !outside(&report)
            .iter()
            .any(|p| p.contains("Python Launcher")),
        "{:?}",
        outside(&report)
    );
    assert!(
        fp.warnings.iter().any(|w| w.contains("other dependents")),
        "{:?}",
        fp.warnings
    );
}

#[test]
fn burn_cache_path_must_be_direct_child_of_package_cache() {
    // Hostile: the bundle's cache path points into the Windows folder.
    let b = bundle(
        machine(),
        BUNDLE,
        "Tool Suite",
        "ToolSuite",
        r"C:\Windows\x.exe",
    );
    let report = harvest_of(&b.build(), "Tool Suite");
    let burn = report.fingerprint.burn.as_ref().unwrap();
    assert_eq!(burn.cache_path, None);
    assert!(
        report
            .fingerprint
            .warnings
            .iter()
            .any(|w| w.contains("BundleCachePath")),
        "{:?}",
        report.fingerprint.warnings
    );

    // A folder deeper than a direct child of the cache root is no bundle folder either.
    let deep = format!(r"C:\ProgramData\Package Cache\{BUNDLE}\sub\setup.exe");
    let b = bundle(machine(), BUNDLE, "Tool Suite", "ToolSuite", &deep);
    let report = harvest_of(&b.build(), "Tool Suite");
    assert_eq!(report.fingerprint.burn.as_ref().unwrap().cache_path, None);

    // The cache root itself is not a bundle folder.
    let b = bundle(
        machine(),
        BUNDLE,
        "Tool Suite",
        "ToolSuite",
        r"C:\ProgramData\Package Cache\setup.exe",
    );
    let report = harvest_of(&b.build(), "Tool Suite");
    assert_eq!(report.fingerprint.burn.as_ref().unwrap().cache_path, None);

    // R2a S7: a machine bundle's folder is in the machine's Package Cache, not a user's.
    let user_cache = format!(r"C:\Users\tester\AppData\Local\Package Cache\{BUNDLE}\setup.exe");
    let b = bundle(machine(), BUNDLE, "Tool Suite", "ToolSuite", &user_cache);
    let report = harvest_of(&b.build(), "Tool Suite");
    assert_eq!(report.fingerprint.burn.as_ref().unwrap().cache_path, None);

    // R2a S7 (hostile): another bundle's folder of the cache is not this bundle's.
    let other = cache("{B0000000-0000-0000-0000-000000000099}");
    let b = bundle(machine(), BUNDLE, "Tool Suite", "ToolSuite", &other);
    let report = harvest_of(&b.build(), "Tool Suite");
    assert_eq!(report.fingerprint.burn.as_ref().unwrap().cache_path, None);

    // A per-user bundle's folder is in its own user's Package Cache, and only there.
    let ui = user_uninstall();
    let b = bundle_in(
        machine(),
        &ui,
        BUNDLE,
        "Tool Suite",
        "ToolSuite",
        &user_cache,
    );
    let report = harvest_of(&b.build(), "Tool Suite");
    assert_eq!(
        report
            .fingerprint
            .burn
            .as_ref()
            .unwrap()
            .cache_path
            .as_deref(),
        Some(format!(r"C:\Users\tester\AppData\Local\Package Cache\{BUNDLE}").as_str())
    );
    let b = bundle_in(
        machine(),
        &ui,
        BUNDLE,
        "Tool Suite",
        "ToolSuite",
        &cache(BUNDLE),
    );
    let report = harvest_of(&b.build(), "Tool Suite");
    assert_eq!(report.fingerprint.burn.as_ref().unwrap().cache_path, None);
}

/// R2a S7 (hostile): `LastUsedSource` naming a folder that is not Burn's folder for the product gives
/// no package cache folder.
#[test]
fn burn_package_cache_dir_must_be_named_by_its_product() {
    let cases = [
        (
            format!(r"n;1;C:\ProgramData\Package Cache\{CORE}v1.0.0\"),
            true,
        ),
        (format!(r"n;1;C:\ProgramData\Package Cache\{CORE}\"), true),
        (
            r"n;1;C:\ProgramData\Package Cache\{C0000000-0000-0000-0000-000000000002}v1\"
                .to_owned(),
            false,
        ),
        (
            format!(r"n;1;C:\ProgramData\Package Cache\{BUNDLE}\"),
            false,
        ),
        (format!(r"n;1;C:\ProgramData\Package Cache\{CORE}x\"), false),
        (
            format!(r"n;1;C:\Users\tester\AppData\Local\Package Cache\{CORE}v1\"),
            false,
        ),
    ];
    for (source, want) in cases {
        let b = bundle(machine(), BUNDLE, "Tool Suite", "ToolSuite", &cache(BUNDLE));
        let b = package(
            b,
            CORE,
            "Tool Suite Core",
            r"C:\Program Files\Tool Suite",
            1,
        );
        let b = depends(b, CORE, BUNDLE).sz(
            &format!(
                r"HKLM\SOFTWARE\Classes\Installer\Products\{}\SourceList",
                packed(CORE)
            ),
            "LastUsedSource",
            &source,
        );
        let report = harvest_of(&b.build(), "Tool Suite");
        let p = &report.fingerprint.burn.as_ref().unwrap().packages[0];
        assert_eq!(p.cache_dir.is_some(), want, "{source}: {:?}", p.cache_dir);
    }
}

/// R2a S6 (hostile): a standard user writes `HKCU\Software\Classes\Installer\Dependencies\{Victim}\
/// Dependents\{machine bundle}`. The machine bundle does not see it: Victim is no package and no
/// child. A per-user bundle sees its own user's records, but they never tie a machine product to it.
#[test]
fn burn_user_dependency_record_claims_nothing_for_a_machine_bundle() {
    const VICTIM: &str = "{E0000000-0000-0000-0000-000000000001}";
    let planted =
        |b: FixtureBuilder| b.key(&format!(r"{}\{VICTIM}\Dependents\{BUNDLE}", user_deps()));
    let b = bundle(machine(), BUNDLE, "Tool Suite", "ToolSuite", &cache(BUNDLE));
    let b = package(b, VICTIM, "Victim", r"C:\Program Files\Victim", 1);
    let report = harvest_of(&planted(b).build(), "Tool Suite");
    let fp = &report.fingerprint;
    let burn = fp.burn.as_ref().unwrap();
    assert!(burn.packages.is_empty(), "{:?}", burn.packages);
    assert!(fp.msi.is_empty(), "{:?}", fp.msi);
    assert!(
        !fp.roots.iter().any(|r| r.path.contains("Victim")),
        "{:?}",
        fp.roots
    );

    // A per-user bundle: its user's record names a product installed for the machine: not the bundle's.
    let ui = user_uninstall();
    let b = bundle_in(
        machine(),
        &ui,
        BUNDLE,
        "Tool Suite",
        "ToolSuite",
        &cache(BUNDLE),
    );
    let b = package(b, VICTIM, "Victim", r"C:\Program Files\Victim", 1);
    let report = harvest_of(&planted(b).build(), "Tool Suite");
    let fp = &report.fingerprint;
    assert!(fp.burn.as_ref().unwrap().packages.is_empty());
    assert!(fp.msi.is_empty(), "{:?}", fp.msi);
    assert!(
        fp.warnings
            .iter()
            .any(|w| w.contains("installed for the machine")),
        "{:?}",
        fp.warnings
    );
}

#[test]
fn burn_provider_default_value_guid_used() {
    let b = bundle(machine(), BUNDLE, "Tool Suite", "ToolSuite", &cache(BUNDLE));
    let b = package(
        b,
        CORE,
        "Tool Suite Core",
        r"C:\Program Files\Tool Suite",
        1,
    );
    // The package's provider key is a name; its default value is the ProductCode.
    let b = depends(b, "ToolSuite-Core_x64", BUNDLE).sz(
        &format!(r"{DEPS}\ToolSuite-Core_x64"),
        "",
        &CORE.to_ascii_lowercase(),
    );
    // A provider whose default value is not a GUID gives no product.
    let b =
        depends(b, "ToolSuite-Docs", BUNDLE).sz(&format!(r"{DEPS}\ToolSuite-Docs"), "", "1.0.0");
    let report = harvest_of(&b.build(), "Tool Suite");
    let fp = &report.fingerprint;
    let burn = fp.burn.as_ref().unwrap();
    let core = burn
        .packages
        .iter()
        .find(|p| p.provider_key == "ToolSuite-Core_x64")
        .unwrap();
    assert_eq!(core.product_code.as_deref(), Some(CORE));
    let docs = burn
        .packages
        .iter()
        .find(|p| p.provider_key == "ToolSuite-Docs")
        .unwrap();
    assert_eq!(docs.product_code, None);
    assert_eq!(fp.msi.len(), 1);
    assert_eq!(fp.msi[0].product_code, CORE);
    assert_eq!(
        roots(&report),
        [(
            r"C:\Program Files\Tool Suite".to_owned(),
            RootSource::MsiComponent
        )]
    );
}
