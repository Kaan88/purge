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
    let key = format!(r"{UNINSTALL}\{id}");
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

    // A per-user bundle cache in the user's own Package Cache is.
    let user_cache = format!(r"C:\Users\tester\AppData\Local\Package Cache\{BUNDLE}\setup.exe");
    let b = bundle(machine(), BUNDLE, "Tool Suite", "ToolSuite", &user_cache);
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
