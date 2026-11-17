//! MSI table rows.

use purge_index::ownership::OwnershipIndex;
use purge_index::ownership::msi_rows::{self, RowContext, RowValue};
use purge_model::MsiContext;
use purge_source::sysobj::{
    MsiClassRow, MsiComponentRow, MsiExtensionRow, MsiRegistryRaw, MsiServiceRaw, MsiTables,
};

use crate::*;

const LP1: &str = r"C:\Windows\Installer\1a.msi";
const LP2: &str = r"C:\Windows\Installer\2b.msi";

pub fn component(name: &str, attributes: i32) -> MsiComponentRow {
    MsiComponentRow {
        component: name.into(),
        component_id: Some(C1.into()),
        attributes,
        key_path: None,
    }
}

pub fn row(
    id: &str,
    root: i32,
    key: &str,
    name: Option<&str>,
    value: Option<&str>,
) -> MsiRegistryRaw {
    MsiRegistryRaw {
        row: id.into(),
        root,
        key: key.into(),
        name: name.map(Into::into),
        value: value.map(Into::into),
        component: "Main".into(),
    }
}

/// Tables with one 64-bit component `Main`, the given registry rows and the usual properties.
pub fn tables(registry: Vec<MsiRegistryRaw>) -> MsiTables {
    MsiTables {
        properties: vec![
            ("Manufacturer".into(), "Vendor".into()),
            ("ProductName".into(), "App".into()),
            ("ProductVersion".into(), "1.2.3".into()),
        ],
        components: vec![component("Main", 256)],
        registry,
        ..MsiTables::default()
    }
}

/// The index over a fixture with one machine product P1 whose package holds `t`.
fn one(t: MsiTables) -> OwnershipIndex {
    let mut fx = base();
    fx.set_msi_tables(LP1, t);
    build(&fx, &[machine(P1, LP1)])
}

fn rows_of(owners: &[purge_index::ownership::RowOwner<'_>]) -> Vec<String> {
    let mut v: Vec<String> = owners.iter().map(|o| o.row.to_owned()).collect();
    v.sort();
    v
}

#[test]
fn rows_root_minus_one_follows_context() {
    let mut fx = base();
    fx.set_msi_tables(
        LP1,
        tables(vec![row(
            "m",
            -1,
            r"Software\Vendor\Machine",
            Some("V"),
            Some("1"),
        )]),
    );
    fx.set_msi_tables(
        LP2,
        tables(vec![row(
            "u",
            -1,
            r"Software\Vendor\User",
            Some("V"),
            Some("1"),
        )]),
    );
    let products = [
        machine(P1, LP1),
        entry(P2, MsiContext::UserUnmanaged, Some(USER), Some(LP2)),
    ];
    let ix = build(&fx, &products);
    let m = ix.reg_owners(r"HKLM\SOFTWARE\Vendor\Machine", Some("V"));
    assert_eq!(rows_of(&m), vec!["m"]);
    assert_eq!(m[0].product.packed_code, packed(P1));
    assert!(
        ix.key_owners(&format!(r"HKU\{USER}\Software\Vendor\Machine"))
            .is_empty()
    );
    let u = ix.reg_owners(&format!(r"HKU\{USER}\Software\Vendor\User"), Some("V"));
    assert_eq!(rows_of(&u), vec!["u"]);
    assert_eq!(u[0].product.user_sid.as_deref(), Some(USER));
    assert!(ix.key_owners(r"HKLM\SOFTWARE\Vendor\User").is_empty());
    assert_eq!(ix.stats().packages_read, 2);
}

#[test]
fn rows_root_one_of_a_machine_product_is_any_user() {
    let ix = one(tables(vec![row(
        "cu",
        1,
        r"Software\Vendor\App",
        Some("X"),
        Some("1"),
    )]));
    let owners = ix.reg_owners(&format!(r"HKU\{USER}\Software\Vendor\App"), Some("X"));
    assert_eq!(rows_of(&owners), vec!["cu"]);
    let other = "S-1-5-21-9-9-9-1002";
    assert_eq!(
        rows_of(&ix.key_owners(&format!(r"HKU\{other}\Software\Vendor"))),
        vec!["cu"]
    );
}

#[test]
fn rows_formatted_known_properties_resolved() {
    let ix = one(tables(vec![row(
        "r",
        2,
        r"SOFTWARE\[Manufacturer]\[ProductName]\[ProductVersion]\[ProductCode]",
        Some("Path"),
        Some("x"),
    )]));
    let key = format!(r"HKLM\SOFTWARE\Vendor\App\1.2.3\{P1}");
    assert_eq!(rows_of(&ix.reg_owners(&key, Some("Path"))), vec!["r"]);
    assert_eq!(ix.stats().unresolved_rows, 0);
}

#[test]
fn rows_formatted_unknown_property_dropped_and_counted() {
    let ix = one(tables(vec![
        row(
            "bad",
            2,
            r"SOFTWARE\Vendor\[INSTALLDIR_UNKNOWN]",
            Some("V"),
            Some("x"),
        ),
        row(
            "badname",
            2,
            r"SOFTWARE\Vendor\Other",
            Some("[NOPE]"),
            Some("x"),
        ),
        row("good", 2, r"SOFTWARE\Elsewhere", Some("V"), Some("x")),
    ]));
    assert_eq!(ix.stats().unresolved_rows, 2);
    assert_eq!(ix.stats().rows, 1);
    // No broader guess: nothing below the vendor key, and no whole-key claim on it.
    assert!(ix.key_owners(r"HKLM\SOFTWARE\Vendor").is_empty());
    assert!(
        ix.reg_owners(r"HKLM\SOFTWARE\Vendor\Other", Some("V"))
            .is_empty()
    );
    assert!(
        ix.reg_owners(r"HKLM\SOFTWARE\Vendor\Other", None)
            .is_empty()
    );
}

#[test]
fn rows_formatted_file_and_component_refs_dropped() {
    let keys = [
        r"SOFTWARE\V\[#app.exe]",
        r"SOFTWARE\V\[!app.exe]",
        r"SOFTWARE\V\[$Main]",
        r"SOFTWARE\V\[%PATH]",
        r"SOFTWARE\V\[\n]",
        r"SOFTWARE\V\[[ProductName]]",
        r"SOFTWARE\V\{[ProductName]}",
        r"SOFTWARE\V\[~]",
    ];
    let rows = keys
        .iter()
        .enumerate()
        .map(|(i, k)| row(&format!("r{i}"), 2, k, Some("N"), Some("1")))
        .collect();
    let ix = one(tables(rows));
    assert_eq!(ix.stats().unresolved_rows, keys.len() as u32);
    assert_eq!(ix.stats().rows, 0);
    assert!(ix.key_owners(r"HKLM\SOFTWARE\V").is_empty());
    // The four bracket escapes are not dropped.
    let ix = one(tables(vec![row(
        "e",
        2,
        r"SOFTWARE\V\a[\[]b[\]]",
        Some("N"),
        Some("1"),
    )]));
    assert_eq!(
        rows_of(&ix.reg_owners(r"HKLM\SOFTWARE\V\a[b]", Some("N"))),
        vec!["e"]
    );
}

#[test]
fn rows_whole_key_only_for_minus_and_star_with_null_value() {
    let ix = one(tables(vec![
        row("minus", 2, r"SOFTWARE\A", Some("-"), None),
        row("star", 2, r"SOFTWARE\B", Some("*"), None),
        row("minusv", 2, r"SOFTWARE\C", Some("-"), Some("x")),
        row("starv", 2, r"SOFTWARE\D", Some("*"), Some("x")),
        row("named", 2, r"SOFTWARE\E", Some("V"), None),
    ]));
    let whole =
        |key: &str| -> Vec<bool> { ix.key_owners(key).iter().map(|o| o.whole_key).collect() };
    assert_eq!(whole(r"HKLM\SOFTWARE\A"), vec![true]);
    assert_eq!(whole(r"HKLM\SOFTWARE\B"), vec![true]);
    assert_eq!(whole(r"HKLM\SOFTWARE\C"), vec![false]);
    assert_eq!(whole(r"HKLM\SOFTWARE\D"), vec![false]);
    assert_eq!(whole(r"HKLM\SOFTWARE\E"), vec![false]);
    // A whole-key row owns everything below; a `-` with a value is a value literally named `-`.
    assert_eq!(
        rows_of(&ix.reg_owners(r"HKLM\SOFTWARE\A\Sub", Some("x"))),
        vec!["minus"]
    );
    assert_eq!(
        rows_of(&ix.key_owners(r"HKLM\SOFTWARE\B\Sub\Deeper"))[..],
        ["star"]
    );
    assert!(ix.reg_owners(r"HKLM\SOFTWARE\C\Sub", Some("x")).is_empty());
    assert_eq!(
        rows_of(&ix.reg_owners(r"HKLM\SOFTWARE\C", Some("-"))),
        vec!["minusv"]
    );
    // msi_rows: only the whole-key rows are facts with whole_key.
    let t = tables(vec![
        row("minus", 2, r"SOFTWARE\A", Some("-"), None),
        row("minusv", 2, r"SOFTWARE\C", Some("-"), Some("x")),
    ]);
    let r = msi_rows::resolve(&t, &ctx_machine());
    let facts: Vec<_> = r.rows.iter().filter_map(|r| r.to_reg_row()).collect();
    assert!(facts[0].whole_key && facts[0].name.is_none());
    assert!(!facts[1].whole_key && facts[1].name.as_deref() == Some("-"));
}

fn ctx_machine() -> RowContext<'static> {
    RowContext {
        product_code: P1,
        context: MsiContext::Machine,
        user_sid: None,
        current_control_set: 1,
    }
}

#[test]
fn rows_plus_name_is_not_whole_key() {
    let ix = one(tables(vec![
        row("plus", 2, r"SOFTWARE\Shared", Some("+"), None),
        row("nothing", 2, r"SOFTWARE\Shared2", None, None),
    ]));
    for key in [r"HKLM\SOFTWARE\Shared", r"HKLM\SOFTWARE\Shared2"] {
        // The key is listed as the row's, never as whole, and no value of it or below it is claimed.
        let owners = ix.key_owners(key);
        assert_eq!(owners.len(), 1);
        assert!(!owners[0].whole_key);
        assert!(ix.reg_owners(key, None).is_empty());
        assert!(ix.reg_owners(key, Some("Other")).is_empty());
        assert!(
            ix.reg_owners(&format!(r"{key}\Child"), Some("x"))
                .is_empty()
        );
        assert!(ix.key_owners(&format!(r"{key}\Child")).is_empty());
    }
    let r = msi_rows::resolve(
        &tables(vec![row("plus", 2, r"SOFTWARE\Shared", Some("+"), None)]),
        &ctx_machine(),
    );
    assert_eq!(r.rows[0].value, RowValue::KeyOnly);
    assert!(r.rows[0].to_reg_row().is_none());
}

#[test]
fn reg_owners_value_row_and_ancestor_whole_key() {
    let ix = one(tables(vec![
        row("val", 2, r"SOFTWARE\Vendor\App", Some("Version"), Some("1")),
        row("def", 2, r"SOFTWARE\Vendor\App", None, Some("d")),
        row("whole", 2, r"SOFTWARE\Vendor\Owned", Some("*"), None),
    ]));
    let k = r"HKLM\SOFTWARE\Vendor\App";
    assert_eq!(rows_of(&ix.reg_owners(k, Some("version"))), vec!["val"]);
    assert!(ix.reg_owners(k, Some("Other")).is_empty());
    assert_eq!(rows_of(&ix.reg_owners(k, None)), vec!["def"]);
    assert_eq!(rows_of(&ix.reg_owners(k, Some(""))), vec!["def"]);
    // A value row owns its value, not values of subkeys.
    assert!(
        ix.reg_owners(&format!(r"{k}\Sub"), Some("Version"))
            .is_empty()
    );
    assert_eq!(
        rows_of(&ix.reg_owners(r"HKLM\SOFTWARE\Vendor\Owned\A\B", Some("x"))),
        vec!["whole"]
    );
    assert_eq!(
        rows_of(&ix.reg_owners(r"HKLM\SOFTWARE\Vendor\Owned", None)),
        vec!["whole"]
    );
    // Case of the key does not matter.
    assert_eq!(
        rows_of(&ix.reg_owners(r"HKLM\SOFTWARE\VENDOR\app", Some("VERSION"))),
        vec!["val"]
    );
}

#[test]
fn key_owners_any_row_below() {
    let ix = one(tables(vec![
        row(
            "deep",
            2,
            r"SOFTWARE\Vendor\App\Sub\Deep",
            Some("V"),
            Some("1"),
        ),
        row("sib", 2, r"SOFTWARE\VendorX\App", Some("V"), Some("1")),
        row("whole", 2, r"SOFTWARE\Top", Some("-"), None),
    ]));
    assert_eq!(
        rows_of(&ix.key_owners(r"HKLM\SOFTWARE\Vendor")),
        vec!["deep"]
    );
    assert_eq!(
        rows_of(&ix.key_owners(r"HKLM\SOFTWARE\Vendor\App\Sub\Deep")),
        vec!["deep"]
    );
    assert!(
        ix.key_owners(r"HKLM\SOFTWARE\Vendor\App\Sub\Deep\Below")
            .is_empty()
    );
    assert_eq!(
        rows_of(&ix.key_owners(r"HKLM\SOFTWARE\VendorX")),
        vec!["sib"]
    );
    assert_eq!(
        rows_of(&ix.key_owners(r"HKLM\SOFTWARE\Top\X\Y")),
        vec!["whole"]
    );
    assert_eq!(
        rows_of(&ix.key_owners(r"HKLM\SOFTWARE")),
        vec!["deep", "sib", "whole"]
    );
}

#[test]
fn rows_32bit_component_maps_to_wow6432_through_guard() {
    let mut t = tables(vec![
        row("r32", 2, r"SOFTWARE\Vendor32", Some("V"), Some("1")),
        MsiRegistryRaw {
            component: "Main64".into(),
            ..row("r64", 2, r"SOFTWARE\Vendor64", Some("V"), Some("1"))
        },
        MsiRegistryRaw {
            component: "Missing".into(),
            ..row("rmiss", 2, r"SOFTWARE\VendorMissing", Some("V"), Some("1"))
        },
    ]);
    t.components = vec![component("Main", 0), component("Main64", 256)];
    let r = msi_rows::resolve(&t, &ctx_machine());
    assert_eq!(
        r.unresolved, 1,
        "a row whose component is missing is unresolved"
    );
    assert_eq!(r.rows[0].key(), r"HKLM\SOFTWARE\WOW6432Node\Vendor32");
    assert_eq!(r.rows[1].keys, vec![r"HKLM\SOFTWARE\Vendor64".to_owned()]);
    let ix = one(t);
    assert_eq!(
        rows_of(&ix.reg_owners(r"HKLM\SOFTWARE\WOW6432Node\Vendor32", Some("V"))),
        vec!["r32"]
    );
    // Looked up under the 64-bit spelling too, for keys both views share.
    assert_eq!(
        rows_of(&ix.reg_owners(r"HKLM\SOFTWARE\Vendor32", Some("V"))),
        vec!["r32"]
    );
    // A 64-bit row is never in the 32-bit view.
    assert!(
        ix.key_owners(r"HKLM\SOFTWARE\WOW6432Node\Vendor64")
            .is_empty()
    );
    assert!(ix.key_owners(r"HKLM\SOFTWARE\VendorMissing").is_empty());
    assert!(
        ix.key_owners(r"HKLM\SOFTWARE\WOW6432Node\VendorMissing")
            .is_empty()
    );
}

#[test]
fn rows_other_tables_resolve_to_classes_and_services() {
    let mut t = tables(Vec::new());
    t.classes = vec![MsiClassRow {
        clsid: "{AAAAAAAA-0000-0000-0000-000000000001}".into(),
        context: "InprocServer32".into(),
        component: "Main".into(),
        progid: None,
        appid: None,
    }];
    t.progids = vec!["Vendor.App.1".into()];
    t.extensions = vec![MsiExtensionRow {
        extension: "vnd".into(),
        component: "Main".into(),
        progid: None,
    }];
    t.typelibs = vec!["{BBBBBBBB-0000-0000-0000-000000000002}".into()];
    t.appids = vec![
        "{CCCCCCCC-0000-0000-0000-000000000003}".into(),
        "bad\\id".into(),
    ];
    t.service_install = vec![MsiServiceRaw {
        name: "[ProductName]Svc".into(),
        component: "Main".into(),
        service_type: 16,
        start_type: 2,
    }];
    let r = msi_rows::resolve(&t, &ctx_machine());
    assert_eq!(r.unresolved, 1);
    assert_eq!(r.services.len(), 1);
    assert_eq!(r.services[0].name, "AppSvc");
    let ix = one(t);
    let table =
        |key: &str| -> Vec<&'static str> { ix.key_owners(key).iter().map(|o| o.table).collect() };
    assert_eq!(
        table(r"HKLM\SOFTWARE\Classes\CLSID\{AAAAAAAA-0000-0000-0000-000000000001}\InprocServer32"),
        vec!["Class"]
    );
    assert_eq!(table(r"HKLM\SOFTWARE\Classes\Vendor.App.1"), vec!["ProgId"]);
    assert_eq!(
        table(r"HKLM\SOFTWARE\WOW6432Node\Classes\Vendor.App.1"),
        vec!["ProgId"]
    );
    assert_eq!(table(r"HKLM\SOFTWARE\Classes\.vnd"), vec!["Extension"]);
    assert_eq!(
        table(r"HKLM\SOFTWARE\Classes\TypeLib\{BBBBBBBB-0000-0000-0000-000000000002}"),
        vec!["TypeLib"]
    );
    assert_eq!(
        table(r"HKLM\SOFTWARE\Classes\AppID\{CCCCCCCC-0000-0000-0000-000000000003}"),
        vec!["AppId"]
    );
    assert_eq!(
        table(r"HKLM\SYSTEM\ControlSet001\Services\AppSvc"),
        vec!["ServiceInstall"]
    );
    // None of these claims a value.
    assert!(
        ix.reg_owners(r"HKLM\SOFTWARE\Classes\.vnd", None)
            .is_empty()
    );
}

#[test]
fn unreadable_package_listed_and_owns_unknown() {
    let mut fx = base();
    fx.set_msi_tables(
        LP1,
        tables(vec![row("ok", 2, r"SOFTWARE\Ok", Some("V"), Some("1"))]),
    );
    let products = [
        machine(P1, LP1),
        machine(P2, r"C:\Windows\Installer\missing.msi"),
        entry(P3, MsiContext::Machine, None, None),
    ];
    let ix = build(&fx, &products);
    let mut unreadable: Vec<&str> = ix
        .unreadable()
        .iter()
        .map(|p| p.product_code.as_str())
        .collect();
    unreadable.sort();
    assert_eq!(unreadable, vec![P2, P3]);
    assert_eq!(ix.stats().packages_unreadable, 2);
    assert_eq!(ix.stats().packages_read, 1);
    assert!(ix.stats().errors.len() >= 2);
    // The installed products are all known, readable or not.
    assert!(ix.installed(&packed(P2)).is_some());
    // A source that captured no tables at all: every product is unreadable.
    let mut fx = base();
    fx.set_msi_tables_captured(false);
    let ix = build(&fx, &products[..1]);
    assert_eq!(ix.unreadable().len(), 1);
}

#[test]
fn truncated_tables_are_unreadable() {
    let mut t = tables(vec![row("r", 2, r"SOFTWARE\Trunc", Some("V"), Some("1"))]);
    t.truncated = true;
    let ix = one(t);
    assert_eq!(ix.unreadable().len(), 1);
    assert_eq!(ix.unreadable()[0].product_code, P1);
    assert!(ix.key_owners(r"HKLM\SOFTWARE\Trunc").is_empty());
    assert_eq!(ix.stats().rows, 0);
}

/// R2a S8: a product Windows Installer lists without an Uninstall entry (an `msi_only` row of the
/// inventory, e.g. `ARPSYSTEMCOMPONENT`) owns its rows like any other; one whose package cannot be read
/// is listed unreadable, never silently owning nothing.
#[test]
fn msi_only_products_own_their_rows() {
    let row_of =
        |code: &str, context, user_sid: Option<&str>, lp: Option<&str>| purge_model::MsiOnlyRow {
            product_code: code.into(),
            context,
            user_sid: user_sid.map(str::to_owned),
            product_name: None,
            version: None,
            publisher: None,
            install_location: None,
            local_package: lp.map(str::to_owned),
            install_date: None,
        };
    let mut fx = base();
    fx.set_msi_tables(
        LP1,
        tables(vec![row(
            "hidden",
            2,
            r"SOFTWARE\Hidden",
            Some("V"),
            Some("1"),
        )]),
    );
    let msi_only = [
        row_of(P1, MsiContext::Machine, None, Some(LP1)),
        row_of(
            P2,
            MsiContext::Machine,
            None,
            Some(r"C:\Windows\Installer\missing.msi"),
        ),
        // Per-user, but the user is not known: its rows cannot be placed.
        row_of(P3, MsiContext::UserManaged, None, Some(LP1)),
    ];
    let ix = OwnershipIndex::build(&purge_index::ownership::OwnershipInput {
        reg: &fx,
        fs: &fx,
        sys: &fx,
        products: &[],
        msi_only: &msi_only,
        cache: None,
        threads: 2,
    });
    assert_eq!(
        rows_of(&ix.key_owners(r"HKLM\SOFTWARE\Hidden")),
        vec!["hidden"]
    );
    let mut unreadable: Vec<&str> = ix
        .unreadable()
        .iter()
        .map(|p| p.product_code.as_str())
        .collect();
    unreadable.sort();
    assert_eq!(unreadable, vec![P2, P3]);
    assert!(
        ix.stats()
            .errors
            .iter()
            .any(|e| e.contains("whose user is not known")),
        "{:?}",
        ix.stats().errors
    );
}
