//! Component clients and key paths.

use purge_index::ownership::{MACHINE_SID, PERMANENT_CLIENT};
use purge_model::{MsiContext, MsiKeyPath};
use purge_source::fixture::Fixture;
use purge_source::types::RegData;

use crate::*;

fn reg(key: &str, name: Option<&str>) -> MsiKeyPath {
    MsiKeyPath::Registry {
        key: key.to_owned(),
        name: name.map(str::to_owned),
    }
}

fn file(path: &str) -> MsiKeyPath {
    MsiKeyPath::File {
        path: path.to_owned(),
    }
}

/// The key path the index recorded for one product and component.
fn key_path_of<'a>(
    ix: &'a purge_index::ownership::OwnershipIndex,
    product: &str,
    component: &str,
) -> Vec<&'a MsiKeyPath> {
    ix.components_of(&packed(product))
        .into_iter()
        .filter(|(c, _)| *c == component)
        .map(|(_, k)| k)
        .collect()
}

#[test]
fn components_union_over_user_sids() {
    let fx = Fixture::from_json_file(&data_dir().join("union.json")).unwrap();
    let products = [
        machine(P1, r"C:\Windows\Installer\1.msi"),
        entry(P2, MsiContext::UserUnmanaged, Some(USER), None),
    ];
    let ix = build(&fx, &products);
    let clients = ix.clients_of(C1);
    assert_eq!(clients.len(), 2, "{clients:?}");
    assert!(clients.contains(&packed(P1)));
    assert!(clients.contains(&packed(P2)));
    // Either spelling of the component id finds it.
    assert_eq!(ix.clients_of(&packed(C1)), clients);
    assert_eq!(ix.clients_of(&C1.to_ascii_lowercase()), clients);
    // The file is owned by the one component, with both clients.
    let owners = ix.file_owners(r"C:\Program Files\Shared\common.dll");
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].component_id, C1);
    assert_eq!(owners[0].clients.len(), 2);
    assert_eq!(
        key_path_of(&ix, P2, C1),
        vec![&file(r"C:\Program Files\Shared\common.dll")]
    );
    assert!(ix.stats().complete("components"));
    assert_eq!(ix.stats().components, 1);
}

#[test]
fn component_keypath_file_plain() {
    let mut fx = base();
    client(
        &mut fx,
        MACHINE_SID,
        C1,
        P1,
        r"c:\Program Files\App\app.exe",
    );
    let ix = build(&fx, &[]);
    assert_eq!(
        key_path_of(&ix, P1, C1),
        vec![&file(r"C:\Program Files\App\app.exe")]
    );
    let owners = ix.file_owners(r"C:\Program Files\App\app.exe");
    assert_eq!(owners.len(), 1);
    assert!(!owners[0].shared_dll);
    assert_eq!(owners[0].clients, &[packed(P1)]);
}

#[test]
fn component_keypath_shared_dll_question_mark() {
    let mut fx = base();
    client(
        &mut fx,
        MACHINE_SID,
        C1,
        P1,
        r"C?\Program Files\Common Files\Vendor\x.dll",
    );
    let ix = build(&fx, &[]);
    let path = r"C:\Program Files\Common Files\Vendor\x.dll";
    assert_eq!(key_path_of(&ix, P1, C1), vec![&file(path)]);
    let owners = ix.file_owners(path);
    assert_eq!(owners.len(), 1);
    assert!(owners[0].shared_dll);
}

#[test]
fn component_keypath_registry_02_and_22_views() {
    let mut fx = base();
    client(
        &mut fx,
        MACHINE_SID,
        C1,
        P1,
        r"02:\SOFTWARE\Vendor\App\Version",
    );
    client(
        &mut fx,
        MACHINE_SID,
        C1,
        P2,
        r"22:\SOFTWARE\Vendor\App\Version",
    );
    client(
        &mut fx,
        MACHINE_SID,
        C2,
        P1,
        r"02:\SOFTWARE\Classes\CLSID\{AAAA}\InprocServer32\",
    );
    client(
        &mut fx,
        MACHINE_SID,
        C2,
        P2,
        r"02:\SYSTEM\CurrentControlSet\Services\VendorSvc\Start",
    );
    let ix = build(&fx, &[]);
    // 02 under SOFTWARE: the 32-bit view.
    assert_eq!(
        key_path_of(&ix, P1, C1),
        vec![&reg(
            r"HKLM\SOFTWARE\WOW6432Node\Vendor\App",
            Some("Version")
        )]
    );
    // 22: the 64-bit view.
    assert_eq!(
        key_path_of(&ix, P2, C1),
        vec![&reg(r"HKLM\SOFTWARE\Vendor\App", Some("Version"))]
    );
    // 02 under SOFTWARE\Classes\CLSID: redirected too, as the guard spells it; trailing `\` = the key.
    assert_eq!(
        key_path_of(&ix, P1, C2),
        vec![&reg(
            r"HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{AAAA}\InprocServer32",
            None
        )]
    );
    // 02 under a key both views share (SYSTEM): no WOW6432Node, and the control set is resolved.
    assert_eq!(
        key_path_of(&ix, P2, C2),
        vec![&reg(
            r"HKLM\SYSTEM\ControlSet001\Services\VendorSvc",
            Some("Start")
        )]
    );
}

#[test]
fn component_keypath_registry_01_under_system_sid_is_any_user() {
    let mut fx = base();
    client(
        &mut fx,
        MACHINE_SID,
        C1,
        P1,
        r"01:\Software\Vendor\App\Setting",
    );
    client(&mut fx, USER, C1, P2, r"01:\Software\Vendor\App\Setting");
    client(&mut fx, MACHINE_SID, C2, P1, r"00:\.vendor\");
    client(&mut fx, USER, C2, P2, r"20:\.vendor\");
    let ix = build(&fx, &[]);
    assert_eq!(
        key_path_of(&ix, P1, C1),
        vec![&reg(r"HKU\*\Software\Vendor\App", Some("Setting"))]
    );
    assert_eq!(
        key_path_of(&ix, P2, C1),
        vec![&reg(
            &format!(r"HKU\{USER}\Software\Vendor\App"),
            Some("Setting")
        )]
    );
    // HKCR: the machine's classes for S-1-5-18 (32-bit view for 00), the user's for a user SID.
    assert_eq!(
        key_path_of(&ix, P1, C2),
        vec![&reg(r"HKLM\SOFTWARE\WOW6432Node\Classes\.vendor", None)]
    );
    assert_eq!(
        key_path_of(&ix, P2, C2),
        vec![&reg(&format!(r"HKU\{USER}_Classes\.vendor"), None)]
    );
}

#[test]
fn component_permanent_client_kept() {
    let mut fx = base();
    let key = component_key(MACHINE_SID, C1);
    fx.set_value(
        &key,
        PERMANENT_CLIENT,
        RegData::from_sz(r"C:\Windows\System32\vendor.dll"),
    );
    client(
        &mut fx,
        MACHINE_SID,
        C1,
        P1,
        r"C:\Windows\System32\vendor.dll",
    );
    let ix = build(&fx, &[]);
    let clients = ix.clients_of(C1);
    assert!(
        clients.contains(&PERMANENT_CLIENT.to_owned()),
        "{clients:?}"
    );
    assert!(clients.contains(&packed(P1)));
    let owners = ix.file_owners(r"C:\Windows\System32\vendor.dll");
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].clients.len(), 2);
}

#[test]
fn component_malformed_data_ignored_not_panic() {
    let mut fx = base();
    let long = format!(r"C:\{}", "a".repeat(70_000));
    let datas = [
        "",
        "C",
        r"9Z:\x",
        &long,
        r"99:\SOFTWARE\x\y",
        r"02:\OnlyName",
        "C:relative",
    ];
    let products = [
        P1,
        P2,
        P3,
        C1,
        C2,
        "{44444444-4444-4444-4444-444444444444}",
        "{55555555-5555-5555-5555-555555555555}",
    ];
    for (data, product) in datas.iter().zip(products) {
        client(&mut fx, MACHINE_SID, C1, product, data);
    }
    // Data of another type, a value name that is not a packed code, and a component name that is not
    // a packed GUID.
    let key = component_key(MACHINE_SID, C1);
    fx.set_value(&key, &packed(P1), RegData::from_dword(7));
    fx.set_value(&key, "not-a-product", RegData::from_sz(r"C:\x.dll"));
    fx.set_value(
        &format!("{USERDATA}\\{MACHINE_SID}\\Components\\NOTAGUID"),
        &packed(P2),
        RegData::from_sz(r"C:\y.dll"),
    );
    let ix = build(&fx, &[]);
    // Every client is kept, with no key path.
    assert_eq!(ix.clients_of(C1).len(), products.len());
    for product in products {
        assert_eq!(
            key_path_of(&ix, product, C1),
            vec![&MsiKeyPath::None],
            "{product}"
        );
    }
    assert!(ix.file_owners(r"C:\x.dll").is_empty());
    assert!(ix.file_owners(r"C:\y.dll").is_empty());
    assert_eq!(ix.stats().components, 1);
}

#[test]
fn stale_client_still_listed() {
    let mut fx = base();
    client(
        &mut fx,
        MACHINE_SID,
        C1,
        P1,
        r"C:\Program Files\App\app.exe",
    );
    client(
        &mut fx,
        MACHINE_SID,
        C1,
        P2,
        r"C:\Program Files\App\app.exe",
    );
    // Only P1 is installed; P2 is a stale registration.
    let ix = build(&fx, &[machine(P1, r"C:\Windows\Installer\1.msi")]);
    assert!(ix.installed(&packed(P1)).is_some());
    assert!(ix.installed(&packed(P2)).is_none());
    let clients = ix.clients_of(C1);
    assert!(clients.contains(&packed(P2)), "{clients:?}");
    let owners = ix.file_owners(r"C:\Program Files\App\app.exe");
    assert!(owners[0].clients.contains(&packed(P2)));
    assert_eq!(ix.components_of(&packed(P2)).len(), 1);
}

#[test]
fn file_owners_case_insensitive_and_short_name_free() {
    let mut fx = base();
    client(
        &mut fx,
        MACHINE_SID,
        C1,
        P1,
        r"C:\Program Files\App\App.EXE",
    );
    // A key path written with a short name is expanded through the file system when the file exists.
    fx.add_file(r"C:\Program Files\Vendor Tools\tool.dll", 10);
    fx.set_short_name(r"C:\Program Files", "PROGRA~1");
    fx.set_short_name(r"C:\Program Files\Vendor Tools", "VENDOR~1");
    client(
        &mut fx,
        MACHINE_SID,
        C2,
        P1,
        r"C:\PROGRA~1\VENDOR~1\tool.dll",
    );
    let ix = build(&fx, &[]);
    for spelling in [
        r"C:\Program Files\App\App.EXE",
        r"C:\PROGRAM FILES\APP\APP.EXE",
        r"C:\program files\app\app.exe",
    ] {
        let owners = ix.file_owners(spelling);
        assert_eq!(owners.len(), 1, "{spelling}");
        assert_eq!(owners[0].component_id, C1);
    }
    let owners = ix.file_owners(r"C:\Program Files\Vendor Tools\tool.dll");
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].component_id, C2);
    assert_eq!(
        key_path_of(&ix, P1, C2),
        vec![&file(r"C:\Program Files\Vendor Tools\tool.dll")]
    );
}

/// The caller canonicalises; a short-name spelling is refused in debug builds.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "not a canonical path")]
fn file_owners_rejects_short_name_input_in_debug() {
    let ix = build(&base(), &[]);
    let _ = ix.file_owners(r"C:\PROGRA~1\App\app.exe");
}

/// A lower-case drive letter is not canonical either.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "not a canonical path")]
fn dir_components_rejects_non_canonical_input_in_debug() {
    let ix = build(&base(), &[]);
    let _ = ix.dir_components(r"c:\App\");
}

#[test]
fn dir_components_does_not_match_sibling_prefix() {
    let mut fx = base();
    client(&mut fx, MACHINE_SID, C1, P1, r"C:\AppData\x.dll");
    client(&mut fx, MACHINE_SID, C2, P2, r"C:\App\sub\deep\y.dll");
    client(
        &mut fx,
        MACHINE_SID,
        "{C3C3C3C3-0000-0000-0000-000000000003}",
        P3,
        r"C:\App\data\",
    );
    client(
        &mut fx,
        MACHINE_SID,
        "{C4C4C4C4-0000-0000-0000-000000000004}",
        P3,
        r"C:\App (x86)\z.dll",
    );
    let ix = build(&fx, &[]);
    let ids = |dir: &str| -> Vec<String> {
        let mut v: Vec<String> = ix
            .dir_components(dir)
            .iter()
            .map(|o| o.component_id.to_owned())
            .collect();
        v.sort();
        v
    };
    assert_eq!(
        ids(r"C:\App"),
        vec![
            C2.to_owned(),
            "{C3C3C3C3-0000-0000-0000-000000000003}".to_owned()
        ]
    );
    assert_eq!(ids(r"C:\App\sub"), vec![C2.to_owned()]);
    assert_eq!(
        ids(r"C:\App\data"),
        vec!["{C3C3C3C3-0000-0000-0000-000000000003}".to_owned()]
    );
    assert_eq!(ids(r"C:\AppData"), vec![C1.to_owned()]);
    assert!(ids(r"C:\Ap").is_empty());
    // A directory key path is not a file.
    assert!(ix.file_owners(r"C:\App\data").is_empty());
    assert_eq!(ids(r"C:\"), {
        let mut all = vec![
            C1.to_owned(),
            C2.to_owned(),
            "{C3C3C3C3-0000-0000-0000-000000000003}".to_owned(),
            "{C4C4C4C4-0000-0000-0000-000000000004}".to_owned(),
        ];
        all.sort();
        all
    });
}

#[test]
fn unreadable_components_area_is_reported_not_empty() {
    let mut fx = base();
    client(&mut fx, MACHINE_SID, C1, P1, r"C:\App\a.dll");
    fx.add_denied(&format!("{USERDATA}\\{USER}"));
    fx.add_key(&format!("{USERDATA}\\{USER}\\Components"));
    let ix = build(&fx, &[]);
    assert!(!ix.stats().complete("components"));
    assert!(!ix.stats().errors.is_empty());
    // What could be read is still there.
    assert_eq!(ix.clients_of(C1), &[packed(P1)]);
}
