//! SharedDLLs, Installer\Folders and Burn dependents.

use purge_index::ownership::{
    BurnProviderRef, INSTALLER_FOLDERS, MACHINE_DEPENDENCIES, SHARED_DLL_UNKNOWN, SHARED_DLLS,
};
use purge_source::types::RegData;

use crate::*;

#[test]
fn shared_dll_count_non_dword_blocks() {
    let mut fx = base();
    fx.set_value(
        SHARED_DLLS[0],
        r"C:\Program Files\Common Files\a.dll",
        RegData::from_dword(3),
    );
    fx.set_value(
        SHARED_DLLS[1],
        r"c:\program files\common files\A.DLL",
        RegData::from_dword(2),
    );
    fx.set_value(
        SHARED_DLLS[0],
        r"C:\Program Files\Common Files\b.dll",
        RegData::from_sz("1"),
    );
    fx.set_value(
        SHARED_DLLS[0],
        r"C:\Program Files\Common Files\c.dll",
        RegData::from_qword(1),
    );
    fx.set_value(
        SHARED_DLLS[0],
        r"C:\Program Files\Common Files\d.dll",
        RegData::from_dword(0),
    );
    let ix = build(&fx, &[]);
    assert_eq!(
        ix.shared_dll_count(r"C:\Program Files\Common Files\a.dll"),
        Some(5)
    );
    assert_eq!(
        ix.shared_dll_count(r"C:\Program Files\Common Files\b.dll"),
        Some(SHARED_DLL_UNKNOWN)
    );
    assert_eq!(
        ix.shared_dll_count(r"C:\Program Files\Common Files\c.dll"),
        Some(SHARED_DLL_UNKNOWN)
    );
    assert_eq!(
        ix.shared_dll_count(r"C:\Program Files\Common Files\d.dll"),
        Some(0)
    );
    assert_eq!(
        ix.shared_dll_count(r"C:\Program Files\Common Files\e.dll"),
        None
    );
    assert!(ix.stats().complete("shared_dlls"));
}

#[test]
fn shared_dll_store_unreadable_is_incomplete() {
    let mut fx = base();
    fx.set_value(SHARED_DLLS[0], r"C:\x.dll", RegData::from_dword(1));
    fx.add_denied(SHARED_DLLS[0]);
    let ix = build(&fx, &[]);
    assert!(!ix.stats().complete("shared_dlls"));
}

#[test]
fn installer_folder_trailing_backslash() {
    let mut fx = base();
    fx.set_value(
        INSTALLER_FOLDERS,
        r"C:\Program Files\App\",
        RegData::from_sz(""),
    );
    fx.set_value(
        INSTALLER_FOLDERS,
        r"c:\program files\Other\Sub\",
        RegData::from_sz(""),
    );
    let ix = build(&fx, &[]);
    assert!(ix.installer_folder(r"C:\Program Files\App"));
    assert!(ix.installer_folder(r"C:\Program Files\other\sub"));
    assert!(!ix.installer_folder(r"C:\Program Files"));
    assert!(!ix.installer_folder(r"C:\Program Files\App\Sub"));
    assert!(!ix.installer_folder(r"C:\Program Files\Other"));
}

#[test]
fn burn_dependents_hklm_and_hku_merged() {
    let mut fx = base();
    fx.add_key(&format!(
        r"{MACHINE_DEPENDENCIES}\Vendor.Runtime,v1\Dependents\{{BUNDLE-1}}"
    ));
    fx.add_key(&format!(r"{MACHINE_DEPENDENCIES}\Lonely\Dependents"));
    fx.add_key(&format!(r"{MACHINE_DEPENDENCIES}\NoDependentsKey"));
    fx.add_key(&format!(
        r"HKU\{USER}_Classes\Installer\Dependencies\vendor.runtime,V1\Dependents\{{BUNDLE-2}}"
    ));
    fx.add_key(&format!(
        r"HKU\{USER}_Classes\Installer\Dependencies\vendor.runtime,V1\Dependents\{{bundle-1}}"
    ));
    let ix = build(&fx, &[]);
    let deps = ix.burn_dependents("VENDOR.RUNTIME,V1");
    assert_eq!(deps, &["{BUNDLE-1}".to_owned(), "{BUNDLE-2}".to_owned()]);
    assert_eq!(
        ix.burn_providers_of("{bundle-2}"),
        vec!["Vendor.Runtime,v1"]
    );
    assert!(ix.burn_dependents("Lonely").is_empty());
    assert!(ix.burn_dependents("Unknown").is_empty());
    assert!(ix.burn_providers_of("{BUNDLE-3}").is_empty());
    assert!(ix.stats().complete("burn"));
}

/// R2a S6 (hostile): a standard user writes `HKCU\Software\Classes\Installer\Dependencies\{Victim}\
/// Dependents\{machine bundle}`. A machine bundle sees the machine's records only; a per-user bundle
/// sees the machine's and its own user's, never another user's.
#[test]
fn burn_providers_in_keeps_each_record_in_its_hive() {
    let mut fx = base();
    fx.add_key(&format!(
        r"{MACHINE_DEPENDENCIES}\Vendor.Runtime,v1\Dependents\{{BUNDLE-1}}"
    ));
    fx.add_key(&format!(
        r"HKU\{USER}_Classes\Installer\Dependencies\{{VICTIM}}\Dependents\{{BUNDLE-1}}"
    ));
    fx.add_key(&format!(
        r"HKU\{USER}_Classes\Installer\Dependencies\User.Pkg\Dependents\{{USER-BUNDLE}}"
    ));
    let ix = build(&fx, &[]);
    let names = |v: Vec<BurnProviderRef<'_>>| -> Vec<(String, bool)> {
        v.into_iter()
            .map(|r| (r.provider.to_owned(), r.machine))
            .collect()
    };
    // The merged view still sees the planted record (it only ever keeps more).
    assert_eq!(ix.burn_providers_of("{bundle-1}").len(), 2);
    assert_eq!(
        names(ix.burn_providers_in("{bundle-1}", None)),
        vec![("Vendor.Runtime,v1".to_owned(), true)]
    );
    assert_eq!(
        names(ix.burn_providers_in("{bundle-1}", Some("S-1-5-21-9-9-9-1001"))),
        vec![("Vendor.Runtime,v1".to_owned(), true)]
    );
    assert_eq!(
        names(ix.burn_providers_in("{USER-BUNDLE}", Some(USER))),
        vec![("User.Pkg".to_owned(), false)]
    );
    assert!(ix.burn_providers_in("{USER-BUNDLE}", None).is_empty());
    let mut both = names(ix.burn_providers_in("{bundle-1}", Some(USER)));
    both.sort();
    assert_eq!(
        both,
        vec![
            ("Vendor.Runtime,v1".to_owned(), true),
            ("{VICTIM}".to_owned(), false)
        ]
    );
}
