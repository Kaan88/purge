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

/// The target of the link `HKU\S-1-5-18` on a real machine.
const DEFAULT_HIVE_TARGET: &str = r"\Registry\User\.Default";
const SYSTEM_DEPS: &str = r"HKU\S-1-5-18\Software\Classes\Installer\Dependencies";
const DEFAULT_DEPS: &str = r"HKU\.DEFAULT\Software\Classes\Installer\Dependencies";

/// A machine as Windows makes it: `HKU\S-1-5-18` is a registry link to the `.DEFAULT` hive, listed
/// among the loaded user hives, and every path through it is refused.
fn machine_with_system_link() -> Fixture {
    let mut fx = base();
    fx.add_key(&format!(
        r"{MACHINE_DEPENDENCIES}\Vendor.Runtime,v1\Dependents\{{BUNDLE-1}}"
    ));
    fx.add_key(r"HKU\.DEFAULT\Software\Classes\Local Settings");
    fx.set_link(r"HKU\S-1-5-18", DEFAULT_HIVE_TARGET);
    fx
}

/// `HKU\S-1-5-18` is the link to `.DEFAULT` (VM runs blx-m1b-vcredist and blx-m1b-python: the read of
/// `HKU\S-1-5-18\Software\Classes\Installer\Dependencies` was refused and the Burn area was incomplete
/// on every machine). LocalSystem's records are read in the `.DEFAULT` hive, by its own name, and are
/// records of the user `S-1-5-18`; the area is complete.
#[test]
fn local_system_dependencies_are_read_in_the_default_hive() {
    let mut fx = machine_with_system_link();
    let ix = build_refusing_links(&fx);
    assert!(ix.stats().complete("burn"), "{:?}", ix.stats().errors);
    assert!(ix.stats().errors.is_empty(), "{:?}", ix.stats().errors);
    assert_eq!(ix.burn_dependents("Vendor.Runtime,v1"), &["{BUNDLE-1}"]);

    // A record LocalSystem holds is found, in its hive.
    fx.add_key(&format!(
        r"{DEFAULT_DEPS}\Vendor.Runtime,v1\Dependents\{{SYSTEM-BUNDLE}}"
    ));
    fx.add_key(&format!(
        r"{DEFAULT_DEPS}\System.Pkg\Dependents\{{SYSTEM-BUNDLE}}"
    ));
    let ix = build_refusing_links(&fx);
    assert!(ix.stats().complete("burn"), "{:?}", ix.stats().errors);
    assert_eq!(
        ix.burn_dependents("Vendor.Runtime,v1"),
        &["{BUNDLE-1}", "{SYSTEM-BUNDLE}"]
    );
    let records: Vec<_> = ix
        .burn_providers()
        .filter(|(provider, _)| *provider == "System.Pkg")
        .flat_map(|(_, records)| records.to_vec())
        .collect();
    assert_eq!(
        records,
        vec![("{SYSTEM-BUNDLE}".to_owned(), Some("S-1-5-18".to_owned()))]
    );
    // A machine bundle still sees the machine's records only (R2a S6).
    assert!(ix.burn_providers_in("{SYSTEM-BUNDLE}", None).is_empty());
}

/// Without the link `S-1-5-18` is read as the hive it names, and `.DEFAULT` is not read in its place.
#[test]
fn a_system_hive_that_is_no_link_is_read_where_it_is() {
    let mut fx = base();
    fx.add_key(&format!(r"{SYSTEM_DEPS}\Own.Pkg\Dependents\{{B-1}}"));
    fx.add_key(&format!(r"{DEFAULT_DEPS}\Default.Pkg\Dependents\{{B-2}}"));
    let ix = build_refusing_links(&fx);
    assert!(ix.stats().complete("burn"), "{:?}", ix.stats().errors);
    assert_eq!(ix.burn_dependents("Own.Pkg"), &["{B-1}"]);
    assert!(ix.burn_dependents("Default.Pkg").is_empty());
}

/// Only the link Windows defines is named at its target. Any other link on the way to a dependency
/// root is not followed and leaves the Burn area incomplete, as before.
#[test]
fn any_other_link_leaves_the_burn_area_incomplete() {
    let user_classes = format!(r"HKU\{USER}_Classes");
    type Change = Box<dyn Fn(&mut Fixture)>;
    let cases: Vec<(&str, Change, String)> = vec![
        (
            "HKU\\S-1-5-18 links somewhere else",
            Box::new(|fx| fx.set_link(r"HKU\S-1-5-18", r"\Registry\User\S-1-5-21-9-9-9-1001")),
            SYSTEM_DEPS.to_owned(),
        ),
        (
            "HKU\\S-1-5-18 links below the default hive",
            Box::new(|fx| fx.set_link(r"HKU\S-1-5-18", r"\Registry\User\.Default\Software")),
            SYSTEM_DEPS.to_owned(),
        ),
        (
            "another service account is a link to the default hive",
            Box::new(|fx| fx.set_link(r"HKU\S-1-5-19", DEFAULT_HIVE_TARGET)),
            r"HKU\S-1-5-19\Software\Classes\Installer\Dependencies".to_owned(),
        ),
        (
            "a user's classes hive is a link to the default hive",
            Box::new(|fx| fx.set_link(&format!(r"HKU\{USER}_Classes"), DEFAULT_HIVE_TARGET)),
            format!(r"{user_classes}\Installer\Dependencies"),
        ),
        (
            "a link inside the default hive",
            Box::new(|fx| {
                fx.set_link(
                    r"HKU\.DEFAULT\Software\Classes",
                    r"\Registry\Machine\Software\Classes",
                )
            }),
            DEFAULT_DEPS.to_owned(),
        ),
        (
            "a link inside a user's classes hive",
            Box::new(|fx| {
                fx.set_link(
                    &format!(r"HKU\{USER}_Classes\Installer"),
                    r"\Registry\Machine\Software\Classes\Installer",
                )
            }),
            format!(r"{user_classes}\Installer\Dependencies"),
        ),
        (
            "a link above the machine's records",
            Box::new(|fx| {
                fx.set_link(
                    r"HKLM\SOFTWARE\Classes\Installer",
                    r"\Registry\Machine\Software\Elsewhere",
                )
            }),
            MACHINE_DEPENDENCIES.to_owned(),
        ),
    ];
    for (what, change, refused) in cases {
        let mut fx = machine_with_system_link();
        fx.add_key(&format!(r"{user_classes}\Installer\Dependencies"));
        change(&mut fx);
        let ix = build_refusing_links(&fx);
        assert!(!ix.stats().complete("burn"), "{what}");
        let want = format!("{refused}: reparse point not traversed");
        assert!(
            ix.stats().errors.contains(&want),
            "{what}: {:?}",
            ix.stats().errors
        );
    }
}
