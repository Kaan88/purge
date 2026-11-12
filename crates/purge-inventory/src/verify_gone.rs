//! Verify-gone: is the app really uninstalled? (ENGINE_PLAN.md §4.4 "Verify-gone", §5.8.3).
//!
//! The check gates the Safe band. It is pure over the three source traits, so it runs the same on the live
//! machine, on a JSON fixture and on a rig snapshot (offline replay). Three parts, each `true` only when
//! positively established:
//!
//! 1. **ARP key gone**: the entry's Uninstall key is [`ExistsState::Absent`]. `Unknown` (access denied, not
//!    captured) is not gone.
//! 2. **MSI unknown in all contexts**: when the entry has a ProductCode, `MsiQueryProductStateW` answers
//!    `INSTALLSTATE_UNKNOWN` in every context the source reports. An error, or an empty context list, is not
//!    established. Without a ProductCode the part holds.
//! 3. **Main exes gone**: every main exe of the fingerprint is `Absent`. `Unknown` counts as not gone. With
//!    no main exes the part holds (there is nothing to check).
//!
//! The result is a [`VerifyGone`] built with [`VerifyGone::new`]; consumers ask
//! [`VerifyGone::is_passed`]. [`VerifyGoneCheck`] keeps the per-part facts for the report and the InfoBar.
//!
//! Also here: the **co-removed products** of an uninstall (§5.2), i.e. the other ARP entries that
//! disappeared during the run (Firefox takes the Mozilla Maintenance Service with it). [`co_removed`] is the
//! plain diff of two inventories; [`disappeared`] reads the after-state key by key, so an entry whose key
//! cannot be read is never reported as removed.

use std::collections::BTreeSet;

use purge_model::{InventoryEntry, ProgramId, VerifyGone};
use purge_source::filesystem::FileSystemSource;
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;
use purge_source::types::{ExistsState, MsiContextState, MsiProductState, SourceError};

/// What verify-gone checks for one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyTarget {
    /// Canonical path of the entry's Uninstall key.
    pub arp_key: String,
    /// The entry's MSI ProductCode (`{GUID}`), when it has one.
    pub product_code: Option<String>,
    /// Canonical absolute paths of the fingerprint's main exes.
    pub main_exes: Vec<String>,
}

impl VerifyTarget {
    /// The target for an inventory entry and the main exes of its fingerprint.
    pub fn from_entry(entry: &InventoryEntry, main_exes: &[String]) -> Self {
        Self {
            arp_key: entry.key_path.clone(),
            product_code: entry.product_code.clone(),
            main_exes: main_exes.to_vec(),
        }
    }
}

/// The MSI part of the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsiCheck {
    /// The entry has no ProductCode; the part holds.
    NoProductCode,
    /// The product's state in each context the source reported.
    States(Vec<MsiContextState>),
    /// The source could not answer; the part does not hold.
    Error(SourceError),
}

impl MsiCheck {
    /// Whether the part holds: no ProductCode, or a non-empty list of contexts that are all `Unknown`.
    pub fn unknown_in_all_contexts(&self) -> bool {
        match self {
            MsiCheck::NoProductCode => true,
            MsiCheck::States(states) => {
                !states.is_empty() && states.iter().all(|s| s.state == MsiProductState::Unknown)
            }
            MsiCheck::Error(_) => false,
        }
    }
}

/// One main exe and whether it still exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExeCheck {
    /// The exe's path.
    pub path: String,
    /// Its existence after the uninstall.
    pub state: ExistsState,
}

/// The full verify-gone result: the facts behind each part and the [`VerifyGone`] they give.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyGoneCheck {
    /// Existence of the Uninstall key.
    pub arp: ExistsState,
    /// The MSI part.
    pub msi: MsiCheck,
    /// Each main exe.
    pub exes: Vec<ExeCheck>,
    /// The result.
    pub result: VerifyGone,
}

/// Runs the three checks for `target` (see the module documentation).
pub fn check(
    reg: &dyn RegistrySource,
    fs: &dyn FileSystemSource,
    sys: &dyn SystemSource,
    target: &VerifyTarget,
) -> VerifyGoneCheck {
    let arp = reg.key_exists(&target.arp_key);
    let msi = match target
        .product_code
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        None => MsiCheck::NoProductCode,
        Some(code) => match sys.msi_product_state_all(code) {
            Ok(states) => MsiCheck::States(states),
            Err(e) => MsiCheck::Error(e),
        },
    };
    let exes: Vec<ExeCheck> = target
        .main_exes
        .iter()
        .map(|path| ExeCheck {
            path: path.clone(),
            state: fs.exists(path),
        })
        .collect();
    let result = VerifyGone::new(
        arp.is_absent(),
        msi.unknown_in_all_contexts(),
        exes.iter().all(|e| e.state.is_absent()),
    );
    VerifyGoneCheck {
        arp,
        msi,
        exes,
        result,
    }
}

/// The [`VerifyGone`] result alone.
pub fn verify_gone(
    reg: &dyn RegistrySource,
    fs: &dyn FileSystemSource,
    sys: &dyn SystemSource,
    target: &VerifyTarget,
) -> VerifyGone {
    check(reg, fs, sys, target).result
}

/// Registry key names are case-insensitive.
fn key_fold(entry: &InventoryEntry) -> String {
    entry.key_path.to_lowercase()
}

/// Co-removed products: the entries of `before` that are missing from `after`, except `target` itself, in
/// `before`'s order. Entries are compared by Uninstall key path, case-insensitively.
///
/// Only meaningful when `after` is a complete enumeration: an Uninstall root that could not be read makes
/// its entries look removed. [`disappeared`] avoids that by reading each key.
pub fn co_removed(
    before: &[InventoryEntry],
    after: &[InventoryEntry],
    target: &ProgramId,
) -> Vec<ProgramId> {
    let remaining: BTreeSet<String> = after.iter().map(key_fold).collect();
    let target_key = target.key_path().to_lowercase();
    before
        .iter()
        .filter(|e| {
            let k = key_fold(e);
            k != target_key && !remaining.contains(&k)
        })
        .map(|e| e.program_id.clone())
        .collect()
}

/// Co-removed products read from the current registry: the entries of `before` (except `target`) whose
/// Uninstall key is now [`ExistsState::Absent`]. A key that cannot be read is not reported.
pub fn disappeared(
    reg: &dyn RegistrySource,
    before: &[InventoryEntry],
    target: &ProgramId,
) -> Vec<ProgramId> {
    let target_key = target.key_path().to_lowercase();
    before
        .iter()
        .filter(|e| key_fold(e) != target_key && reg.key_exists(&e.key_path).is_absent())
        .map(|e| e.program_id.clone())
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use purge_model::{InstallScope, InstallerKind, MsiContext, RawFlags, View, WritableBy};
    use purge_source::fixture::Fixture;
    use purge_source::types::VolumeInfo;

    const UNINSTALL: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    const UNINSTALL32: &str =
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
    const CODE: &str = "{11111111-2222-3333-4444-555555555555}";

    /// A minimal inventory entry for tests.
    pub(crate) fn entry(view: View, key: &str, kind: InstallerKind) -> InventoryEntry {
        let id = ProgramId::machine(view, key).unwrap();
        InventoryEntry {
            key_path: id.key_path(),
            program_id: id,
            hive_sid: None,
            view,
            display_name: key.into(),
            version: None,
            publisher: None,
            flags: RawFlags::default(),
            installer_kind: kind,
            scope: InstallScope::Machine,
            product_code: None,
            upgrade_code: None,
            inno_app_id: None,
            writable_by: WritableBy::Admin,
            install_location: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            display_icon: None,
            install_time_evidence: Vec::new(),
            msi: None,
        }
    }

    fn target(arp: bool, code: Option<&str>, exes: &[&str]) -> (Fixture, VerifyTarget) {
        let mut f = Fixture::new();
        let key = format!(r"{UNINSTALL}\App");
        f.add_key(UNINSTALL);
        if arp {
            f.add_key(&key);
        }
        (
            f,
            VerifyTarget {
                arp_key: key,
                product_code: code.map(String::from),
                main_exes: exes.iter().map(|s| s.to_string()).collect(),
            },
        )
    }

    fn run(f: &Fixture, t: &VerifyTarget) -> VerifyGoneCheck {
        check(f, f, f, t)
    }

    #[test]
    fn arp_part() {
        let (f, t) = target(false, None, &[]);
        let c = run(&f, &t);
        assert_eq!(c.arp, ExistsState::Absent);
        assert_eq!(c.msi, MsiCheck::NoProductCode);
        assert!(c.result.is_passed());

        let (f, t) = target(true, None, &[]);
        let c = run(&f, &t);
        assert_eq!(c.arp, ExistsState::Present);
        assert!(!c.result.arp_gone && !c.result.is_passed());
        assert!(c.result.msi_unknown_all_ctx && c.result.main_exes_gone);

        // Unreadable key: not gone.
        let (mut f, t) = target(false, None, &[]);
        f.add_denied(UNINSTALL);
        let c = run(&f, &t);
        assert_eq!(c.arp, ExistsState::Unknown);
        assert!(!c.result.arp_gone && !c.result.is_passed());
    }

    #[test]
    fn msi_part() {
        use MsiProductState::*;
        let all = [
            MsiContext::Machine,
            MsiContext::UserManaged,
            MsiContext::UserUnmanaged,
        ];
        let cases: [(&[MsiProductState], bool); 5] = [
            (&[Unknown, Unknown, Unknown], true),
            (&[Default, Unknown, Unknown], false),
            (&[Unknown, Advertised, Unknown], false),
            (&[Unknown, Unknown, Absent], false),
            (&[Unknown, Other(3), Unknown], false),
        ];
        for (states, expect) in cases {
            let (mut f, t) = target(false, Some(CODE), &[]);
            for (ctx, st) in all.iter().zip(states) {
                f.set_msi_state(CODE, *ctx, *st);
            }
            let c = run(&f, &t);
            assert!(matches!(c.msi, MsiCheck::States(ref s) if s.len() == 3));
            assert_eq!(c.result.msi_unknown_all_ctx, expect, "{states:?}");
            assert_eq!(c.result.is_passed(), expect, "{states:?}");
        }

        // A product listed in the machine context is installed; the derived states say so.
        let (mut f, t) = target(false, Some(&CODE.to_lowercase()), &[]);
        f.add_msi_product(purge_source::types::MsiProduct {
            code: CODE.into(),
            context: MsiContext::Machine,
            user_sid: None,
            name: None,
            version: None,
            publisher: None,
            install_location: None,
            local_package: None,
            install_date: None,
        });
        assert!(!run(&f, &t).result.msi_unknown_all_ctx);

        // The product list was not captured: the source cannot tell.
        let (mut f, t) = target(false, Some(CODE), &[]);
        f.set_msi_products(None);
        let c = run(&f, &t);
        assert_eq!(c.msi, MsiCheck::Error(SourceError::NotCaptured));
        assert!(!c.result.msi_unknown_all_ctx && !c.result.is_passed());

        // An empty context list establishes nothing.
        assert!(!MsiCheck::States(Vec::new()).unknown_in_all_contexts());

        // No ProductCode: the part holds, even when the source knows nothing about MSI.
        let (mut f, mut t) = target(false, None, &[]);
        f.set_msi_products(None);
        assert!(run(&f, &t).result.msi_unknown_all_ctx);
        t.product_code = Some("  ".into());
        assert!(run(&f, &t).result.msi_unknown_all_ctx);
    }

    #[test]
    fn main_exes_part() {
        let present = r"C:\Program Files\App\app.exe";
        let absent = r"C:\Program Files\App\helper.exe";
        let unknown = r"D:\Apps\App\app.exe";

        let (mut f, t) = target(false, None, &[absent]);
        f.add_volume(r"C:\", fixed());
        f.add_volume(r"D:\", removable());
        f.add_dir(r"C:\Program Files");
        let c = run(&f, &t);
        assert_eq!(c.exes[0].state, ExistsState::Absent);
        assert!(c.result.main_exes_gone && c.result.is_passed());

        for (exes, expect) in [
            (vec![present], false),
            (vec![absent, present], false),
            (vec![unknown], false),
            (vec![absent, unknown], false),
            (vec![absent], true),
            (vec![], true),
        ] {
            let (mut f, t) = target(false, None, &exes);
            f.add_volume(r"C:\", fixed());
            f.add_volume(r"D:\", removable());
            f.add_file(present, 10);
            let c = run(&f, &t);
            assert_eq!(c.exes.len(), exes.len());
            assert_eq!(c.result.main_exes_gone, expect, "{exes:?}");
            assert_eq!(c.result.is_passed(), expect, "{exes:?}");
        }
        let (mut f, t) = target(false, None, &[present, absent, unknown]);
        f.add_volume(r"C:\", fixed());
        f.add_volume(r"D:\", removable());
        f.add_file(present, 10);
        let states: Vec<_> = run(&f, &t).exes.iter().map(|e| e.state).collect();
        assert_eq!(
            states,
            [
                ExistsState::Present,
                ExistsState::Absent,
                ExistsState::Unknown
            ]
        );
    }

    #[test]
    fn all_parts_must_hold() {
        let exe = r"C:\App\app.exe";
        let (mut f, t) = target(true, Some(CODE), &[exe]);
        f.set_msi_state(CODE, MsiContext::Machine, MsiProductState::Default);
        f.add_file(exe, 1);
        let c = run(&f, &t);
        assert_eq!(c.result, VerifyGone::new(false, false, false));
        let t2 = VerifyTarget::from_entry(
            &{
                let mut e = entry(View::K64, "App", InstallerKind::Msi);
                e.product_code = Some(CODE.into());
                e
            },
            &[exe.to_string()],
        );
        assert_eq!(t2, t);
        assert_eq!(verify_gone(&f, &f, &f, &t2), c.result);
    }

    fn fixed() -> VolumeInfo {
        VolumeInfo {
            serial: Some(1),
            fixed: true,
            fs: "NTFS".into(),
        }
    }

    fn removable() -> VolumeInfo {
        VolumeInfo {
            serial: Some(2),
            fixed: false,
            fs: "FAT32".into(),
        }
    }

    fn firefox_inventory() -> Vec<InventoryEntry> {
        vec![
            entry(
                View::K64,
                "Mozilla Firefox 128.0 (x64 en-US)",
                InstallerKind::Nsis,
            ),
            entry(View::K32, "MozillaMaintenanceService", InstallerKind::Nsis),
            entry(
                View::K64,
                "Mozilla Thunderbird 128.0 (x64 en-US)",
                InstallerKind::Nsis,
            ),
            entry(View::K64, "Git_is1", InstallerKind::Inno),
        ]
    }

    #[test]
    fn co_removed_diff_firefox_and_maintenance_service() {
        let before = firefox_inventory();
        let target = before[0].program_id.clone();
        let after = vec![before[2].clone(), before[3].clone()];
        let removed = co_removed(&before, &after, &target);
        assert_eq!(removed, vec![before[1].program_id.clone()]);
        assert_eq!(removed[0].key_name(), "MozillaMaintenanceService");

        // Nothing else disappeared.
        let after = vec![before[1].clone(), before[2].clone(), before[3].clone()];
        assert!(co_removed(&before, &after, &target).is_empty());

        // Key names compare case-insensitively.
        let mut renamed = before[1].clone();
        renamed.key_path = renamed.key_path.to_uppercase();
        let after = vec![renamed, before[2].clone(), before[3].clone()];
        assert!(co_removed(&before, &after, &target).is_empty());

        // The target is never its own co-product, even when it is still there.
        let after = vec![before[0].clone()];
        assert_eq!(co_removed(&before, &after, &target).len(), 3);
        assert!(!co_removed(&before, &after, &target).contains(&target));
    }

    #[test]
    fn disappeared_reads_each_key() {
        let before = firefox_inventory();
        let target = before[0].program_id.clone();
        let mut f = Fixture::new();
        f.add_key(&before[2].key_path);
        f.add_key(&before[3].key_path);
        assert_eq!(
            disappeared(&f, &before, &target),
            vec![before[1].program_id.clone()]
        );

        // An unreadable Uninstall root hides its entries from the diff instead of reporting them removed.
        f.add_denied(UNINSTALL32);
        assert!(disappeared(&f, &before, &target).is_empty());
    }
}
