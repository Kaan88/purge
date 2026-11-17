//! Derived structural containers (ENGINE_PLAN.md §5.10): keys that a value-level scanner reads values
//! from. Such a key is shared by every app that registers there, so it is never deleted as a key, however
//! empty it looks; only single values (or segments of one) inside it are offered.
//!
//! [`VALUE_CONTAINERS`] is the table for the M1a scanners. `purge-scan` checks that the union of its
//! scanners' `value_containers()` equals this table, so a scanner that starts reading values from a new
//! key cannot ship without the key becoming structural. The strings use the key-pattern syntax of the
//! deny-list: `*\` for either hive (`HKLM` or `HKU\<SID>`), `HKU\*\` for any user hive, `*` for one
//! segment, no `WOW6432Node` (both views are covered), and `CurrentControlSet` for any control set.
//!
//! `FileExts\*\OpenWithProgids` is deliberately absent: an app's own `OpenWithProgids` key can be removed
//! once it is a proven owned skeleton (§5.7.1).
//!
//! [`M1B_VALUE_CONTAINERS`] holds the containers of the M1b scanners: every path-keyed store of
//! C-PATHSTORES, the shell-extension lists (`Shell Extensions\Approved` and `Cached`,
//! `ShellExecuteHooks`, `SharedTaskScheduler`) and the MSI `UpgradeCodes` and `Components` keys. The
//! guard treats them as structural ([`value_container`], [`check`]). `purge-scan` and
//! `xtask scanner-coverage` require the catalog's containers to equal [`all_value_containers`], the two
//! tables in order (M1B-SCAN-INTEG).

use purge_model::{Blocker, Target};

use crate::canon::{GuardEnv, canon_key};
use crate::deny::RegLogical;
use crate::deny::pattern::{Rel, parse_key_pattern, relate};

/// The value containers of the M1a scanners.
pub const VALUE_CONTAINERS: &[&str] = &[
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

/// The value containers of the M1b scanners (C-PATHSTORES and C-GUARD). Same syntax as
/// [`VALUE_CONTAINERS`]; the patterns are view-agnostic, so each covers the `WOW6432Node` view too, and a
/// user's Classes matches both `HKU\<sid>\Software\Classes` and `HKU\<sid>_Classes`.
pub const M1B_VALUE_CONTAINERS: &[&str] = &[
    // C-PATHSTORES: SharedDlls (both views).
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs",
    // InstallerFolders.
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders",
    // AppCompatLayers (HKLM and every user).
    r"*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
    // PcaStore and PcaPersisted.
    r"HKU\*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
    r"HKU\*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted",
    // MuiCache.
    r"HKU\*\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    // UserAssist.
    r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count",
    // FeatureUsage.
    r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppBadgeUpdated",
    r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch",
    r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched",
    r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView",
    // Shell extension approvals (both views, HKLM and every user).
    r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
    // The other shell-extension lists COM-SHELLEX offers single values from (R3a M10): the per-user
    // cache of approved handlers, and the Explorer hook lists (both views, HKLM and every user).
    r"HKU\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Cached",
    r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
    r"*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
    // MSI upgrade codes and component client lists.
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\*",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\*\Components\*",
    r"HKLM\SOFTWARE\Classes\Installer\UpgradeCodes\*",
];

/// Every value container the guard enforces: [`VALUE_CONTAINERS`], then [`M1B_VALUE_CONTAINERS`].
pub fn all_value_containers() -> impl Iterator<Item = &'static str> {
    VALUE_CONTAINERS.iter().chain(M1B_VALUE_CONTAINERS).copied()
}

/// The entry of [`VALUE_CONTAINERS`] or [`M1B_VALUE_CONTAINERS`] that names `key_path`, if any. The key
/// is canonicalised first; one that does not canonicalise is not a container (the deny-list refuses it
/// anyway).
pub fn value_container(key_path: &str, env: &GuardEnv) -> Option<&'static str> {
    let logical = RegLogical::new(canon_key(key_path, None, env, None).ok()?);
    all_value_containers().find(|pattern| {
        parse_key_pattern(pattern).is_ok_and(|(base, segs)| {
            logical
                .segs_for(base)
                .is_some_and(|target| relate(&segs, target) == Some(Rel::Exact))
        })
    })
}

/// Whether `key_path` is a value container.
pub fn is_value_container(key_path: &str, env: &GuardEnv) -> bool {
    value_container(key_path, env).is_some()
}

/// [`Blocker::StructuralContainer`] when the target is the deletion of a value container as a key.
/// Values and segments inside a container, and every non-key target, pass.
pub fn check(target: &Target, env: &GuardEnv) -> Option<Blocker> {
    match target {
        Target::RegKey { path } if is_value_container(path, env) => {
            Some(Blocker::StructuralContainer)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SID: &str = GuardEnv::SAMPLE_SID;

    fn key(path: &str) -> Target {
        Target::RegKey { path: path.into() }
    }

    #[test]
    fn every_pattern_parses() {
        for pattern in all_value_containers() {
            assert!(parse_key_pattern(pattern).is_ok(), "{pattern}");
        }
    }

    #[test]
    fn containers_are_blocked_as_keys() {
        let env = GuardEnv::sample();
        let cv = r"Software\Microsoft\Windows\CurrentVersion";
        let blocked = [
            format!(r"HKLM\{cv}\Run"),
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run".to_owned(),
            format!(r"HKEY_LOCAL_MACHINE\{cv}\RunOnce"),
            format!(r"HKU\{SID}\{cv}\Run"),
            format!(r"HKU\{SID}\{cv}\Explorer\StartupApproved\Run"),
            format!(r"HKLM\{cv}\Explorer\StartupApproved\Run32"),
            format!(r"HKU\{SID}\Environment"),
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment".to_owned(),
            r"HKLM\SYSTEM\ControlSet001\Control\Session Manager\Environment".to_owned(),
            format!(r"HKU\{SID}\{cv}\Explorer\FileExts\.txt\OpenWithList"),
            format!(r"HKU\{SID}\{cv}\ApplicationAssociationToasts"),
            r"HKLM\SOFTWARE\RegisteredApplications".to_owned(),
            format!(r"HKU\{SID}\Software\RegisteredApplications"),
            r"HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList".to_owned(),
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\MediaPlayer\ShimInclusionList".to_owned(),
            format!(r"HKLM\{cv}\App Paths"),
        ];
        for path in &blocked {
            assert_eq!(
                check(&key(path), &env),
                Some(Blocker::StructuralContainer),
                "{path}"
            );
        }
    }

    #[test]
    fn neighbours_and_values_pass() {
        let env = GuardEnv::sample();
        let cv = r"SOFTWARE\Microsoft\Windows\CurrentVersion";
        let allowed = [
            format!(r"HKLM\{cv}\App Paths\code.exe"),
            format!(r"HKLM\{cv}\RunNotification"),
            format!(r"HKU\{SID}\{cv}\Explorer\FileExts\.txt\OpenWithProgids"),
            format!(r"HKU\{SID}\{cv}\Explorer\FileExts\.txt"),
            format!(r"HKU\{SID}\{cv}\Explorer\StartupApproved"),
            format!(r"HKU\{SID}\{cv}\Explorer\StartupApproved\Run\Sub"),
            r"HKLM\SOFTWARE\Microsoft\MediaPlayer\ShimInclusionList\app.exe".to_owned(),
            r"HKLM\SOFTWARE\Vendor\Environment".to_owned(),
            // Machine-wide FileExts and a user-hive ShimInclusionList are not in the table.
            format!(r"HKLM\{cv}\Explorer\FileExts\.txt\OpenWithList"),
            format!(r"HKU\{SID}\Software\Microsoft\MediaPlayer\ShimInclusionList"),
        ];
        for path in &allowed {
            assert_eq!(check(&key(path), &env), None, "{path}");
        }
        let value = Target::RegValue {
            path: format!(r"HKLM\{cv}\Run"),
            name: "App".into(),
        };
        assert_eq!(check(&value, &env), None);
        let segment = Target::RegMultiSzSegment {
            path: format!(r"HKU\{SID}\Environment"),
            name: "Path".into(),
            segment: r"C:\App\bin".into(),
            index: None,
        };
        assert_eq!(check(&segment, &env), None);
        assert_eq!(
            check(
                &Target::Path {
                    path: r"C:\X".into()
                },
                &env
            ),
            None
        );
    }

    #[test]
    fn open_with_progids_is_not_a_container() {
        assert!(
            !VALUE_CONTAINERS
                .iter()
                .any(|p| p.contains("OpenWithProgids"))
        );
    }

    #[test]
    fn value_container_reports_the_table_entry() {
        let env = GuardEnv::sample();
        assert_eq!(
            value_container(r"HKCU\Environment", &env),
            None,
            "an unbound HKCU does not canonicalise"
        );
        assert_eq!(
            value_container(&format!(r"hku\{SID}\environment"), &env),
            Some(r"HKU\*\Environment")
        );
    }
}
