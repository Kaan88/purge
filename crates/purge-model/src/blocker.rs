//! Blockers: reasons a candidate must not, or should not by default, be removed (ENGINE_PLAN.md §5.3).
//!
//! A hard blocker puts the candidate in the Blocked band: it is listed under "Protected" with the reason
//! and can never be selected. A soft blocker keeps it offered but unchecked (at most Likely).
//! [`Blocker::is_hard`] is the one place that split is written down.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A reason against removing a candidate. Serialised as an object tagged by `"kind"`, e.g.
/// `{"kind":"ReferencedByOtherApp","app":"Mozilla Thunderbird"}`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum Blocker {
    // Hard blockers.
    /// Hard. A rule of the hard deny-list matches (§5.10).
    DenyListed {
        /// Id of the deny rule.
        rule: String,
    },
    /// Hard. The target is a structural container that other software lives in (§5.10).
    StructuralContainer,
    /// Hard. The target is part of a clean Windows of this (edition, build). Its children may still go.
    WindowsBaseline,
    /// Hard. A row of an installed MSI product other than the target owns it.
    OwnedByInstalledMsi {
        /// ProductCode of the owning product.
        product: String,
        /// The owning row, as `<Table>:<key>`.
        row: String,
    },
    /// Hard. Another installed app references the target.
    ReferencedByOtherApp {
        /// Display name or program id of the other app.
        app: String,
    },
    /// Hard. The target lies inside another app's root or key.
    InsideOtherApp {
        /// Display name or program id of the other app.
        app: String,
    },
    /// Hard. The target contains another app's root, key or anchor.
    ContainsOtherApp {
        /// Display name or program id of the other app.
        app: String,
    },
    /// Hard. A shared reference count (MSI component clients, `SharedDLLs`) still holds the target.
    SharedRefcount,
    /// Hard. The MSI product is still registered in some context.
    MsiProductStillRegistered,
    /// Hard. Other Burn bundles still depend on the package.
    BurnDependentsRemain,
    /// Hard. The target existed before the app was installed.
    ExistedBeforeInstall,
    /// Hard. The key is owned by TrustedInstaller or carries a TrustedInstaller ACE.
    TrustedInstallerOwned,
    /// Hard. A referenced or target file exists and is Microsoft-signed, in WinSxS or in the baseline.
    MicrosoftSystemTarget,
    /// Hard. The interface id is a shared one (`kb/shared-iids.json`).
    SharedIid,
    /// Hard. The target is under a cloud sync root.
    SyncRoot,
    /// Hard. The file has a hard link outside the plan.
    HardLinkOutsidePlan,
    /// Hard. The key is a registry link.
    RegLink,
    /// Hard. The final path differs from the lexical path (a reparse point on the way).
    ReparseMismatch,
    /// Hard. The data is managed by Windows and opaque to the engine.
    WindowsManagedOpaque,
    /// Hard. The target cannot be backed up, so it is report-only.
    CannotBackUp,
    /// Hard. Verify-gone failed: the app still appears installed (for Safe-only evidence paths).
    NotGone,

    // Soft blockers.
    /// Soft. The container has children that are not attributed to the app.
    UnmatchedChildren {
        /// How many children are not attributed.
        n: u32,
    },
    /// Soft. The target is user data.
    UserData,
    /// Soft. The target is larger than 2 GB or 50 000 files.
    TooLarge,
    /// Soft. The target is older than the app's install.
    OlderThanInstall,
    /// Soft. Several apps removed in one batch own the target; decided when all are gone (§5.8.4).
    MultiTargetOwner,
    /// Soft. Removing the target cannot be undone.
    ReversibilityNone,
    /// Soft. The target is in use.
    InUse,
    /// Soft. An installed product's cached MSI package cannot be read, and its tokens or anchors match.
    MsiPackageUnreadable,
    /// Soft. The target changed between the scan and the execution; it is skipped.
    ChangedSinceScan,
}

impl Blocker {
    /// Whether the blocker is hard (the candidate is Blocked) rather than soft (offered, unchecked).
    pub fn is_hard(&self) -> bool {
        use Blocker::*;
        match self {
            DenyListed { .. }
            | StructuralContainer
            | WindowsBaseline
            | OwnedByInstalledMsi { .. }
            | ReferencedByOtherApp { .. }
            | InsideOtherApp { .. }
            | ContainsOtherApp { .. }
            | SharedRefcount
            | MsiProductStillRegistered
            | BurnDependentsRemain
            | ExistedBeforeInstall
            | TrustedInstallerOwned
            | MicrosoftSystemTarget
            | SharedIid
            | SyncRoot
            | HardLinkOutsidePlan
            | RegLink
            | ReparseMismatch
            | WindowsManagedOpaque
            | CannotBackUp
            | NotGone => true,
            UnmatchedChildren { .. }
            | UserData
            | TooLarge
            | OlderThanInstall
            | MultiTargetOwner
            | ReversibilityNone
            | InUse
            | MsiPackageUnreadable
            | ChangedSinceScan => false,
        }
    }

    /// The blocker's name as serialised in `"kind"`, for messages and grouping.
    pub fn name(&self) -> &'static str {
        use Blocker::*;
        match self {
            DenyListed { .. } => "DenyListed",
            StructuralContainer => "StructuralContainer",
            WindowsBaseline => "WindowsBaseline",
            OwnedByInstalledMsi { .. } => "OwnedByInstalledMsi",
            ReferencedByOtherApp { .. } => "ReferencedByOtherApp",
            InsideOtherApp { .. } => "InsideOtherApp",
            ContainsOtherApp { .. } => "ContainsOtherApp",
            SharedRefcount => "SharedRefcount",
            MsiProductStillRegistered => "MsiProductStillRegistered",
            BurnDependentsRemain => "BurnDependentsRemain",
            ExistedBeforeInstall => "ExistedBeforeInstall",
            TrustedInstallerOwned => "TrustedInstallerOwned",
            MicrosoftSystemTarget => "MicrosoftSystemTarget",
            SharedIid => "SharedIid",
            SyncRoot => "SyncRoot",
            HardLinkOutsidePlan => "HardLinkOutsidePlan",
            RegLink => "RegLink",
            ReparseMismatch => "ReparseMismatch",
            WindowsManagedOpaque => "WindowsManagedOpaque",
            CannotBackUp => "CannotBackUp",
            NotGone => "NotGone",
            UnmatchedChildren { .. } => "UnmatchedChildren",
            UserData => "UserData",
            TooLarge => "TooLarge",
            OlderThanInstall => "OlderThanInstall",
            MultiTargetOwner => "MultiTargetOwner",
            ReversibilityNone => "ReversibilityNone",
            InUse => "InUse",
            MsiPackageUnreadable => "MsiPackageUnreadable",
            ChangedSinceScan => "ChangedSinceScan",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn hard() -> Vec<Blocker> {
        use Blocker::*;
        let app = || "Mozilla Thunderbird".to_owned();
        vec![
            DenyListed {
                rule: "windir".into(),
            },
            StructuralContainer,
            WindowsBaseline,
            OwnedByInstalledMsi {
                product: "{90160000-008C-0000-1000-0000000FF1CE}".into(),
                row: "Registry:reg1".into(),
            },
            ReferencedByOtherApp { app: app() },
            InsideOtherApp { app: app() },
            ContainsOtherApp { app: app() },
            SharedRefcount,
            MsiProductStillRegistered,
            BurnDependentsRemain,
            ExistedBeforeInstall,
            TrustedInstallerOwned,
            MicrosoftSystemTarget,
            SharedIid,
            SyncRoot,
            HardLinkOutsidePlan,
            RegLink,
            ReparseMismatch,
            WindowsManagedOpaque,
            CannotBackUp,
            NotGone,
        ]
    }

    fn soft() -> Vec<Blocker> {
        use Blocker::*;
        vec![
            UnmatchedChildren { n: 3 },
            UserData,
            TooLarge,
            OlderThanInstall,
            MultiTargetOwner,
            ReversibilityNone,
            InUse,
            MsiPackageUnreadable,
            ChangedSinceScan,
        ]
    }

    /// The hard/soft split of §5.3: 21 hard blockers, 9 soft ones.
    #[test]
    fn hard_and_soft_split_matches_the_plan() {
        let (hard, soft) = (hard(), soft());
        assert_eq!((hard.len(), soft.len()), (21, 9));
        for b in &hard {
            assert!(b.is_hard(), "{b:?} must be hard");
        }
        for b in &soft {
            assert!(!b.is_hard(), "{b:?} must be soft");
        }
        let mut names: Vec<_> = hard.iter().chain(&soft).map(Blocker::name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 30, "a blocker is listed twice");
    }

    #[test]
    fn every_blocker_round_trips_and_is_tagged_by_its_name() {
        for b in hard().into_iter().chain(soft()) {
            let v = serde_json::to_value(&b).unwrap();
            assert_eq!(v["kind"], json!(b.name()));
            assert_eq!(serde_json::from_value::<Blocker>(v).unwrap(), b);
        }
        assert_eq!(
            serde_json::to_value(Blocker::UnmatchedChildren { n: 2 }).unwrap(),
            json!({"kind": "UnmatchedChildren", "n": 2})
        );
        assert_eq!(
            serde_json::to_value(Blocker::SyncRoot).unwrap(),
            json!({"kind": "SyncRoot"})
        );
        assert!(serde_json::from_value::<Blocker>(json!({"kind": "Nope"})).is_err());
    }

    #[test]
    fn json_schema_lists_every_blocker() {
        let text = serde_json::to_string(&schemars::schema_for!(Blocker)).unwrap();
        for b in hard().into_iter().chain(soft()) {
            assert!(text.contains(b.name()), "schema lacks {}", b.name());
        }
    }
}
