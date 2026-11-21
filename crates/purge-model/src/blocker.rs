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
    /// Hard. The service is a kernel, file-system or recognizer driver (M1b).
    Driver,
    /// Hard. Other services depend on this service (M1b). They go first, in a later run.
    HasDependents {
        /// Names of the dependent services.
        names: Vec<String>,
    },
    /// Hard. The object's identity digest differs from the one the harvest recorded (M1b).
    ObjectChangedSinceHarvest,

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
    /// Soft. Undo cannot restore everything (M1b), e.g. the stored password of a service account.
    ReversibilityPartial,
    /// Soft. The object's program path could not be resolved to one file (M1b).
    ProgramUnresolved,
    /// Soft. The proof that the key is not Windows' own rests on *inferred* absence: no shipped baseline
    /// matches this Windows exactly, and the key is merely in no list the baseline view holds (trust
    /// Merged or Local, BASELINE_LOCAL_DESIGN.md §4.4). It carries the trust cap (L4): the item is
    /// offered, at most Likely, and never preselected.
    BaselineInferred,
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
            | NotGone
            | Driver
            | HasDependents { .. }
            | ObjectChangedSinceHarvest => true,
            UnmatchedChildren { .. }
            | UserData
            | TooLarge
            | OlderThanInstall
            | MultiTargetOwner
            | ReversibilityNone
            | InUse
            | MsiPackageUnreadable
            | ChangedSinceScan
            | ReversibilityPartial
            | ProgramUnresolved
            | BaselineInferred => false,
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
            Driver => "Driver",
            HasDependents { .. } => "HasDependents",
            ObjectChangedSinceHarvest => "ObjectChangedSinceHarvest",
            UnmatchedChildren { .. } => "UnmatchedChildren",
            UserData => "UserData",
            TooLarge => "TooLarge",
            OlderThanInstall => "OlderThanInstall",
            MultiTargetOwner => "MultiTargetOwner",
            ReversibilityNone => "ReversibilityNone",
            InUse => "InUse",
            MsiPackageUnreadable => "MsiPackageUnreadable",
            ChangedSinceScan => "ChangedSinceScan",
            ReversibilityPartial => "ReversibilityPartial",
            ProgramUnresolved => "ProgramUnresolved",
            BaselineInferred => "BaselineInferred",
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
            Driver,
            HasDependents {
                names: vec!["VendorHelper".into(), "VendorUi".into()],
            },
            ObjectChangedSinceHarvest,
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
            ReversibilityPartial,
            ProgramUnresolved,
            BaselineInferred,
        ]
    }

    /// The hard/soft split of §5.3 with the M1b additions and the baseline trust cap: 24 hard blockers,
    /// 12 soft ones.
    #[test]
    fn hard_and_soft_split_matches_the_plan() {
        let (hard, soft) = (hard(), soft());
        assert_eq!((hard.len(), soft.len()), (24, 12));
        for b in &hard {
            assert!(b.is_hard(), "{b:?} must be hard");
        }
        for b in &soft {
            assert!(!b.is_hard(), "{b:?} must be soft");
        }
        let mut names: Vec<_> = hard.iter().chain(&soft).map(Blocker::name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), 36, "a blocker is listed twice");
    }

    /// C-MODEL-SCOPE: the classes of the M1b blockers, and the lists above cover every variant. The
    /// match below has no wildcard arm, like the one in [`Blocker::is_hard`]: a new variant does not
    /// compile until it is listed here and classified there.
    #[test]
    fn blocker_classification_exhaustive() {
        use Blocker::*;
        for b in [
            Driver,
            HasDependents { names: vec![] },
            ObjectChangedSinceHarvest,
        ] {
            assert!(b.is_hard(), "{b:?}");
        }
        for b in [ReversibilityPartial, ProgramUnresolved, BaselineInferred] {
            assert!(!b.is_hard(), "{b:?}");
        }
        let all: Vec<Blocker> = hard().into_iter().chain(soft()).collect();
        let mut covered = Vec::new();
        for b in &all {
            // One arm per variant, in declaration order: the index is the variant's position.
            let position = match b {
                DenyListed { .. } => 0,
                StructuralContainer => 1,
                WindowsBaseline => 2,
                OwnedByInstalledMsi { .. } => 3,
                ReferencedByOtherApp { .. } => 4,
                InsideOtherApp { .. } => 5,
                ContainsOtherApp { .. } => 6,
                SharedRefcount => 7,
                MsiProductStillRegistered => 8,
                BurnDependentsRemain => 9,
                ExistedBeforeInstall => 10,
                TrustedInstallerOwned => 11,
                MicrosoftSystemTarget => 12,
                SharedIid => 13,
                SyncRoot => 14,
                HardLinkOutsidePlan => 15,
                RegLink => 16,
                ReparseMismatch => 17,
                WindowsManagedOpaque => 18,
                CannotBackUp => 19,
                NotGone => 20,
                Driver => 21,
                HasDependents { .. } => 22,
                ObjectChangedSinceHarvest => 23,
                UnmatchedChildren { .. } => 24,
                UserData => 25,
                TooLarge => 26,
                OlderThanInstall => 27,
                MultiTargetOwner => 28,
                ReversibilityNone => 29,
                InUse => 30,
                MsiPackageUnreadable => 31,
                ChangedSinceScan => 32,
                ReversibilityPartial => 33,
                ProgramUnresolved => 34,
                BaselineInferred => 35,
            };
            assert_eq!(b.is_hard(), position < 24, "{b:?}");
            covered.push(position);
        }
        covered.sort_unstable();
        assert_eq!(
            covered,
            (0..36).collect::<Vec<_>>(),
            "a variant is missing from the lists"
        );
        assert_eq!(
            serde_json::to_value(HasDependents {
                names: vec!["A".into()]
            })
            .unwrap(),
            json!({"kind": "HasDependents", "names": ["A"]})
        );
        assert!(serde_json::from_value::<Blocker>(json!({"kind": "HasDependents"})).is_err());
        assert_eq!(
            serde_json::to_value(ReversibilityPartial).unwrap(),
            json!({"kind": "ReversibilityPartial"})
        );
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

    /// BL-POLICY: the trust-cap blocker is soft, is the last variant (position 35, so no earlier
    /// position moved), has the stable wire form `{"kind":"BaselineInferred"}`, and a blocker list
    /// written before it existed reads and writes as before.
    #[test]
    fn baseline_inferred_is_soft_and_old_lists_still_read() {
        let b = Blocker::BaselineInferred;
        assert!(!b.is_hard());
        assert_eq!(b.name(), "BaselineInferred");
        assert_eq!(soft().last(), Some(&b));
        let wire = json!({"kind": "BaselineInferred"});
        assert_eq!(serde_json::to_value(&b).unwrap(), wire);
        assert_eq!(serde_json::from_value::<Blocker>(wire).unwrap(), b);
        assert!(serde_json::from_value::<Blocker>(json!({"kind": "baselineinferred"})).is_err());
        let old = json!([
            {"kind": "WindowsBaseline"},
            {"kind": "UnmatchedChildren", "n": 2},
            {"kind": "HasDependents", "names": ["A"]},
            {"kind": "ReversibilityPartial"},
            {"kind": "ProgramUnresolved"}
        ]);
        let read: Vec<Blocker> = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(read.len(), 5);
        assert!(!read.contains(&b));
        assert_eq!(serde_json::to_value(&read).unwrap(), old);
    }

    #[test]
    fn json_schema_lists_every_blocker() {
        let text = serde_json::to_string(&schemars::schema_for!(Blocker)).unwrap();
        for b in hard().into_iter().chain(soft()) {
            assert!(text.contains(b.name()), "schema lacks {}", b.name());
        }
    }
}
