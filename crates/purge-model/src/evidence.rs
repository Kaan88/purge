//! Evidence: the facts that tie a candidate to the app being removed (ENGINE_PLAN.md §5.2, §5.3).
//!
//! [`EvidenceKind`] lists the §5.3 rows the M1a scanners can produce. The tier, weight and scope of each
//! row are data of this crate ([`EvidenceKind::default_tier`], [`EvidenceKind::default_weight`],
//! [`EvidenceKind::scope`]) so that no scanner invents its own numbers; `purge-policy` turns evidence into
//! a score and a band. Rows of later milestones (`Traced`, `RememberedManifest`, `KnowledgeRule`,
//! `ContentMentionsAppPath`, `Ai`) are added when their producers land.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{Scope, ScopeSet, SourceId, SourceTrust, Target};

/// How strong a kind of evidence is (§5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Tier {
    /// A checked fact from the system or the installer's own record.
    A,
    /// A strong hint that is not proof (a referenced data dir, an exact full name).
    B,
    /// A weak hint (a name token, a vendor folder, a time window).
    C,
    /// A note from an AI agent. Never counted toward the band (§5.8).
    Ai,
}

impl Tier {
    /// Strength rank: higher is stronger. `Ai` is the weakest, as it never counts toward the band.
    fn rank(self) -> u8 {
        match self {
            Tier::A => 3,
            Tier::B => 2,
            Tier::C => 1,
            Tier::Ai => 0,
        }
    }

    /// The weaker of `self` and `cap`: lowers a tier to `cap`, never raises it. For the `ChainedRef`
    /// anchor rule and Rule T downgrades (§5.3).
    #[must_use]
    pub fn at_most(self, cap: Tier) -> Tier {
        if cap.rank() < self.rank() { cap } else { self }
    }
}

/// Which installer record an [`EvidenceKind::InstallerManifest`] was read from. Serialised by its
/// variant name (`"Inno"`, `"Msi"`, `"Burn"`), the rule the enum has always followed, so M1a plans read
/// unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum ManifestKind {
    /// The Inno Setup uninstall log (`unins*.dat`), read before the uninstall.
    Inno,
    /// The product's cached MSI package and its Windows Installer registration, read at harvest (M1b).
    Msi,
    /// A Burn bundle's registration and package cache, read at harvest (M1b).
    Burn,
}

/// A kind of evidence: one row of the §5.3 table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum EvidenceKind {
    /// The path lies under a validated InstallRoot.
    InsideInstallRoot,
    /// The installer's own record names the target; read before the uninstall. A value record gives
    /// Value scope only, a key-create record gives Key scope.
    InstallerManifest(ManifestKind),
    /// The harvest recorded this value referencing a root, exe, ProgID, CLSID, AUMID or token.
    InPreUninstallRefSnapshot,
    /// At harvest every value and subkey of the key's subtree was attributed to the app with Tier A (or
    /// the key is an installer key-create record); the key is now value-free, absent from the
    /// (edition, build) baseline and not TrustedInstaller-owned.
    ProvenOwnedSkeleton,
    /// The value points to a path that no longer exists on the recorded volume, below a root's recorded
    /// parent.
    DanglingRef,
    /// The value's data or name resolves into an InstallRoot or the exe set.
    PointsIntoInstallRoot,
    /// A whole path, key or value segment equals a GUID or long hex token harvested from the app's own
    /// anchors, and no other app or the baseline has it.
    HarvestedToken,
    /// A `Software\<Vendor>\<Product>` key matching the app's tokens with at least one value into an
    /// InstallRoot and nothing referencing another app.
    AppNamedKeyWithRootRef,
    /// A CLSID/AppID/TypeLib key whose harvested server path lies in an InstallRoot, with no other
    /// referrer.
    ComKeyOwnership,
    /// A service, scheduled task or firewall rule the harvest recorded as the app's (its program lies in
    /// an InstallRoot or is one of the app's exes, or an MSI `ServiceInstall` row of the product names
    /// it), still with the identity digest the harvest recorded (M1b).
    OwnedSystemObject,
    /// The app's own ARP key or uninstaller file.
    UninstallerArtifact,
    /// A package whose external location equals or lies under an InstallRoot, or whose family was
    /// harvested.
    AppxExternalLocation,
    /// A reference to something the app owns (an `.ext` default or OpenWithProgids value naming an owned
    /// ProgID). Its tier is the anchor's tier, at most [`Tier::A`].
    ChainedRef,
    /// A data directory referenced by the app's configuration. Always user data.
    ReferencedByApp,
    /// `<VendorAlias>\<ProductToken>`.
    ProductSubfolderOfVendor,
    /// The item's name is the app's full name, directly under an AppData, ProgramData or Software root.
    ExactFullName,
    /// The item's name holds every significant token of the app's name (§5.4).
    NameTokenExact,
    /// The item is named after a vendor alias. Only ever removed when empty.
    VendorContainer,
    /// Created or last written within `[install − 1 d, t_end]`.
    TimeWindow,
    /// A container that holds nothing once the rest of the plan has run (§7.1). Added by `purge-plan`.
    EmptyAfterPlan,
    /// Negative: the directory holds executables.
    ExecutablesPresent,
    /// Negative: the directory holds many files.
    ManyFiles,
    /// Negative: the matching name is a generic word.
    GenericName,
    /// Negative: the name matched only fuzzily.
    NameFuzzy,
    /// Negative: the item was modified after the uninstall ended.
    ModifiedAfterUninstall,
}

impl EvidenceKind {
    /// Every kind, in §5.3 order (positives, then `EmptyAfterPlan`, then the negatives). One entry per row:
    /// [`EvidenceKind::InstallerManifest`] appears once, as its Inno form; its Msi and Burn forms have the
    /// same tier, weight and scope.
    pub const ALL: [EvidenceKind; 25] = [
        EvidenceKind::InsideInstallRoot,
        EvidenceKind::InstallerManifest(ManifestKind::Inno),
        EvidenceKind::InPreUninstallRefSnapshot,
        EvidenceKind::ProvenOwnedSkeleton,
        EvidenceKind::DanglingRef,
        EvidenceKind::PointsIntoInstallRoot,
        EvidenceKind::HarvestedToken,
        EvidenceKind::AppNamedKeyWithRootRef,
        EvidenceKind::ComKeyOwnership,
        EvidenceKind::OwnedSystemObject,
        EvidenceKind::UninstallerArtifact,
        EvidenceKind::AppxExternalLocation,
        EvidenceKind::ChainedRef,
        EvidenceKind::ReferencedByApp,
        EvidenceKind::ProductSubfolderOfVendor,
        EvidenceKind::ExactFullName,
        EvidenceKind::NameTokenExact,
        EvidenceKind::VendorContainer,
        EvidenceKind::TimeWindow,
        EvidenceKind::EmptyAfterPlan,
        EvidenceKind::ExecutablesPresent,
        EvidenceKind::ManyFiles,
        EvidenceKind::GenericName,
        EvidenceKind::NameFuzzy,
        EvidenceKind::ModifiedAfterUninstall,
    ];

    /// Weight of a [`EvidenceKind::VendorContainer`] match when the vendor is a mega-vendor (§5.4).
    pub const MEGA_VENDOR_WEIGHT: i8 = 0;

    /// The tier of the §5.3 row.
    ///
    /// Two rows depend on context, and the caller lowers the tier where needed: [`EvidenceKind::ChainedRef`]
    /// takes the tier of its anchor (the value here, `A`, is the upper bound), and Rule T downgrades any
    /// Tier A evidence from a user-writable source to `B` for machine-scope targets (applied by
    /// `purge-policy`). The negatives have no tier in §5.3; they are reported as `C` because they never
    /// establish ownership.
    pub fn default_tier(self) -> Tier {
        use EvidenceKind::*;
        match self {
            InsideInstallRoot
            | InstallerManifest(_)
            | InPreUninstallRefSnapshot
            | ProvenOwnedSkeleton
            | DanglingRef
            | PointsIntoInstallRoot
            | HarvestedToken
            | AppNamedKeyWithRootRef
            | ComKeyOwnership
            | OwnedSystemObject
            | UninstallerArtifact
            | AppxExternalLocation
            | ChainedRef
            | EmptyAfterPlan => Tier::A,
            ReferencedByApp | ProductSubfolderOfVendor | ExactFullName => Tier::B,
            NameTokenExact | VendorContainer | TimeWindow => Tier::C,
            ExecutablesPresent | ManyFiles | GenericName | NameFuzzy | ModifiedAfterUninstall => {
                Tier::C
            }
        }
    }

    /// The weight (W) of the §5.3 row; negative for the negatives.
    ///
    /// [`EvidenceKind::VendorContainer`] weighs [`EvidenceKind::MEGA_VENDOR_WEIGHT`] instead when the
    /// vendor is a mega-vendor.
    pub fn default_weight(self) -> i8 {
        use EvidenceKind::*;
        match self {
            InsideInstallRoot => 9,
            InstallerManifest(_) => 8,
            InPreUninstallRefSnapshot => 8,
            ProvenOwnedSkeleton => 8,
            DanglingRef => 7,
            PointsIntoInstallRoot => 6,
            HarvestedToken => 7,
            AppNamedKeyWithRootRef => 7,
            ComKeyOwnership => 7,
            OwnedSystemObject => 8,
            UninstallerArtifact => 6,
            AppxExternalLocation => 8,
            ChainedRef => 5,
            ReferencedByApp => 4,
            ProductSubfolderOfVendor => 3,
            ExactFullName => 4,
            NameTokenExact => 3,
            VendorContainer => 2,
            TimeWindow => 1,
            EmptyAfterPlan => 8,
            ExecutablesPresent => -4,
            ManyFiles => -2,
            GenericName => -3,
            NameFuzzy => -2,
            ModifiedAfterUninstall => -4,
        }
    }

    /// The scopes the §5.3 row may be recorded with. "As recorded" and "any" are [`ScopeSet::ANY`]: the
    /// producer states the scope of the record it actually read.
    pub fn scope(self) -> ScopeSet {
        use EvidenceKind::*;
        match self {
            InsideInstallRoot => ScopeSet::PATH,
            InstallerManifest(_) => ScopeSet::ANY,
            InPreUninstallRefSnapshot => ScopeSet::VALUE,
            ProvenOwnedSkeleton => ScopeSet::KEY,
            DanglingRef => ScopeSet::VALUE,
            PointsIntoInstallRoot => ScopeSet::VALUE,
            HarvestedToken => ScopeSet::PATH_KEY_VALUE,
            AppNamedKeyWithRootRef => ScopeSet::KEY,
            ComKeyOwnership => ScopeSet::KEY,
            OwnedSystemObject => ScopeSet::OBJECT,
            UninstallerArtifact => ScopeSet::PATH_KEY,
            AppxExternalLocation => ScopeSet::PACKAGE,
            ChainedRef => ScopeSet::VALUE_KEY,
            ReferencedByApp => ScopeSet::PATH,
            ProductSubfolderOfVendor => ScopeSet::PATH_KEY,
            ExactFullName => ScopeSet::PATH_KEY,
            NameTokenExact => ScopeSet::PATH_KEY,
            VendorContainer => ScopeSet::PATH_KEY,
            TimeWindow => ScopeSet::ANY,
            EmptyAfterPlan => ScopeSet::PATH_KEY,
            ExecutablesPresent | ManyFiles | GenericName | NameFuzzy | ModifiedAfterUninstall => {
                ScopeSet::ANY
            }
        }
    }

    /// Whether this is one of the negative rows, which only lower the score.
    pub fn is_negative(self) -> bool {
        self.default_weight() < 0
    }
}

/// Free-form details of one piece of evidence, for the explanation templates (§5.8.6) and for debugging:
/// e.g. `root` → `C:\Program Files\Git`, `anchor` → `VSCode.txt`. Keys are sorted, so output is stable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Facts(pub BTreeMap<String, String>);

impl Facts {
    /// No details.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one detail and returns the set, for chained construction.
    #[must_use]
    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.0.insert(key.into(), value.into());
        self
    }

    /// The detail stored under `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
}

/// One piece of evidence attached to a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Evidence {
    /// Which §5.3 row this is.
    pub kind: EvidenceKind,
    /// Its tier, after any lowering by the producer (see [`EvidenceKind::default_tier`]).
    pub tier: Tier,
    /// Its weight.
    pub weight: i8,
    /// The kind of target it speaks about.
    pub scope: Scope,
    /// Who could have written the record it was read from.
    pub trust: SourceTrust,
    /// The record it was read from.
    pub source: SourceId,
    /// Details for the explanation.
    #[serde(default)]
    pub detail: Facts,
}

impl Evidence {
    /// Evidence of `kind` with the tier and weight of the §5.3 table and no details.
    ///
    /// Returns `None` when `scope` is not one the table allows for `kind` (e.g. a Key-scope
    /// `PointsIntoInstallRoot`), so that evidence about a value can never be recorded as proof for a key.
    pub fn new(
        kind: EvidenceKind,
        scope: Scope,
        trust: SourceTrust,
        source: impl Into<SourceId>,
    ) -> Option<Self> {
        kind.scope().contains(scope).then(|| Self {
            kind,
            tier: kind.default_tier(),
            weight: kind.default_weight(),
            scope,
            trust,
            source: source.into(),
            detail: Facts::new(),
        })
    }

    /// [`EvidenceKind::ChainedRef`] evidence, whose tier is the tier of the anchor it chains to (§5.3) and
    /// never higher. Producers of `ChainedRef` use this instead of [`Evidence::new`], which records the
    /// table's upper bound (Tier A) and would overstate a reference to a Tier B or C anchor.
    ///
    /// Returns `None` for a scope other than Value or Key.
    pub fn chained(
        anchor_tier: Tier,
        scope: Scope,
        trust: SourceTrust,
        source: impl Into<SourceId>,
    ) -> Option<Self> {
        let mut evidence = Self::new(EvidenceKind::ChainedRef, scope, trust, source)?;
        evidence.tier = evidence.tier.at_most(anchor_tier);
        Some(evidence)
    }

    /// The same evidence with `detail` attached.
    #[must_use]
    pub fn with_detail(mut self, detail: Facts) -> Self {
        self.detail = detail;
        self
    }

    /// Whether this evidence, about `target`, is of an **absence-dependent** kind
    /// (BASELINE_LOCAL_DESIGN.md §4.4): one conjunct of its proof is "the clean-Windows baseline does not
    /// have this key". That holds only for a registry key target, and there for `ProvenOwnedSkeleton`,
    /// `ComKeyOwnership` and `HarvestedToken` with any scope, and for `InstallerManifest` (Inno, Msi,
    /// Burn) and `ChainedRef` recorded with Key scope. The tier and the weight are not looked at.
    ///
    /// This is the one definition the trust cap uses: the policy (P-BL-1) and the scan seal
    /// ([`Candidate::lacks_baseline_cap`](crate::Candidate::lacks_baseline_cap)) both ask it.
    #[must_use]
    pub fn is_absence_dependent(&self, target: &Target) -> bool {
        use EvidenceKind::*;
        if !matches!(target, Target::RegKey { .. }) {
            return false;
        }
        // No wildcard arm: a new kind does not compile until it is classified here.
        match self.kind {
            ProvenOwnedSkeleton | ComKeyOwnership | HarvestedToken => true,
            InstallerManifest(_) | ChainedRef => self.scope == Scope::Key,
            InsideInstallRoot
            | InPreUninstallRefSnapshot
            | DanglingRef
            | PointsIntoInstallRoot
            | AppNamedKeyWithRootRef
            | OwnedSystemObject
            | UninstallerArtifact
            | AppxExternalLocation
            | ReferencedByApp
            | ProductSubfolderOfVendor
            | ExactFullName
            | NameTokenExact
            | VendorContainer
            | TimeWindow
            | EmptyAfterPlan
            | ExecutablesPresent
            | ManyFiles
            | GenericName
            | NameFuzzy
            | ModifiedAfterUninstall => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use EvidenceKind::*;
    use Scope::{Key, Object, Package, Path, Value};

    /// The §5.3 table, line by line: kind, tier, weight, allowed scopes.
    const GOLDEN: [(EvidenceKind, Tier, i8, &[Scope]); 25] = [
        (InsideInstallRoot, Tier::A, 9, &[Path]),
        (
            InstallerManifest(ManifestKind::Inno),
            Tier::A,
            8,
            &[Value, Key, Path, Package, Object],
        ),
        (InPreUninstallRefSnapshot, Tier::A, 8, &[Value]),
        (ProvenOwnedSkeleton, Tier::A, 8, &[Key]),
        (DanglingRef, Tier::A, 7, &[Value]),
        (PointsIntoInstallRoot, Tier::A, 6, &[Value]),
        (HarvestedToken, Tier::A, 7, &[Value, Key, Path]),
        (AppNamedKeyWithRootRef, Tier::A, 7, &[Key]),
        (ComKeyOwnership, Tier::A, 7, &[Key]),
        (OwnedSystemObject, Tier::A, 8, &[Object]),
        (UninstallerArtifact, Tier::A, 6, &[Key, Path]),
        (AppxExternalLocation, Tier::A, 8, &[Package]),
        (ChainedRef, Tier::A, 5, &[Value, Key]),
        (ReferencedByApp, Tier::B, 4, &[Path]),
        (ProductSubfolderOfVendor, Tier::B, 3, &[Key, Path]),
        (ExactFullName, Tier::B, 4, &[Key, Path]),
        (NameTokenExact, Tier::C, 3, &[Key, Path]),
        (VendorContainer, Tier::C, 2, &[Key, Path]),
        (TimeWindow, Tier::C, 1, &[Value, Key, Path, Package, Object]),
        (EmptyAfterPlan, Tier::A, 8, &[Key, Path]),
        (
            ExecutablesPresent,
            Tier::C,
            -4,
            &[Value, Key, Path, Package, Object],
        ),
        (ManyFiles, Tier::C, -2, &[Value, Key, Path, Package, Object]),
        (
            GenericName,
            Tier::C,
            -3,
            &[Value, Key, Path, Package, Object],
        ),
        (NameFuzzy, Tier::C, -2, &[Value, Key, Path, Package, Object]),
        (
            ModifiedAfterUninstall,
            Tier::C,
            -4,
            &[Value, Key, Path, Package, Object],
        ),
    ];

    #[test]
    fn default_table_matches_the_plan() {
        for (kind, tier, weight, scopes) in GOLDEN {
            assert_eq!(kind.default_tier(), tier, "{kind:?} tier");
            assert_eq!(kind.default_weight(), weight, "{kind:?} weight");
            assert_eq!(
                kind.scope().iter().collect::<Vec<_>>(),
                scopes,
                "{kind:?} scope"
            );
            assert_eq!(kind.is_negative(), weight < 0, "{kind:?}");
        }
        // The golden table covers every kind exactly once, in the order of `ALL`.
        assert_eq!(GOLDEN.map(|row| row.0), EvidenceKind::ALL);
        assert_eq!(EvidenceKind::MEGA_VENDOR_WEIGHT, 0);
    }

    /// BL-POLICY: the absence-dependent kinds of design §4.4, for every kind, scope and target type.
    #[test]
    fn absence_dependent_kinds_are_the_five_of_the_design() {
        let key = Target::RegKey {
            path: r"HKLM\SOFTWARE\Classes\CLSID\{X}".into(),
        };
        let others = [
            Target::Path {
                path: r"C:\Program Files\App".into(),
            },
            Target::RegValue {
                path: r"HKLM\SOFTWARE\App".into(),
                name: "v".into(),
            },
            Target::RegMultiSzSegment {
                path: r"HKLM\SOFTWARE\App".into(),
                name: "Path".into(),
                segment: "s".into(),
                index: None,
            },
            Target::AppxPackage {
                full_name: "p".into(),
            },
            Target::Service { name: "s".into() },
            Target::Task {
                path: r"\V\T".into(),
            },
        ];
        let mut manifests = vec![
            InstallerManifest(ManifestKind::Msi),
            InstallerManifest(ManifestKind::Burn),
        ];
        manifests.extend(EvidenceKind::ALL);
        for kind in manifests {
            for scope in Scope::ALL {
                // Also scopes the table does not allow for the kind: the predicate reads what is stored.
                let e = Evidence {
                    kind,
                    tier: kind.default_tier(),
                    weight: kind.default_weight(),
                    scope,
                    trust: SourceTrust::AdminOnly,
                    source: "s".into(),
                    detail: Facts::new(),
                };
                let expected = match kind {
                    ProvenOwnedSkeleton | ComKeyOwnership | HarvestedToken => true,
                    InstallerManifest(_) | ChainedRef => scope == Key,
                    _ => false,
                };
                assert_eq!(e.is_absence_dependent(&key), expected, "{kind:?} {scope:?}");
                for other in &others {
                    assert!(
                        !e.is_absence_dependent(other),
                        "{kind:?} {scope:?} {other:?}"
                    );
                }
                // Neither the tier nor the weight changes the answer.
                let mut weak = e.clone();
                weak.tier = Tier::Ai;
                weak.weight = -3;
                assert_eq!(weak.is_absence_dependent(&key), expected);
            }
        }
        // Not absence-dependent on a key: these may support Safe at any trust.
        for kind in [UninstallerArtifact, AppNamedKeyWithRootRef, EmptyAfterPlan] {
            let e = Evidence::new(kind, Key, SourceTrust::AdminOnly, "s").unwrap();
            assert!(!e.is_absence_dependent(&key), "{kind:?}");
        }
    }

    /// C-MODEL-SCOPE: the one new row, and nothing else moved (the golden table above is otherwise the
    /// M1a table).
    #[test]
    fn owned_system_object_is_tier_a_weight_8_scope_object_only() {
        assert_eq!(OwnedSystemObject.default_tier(), Tier::A);
        assert_eq!(OwnedSystemObject.default_weight(), 8);
        assert_eq!(OwnedSystemObject.scope(), ScopeSet::OBJECT);
        assert_eq!(
            OwnedSystemObject.scope().iter().collect::<Vec<_>>(),
            [Object]
        );
        assert!(!OwnedSystemObject.is_negative());
        let e = Evidence::new(OwnedSystemObject, Object, SourceTrust::AdminOnly, "sysobj").unwrap();
        assert_eq!((e.tier, e.weight, e.scope), (Tier::A, 8, Object));
        for scope in [Value, Key, Path, Package] {
            assert!(Evidence::new(OwnedSystemObject, scope, SourceTrust::AdminOnly, "x").is_none());
        }
        // No other kind may be recorded with Object scope except the "as recorded" and "any" rows.
        for kind in EvidenceKind::ALL {
            if kind.scope().contains(Object) {
                assert!(
                    kind == OwnedSystemObject || kind.scope() == ScopeSet::ANY,
                    "{kind:?}"
                );
            }
        }
        assert_eq!(
            serde_json::to_value(OwnedSystemObject).unwrap(),
            json!("OwnedSystemObject")
        );
        // The manifest kinds keep the enum's spelling; M1a's `Inno` reads as before.
        for (kind, name) in [
            (ManifestKind::Inno, "Inno"),
            (ManifestKind::Msi, "Msi"),
            (ManifestKind::Burn, "Burn"),
        ] {
            let ev = InstallerManifest(kind);
            assert_eq!(
                serde_json::to_value(ev).unwrap(),
                json!({"InstallerManifest": name})
            );
            assert_eq!(
                (ev.default_tier(), ev.default_weight(), ev.scope()),
                (Tier::A, 8, ScopeSet::ANY)
            );
        }
    }

    #[test]
    fn every_kind_round_trips() {
        for kind in EvidenceKind::ALL {
            let v = serde_json::to_value(kind).unwrap();
            assert_eq!(serde_json::from_value::<EvidenceKind>(v).unwrap(), kind);
        }
        assert_eq!(
            serde_json::to_value(InstallerManifest(ManifestKind::Inno)).unwrap(),
            json!({"InstallerManifest": "Inno"})
        );
        assert_eq!(
            serde_json::to_value(DanglingRef).unwrap(),
            json!("DanglingRef")
        );
        assert!(serde_json::from_value::<EvidenceKind>(json!("Traced")).is_err());
        for tier in [Tier::A, Tier::B, Tier::C, Tier::Ai] {
            let v = serde_json::to_value(tier).unwrap();
            assert_eq!(serde_json::from_value::<Tier>(v).unwrap(), tier);
        }
    }

    #[test]
    fn new_uses_the_table_and_refuses_a_wrong_scope() {
        let e = Evidence::new(
            InPreUninstallRefSnapshot,
            Value,
            SourceTrust::AdminOnly,
            "refsnap",
        )
        .unwrap()
        .with_detail(Facts::new().with("anchor", "VSCode.txt"));
        assert_eq!((e.tier, e.weight, e.scope), (Tier::A, 8, Value));
        assert_eq!(e.detail.get("anchor"), Some("VSCode.txt"));
        assert_eq!(e.detail.get("other"), None);
        // Value evidence cannot be recorded as proof for a key, nor path evidence for a package.
        assert!(
            Evidence::new(InPreUninstallRefSnapshot, Key, SourceTrust::AdminOnly, "x").is_none()
        );
        assert!(Evidence::new(InsideInstallRoot, Package, SourceTrust::AdminOnly, "x").is_none());
        assert!(Evidence::new(ProvenOwnedSkeleton, Value, SourceTrust::AdminOnly, "x").is_none());
    }

    /// A chained reference is never stronger than its anchor.
    #[test]
    fn chained_ref_takes_the_anchor_tier() {
        for anchor in [Tier::A, Tier::B, Tier::C, Tier::Ai] {
            let e = Evidence::chained(anchor, Value, SourceTrust::AdminOnly, "assoc").unwrap();
            assert_eq!((e.kind, e.tier, e.weight), (ChainedRef, anchor, 5));
        }
        assert!(Evidence::chained(Tier::A, Key, SourceTrust::AdminOnly, "x").is_some());
        assert!(Evidence::chained(Tier::A, Path, SourceTrust::AdminOnly, "x").is_none());
        assert!(Evidence::chained(Tier::A, Package, SourceTrust::AdminOnly, "x").is_none());
        // `at_most` only ever lowers.
        assert_eq!(Tier::B.at_most(Tier::A), Tier::B);
        assert_eq!(Tier::A.at_most(Tier::B), Tier::B);
        assert_eq!(Tier::C.at_most(Tier::Ai), Tier::Ai);
        assert_eq!(Tier::Ai.at_most(Tier::A), Tier::Ai);
    }

    #[test]
    fn evidence_round_trips() {
        let v = json!({
            "kind": {"InstallerManifest": "Inno"}, "tier": "A", "weight": 8, "scope": "Key",
            "trust": "AdminOnly", "source": "inno:unins000.dat",
            "detail": {"flags": "key_create", "record": "17"}
        });
        let e: Evidence = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(e.source, SourceId::from("inno:unins000.dat"));
        assert_eq!(serde_json::to_value(&e).unwrap(), v);
        let negative = json!({
            "kind": "ManyFiles", "tier": "C", "weight": -2, "scope": "Path",
            "trust": "UserWritable", "source": "fs", "detail": {}
        });
        let e: Evidence = serde_json::from_value(negative.clone()).unwrap();
        assert_eq!(serde_json::to_value(&e).unwrap(), negative);
        let text = serde_json::to_string(&schemars::schema_for!(Evidence)).unwrap();
        for name in [
            "ProvenOwnedSkeleton",
            "EmptyAfterPlan",
            "ModifiedAfterUninstall",
            "Inno",
        ] {
            assert!(text.contains(name), "schema lacks {name}");
        }
    }
}
