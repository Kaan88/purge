// Ported from BCU: source/UninstallTools/Junk/Confidence/ConfidenceRecords.cs (Apache-2.0)
// Copyright (c) 2017 Marcin Szeniak
// Modified by Purge: only the record names are kept, each mapped onto Purge's evidence and blocker
// vocabulary; BCU's numeric confidence values and texts are not used.

//! How Bulk Crap Uninstaller's confidence records map onto Purge kinds (ENGINE_PLAN.md §5.8.1).
//!
//! BCU rates a leftover by adding up named confidence records. Purge keeps the idea of named, additive
//! reasons but with its own tiers, weights and blockers (§5.3). This table is the single place the
//! correspondence is written down; it is used when BCU-derived heuristics are ported (each must emit the
//! mapped kind, not a number of its own) and when BCU results are read for comparison. It carries no
//! weights: those come from `EvidenceKind::default_weight` only.
//!
//! The record names were written from knowledge of BCU's published source, not from a checkout. Before any
//! BCU heuristic is ported against this table, check the names against the BCU release that is ported from.

use purge_model::EvidenceKind;

/// What a BCU confidence record corresponds to in Purge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PurgeMeaning {
    /// Evidence of one of these kinds; the producer picks the one whose §5.3 check it actually performed.
    Evidence(&'static [EvidenceKind]),
    /// A blocker, by its `Blocker::name`.
    Blocker(&'static str),
    /// Nothing in Purge corresponds to it; the text says what covers the concern instead.
    Unmapped(&'static str),
}

/// The §5.8.1 table: BCU record name → Purge meaning.
pub const BCU_MAP: &[(&str, PurgeMeaning)] = &[
    (
        "ExplicitConnection",
        PurgeMeaning::Evidence(&[
            EvidenceKind::PointsIntoInstallRoot,
            EvidenceKind::InsideInstallRoot,
        ]),
    ),
    (
        "IsUninstallerRegistryKey",
        PurgeMeaning::Evidence(&[EvidenceKind::UninstallerArtifact]),
    ),
    (
        "ProductNamePerfectMatch",
        PurgeMeaning::Evidence(&[EvidenceKind::NameTokenExact]),
    ),
    (
        "ProductNameDodgyMatch",
        PurgeMeaning::Evidence(&[EvidenceKind::NameFuzzy]),
    ),
    (
        "PublisherNameMatch",
        PurgeMeaning::Evidence(&[EvidenceKind::ProductSubfolderOfVendor]),
    ),
    (
        "ItemNameEqualsCompanyName",
        PurgeMeaning::Evidence(&[EvidenceKind::VendorContainer]),
    ),
    (
        "QuestionableDirectoryName",
        PurgeMeaning::Evidence(&[EvidenceKind::GenericName]),
    ),
    (
        "ExecutablesArePresent",
        PurgeMeaning::Evidence(&[EvidenceKind::ExecutablesPresent]),
    ),
    (
        "ManyFilesArePresent",
        PurgeMeaning::Evidence(&[EvidenceKind::ManyFiles]),
    ),
    (
        "DirectoryStillUsed",
        PurgeMeaning::Blocker("ContainsOtherApp"),
    ),
    (
        "UsedBySimilarNamedApp",
        PurgeMeaning::Blocker("ReferencedByOtherApp"),
    ),
    (
        "AllSubdirsMatched",
        PurgeMeaning::Unmapped(
            "covered from the other side by the UnmatchedChildren soft blocker and EmptyAfterPlan",
        ),
    ),
    (
        "IsStoreApp",
        PurgeMeaning::Unmapped("packages are separate AppxPackage targets with their own evidence"),
    ),
];

/// The Purge meaning of the BCU confidence record called `record` (exact, case-sensitive name).
#[must_use]
pub fn lookup(record: &str) -> Option<PurgeMeaning> {
    BCU_MAP
        .iter()
        .find(|(name, _)| *name == record)
        .map(|(_, meaning)| *meaning)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every blocker name the table may use; kept in step with `Blocker::name` by the test below.
    fn blocker_names() -> Vec<&'static str> {
        use purge_model::Blocker;
        let app = || "a".to_owned();
        vec![
            Blocker::ContainsOtherApp { app: app() }.name(),
            Blocker::ReferencedByOtherApp { app: app() }.name(),
            Blocker::InsideOtherApp { app: app() }.name(),
        ]
    }

    #[test]
    fn the_rows_named_in_the_plan() {
        assert_eq!(
            lookup("ExplicitConnection"),
            Some(PurgeMeaning::Evidence(&[
                EvidenceKind::PointsIntoInstallRoot,
                EvidenceKind::InsideInstallRoot
            ]))
        );
        assert_eq!(
            lookup("DirectoryStillUsed"),
            Some(PurgeMeaning::Blocker("ContainsOtherApp"))
        );
        assert_eq!(
            lookup("ProductNamePerfectMatch"),
            Some(PurgeMeaning::Evidence(&[EvidenceKind::NameTokenExact]))
        );
        assert_eq!(lookup("productnameperfectmatch"), None);
        assert_eq!(lookup("NoSuchRecord"), None);
    }

    #[test]
    fn table_is_well_formed() {
        let names = blocker_names();
        for (i, (record, meaning)) in BCU_MAP.iter().enumerate() {
            assert!(
                BCU_MAP[..i].iter().all(|(other, _)| other != record),
                "{record} is listed twice"
            );
            match meaning {
                PurgeMeaning::Evidence(kinds) => assert!(!kinds.is_empty(), "{record}"),
                PurgeMeaning::Blocker(name) => {
                    assert!(names.contains(name), "{record}: unknown blocker {name}");
                }
                PurgeMeaning::Unmapped(why) => assert!(!why.is_empty(), "{record}"),
            }
        }
    }
}
