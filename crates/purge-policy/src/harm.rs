//! Harm: what the user loses if a removal turns out to be wrong (ENGINE_PLAN.md §5.8.5). Pure.
//!
//! [`default_harm`] is the table scanners use when they know nothing more specific about an item.
//! [`effective_harm`] is what the band rules compare against `Low`; it differs from the candidate's own
//! harm in exactly one documented case, the declared `PATH` segment edit.
//!
//! # The declared-segment exception
//!
//! §5.8.5 lists a `PATH` edit as harm Medium and §5.8.2 lets only harm ≤ Low into Safe, while §1.4 requires
//! "PATH segment Safe" for VS Code, Git and Node.js. Decision of record (user, 2026-11-12): a segment edit
//! (`Action::EditSegment` on a `RegMultiSzSegment` target) counts as harm **Low** when Tier A evidence says
//! the installer declared the segment (`InstallerManifest`) or the segment lies under a validated install
//! root (`PointsIntoInstallRoot`, or `InsideInstallRoot` where a producer records the segment as a path).
//! Removing such a segment only undoes what the installer added, and the edit keeps every other segment.
//! Any other segment edit stays Medium. The exception lowers Medium to Low and nothing else: an item marked
//! High or Critical keeps its harm.

use purge_model::{Action, Category, EvidenceKind, Harm, Target};

/// The default harm of removing an item of `category` through `action`.
///
/// | Case | Harm |
/// |---|---|
/// | `RemoveDirIfEmpty` (only ever removes something empty) | None |
/// | category `System` (drivers, filters, services) | Critical |
/// | category `UserData` | High |
/// | category `AppData` (configuration) | Medium |
/// | `EditSegment` (a `PATH` edit) | Medium |
/// | `RemovePackage` | Medium |
/// | everything else (program files, caches, registrations, traces) | Low |
///
/// `ReportOnly` items get the harm their category would have if they were acted on.
#[must_use]
pub fn default_harm(category: Category, action: Action) -> Harm {
    if action == Action::RemoveDirIfEmpty {
        return Harm::None;
    }
    match category {
        Category::System => Harm::Critical,
        Category::UserData => Harm::High,
        Category::AppData => Harm::Medium,
        Category::AppFiles
        | Category::Cache
        | Category::Registration
        | Category::Association
        | Category::ShellCom
        | Category::Startup
        | Category::Privacy
        | Category::Package => match action {
            Action::EditSegment | Action::RemovePackage => Harm::Medium,
            _ => Harm::Low,
        },
    }
}

/// Whether Tier A evidence of `kind` makes a segment edit a declared one (see the module docs).
#[must_use]
pub fn declares_segment(kind: EvidenceKind) -> bool {
    matches!(
        kind,
        EvidenceKind::InstallerManifest(_)
            | EvidenceKind::PointsIntoInstallRoot
            | EvidenceKind::InsideInstallRoot
    )
}

/// Whether the declared-segment exception applies: a segment edit of a list value, with at least one of
/// `tier_a_kinds` (the kinds of the candidate's evidence that is Tier A after Rule T) declaring the segment.
#[must_use]
pub fn is_declared_segment_edit(
    action: Action,
    target: &Target,
    tier_a_kinds: impl IntoIterator<Item = EvidenceKind>,
) -> bool {
    action == Action::EditSegment
        && matches!(target, Target::RegMultiSzSegment { .. })
        && tier_a_kinds.into_iter().any(declares_segment)
}

/// The harm the band rules use: `harm`, lowered from Medium to Low when `declared_segment_edit` holds.
#[must_use]
pub fn effective_harm(harm: Harm, declared_segment_edit: bool) -> Harm {
    if declared_segment_edit && harm == Harm::Medium {
        Harm::Low
    } else {
        harm
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_model::ManifestKind;

    #[test]
    fn default_table() {
        use Action::*;
        use Category::*;
        assert_eq!(default_harm(Registration, RemoveDirIfEmpty), Harm::None);
        assert_eq!(default_harm(UserData, RemoveDirIfEmpty), Harm::None);
        assert_eq!(default_harm(Cache, Quarantine), Harm::Low);
        assert_eq!(default_harm(AppFiles, Quarantine), Harm::Low);
        assert_eq!(default_harm(Registration, DeleteKey), Harm::Low);
        assert_eq!(default_harm(Association, DeleteValue), Harm::Low);
        assert_eq!(default_harm(ShellCom, DeleteKey), Harm::Low);
        assert_eq!(default_harm(Startup, DeleteValue), Harm::Low);
        assert_eq!(default_harm(Privacy, DeleteValue), Harm::Low);
        assert_eq!(default_harm(Package, Quarantine), Harm::Low);
        assert_eq!(default_harm(Package, RemovePackage), Harm::Medium);
        assert_eq!(default_harm(Registration, EditSegment), Harm::Medium);
        assert_eq!(default_harm(AppData, Quarantine), Harm::Medium);
        assert_eq!(default_harm(AppData, DeleteKey), Harm::Medium);
        assert_eq!(default_harm(UserData, Quarantine), Harm::High);
        assert_eq!(default_harm(System, ReportOnly), Harm::Critical);
        assert_eq!(default_harm(Registration, ReportOnly), Harm::Low);
    }

    #[test]
    fn declared_segment_exception() {
        let segment = Target::RegMultiSzSegment {
            path: r"HKU\S-1-5-21-1\Environment".into(),
            name: "Path".into(),
            segment: r"C:\Users\u\AppData\Roaming\npm".into(),
            index: None,
        };
        let value = Target::RegValue {
            path: r"HKU\S-1-5-21-1\Environment".into(),
            name: "Path".into(),
        };
        let inno = EvidenceKind::InstallerManifest(ManifestKind::Inno);
        let edit = Action::EditSegment;
        assert!(is_declared_segment_edit(edit, &segment, [inno]));
        assert!(is_declared_segment_edit(
            edit,
            &segment,
            [
                EvidenceKind::DanglingRef,
                EvidenceKind::PointsIntoInstallRoot
            ]
        ));
        assert!(!is_declared_segment_edit(
            edit,
            &segment,
            [EvidenceKind::DanglingRef, EvidenceKind::HarvestedToken]
        ));
        assert!(!is_declared_segment_edit(edit, &segment, []));
        assert!(!is_declared_segment_edit(
            Action::DeleteValue,
            &segment,
            [inno]
        ));
        assert!(!is_declared_segment_edit(edit, &value, [inno]));
        assert_eq!(effective_harm(Harm::Medium, true), Harm::Low);
        assert_eq!(effective_harm(Harm::Medium, false), Harm::Medium);
        assert_eq!(effective_harm(Harm::High, true), Harm::High);
        assert_eq!(effective_harm(Harm::Critical, true), Harm::Critical);
        assert_eq!(effective_harm(Harm::None, true), Harm::None);
    }
}
