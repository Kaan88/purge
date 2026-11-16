//! Explanations: fixed templates rendered from evidence, blockers and policy notes (ENGINE_PLAN.md
//! §5.8.6). Pure.
//!
//! Nothing here is free text. Every line is one of the templates below; the only variable parts are the
//! owner's display name and a few detail values the producer recorded in [`Facts`] (a root, an anchor, a
//! token), which are stripped of control characters and cut to [`MAX_FACT_CHARS`] before use.
//!
//! Detail keys the templates understand (all optional): `root`, `path`, `anchor`, `token`, `baseline`,
//! and `place` (`shared`: the evidence was lowered because the value is not in a place of the app's own,
//! which adds [`shared_place_line`]).
//!
//! A Blocked candidate is explained by its hard blockers only ("Kept: …"). Any other candidate lists its
//! evidence from the strongest kind down, then what speaks against it, then the soft blockers and the
//! policy notes. Evidence of tier `Ai` is never rendered: AI notes are shown separately by the UI.

use purge_model::{Band, Blocker, Candidate, Evidence, EvidenceKind, ManifestKind, Tier};

use crate::score::effective_weight;

/// What joins the lines of an explanation into the one string stored in a decision.
pub const SEPARATOR: &str = " · ";

/// The longest detail value a template takes over, in characters.
pub const MAX_FACT_CHARS: usize = 160;

/// Detail key by which a scanner marks reference evidence it lowered because the value lies in a place
/// that is not the app's own (`purge_scan::framework::SHARED_PLACE_KEY`).
pub const SHARED_PLACE_KEY: &str = "place";
/// Detail value of [`SHARED_PLACE_KEY`].
pub const SHARED_PLACE_VALUE: &str = "shared";

/// The line shown for an item whose reference evidence was lowered for lying in a shared place.
#[must_use]
pub fn shared_place_line(owner: &str) -> String {
    format!(
        "In a place other software and you also write to; nothing shows that {} put it there",
        clean_name(owner)
    )
}

/// A remark of the policy itself on how it reached a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Note {
    /// Forced mode: nothing is preselected and Safe is shown as Likely (§5.8.3).
    ForcedMode,
    /// Verify-gone failed: nothing is preselected and Safe is shown as Likely (§5.8.3).
    NotVerifiedGone,
    /// External mode and the proof does not come from an admin-only source (§5.8.3).
    ExternalNeedsAdminSource,
    /// Rule T lowered evidence from a user-writable source for a machine-wide target (§5.3).
    UserWritableSource,
    /// There is Tier A evidence, but none about this type of target (§5.8.2).
    ScopeMismatch,
    /// The declared-segment exception applied: the edit counts as harm Low (see `harm`).
    DeclaredSegment,
    /// The category (user data, system) is never preselected.
    CategoryNeverPreselected,
    /// The harm is above Low.
    HarmAboveLow,
    /// A knowledge-pack signature that is not shipped and anchored is at most Likely (§5.8.2).
    SignatureCap,
    /// An item proposed by an agent starts unticked (§5.8.2).
    AgentProposed,
    /// The item is report-only, or its action does not fit its target.
    NotActionable,
    /// A negative AI note moved the item down one band (§5.8.1).
    AiLowered,
    /// The removal cannot be undone and no `ReversibilityNone` blocker says so already.
    CannotBeUndone,
}

/// The line of a policy note.
#[must_use]
pub fn note_line(note: Note) -> &'static str {
    match note {
        Note::ForcedMode => "Not ticked: the uninstaller did not run, so nothing is preselected",
        Note::NotVerifiedGone => "Not ticked: the app still looks installed",
        Note::ExternalNeedsAdminSource => {
            "Not ticked: removed outside Purge and the proof is not from an admin-only record"
        }
        Note::UserWritableSource => {
            "A record the user can change does not prove a machine-wide item"
        }
        Note::ScopeMismatch => "The proof is about a different kind of item than this one",
        Note::DeclaredSegment => {
            "Only this one entry is taken out of the list; the installer added it"
        }
        Note::CategoryNeverPreselected => "Items of this category are never ticked for you",
        Note::HarmAboveLow => {
            "Not ticked: removing it by mistake would cost more than a cache or log"
        }
        Note::SignatureCap => "Matched by a rule that is not verified for this app",
        Note::AgentProposed => "Proposed by an assistant, so it starts unticked",
        Note::NotActionable => "Shown for information only",
        Note::AiLowered => "Moved down after an assistant's note",
        // The same line as `Blocker::ReversibilityNone`.
        Note::CannotBeUndone => "Removing it cannot be undone",
    }
}

/// A detail value made safe for a template: control characters dropped, cut to [`MAX_FACT_CHARS`].
fn fact<'a>(evidence: &'a Evidence, key: &str) -> Option<String> {
    let raw: &'a str = evidence.detail.get(key)?;
    let clean: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_FACT_CHARS)
        .collect();
    let clean = clean.trim();
    (!clean.is_empty()).then(|| clean.to_owned())
}

/// The owner's name as the templates print it (same cleaning as detail values).
fn clean_name(name: &str) -> String {
    let clean: String = name
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_FACT_CHARS)
        .collect();
    let clean = clean.trim();
    if clean.is_empty() {
        "the app".to_owned()
    } else {
        clean.to_owned()
    }
}

/// The lines one piece of evidence contributes, for an owner called `owner`.
#[must_use]
pub fn evidence_lines(evidence: &Evidence, owner: &str) -> Vec<String> {
    use EvidenceKind::*;
    let owner = clean_name(owner);
    let e = evidence;
    let line = match e.kind {
        InsideInstallRoot => match fact(e, "root") {
            Some(root) => format!("Inside {owner}'s install folder {root}"),
            None => format!("Inside {owner}'s install folder"),
        },
        InstallerManifest(ManifestKind::Inno) => format!("Named in {owner}'s uninstall log"),
        // M1b: wired by M1B-POLICY
        InstallerManifest(ManifestKind::Msi | ManifestKind::Burn) => {
            format!("Named in {owner}'s installer record")
        }
        // M1b: wired by M1B-POLICY
        OwnedSystemObject => format!("Runs a program that belongs to {owner}"),
        InPreUninstallRefSnapshot => match fact(e, "anchor").or_else(|| fact(e, "path")) {
            Some(anchor) => format!("Pointed to {anchor} before uninstall"),
            None => format!("Pointed to {owner} before uninstall"),
        },
        ProvenOwnedSkeleton => {
            let mut lines = vec![
                format!("Everything in it belonged to {owner}"),
                "now empty".to_owned(),
            ];
            if let Some(baseline) = fact(e, "baseline") {
                lines.push(format!("not on clean Windows {baseline}"));
            }
            return lines;
        }
        DanglingRef => match fact(e, "path") {
            Some(path) => format!("Points to {path}, which no longer exists"),
            None => "Points to a location that no longer exists".to_owned(),
        },
        PointsIntoInstallRoot => match fact(e, "path") {
            Some(path) => format!("Points to {path} in {owner}'s install folder"),
            None => format!("Points into {owner}'s install folder"),
        },
        HarvestedToken => match fact(e, "token") {
            Some(token) => format!("Carries {owner}'s identifier {token}"),
            None => format!("Carries an identifier unique to {owner}"),
        },
        AppNamedKeyWithRootRef => {
            format!("Named after {owner} and refers to its install folder")
        }
        ComKeyOwnership => format!("Component registration served from {owner}'s install folder"),
        UninstallerArtifact => format!("{owner}'s own uninstall entry or uninstaller"),
        AppxExternalLocation => format!("Package registered from {owner}'s install folder"),
        ChainedRef => match fact(e, "anchor") {
            Some(anchor) => format!("Refers to {anchor}, which belongs to {owner}"),
            None => format!("Refers to an item that belongs to {owner}"),
        },
        ReferencedByApp => format!("{owner} was set up to keep data here"),
        ProductSubfolderOfVendor => format!("{owner}'s product name under its vendor's name"),
        ExactFullName => format!("Named exactly like {owner}"),
        NameTokenExact => format!("Name matches {owner}"),
        VendorContainer => "Vendor container, removed only if it is empty".to_owned(),
        TimeWindow => format!("Created or changed while {owner} was being installed or removed"),
        EmptyAfterPlan => "Empty once the ticked items inside it are removed".to_owned(),
        ExecutablesPresent => "Against: it contains programs".to_owned(),
        ManyFiles => "Against: it contains many files".to_owned(),
        GenericName => "Against: the name is a common word".to_owned(),
        NameFuzzy => "Against: the name is only similar".to_owned(),
        ModifiedAfterUninstall => "Against: changed after the uninstall finished".to_owned(),
    };
    vec![line]
}

/// The line of a blocker. Hard blockers start with "Kept:".
#[must_use]
pub fn blocker_line(blocker: &Blocker) -> String {
    use Blocker::*;
    let s = |text: &str| text.to_owned();
    match blocker {
        DenyListed { rule } => format!("Kept: protected location (rule {})", clean_name(rule)),
        StructuralContainer => s("Kept: other software lives inside this container"),
        WindowsBaseline => s("Kept: part of a clean Windows installation"),
        OwnedByInstalledMsi { product, row } => format!(
            "Kept: owned by installed product {} ({})",
            clean_name(product),
            clean_name(row)
        ),
        ReferencedByOtherApp { app } => format!("Kept: still used by {}", clean_name(app)),
        InsideOtherApp { app } => format!("Kept: it is inside {}", clean_name(app)),
        ContainsOtherApp { app } => format!("Kept: it contains {}", clean_name(app)),
        SharedRefcount => s("Kept: a shared component that is still counted as in use"),
        MsiProductStillRegistered => {
            s("Kept: the product is still registered with Windows Installer")
        }
        BurnDependentsRemain => s("Kept: other installed bundles depend on it"),
        ExistedBeforeInstall => s("Kept: it existed before the app was installed"),
        TrustedInstallerOwned => s("Kept: owned by Windows (TrustedInstaller)"),
        MicrosoftSystemTarget => s("Kept: refers to a Microsoft system file that exists"),
        SharedIid => s("Kept: a shared interface other software relies on"),
        SyncRoot => s("Kept: inside a cloud-synced folder"),
        HardLinkOutsidePlan => s("Kept: the file has another hard link elsewhere"),
        RegLink => s("Kept: the key is a registry link"),
        ReparseMismatch => s("Kept: the path leads somewhere else through a link"),
        WindowsManagedOpaque => s("Kept: managed by Windows"),
        CannotBackUp => s("Kept: it cannot be backed up, so it is only reported"),
        NotGone => s("Kept: the app still appears to be installed"),
        UnmatchedChildren { n: 1 } => s("Holds 1 item not known to belong to the app"),
        UnmatchedChildren { n } => format!("Holds {n} items not known to belong to the app"),
        UserData => s("May hold your own data"),
        TooLarge => s("Very large; look before removing"),
        OlderThanInstall => s("Older than the app's install"),
        MultiTargetOwner => s("Shared by several apps that are being removed"),
        ReversibilityNone => s("Removing it cannot be undone"),
        InUse => s("Currently in use"),
        MsiPackageUnreadable => {
            s("An installed product's package could not be read to rule it out")
        }
        ChangedSinceScan => s("Changed since the scan"),
        // M1b: wired by M1B-POLICY
        Driver => s("Kept: it is a driver"),
        // M1b: wired by M1B-POLICY
        HasDependents { names } => format!(
            "Kept: other services depend on it ({})",
            names
                .iter()
                .map(|n| clean_name(n))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        // M1b: wired by M1B-POLICY
        ObjectChangedSinceHarvest => s("Kept: it changed since the app was examined"),
        // M1b: wired by M1B-POLICY
        ReversibilityPartial => s("Undo cannot bring back all of it"),
        // M1b: wired by M1B-POLICY
        ProgramUnresolved => s("Its program could not be pinned to one file"),
    }
}

fn push_unique(lines: &mut Vec<String>, line: String) {
    if !lines.contains(&line) {
        lines.push(line);
    }
}

/// The explanation of `candidate` as a list of lines, given the band it is shown in and the policy's notes.
///
/// The result depends only on its arguments, and is never empty.
#[must_use]
pub fn render(candidate: &Candidate, band: Band, notes: &[Note]) -> Vec<String> {
    let mut lines = Vec::new();
    if band == Band::Blocked {
        for b in candidate.blockers.iter().filter(|b| b.is_hard()) {
            push_unique(&mut lines, blocker_line(b));
        }
        if lines.is_empty() {
            lines.push("Kept: protected".to_owned());
        }
        return lines;
    }
    let owner = candidate.owner.display_name.as_str();
    let mut shown: Vec<&Evidence> = candidate
        .evidence
        .iter()
        .filter(|e| e.tier != Tier::Ai)
        .collect();
    // Strongest first; the negatives (below zero) end up last. The sort is stable.
    shown.sort_by_key(|e| std::cmp::Reverse(effective_weight(e)));
    let mut shared_place = false;
    for e in shown {
        for line in evidence_lines(e, owner) {
            push_unique(&mut lines, line);
        }
        shared_place |= e.detail.get(SHARED_PLACE_KEY) == Some(SHARED_PLACE_VALUE);
    }
    if shared_place {
        push_unique(&mut lines, shared_place_line(owner));
    }
    for b in candidate.blockers.iter().filter(|b| !b.is_hard()) {
        push_unique(&mut lines, blocker_line(b));
    }
    for note in notes {
        push_unique(&mut lines, note_line(*note).to_owned());
    }
    if lines.is_empty() {
        lines.push("Nothing ties it to the app".to_owned());
    }
    lines
}

/// [`render`], joined with [`SEPARATOR`] into the string a decision stores.
#[must_use]
pub fn render_joined(candidate: &Candidate, band: Band, notes: &[Note]) -> String {
    render(candidate, band, notes).join(SEPARATOR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_model::{Facts, Scope, SourceTrust};

    fn ev(kind: EvidenceKind) -> Evidence {
        let scope = kind.scope().iter().next().unwrap();
        Evidence::new(kind, scope, SourceTrust::AdminOnly, "s").unwrap()
    }

    #[test]
    fn every_kind_has_a_line_naming_no_placeholder() {
        for kind in EvidenceKind::ALL {
            let lines = evidence_lines(&ev(kind), "Git");
            assert!(!lines.is_empty(), "{kind:?}");
            for line in lines {
                assert!(!line.is_empty() && !line.contains('{'), "{kind:?}: {line}");
            }
        }
    }

    #[test]
    fn detail_values_fill_the_templates() {
        let snap = ev(EvidenceKind::InPreUninstallRefSnapshot).with_detail(
            Facts::new().with("anchor", r"C:\Program Files\Microsoft VS Code\Code.exe"),
        );
        assert_eq!(
            evidence_lines(&snap, "VS Code"),
            [r"Pointed to C:\Program Files\Microsoft VS Code\Code.exe before uninstall"]
        );
        let skeleton = ev(EvidenceKind::ProvenOwnedSkeleton)
            .with_detail(Facts::new().with("baseline", "11 Pro 26300"));
        assert_eq!(
            evidence_lines(&skeleton, "Git").join(SEPARATOR),
            "Everything in it belonged to Git · now empty · not on clean Windows 11 Pro 26300"
        );
        assert_eq!(
            evidence_lines(
                &ev(EvidenceKind::InstallerManifest(ManifestKind::Inno)),
                "Git"
            ),
            ["Named in Git's uninstall log"]
        );
    }

    #[test]
    fn detail_values_are_cleaned_and_cut() {
        let long = format!("C:\\x\r\n\u{7}{}", "a".repeat(500));
        let e = ev(EvidenceKind::DanglingRef).with_detail(Facts::new().with("path", long));
        let line = &evidence_lines(&e, "App")[0];
        assert!(!line.chars().any(char::is_control));
        assert!(line.chars().count() < MAX_FACT_CHARS + 60);
        let blank = ev(EvidenceKind::DanglingRef).with_detail(Facts::new().with("path", " \n "));
        assert_eq!(
            evidence_lines(&blank, "App"),
            ["Points to a location that no longer exists"]
        );
        assert_eq!(
            evidence_lines(&ev(EvidenceKind::NameTokenExact), "\n"),
            ["Name matches the app"]
        );
    }

    #[test]
    fn hard_blockers_say_kept_and_soft_ones_do_not() {
        let all = [
            Blocker::DenyListed {
                rule: "windir".into(),
            },
            Blocker::StructuralContainer,
            Blocker::WindowsBaseline,
            Blocker::OwnedByInstalledMsi {
                product: "{P}".into(),
                row: "Registry:r1".into(),
            },
            Blocker::ReferencedByOtherApp {
                app: "Mozilla Thunderbird".into(),
            },
            Blocker::InsideOtherApp { app: "A".into() },
            Blocker::ContainsOtherApp { app: "A".into() },
            Blocker::SharedRefcount,
            Blocker::MsiProductStillRegistered,
            Blocker::BurnDependentsRemain,
            Blocker::ExistedBeforeInstall,
            Blocker::TrustedInstallerOwned,
            Blocker::MicrosoftSystemTarget,
            Blocker::SharedIid,
            Blocker::SyncRoot,
            Blocker::HardLinkOutsidePlan,
            Blocker::RegLink,
            Blocker::ReparseMismatch,
            Blocker::WindowsManagedOpaque,
            Blocker::CannotBackUp,
            Blocker::NotGone,
            Blocker::UnmatchedChildren { n: 1 },
            Blocker::UnmatchedChildren { n: 3 },
            Blocker::UserData,
            Blocker::TooLarge,
            Blocker::OlderThanInstall,
            Blocker::MultiTargetOwner,
            Blocker::ReversibilityNone,
            Blocker::InUse,
            Blocker::MsiPackageUnreadable,
            Blocker::ChangedSinceScan,
        ];
        for b in &all {
            assert_eq!(blocker_line(b).starts_with("Kept: "), b.is_hard(), "{b:?}");
        }
        assert_eq!(
            blocker_line(&all[4]),
            "Kept: still used by Mozilla Thunderbird"
        );
        assert_eq!(
            blocker_line(&all[22]),
            "Holds 3 items not known to belong to the app"
        );
    }

    #[test]
    fn scope_of_the_helper_evidence_is_valid() {
        // Guards the test helper itself: the first allowed scope of each kind.
        assert_eq!(ev(EvidenceKind::InsideInstallRoot).scope, Scope::Path);
    }
}
