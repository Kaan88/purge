//! The advice mapping against the real policy (BASELINE_LOCAL_DESIGN.md §7): `windows` may move an
//! item down one band, `app` and `unknown` change nothing, and no verdict can create a candidate, touch a
//! blocker or preselect anything.

use purge_model::{
    Action, AdviceDoc, AdviceItem, AdviceReason, AdviceSchema, AdviceVerdict, AppRef, Band,
    BaselineTrust, Blocker, Candidate, CandidateId, Category, Evidence, EvidenceKind, Harm, Origin,
    ProgramId, ResidueBaselineView, ResidueDoc, ResidueItem, ResidueOwner, ResidueSchema,
    ResidueShape, ResidueWhy, ResidueWritten, Reversibility, ScanMode, Scope, SourceTrust, Target,
    VerifyGone, View, apply,
};
use purge_policy::band::{PolicyCtx, TargetScope, decide, rank};

const ADMIN: SourceTrust = SourceTrust::AdminOnly;

fn key(path: &str) -> Target {
    Target::RegKey { path: path.into() }
}

fn ev(kind: EvidenceKind, scope: Scope) -> Evidence {
    Evidence::new(kind, scope, ADMIN, "test").expect("the kind takes the scope")
}

fn cand(id: &str, path: &str, evidence: Vec<Evidence>, blockers: Vec<Blocker>) -> Candidate {
    Candidate {
        id: CandidateId(id.into()),
        target: key(path),
        action: Action::DeleteKey,
        owner: AppRef {
            program_id: ProgramId::machine(View::K64, "App_is1").unwrap(),
            display_name: "App".into(),
        },
        origin: Origin::Scanner,
        scanner: "TEST".into(),
        category: Category::Registration,
        evidence,
        blockers,
        harm: Harm::Low,
        reversibility: Reversibility::Full,
        children: Vec::new(),
        size_bytes: None,
        child_count: None,
        decision: None,
        item_fp: None,
        object_fp: None,
        display_name: None,
        owner_program: None,
    }
}

fn ctx() -> PolicyCtx {
    PolicyCtx {
        baseline_trust: BaselineTrust::Exact,
        mode: ScanMode::Post,
        verify_gone: VerifyGone::new(true, true, true),
        target_scope: TargetScope::Machine,
    }
}

/// One candidate per band the policy produces; the Likely one carries the soft baseline cap.
fn candidates() -> Vec<Candidate> {
    vec![
        cand(
            "c-safe",
            r"HKLM\SOFTWARE\Vendor\Safe",
            vec![ev(EvidenceKind::ProvenOwnedSkeleton, Scope::Key)],
            Vec::new(),
        ),
        cand(
            "c-likely",
            r"HKLM\SOFTWARE\Vendor\Likely",
            vec![
                ev(EvidenceKind::TimeWindow, Scope::Key),
                ev(EvidenceKind::NameTokenExact, Scope::Key),
            ],
            vec![Blocker::BaselineInferred],
        ),
        cand(
            "c-weak",
            r"HKLM\SOFTWARE\Vendor\Weak",
            vec![ev(EvidenceKind::NameTokenExact, Scope::Key)],
            Vec::new(),
        ),
        cand(
            "c-blocked",
            r"HKLM\SOFTWARE\Vendor\Blocked",
            vec![ev(EvidenceKind::ProvenOwnedSkeleton, Scope::Key)],
            vec![Blocker::WindowsBaseline],
        ),
    ]
}

fn shape() -> ResidueShape {
    ResidueShape {
        values: 0,
        subkeys: 0,
        owner: ResidueOwner::Other,
        written: ResidueWritten::Unknown,
        parent_in_view: false,
        siblings_in_view: 0,
        siblings: 0,
        in_local: false,
        in_neighbours: Vec::new(),
    }
}

fn residue(candidates: &[Candidate]) -> ResidueDoc {
    ResidueDoc {
        schema: ResidueSchema,
        scan_id: "scan-1".into(),
        baseline_view: ResidueBaselineView {
            name: "none".into(),
            trust: BaselineTrust::None,
        },
        items: candidates
            .iter()
            .map(|candidate| ResidueItem {
                id: candidate.id.0.clone(),
                item_fp: String::new(),
                key: match &candidate.target {
                    Target::RegKey { path } => path.clone(),
                    _ => unreachable!("the test candidates are keys"),
                },
                area: None,
                why: ResidueWhy::NoView,
                site: "TEST".into(),
                shape: shape(),
            })
            .collect(),
        omitted: 0,
    }
}

fn advice(candidates: &[Candidate], verdict: AdviceVerdict) -> AdviceDoc {
    AdviceDoc {
        schema: AdviceSchema,
        scan_id: "scan-1".into(),
        model: "test-model".into(),
        items: candidates
            .iter()
            .map(|candidate| AdviceItem {
                id: candidate.id.0.clone(),
                item_fp: String::new(),
                verdict,
                confidence: 0.5,
                reason: AdviceReason::Other,
                note: String::new(),
            })
            .collect(),
    }
}

#[test]
fn advice_against_the_real_policy_never_adds_or_raises() {
    let candidates = candidates();
    let before: Vec<Band> = candidates.iter().map(|c| decide(c, &ctx()).band).collect();
    assert_eq!(
        before,
        [Band::Safe, Band::Likely, Band::Weak, Band::Blocked],
        "the test covers every band"
    );

    for verdict in [
        AdviceVerdict::Windows,
        AdviceVerdict::App,
        AdviceVerdict::Unknown,
    ] {
        let mut after = candidates.clone();
        let doc = advice(&candidates, verdict);
        assert_eq!(
            apply(&doc, &residue(&candidates), &mut after),
            candidates.len(),
            "{verdict:?}: every item binds"
        );
        assert_eq!(
            after.len(),
            candidates.len(),
            "{verdict:?}: no new candidate"
        );

        for (i, (old, new)) in candidates.iter().zip(&after).enumerate() {
            let was = decide(old, &ctx());
            let now = decide(new, &ctx());
            assert_eq!(new.blockers, old.blockers, "{verdict:?} item {i}: blockers");
            assert!(
                !(now.preselected && !was.preselected),
                "{verdict:?} item {i}: became preselected"
            );
            match verdict {
                AdviceVerdict::Windows => {
                    assert!(
                        rank(now.band) <= rank(was.band),
                        "{verdict:?} item {i}: {:?} -> {:?}",
                        was.band,
                        now.band
                    );
                    assert!(
                        rank(was.band) - rank(now.band) <= 1,
                        "{verdict:?} item {i}: {:?} -> {:?} is more than one band",
                        was.band,
                        now.band
                    );
                }
                AdviceVerdict::App | AdviceVerdict::Unknown => {
                    assert_eq!(now.band, was.band, "{verdict:?} item {i}: band changed");
                    assert_eq!(
                        now.preselected, was.preselected,
                        "{verdict:?} item {i}: preselection changed"
                    );
                }
            }
        }
        assert!(
            after[1].blockers.contains(&Blocker::BaselineInferred),
            "{verdict:?}: BaselineInferred survives"
        );
    }
}
