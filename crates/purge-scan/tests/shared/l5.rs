//! Invariant L5 of BASELINE_LOCAL_DESIGN.md over a scanner test world, shared by the test crates of
//! this directory (`#[path = "../shared/l5.rs"] mod l5;`).
//!
//! For every scan: `preselected(view below Exact) ⊆ preselected(no baseline)` and
//! `Blocked(view below Exact) ⊇ Blocked(no baseline)`. The local baseline is presence-only, so two
//! stronger things hold and are checked:
//!
//! 1. a view below Exact that holds **nothing the scan meets** gives exactly the candidates of the
//!    no-baseline scan, whatever its trust and however permissive its rules (an A site never sees
//!    inferred absence);
//! 2. a view below Exact that says "Windows has it" of every key, directory, service and task the
//!    no-baseline scan touches only takes away: nothing is preselected that was not, and what was Blocked is still Blocked or is no
//!    longer listed at all (a scanner may withhold a Windows key outright).
//!
//! Bands come from the real policy (`purge_policy::band::decide`), asked with the trust a presence-only
//! scan hands on (None) and with the view's own trust (the backstop P-BL-1 on).

use std::collections::BTreeSet;

use purge_index::baseline_view::{BaselineView, fixture};
use purge_model::{Band, BaselineTrust, Candidate, CandidateId, OsInfo, Target};
use purge_policy::band::{PolicyCtx, TargetScope, decide};

/// The tasks' tree in the registry, followed by the task path (as SYS-TASK and the harvest use it).
const TASK_TREE: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree";

/// What the candidates name, as entries of a fixture view (`fixture::shipped`): the registry keys (a
/// key target, the key of a value target, and every ancestor of both down to depth 3, so that a
/// presence view also holds the containers above them), the files and directories (a path target,
/// entered as a directory), and the keys of the services and tasks. A firewall rule is a value of the
/// baseline, which the fixture views do not hold: for it only the first half of the check says
/// something.
fn keys_of(candidates: &[Candidate]) -> Vec<String> {
    let mut keys = BTreeSet::new();
    for c in candidates {
        let key = match &c.target {
            Target::RegKey { path }
            | Target::RegValue { path, .. }
            | Target::RegMultiSzSegment { path, .. } => path.clone(),
            Target::Path { path } => {
                keys.insert(path.clone());
                continue;
            }
            // Where a baseline records that Windows has the object (the object guard's `in_baseline`).
            Target::Service { name } => {
                keys.insert(format!(r"{}\{name}", purge_index::sysobj::SERVICES_KEY));
                continue;
            }
            Target::Task { path } => {
                keys.insert(format!("{TASK_TREE}{path}"));
                continue;
            }
            _ => continue,
        };
        let segments: Vec<&str> = key.split('\\').collect();
        for depth in 3..=segments.len() {
            keys.insert(segments[..depth].join("\\"));
        }
    }
    keys.into_iter().collect()
}

fn bands(candidates: &[Candidate], trust: BaselineTrust) -> Vec<(CandidateId, Band, bool)> {
    candidates
        .iter()
        .map(|c| {
            let per_user = match &c.target {
                Target::RegKey { path }
                | Target::RegValue { path, .. }
                | Target::RegMultiSzSegment { path, .. } => path
                    .get(..4)
                    .is_some_and(|root| root.eq_ignore_ascii_case(r"HKU\")),
                _ => false,
            };
            let d = decide(
                c,
                &PolicyCtx {
                    baseline_trust: trust,
                    mode: purge_model::ScanMode::Post,
                    verify_gone: purge_model::VerifyGone::new(true, true, true),
                    target_scope: if per_user {
                        TargetScope::PerUser
                    } else {
                        TargetScope::Machine
                    },
                },
            );
            (c.id.clone(), d.band, d.preselected)
        })
        .collect()
}

/// `preselected(below) ⊆ preselected(none)`, `Blocked(below) ⊇ Blocked(none)` up to withheld items.
fn assert_monotone(what: &str, none: &[Candidate], below: &[Candidate], trust: BaselineTrust) {
    let none_bands = bands(none, BaselineTrust::None);
    let below_bands = bands(below, trust);
    let preselected_none: BTreeSet<&CandidateId> = none_bands
        .iter()
        .filter(|(_, _, pre)| *pre)
        .map(|(id, _, _)| id)
        .collect();
    for (i, (id, band, pre)) in below_bands.iter().enumerate() {
        assert!(
            !*pre || preselected_none.contains(id),
            "{what}: {:?} is preselected ({band:?}) below Exact and was not without a baseline: {:#?}",
            below[i].target,
            below[i]
        );
    }
    for (i, (id, band, _)) in none_bands.iter().enumerate() {
        if *band != Band::Blocked {
            continue;
        }
        let still: Vec<&Band> = below_bands
            .iter()
            .filter(|(other, _, _)| other == id)
            .map(|(_, band, _)| band)
            .collect();
        assert!(
            still.iter().all(|band| **band == Band::Blocked),
            "{what}: {:?} was Blocked without a baseline and is {still:?} below Exact",
            none[i].target
        );
    }
}

/// Checks L5 for one scan. `scan` runs the scanner over a fresh copy of the world with the given
/// baseline (`None`: no baseline at all) and returns its candidates. Returns the no-baseline candidates.
pub fn check(
    what: &str,
    os: &OsInfo,
    scan: &dyn Fn(Option<BaselineView>) -> Vec<Candidate>,
) -> Vec<Candidate> {
    let none = scan(None);

    // 1. Nothing the scan meets is in the view: the no-baseline scan, exactly.
    for which in 1..fixture::BELOW_EXACT {
        let view = fixture::below_exact(which, os).expect("a view");
        let trust = view.trust();
        let below = scan(Some(view));
        assert_eq!(
            below, none,
            "{what}: a {trust} view that holds nothing differs from no baseline"
        );
    }

    // 2. Windows has every key the scan touches: only takes away.
    let keys = keys_of(&none);
    let keys: Vec<&str> = keys.iter().map(String::as_str).collect();
    let (e, b, u) = (os.edition.as_str(), os.build, os.ubr);
    let views = [
        (
            "merged, local has",
            fixture::merged_view(e, b, u, &keys, &[]),
        ),
        (
            "merged, neighbour has",
            fixture::merged_view(e, b, u, &[], &keys),
        ),
        ("local", fixture::local_view(e, b, u, &keys)),
        ("none with a neighbour", fixture::none_view(e, b, u, &keys)),
    ];
    for (name, view) in views {
        let trust = view.trust();
        let below = scan(Some(view));
        let what = format!("{what} ({name})");
        // What a presence-only scan hands to the policy, and the view's own trust (P-BL-1 on).
        assert_monotone(&what, &none, &below, trust.presence_only());
        assert_monotone(&what, &none, &below, trust);
        // No evidence of a key rests on absence below Exact.
        for c in &below {
            assert!(
                !c.evidence
                    .iter()
                    .any(|e| purge_scan::framework::claims_absence(e, &c.target)),
                "{what}: {:?} claims baseline absence below Exact: {c:#?}",
                c.target
            );
            assert!(
                !c.blockers.contains(&purge_model::Blocker::BaselineInferred),
                "{what}: {:?} carries BaselineInferred: no production path infers absence",
                c.target
            );
        }
    }
    none
}
