//! Tests of the plan binding. Pure: nothing here touches the system. The builders at the top are shared
//! with the tests of the execute pipeline and the report.

use purge_model::exec::op::{ExecOp, Mismatch, OpId};
use purge_model::{
    Action, AppRef, Band, Blocker, Candidate, CandidateId, Category, Decision, Harm, Origin,
    Reversibility, ScanMode, Target, Tool,
};
use purge_plan::emit::{ScanDoc, ScanSchema};

use super::*;

// ---------------------------------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------------------------------

pub(crate) fn cid(id: &str) -> CandidateId {
    CandidateId(id.to_owned())
}

pub(crate) fn path(p: &str) -> Target {
    Target::Path { path: p.to_owned() }
}

pub(crate) fn key(p: &str) -> Target {
    Target::RegKey { path: p.to_owned() }
}

pub(crate) fn value(p: &str, name: &str) -> Target {
    Target::RegValue {
        path: p.to_owned(),
        name: name.to_owned(),
    }
}

/// A decided candidate with no evidence and no blockers.
pub(crate) fn candidate(
    id: &str,
    target: Target,
    action: Action,
    band: Band,
    preselected: bool,
) -> Candidate {
    Candidate {
        id: cid(id),
        target,
        action,
        owner: AppRef {
            program_id: "HKLM|64|VendorApp".parse().unwrap(),
            display_name: "Vendor App".into(),
        },
        origin: Origin::Scanner,
        scanner: "TEST".into(),
        category: Category::AppFiles,
        evidence: Vec::new(),
        blockers: Vec::new(),
        harm: Harm::Low,
        reversibility: Reversibility::Full,
        children: Vec::new(),
        size_bytes: None,
        child_count: None,
        decision: Some(Decision {
            band,
            preselected,
            score: 9,
            explanation: "test".into(),
        }),
    }
}

/// A Safe, preselected candidate.
pub(crate) fn safe(id: &str, target: Target, action: Action) -> Candidate {
    candidate(id, target, action, Band::Safe, true)
}

/// A scan document over `items` with its plan hash computed.
pub(crate) fn scan_doc(items: Vec<Candidate>, absorbed: Vec<Candidate>) -> ScanDoc {
    let mut scan = ScanDoc {
        schema: ScanSchema,
        app: "vendor-app".into(),
        tool: Tool::Purge,
        mode: ScanMode::Post,
        policy_version: "m1a.6".into(),
        plan_hash: String::new(),
        items,
        absorbed,
    };
    rehash(&mut scan);
    scan
}

/// Recomputes the plan hash after the items were edited (a plan built that way, not a tampered one).
pub(crate) fn rehash(scan: &mut ScanDoc) {
    scan.plan_hash = purge_plan::hash::plan_hash(&scan.items, &scan.policy_version, scan.mode);
}

/// The confirm hash a consent over `ids` of `scan` produces.
pub(crate) fn confirm_for(scan: &ScanDoc, ids: &[CandidateId]) -> String {
    confirm_hash(scan.plan_hash.parse().unwrap(), selection_hash(ids)).to_string()
}

/// A request for `selection` with the confirm hash of exactly that selection.
pub(crate) fn request(scan: &ScanDoc, selection: Selection) -> ExecRequest {
    let ids: Vec<CandidateId> = match &selection {
        Selection::Ids(ids) => ids.clone(),
        Selection::Preselected => scan
            .items
            .iter()
            .filter(|c| {
                c.decision
                    .as_ref()
                    .is_some_and(|d| d.band == Band::Safe && d.preselected)
            })
            .map(|c| c.id.clone())
            .collect(),
    };
    ExecRequest {
        scan: scan.clone(),
        confirm: confirm_for(scan, &ids),
        selection,
        allow_irreversible: false,
        settings: ExecSettings::default(),
    }
}

fn ids(list: &[&str]) -> Selection {
    Selection::Ids(list.iter().map(|id| cid(id)).collect())
}

/// Three independent items: a Safe preselected file, a Likely key, a Weak value.
fn plan() -> ScanDoc {
    scan_doc(
        vec![
            safe("c-1", path(r"C:\Vendor\a.txt"), Action::Quarantine),
            candidate(
                "c-2",
                key(r"HKLM\SOFTWARE\Vendor\App"),
                Action::DeleteKey,
                Band::Likely,
                false,
            ),
            candidate(
                "c-3",
                value(r"HKLM\SOFTWARE\Other", "Vendor"),
                Action::DeleteValue,
                Band::Weak,
                false,
            ),
        ],
        Vec::new(),
    )
}

fn not_selectable(result: Result<BoundPlan, PlanRefusal>) -> NotSelectable {
    match result {
        Err(PlanRefusal::NotSelectable { why, .. }) => why,
        other => panic!("expected NotSelectable, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------------
// The recipe
// ---------------------------------------------------------------------------------------------------

/// The fixed vector of the module docs, computed independently (Python `hashlib`).
#[test]
fn confirm_recipe_fixed_vector() {
    let selection = selection_hash(&[cid("c-2"), cid("c-10"), cid("c-1"), cid("c-2")]);
    assert_eq!(
        selection.to_string(),
        "2f2400bd148f06ab24831566736224e0608bbd75547ce869857bd1f5d3d53901"
    );
    let plan_hash = "10e9da8690be9214c32b5379a6688586b78ff5b221b3877b2f59cfefc3f149b2"
        .parse()
        .unwrap();
    assert_eq!(
        confirm_hash(plan_hash, selection).to_string(),
        "005cd48e39de487e9536e5ab5ff917582763f70d7c04a5614db1d7f57aa43788"
    );
}

#[test]
fn selection_hash_ignores_order_repeats_and_empty_ids() {
    let a = selection_hash(&[cid("b"), cid("a")]);
    assert_eq!(a, selection_hash(&[cid("a"), cid("b"), cid("a"), cid("")]));
    assert_eq!(a, sha256_bytes(b"a\nb"));
    assert_ne!(a, selection_hash(&[cid("a")]));
    assert_eq!(selection_hash(&[]), sha256_bytes(b""));
}

/// .NET's ordinal order compares UTF-16 code units: U+1F600 (D83D DE00) sorts before U+FF5E, although
/// its code point is larger.
#[test]
fn selection_hash_sorts_by_utf16_code_unit() {
    let astral = "\u{1f600}";
    let bmp = "\u{ff5e}";
    assert_eq!(
        selection_hash(&[cid(bmp), cid(astral)]),
        sha256_bytes(format!("{astral}\n{bmp}").as_bytes())
    );
}

// ---------------------------------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------------------------------

#[test]
fn preselected_takes_safe_preselected_items_only() {
    let scan = plan();
    let bound = bind(&request(&scan, Selection::Preselected)).unwrap();
    assert_eq!(bound.items().len(), 1);
    assert_eq!(bound.items()[0].op, OpId(1));
    assert_eq!(
        bound.items()[0].exec_op,
        Some(ExecOp::QuarantineMove {
            path: r"C:\Vendor\a.txt".into()
        })
    );
    assert_eq!(bound.plan_hash().to_string(), scan.plan_hash);
    assert_eq!(bound.selection_hash(), selection_hash(&[cid("c-1")]));
}

#[test]
fn explicit_ids_may_add_likely_and_weak_in_plan_order() {
    let scan = plan();
    let bound = bind(&request(&scan, ids(&["c-3", "c-1", "c-2", "c-3", ""]))).unwrap();
    let order: Vec<(u32, usize)> = bound.items().iter().map(|i| (i.op.0, i.index)).collect();
    assert_eq!(order, [(1, 0), (2, 1), (3, 2)]);
    assert_eq!(bound.item(OpId(2)).unwrap().index, 1);
    assert!(bound.item(OpId(0)).is_none() && bound.item(OpId(4)).is_none());
    assert_eq!(bound.exec_ops().len(), 3);
}

#[test]
fn wrong_or_missing_confirm_is_refused() {
    let scan = plan();
    let good = request(&scan, Selection::Preselected);
    let with = |confirm: &str| ExecRequest {
        confirm: confirm.to_owned(),
        ..good.clone()
    };
    assert_eq!(bind(&with("")), Err(PlanRefusal::ConfirmForm));
    assert_eq!(
        bind(&with(&good.confirm.to_uppercase())),
        Err(PlanRefusal::ConfirmForm)
    );
    // The plan hash alone is not a confirmation, nor is the selection hash.
    assert_eq!(
        bind(&with(&scan.plan_hash)),
        Err(PlanRefusal::ConfirmMismatch)
    );
    assert_eq!(
        bind(&with(&selection_hash(&[cid("c-1")]).to_string())),
        Err(PlanRefusal::ConfirmMismatch)
    );
    assert!(bind(&good).is_ok());
}

#[test]
fn a_confirmation_does_not_carry_to_another_selection() {
    let scan = plan();
    let confirmed = request(&scan, ids(&["c-1"]));
    for other in [ids(&["c-1", "c-2"]), ids(&["c-2"]), ids(&["c-3", "c-1"])] {
        let altered = ExecRequest {
            selection: other,
            ..confirmed.clone()
        };
        assert_eq!(bind(&altered), Err(PlanRefusal::ConfirmMismatch));
    }
    // The preselection is the same selection here, so the same confirmation fits it.
    let same = ExecRequest {
        selection: Selection::Preselected,
        ..confirmed
    };
    assert!(bind(&same).is_ok());
}

#[test]
fn any_change_to_a_hashed_field_is_refused() {
    let base = scan_doc(
        vec![
            {
                let mut parent = safe("c-1", path(r"C:\Vendor"), Action::Quarantine);
                parent.children.push(cid("c-1a"));
                parent
            },
            safe("c-2", key(r"HKLM\SOFTWARE\Vendor"), Action::DeleteKey),
        ],
        vec![safe("c-1a", path(r"C:\Vendor\a.txt"), Action::Quarantine)],
    );
    let good = request(&base, Selection::Preselected);
    assert!(bind(&good).is_ok());

    type Edit = fn(&mut ScanDoc);
    let edits: [(&str, Edit); 10] = [
        ("target", |s| s.items[0].target = path(r"C:\Windows")),
        ("action", |s| s.items[0].action = Action::RemoveDirIfEmpty),
        ("band", |s| {
            s.items[1].decision.as_mut().unwrap().band = Band::Likely
        }),
        ("preselected", |s| {
            s.items[1].decision.as_mut().unwrap().preselected = false
        }),
        ("id", |s| s.items[1].id = cid("c-9")),
        ("order", |s| s.items.swap(0, 1)),
        ("dropped item", |s| {
            s.items.pop();
        }),
        ("child list", |s| s.items[0].children.clear()),
        ("policy version", |s| s.policy_version = "m1a.7".into()),
        ("mode", |s| s.mode = ScanMode::Forced),
    ];
    for (label, edit) in edits {
        let mut altered = good.clone();
        edit(&mut altered.scan);
        assert!(
            matches!(bind(&altered), Err(PlanRefusal::PlanHashMismatch { .. })),
            "{label}"
        );
    }

    let mut bad_form = good.clone();
    bad_form.scan.plan_hash = base.plan_hash.to_uppercase();
    assert!(matches!(bind(&bad_form), Err(PlanRefusal::PlanHashForm(_))));
}

#[test]
fn absorbed_children_must_exist_and_lie_inside_their_parent() {
    let mut parent = safe("c-1", path(r"C:\Vendor"), Action::Quarantine);
    parent.children.push(cid("c-1a"));
    let child = safe("c-1a", path(r"C:\Vendor\a.txt"), Action::Quarantine);

    let good = scan_doc(vec![parent.clone()], vec![child.clone()]);
    let bound = bind(&request(&good, Selection::Preselected)).unwrap();
    let riding: Vec<&str> = bound
        .children(&good.items[0])
        .map(|c| c.id.0.as_str())
        .collect();
    assert_eq!(riding, ["c-1a"]);

    // The absorbed list is not hashed: dropping or moving a child must be caught on its own.
    let mut missing = request(&good, Selection::Preselected);
    missing.scan.absorbed.clear();
    assert_eq!(
        bind(&missing),
        Err(PlanRefusal::ChildMissing {
            parent: cid("c-1"),
            child: cid("c-1a")
        })
    );
    let mut outside = request(&good, Selection::Preselected);
    outside.scan.absorbed[0].target = path(r"C:\Windows\System32\drivers\etc\hosts");
    assert_eq!(
        bind(&outside),
        Err(PlanRefusal::ChildOutside {
            parent: cid("c-1"),
            child: cid("c-1a")
        })
    );
    let mut twice = request(&good, Selection::Preselected);
    twice.scan.absorbed.push(child);
    assert_eq!(bind(&twice), Err(PlanRefusal::DuplicateId(cid("c-1a"))));

    // An absorbed child rides with its parent; it is not selectable by itself.
    assert_eq!(
        bind(&request(&good, ids(&["c-1a"]))),
        Err(PlanRefusal::AbsorbedSelected(cid("c-1a")))
    );
}

#[test]
fn forbidden_items_cannot_be_selected() {
    let mut scan = plan();
    scan.items.extend([
        candidate(
            "blocked",
            path(r"C:\Vendor\b.txt"),
            Action::Quarantine,
            Band::Blocked,
            false,
        ),
        {
            let mut c = candidate(
                "hard",
                path(r"C:\Vendor\c.txt"),
                Action::Quarantine,
                Band::Likely,
                false,
            );
            c.blockers.push(Blocker::WindowsBaseline);
            c
        },
        {
            let mut c = safe("undecided", path(r"C:\Vendor\d.txt"), Action::Quarantine);
            c.decision = None;
            c
        },
        candidate(
            "report",
            path(r"C:\Vendor\e.txt"),
            Action::ReportOnly,
            Band::Likely,
            false,
        ),
        candidate(
            "wrong-action",
            path(r"C:\Vendor\f.txt"),
            Action::DeleteKey,
            Band::Likely,
            false,
        ),
        candidate(
            "truth-only",
            Target::RegValueChanged {
                path: r"HKLM\SOFTWARE\Vendor".into(),
                name: "Path".into(),
                before: "a".into(),
                after: "a;b".into(),
            },
            Action::DeleteValue,
            Band::Likely,
            false,
        ),
    ]);
    rehash(&mut scan);

    // Each is refused although the confirmation was computed for exactly that selection.
    let why = |id: &str| not_selectable(bind(&request(&scan, ids(&["c-1", id]))));
    assert_eq!(why("blocked"), NotSelectable::Blocked);
    assert_eq!(
        why("hard"),
        NotSelectable::HardBlocker(Blocker::WindowsBaseline)
    );
    assert_eq!(why("undecided"), NotSelectable::Undecided);
    assert_eq!(why("report"), NotSelectable::ReportOnly);
    assert_eq!(
        why("wrong-action"),
        NotSelectable::Unresolvable(Mismatch::WrongAction)
    );
    assert_eq!(
        why("truth-only"),
        NotSelectable::Unresolvable(Mismatch::TruthOnlyTarget)
    );

    assert_eq!(
        bind(&request(&scan, ids(&["c-1", "nope"]))),
        Err(PlanRefusal::UnknownId(cid("nope")))
    );
    assert_eq!(
        bind(&request(&scan, ids(&[]))),
        Err(PlanRefusal::EmptySelection)
    );
    assert_eq!(
        bind(&request(&scan, ids(&[""]))),
        Err(PlanRefusal::EmptySelection)
    );
    // The rest of the plan is still executable.
    assert!(bind(&request(&scan, Selection::Preselected)).is_ok());
}

#[test]
fn a_preselection_of_nothing_is_refused() {
    let scan = scan_doc(
        vec![candidate(
            "c-1",
            path(r"C:\Vendor\a.txt"),
            Action::Quarantine,
            Band::Likely,
            true,
        )],
        Vec::new(),
    );
    assert_eq!(
        bind(&request(&scan, Selection::Preselected)),
        Err(PlanRefusal::EmptySelection)
    );
}

#[test]
fn targets_without_an_executor_are_selectable_and_unresolved() {
    let scan = scan_doc(
        vec![
            safe(
                "svc",
                Target::Service {
                    name: "VendorSvc".into(),
                },
                Action::ReportOnly,
            ),
            safe(
                "task",
                Target::Task {
                    path: r"\Vendor\Update".into(),
                },
                Action::Quarantine,
            ),
            safe(
                "fw",
                Target::FirewallRule {
                    id: "{11111111-2222-3333-4444-555555555555}".into(),
                },
                Action::Quarantine,
            ),
        ],
        Vec::new(),
    );
    // Report-only stays report-only whatever the target.
    assert_eq!(
        not_selectable(bind(&request(&scan, ids(&["svc"])))),
        NotSelectable::ReportOnly
    );
    let bound = bind(&request(&scan, ids(&["task", "fw"]))).unwrap();
    assert!(bound.items().iter().all(|item| item.exec_op.is_none()));
    assert!(bound.exec_ops().is_empty());
}

#[test]
fn a_whole_tree_removal_over_a_protected_item_is_refused() {
    let mut scan = scan_doc(
        vec![
            candidate(
                "inner",
                path(r"C:\Vendor\keep\user.db"),
                Action::Quarantine,
                Band::Blocked,
                false,
            ),
            safe("tree", path(r"C:\Vendor"), Action::Quarantine),
        ],
        Vec::new(),
    );
    assert!(matches!(
        not_selectable(bind(&request(&scan, Selection::Preselected))),
        NotSelectable::ProtectedDescendant(_)
    ));
    // The same for an absorbed child with a hard blocker.
    scan.items.remove(0);
    let mut child = safe("kid", path(r"C:\Vendor\x.dll"), Action::Quarantine);
    child.blockers.push(Blocker::SharedRefcount);
    scan.items[0].children.push(cid("kid"));
    scan.absorbed.push(child);
    rehash(&mut scan);
    assert_eq!(
        not_selectable(bind(&request(&scan, Selection::Preselected))),
        NotSelectable::ProtectedDescendant(Blocker::SharedRefcount)
    );
    // A remove-if-empty of the same directory removes no tree and passes.
    scan.items[0].action = Action::RemoveDirIfEmpty;
    scan.items[0].children.clear();
    rehash(&mut scan);
    assert!(bind(&request(&scan, Selection::Preselected)).is_ok());
}

#[test]
fn the_inner_item_must_come_first() {
    let inner = safe("file", path(r"C:\Vendor\a.txt"), Action::Quarantine);
    let outer = safe("dir", path(r"C:\Vendor"), Action::RemoveDirIfEmpty);
    let val = safe(
        "val",
        value(r"HKLM\SOFTWARE\Vendor", "x"),
        Action::DeleteValue,
    );
    let its_key = safe(
        "key",
        key(r"HKLM\SOFTWARE\Vendor"),
        Action::RemoveDirIfEmpty,
    );

    let good = scan_doc(
        vec![inner.clone(), outer.clone(), val.clone(), its_key.clone()],
        Vec::new(),
    );
    assert!(bind(&request(&good, Selection::Preselected)).is_ok());

    let bad = scan_doc(vec![outer.clone(), inner.clone()], Vec::new());
    assert_eq!(
        bind(&request(&bad, Selection::Preselected)),
        Err(PlanRefusal::Order {
            inner: cid("file"),
            outer: cid("dir")
        })
    );
    // Only selected items count: the outer one alone is in order.
    assert!(bind(&request(&bad, ids(&["dir"]))).is_ok());

    let bad = scan_doc(vec![its_key, val], Vec::new());
    assert_eq!(
        bind(&request(&bad, Selection::Preselected)),
        Err(PlanRefusal::Order {
            inner: cid("val"),
            outer: cid("key")
        })
    );
}
