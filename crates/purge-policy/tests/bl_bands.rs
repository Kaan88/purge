//! The baseline trust cap in the policy (docs/BASELINE_LOCAL_DESIGN.md §4.4, invariants L4 and L5;
//! docs/BASELINE_LOCAL_DESIGN.json, package BL-POLICY), policy `bl.1`.
//!
//! - **The carrier.** `Blocker::BaselineInferred` is soft: an item that carries it is never Safe and never
//!   preselected, at any trust.
//! - **P-BL-1, the backstop.** With trust Merged or Local, evidence of an absence-dependent kind on a
//!   registry key does not support Safe, whether or not the blocker is there.
//! - With trust Exact or None nothing is capped: the rows of tests/golden.rs and tests/m1b_bands.rs run
//!   with trust Exact and are unchanged (`m1a_band_table_unchanged`).
//!
//! The golden rows are every absence-dependent kind x trust x blocker; the property checks draw candidates
//! from a small deterministic generator, so a failure reproduces from the printed seed.

use purge_model::{
    Action, AppRef, Band, BaselineTrust, Blocker, Candidate, CandidateId, Category, Evidence,
    EvidenceKind, Facts, Harm, ManifestKind, Origin, ProgramId, Reversibility, ScanMode, Scope,
    SourceTrust, Target, Tier, VerifyGone, View,
};
use purge_policy::band::{POLICY_VERSION, PolicyCtx, TargetScope, decide, is_capped, rank};
use purge_policy::explain::{
    BASELINE_KEY, BASELINE_NEIGHBOURS_KEY, BASELINE_TRUST_KEY, WINDOWS_BUILD_KEY,
};

const ADMIN: SourceTrust = SourceTrust::AdminOnly;
const USER: SourceTrust = SourceTrust::UserWritable;
const TRUSTS: [BaselineTrust; 4] = [
    BaselineTrust::Exact,
    BaselineTrust::Merged,
    BaselineTrust::Local,
    BaselineTrust::None,
];

const HKLM_KEY: &str = r"HKLM\SOFTWARE\Vendor\App";
const CLSID_KEY: &str = r"HKLM\SOFTWARE\Classes\CLSID\{11111111-2222-3333-4444-555555555555}";
const HKU_KEY: &str = r"HKU\S-1-5-21-1-2-3-1001\Software\Vendor\App";

// ---------------------------------------------------------------------------------------------------
// Builders

fn key(p: &str) -> Target {
    Target::RegKey { path: p.into() }
}
fn value(p: &str, name: &str) -> Target {
    Target::RegValue {
        path: p.into(),
        name: name.into(),
    }
}
fn path(p: &str) -> Target {
    Target::Path { path: p.into() }
}

fn ev(kind: EvidenceKind, scope: Scope, trust: SourceTrust, source: &str) -> Evidence {
    Evidence::new(kind, scope, trust, source)
        .unwrap_or_else(|| panic!("{kind:?} cannot have scope {scope:?}"))
}

/// A candidate with the usual defaults: scanner origin, harm Low, fully reversible, the action that
/// fits its target.
fn cand(target: Target, evidence: Vec<Evidence>) -> Candidate {
    let action = match &target {
        Target::Path { .. } => Action::Quarantine,
        Target::RegKey { .. } => Action::DeleteKey,
        _ => Action::DeleteValue,
    };
    Candidate {
        id: CandidateId("c-1".into()),
        target,
        action,
        owner: AppRef {
            program_id: ProgramId::machine(View::K64, "App_is1").unwrap(),
            display_name: "App".into(),
        },
        origin: Origin::Scanner,
        scanner: "TEST".into(),
        category: Category::Registration,
        evidence,
        blockers: Vec::new(),
        harm: Harm::Low,
        reversibility: Reversibility::Full,
        children: Vec::new(),
        size_bytes: None,
        child_count: None,
        decision: None,
        item_fp: None,
        object_fp: None,
    }
}

fn carried(mut c: Candidate) -> Candidate {
    c.blockers.push(Blocker::BaselineInferred);
    c
}

fn post(trust: BaselineTrust) -> PolicyCtx {
    PolicyCtx {
        mode: ScanMode::Post,
        verify_gone: VerifyGone::new(true, true, true),
        target_scope: TargetScope::Machine,
        baseline_trust: trust,
    }
}

fn verdict(c: &Candidate, ctx: &PolicyCtx) -> (Band, bool, i32) {
    let d = decide(c, ctx);
    (d.band, d.preselected, d.score)
}

fn time(scope: Scope) -> Evidence {
    ev(EvidenceKind::TimeWindow, scope, ADMIN, "time")
}

/// One Safe-capable key candidate per absence-dependent kind of design §4.4 (the three installer
/// manifests each have their own), with the score it has: at the M1b gate every one of them is Safe
/// and preselected.
fn absence_dependent_keys() -> Vec<(&'static str, Candidate, i32)> {
    use EvidenceKind::*;
    let manifest = |kind: ManifestKind| {
        cand(
            key(HKLM_KEY),
            vec![ev(InstallerManifest(kind), Scope::Key, ADMIN, "installer")],
        )
    };
    vec![
        (
            "ProvenOwnedSkeleton",
            cand(
                key(r"HKLM\SOFTWARE\Classes\sh_auto_file"),
                vec![ev(ProvenOwnedSkeleton, Scope::Key, ADMIN, "subtree")],
            ),
            8,
        ),
        (
            "ComKeyOwnership",
            cand(
                key(CLSID_KEY),
                vec![
                    ev(ComKeyOwnership, Scope::Key, ADMIN, "com"),
                    time(Scope::Key),
                ],
            ),
            8,
        ),
        (
            "HarvestedToken",
            cand(
                key(r"HKLM\SOFTWARE\Classes\FirefoxHTML-308046B0AF4A39CB"),
                vec![
                    ev(HarvestedToken, Scope::Key, ADMIN, "tokens"),
                    time(Scope::Key),
                ],
            ),
            8,
        ),
        (
            "InstallerManifest(Inno), key scope",
            manifest(ManifestKind::Inno),
            8,
        ),
        (
            "InstallerManifest(Msi), key scope",
            manifest(ManifestKind::Msi),
            8,
        ),
        (
            "InstallerManifest(Burn), key scope",
            manifest(ManifestKind::Burn),
            8,
        ),
        (
            "ChainedRef, key scope",
            cand(
                key(r"HKLM\SOFTWARE\Classes\.app\OpenWithProgids"),
                vec![
                    Evidence::chained(Tier::A, Scope::Key, ADMIN, "assoc").unwrap(),
                    ev(NameTokenExact, Scope::Key, ADMIN, "name"),
                ],
            ),
            8,
        ),
    ]
}

// ---------------------------------------------------------------------------------------------------
// Golden rows

#[test]
fn policy_version_is_bl_1() {
    assert_eq!(POLICY_VERSION, "bl.1");
}

/// What every absence-dependent kind decides, by trust and by whether the carrier blocker is there.
/// Rows in the order of [`TRUSTS`]: Exact, Merged, Local, None.
const WITHOUT_BLOCKER: [(Band, bool); 4] = [
    (Band::Safe, true),
    (Band::Likely, false),
    (Band::Likely, false),
    (Band::Safe, true),
];
const WITH_BLOCKER: [(Band, bool); 4] = [
    (Band::Likely, false),
    (Band::Likely, false),
    (Band::Likely, false),
    (Band::Likely, false),
];

/// Golden rows: each absence-dependent kind x trust (Exact, Merged, Local, None) x blocker present or
/// absent. 7 evidence forms x 4 x 2 = 56 rows. The score is the same in all eight: the cap changes what
/// supports Safe, not what the item is shown with.
#[test]
fn golden_absence_dependent_kind_by_trust_by_blocker() {
    let mut rows = 0;
    let mut failures = Vec::new();
    for (name, candidate, score) in absence_dependent_keys() {
        assert!(
            candidate
                .evidence
                .iter()
                .any(|e| e.is_absence_dependent(&candidate.target)),
            "{name}"
        );
        for (blocker, expected) in [(false, WITHOUT_BLOCKER), (true, WITH_BLOCKER)] {
            let c = if blocker {
                carried(candidate.clone())
            } else {
                candidate.clone()
            };
            for (trust, (band, preselected)) in TRUSTS.into_iter().zip(expected) {
                rows += 1;
                let got = verdict(&c, &post(trust));
                if got != (band, preselected, score) {
                    failures.push(format!(
                        "{name}, {trust:?}, blocker {blocker}: got {got:?}, expected \
                         ({band:?}, {preselected}, {score})"
                    ));
                }
            }
        }
    }
    assert_eq!(rows, 56);
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// Golden rows: evidence on a key that is **not** absence-dependent stays Safe at every trust, and the
/// carrier alone still caps it.
#[test]
fn golden_not_absence_dependent_keys_stay_safe() {
    use EvidenceKind::*;
    let cases = [
        (
            "UninstallerArtifact",
            cand(
                key(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\App_is1"),
                vec![
                    ev(UninstallerArtifact, Scope::Key, ADMIN, "arp"),
                    ev(NameTokenExact, Scope::Key, ADMIN, "name"),
                ],
            ),
            9,
        ),
        (
            "AppNamedKeyWithRootRef",
            cand(
                key(HKLM_KEY),
                vec![
                    ev(AppNamedKeyWithRootRef, Scope::Key, ADMIN, "software"),
                    time(Scope::Key),
                ],
            ),
            8,
        ),
    ];
    for (name, candidate, score) in cases {
        assert!(!candidate.has_absence_dependent_evidence(), "{name}");
        for trust in TRUSTS {
            assert_eq!(
                verdict(&candidate, &post(trust)),
                (Band::Safe, true, score),
                "{name} {trust:?}"
            );
            assert_eq!(
                verdict(&carried(candidate.clone()), &post(trust)),
                (Band::Likely, false, score),
                "{name} {trust:?} with the blocker"
            );
        }
    }
}

struct Row {
    name: &'static str,
    candidate: Candidate,
    ctx: PolicyCtx,
    band: Band,
    preselected: bool,
    score: i32,
}

/// Golden rows around the edges of P-BL-1.
#[allow(clippy::too_many_lines)]
#[test]
fn golden_edges_of_the_backstop() {
    use Band::{Blocked, Likely, Safe};
    use BaselineTrust::{Exact, Local, Merged, None as NoBaseline};
    use EvidenceKind::*;
    let mut rows: Vec<Row> = Vec::new();
    let mut add = |name, candidate, ctx, band, preselected, score| {
        rows.push(Row {
            name,
            candidate,
            ctx,
            band,
            preselected,
            score,
        });
    };
    let app_named = || {
        cand(
            key(HKLM_KEY),
            vec![
                ev(AppNamedKeyWithRootRef, Scope::Key, ADMIN, "software"),
                time(Scope::Key),
            ],
        )
    };
    let token = || ev(HarvestedToken, Scope::Key, ADMIN, "tokens");
    let with = |mut c: Candidate, e: Evidence| {
        c.evidence.push(e);
        c
    };

    // --- An item that is Safe on its other evidence alone is not under the cap (L5: it is Safe with no
    //     baseline too) ---------------------------------------------------------------------------
    add(
        "merged: safe on other evidence, the inferred token adds nothing and takes nothing",
        with(app_named(), token()),
        post(Merged),
        Safe,
        true,
        15,
    );
    add(
        "exact: the same item",
        with(app_named(), token()),
        post(Exact),
        Safe,
        true,
        15,
    );
    // --- The weight of capped evidence does not count toward S >= 8 --------------------------------
    let seven_plus_token = || {
        cand(
            key(HKLM_KEY),
            vec![
                ev(AppNamedKeyWithRootRef, Scope::Key, ADMIN, "software"),
                token(),
            ],
        )
    };
    add(
        "exact: other evidence scores 7, the token brings it to 14",
        seven_plus_token(),
        post(Exact),
        Safe,
        true,
        14,
    );
    add(
        "merged: other evidence scores 7, the inferred token does not bring it to 8",
        seven_plus_token(),
        post(Merged),
        Likely,
        false,
        14,
    );
    add(
        "local: other evidence scores 7, the inferred token does not bring it to 8",
        seven_plus_token(),
        post(Local),
        Likely,
        false,
        14,
    );
    add(
        "none: the policy decides as with exact (the scanner answers no absence there)",
        seven_plus_token(),
        post(NoBaseline),
        Safe,
        true,
        14,
    );
    // --- External mode: capped evidence is not the admin-only proof either -------------------------
    let external = |trust| PolicyCtx {
        mode: ScanMode::External,
        ..post(trust)
    };
    let external_item = || {
        cand(
            key(HKLM_KEY),
            vec![
                ev(AppNamedKeyWithRootRef, Scope::Key, ADMIN, "software"),
                ev(TimeWindow, Scope::Key, USER, "time"),
                token(),
            ],
        )
    };
    add(
        "external, exact: admin-only evidence scores 14",
        external_item(),
        external(Exact),
        Safe,
        true,
        15,
    );
    add(
        "external, merged: admin-only evidence without the inferred token scores 7",
        external_item(),
        external(Merged),
        Likely,
        false,
        15,
    );
    // --- Only keys, and only key-scope records -----------------------------------------------------
    let token_value = || {
        cand(
            value(HKLM_KEY, "308046B0AF4A39CB"),
            vec![
                ev(HarvestedToken, Scope::Value, ADMIN, "tokens"),
                time(Scope::Value),
            ],
        )
    };
    add(
        "merged: a token on a value is not about a key's absence",
        token_value(),
        post(Merged),
        Safe,
        true,
        8,
    );
    let token_path = || {
        cand(
            path(r"C:\ProgramData\Vendor\308046B0AF4A39CB"),
            vec![
                ev(HarvestedToken, Scope::Path, ADMIN, "tokens"),
                time(Scope::Path),
            ],
        )
    };
    add(
        "local: a token on a path is not about a key's absence",
        token_path(),
        post(Local),
        Safe,
        true,
        8,
    );
    add(
        "merged: a value record of the installer on a value",
        cand(
            value(HKLM_KEY, "InstallDir"),
            vec![ev(
                InstallerManifest(ManifestKind::Msi),
                Scope::Value,
                ADMIN,
                "msi",
            )],
        ),
        post(Merged),
        Safe,
        true,
        8,
    );
    add(
        "merged: a chained reference on a value",
        cand(
            value(r"HKLM\SOFTWARE\Classes\.txt\OpenWithProgids", "App.txt"),
            vec![
                Evidence::chained(Tier::A, Scope::Value, ADMIN, "assoc").unwrap(),
                ev(InPreUninstallRefSnapshot, Scope::Value, ADMIN, "refsnap"),
            ],
        ),
        post(Merged),
        Safe,
        true,
        13,
    );
    add(
        "merged: a value record beside the app-named key is not capped and scores",
        with(
            app_named(),
            ev(
                InstallerManifest(ManifestKind::Inno),
                Scope::Value,
                ADMIN,
                "inno",
            ),
        ),
        post(Merged),
        Safe,
        true,
        16,
    );
    add(
        "merged: the carrier on a path caps it too",
        carried(token_path()),
        post(Merged),
        Likely,
        false,
        8,
    );
    add(
        "exact: the carrier on a value caps it too",
        carried(token_value()),
        post(Exact),
        Likely,
        false,
        8,
    );
    // --- Evidence that says of itself that its absence was inferred --------------------------------
    let declared = |trust_fact: &str| {
        cand(
            key(r"HKLM\SOFTWARE\Classes\sh_auto_file"),
            vec![
                ev(ProvenOwnedSkeleton, Scope::Key, ADMIN, "subtree")
                    .with_detail(Facts::new().with(BASELINE_TRUST_KEY, trust_fact)),
            ],
        )
    };
    add(
        "exact context, evidence declares merged: capped (a fingerprint harvested below Exact)",
        declared("merged"),
        post(Exact),
        Likely,
        false,
        8,
    );
    add(
        "no-baseline context, evidence declares local: capped",
        declared("local"),
        post(NoBaseline),
        Likely,
        false,
        8,
    );
    add(
        "exact context, evidence declares an unknown trust: capped",
        declared("verified"),
        post(Exact),
        Likely,
        false,
        8,
    );
    add(
        "exact context, evidence declares exact: proof, as before",
        declared("exact"),
        post(Exact),
        Safe,
        true,
        8,
    );
    add(
        "merged context, evidence declares exact: the context caps it",
        declared("exact"),
        post(Merged),
        Likely,
        false,
        8,
    );
    // --- The other rules still apply on top --------------------------------------------------------
    add(
        "merged: a hard blocker blocks as ever",
        {
            let mut c = carried(absence_dependent_keys().remove(0).1);
            c.blockers.push(Blocker::WindowsBaseline);
            c
        },
        post(Merged),
        Blocked,
        false,
        8,
    );
    add(
        "merged, forced: an item safe on other evidence is still not ticked in forced mode",
        with(app_named(), token()),
        PolicyCtx {
            mode: ScanMode::Forced,
            ..post(Merged)
        },
        Likely,
        false,
        15,
    );
    add(
        "merged: an Ai note of an absence-dependent kind is no evidence and brings no cap",
        {
            let mut ai = token();
            ai.tier = Tier::Ai;
            ai.weight = 3;
            with(app_named(), ai)
        },
        post(Merged),
        Safe,
        true,
        8,
    );
    add(
        "merged: a per-user key is capped like a machine key",
        cand(
            key(HKU_KEY),
            vec![ev(
                InstallerManifest(ManifestKind::Inno),
                Scope::Key,
                USER,
                "inno",
            )],
        ),
        PolicyCtx {
            target_scope: TargetScope::PerUser,
            ..post(Merged)
        },
        Likely,
        false,
        8,
    );

    let mut names: Vec<_> = rows.iter().map(|r| r.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), rows.len(), "a row name is used twice");
    assert_eq!(rows.len(), 24);
    let mut failures = Vec::new();
    for r in &rows {
        let d = decide(&r.candidate, &r.ctx);
        if (d.band, d.preselected, d.score) != (r.band, r.preselected, r.score) {
            failures.push(format!(
                "{}: got ({:?}, {}, {}), expected ({:?}, {}, {}) [{}]",
                r.name,
                d.band,
                d.preselected,
                d.score,
                r.band,
                r.preselected,
                r.score,
                d.explanation
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// `is_capped` is the one predicate behind P-BL-1: an absence-dependent kind, on a key, with an inferred
/// trust (from the context or declared by the evidence).
#[test]
fn is_capped_is_kind_and_key_and_inferred_trust() {
    for (name, candidate, _) in absence_dependent_keys() {
        let e = candidate
            .evidence
            .iter()
            .find(|e| e.is_absence_dependent(&candidate.target))
            .unwrap();
        for trust in TRUSTS {
            assert_eq!(
                is_capped(e, &candidate.target, trust),
                trust.is_inferred(),
                "{name} {trust:?}"
            );
            assert!(
                !is_capped(e, &value(HKLM_KEY, "v"), trust),
                "{name} {trust:?}"
            );
            assert!(!is_capped(e, &path(r"C:\x"), trust), "{name} {trust:?}");
            let declared = e
                .clone()
                .with_detail(Facts::new().with(BASELINE_TRUST_KEY, "merged"));
            assert!(
                is_capped(&declared, &candidate.target, trust),
                "{name} {trust:?}"
            );
        }
        // The seal's question (design §4.4 layer 2) has the same definition.
        assert!(candidate.lacks_baseline_cap(), "{name}");
        assert!(!carried(candidate.clone()).lacks_baseline_cap(), "{name}");
    }
    let other = ev(
        EvidenceKind::AppNamedKeyWithRootRef,
        Scope::Key,
        ADMIN,
        "software",
    );
    assert!(!is_capped(&other, &key(HKLM_KEY), BaselineTrust::Merged));
    assert!(!cand(key(HKLM_KEY), vec![other]).lacks_baseline_cap());
}

// ---------------------------------------------------------------------------------------------------
// Explanations

#[test]
fn golden_explanations_of_the_cap() {
    let explain = |c: &Candidate, trust: BaselineTrust| decide(c, &post(trust)).explanation;
    let skeleton = |facts: Facts| {
        cand(
            key(r"HKLM\SOFTWARE\Classes\sh_auto_file"),
            vec![
                ev(
                    EvidenceKind::ProvenOwnedSkeleton,
                    Scope::Key,
                    ADMIN,
                    "subtree",
                )
                .with_detail(facts),
            ],
        )
    };
    let merged_facts = || {
        Facts::new()
            .with(BASELINE_KEY, "local-Professional-26300.9974-ab12+2")
            .with(BASELINE_TRUST_KEY, "merged")
            .with(
                BASELINE_NEIGHBOURS_KEY,
                "Professional-26340.9882, EnterpriseSEval-26100.1742",
            )
            .with(WINDOWS_BUILD_KEY, "26300.9974")
    };
    const FULL: &str = "Everything in it belonged to App · now empty · not in this PC's Windows \
                        component list, nor in clean Windows Professional-26340.9882, \
                        EnterpriseSEval-26100.1742 · Not preselected: there is no verified \
                        clean-install list for Windows build 26300.9974";

    // Both templates of design §4.4, as the scanner layer produces them: facts and the carrier.
    let carrier = carried(skeleton(merged_facts()));
    assert_eq!(explain(&carrier, BaselineTrust::Merged), FULL);
    // The carrier alone is enough: the same text when the context was not told the trust.
    assert_eq!(explain(&carrier, BaselineTrust::Exact), FULL);
    assert_eq!(explain(&carrier, BaselineTrust::None), FULL);
    // The backstop alone is enough: the same text without the blocker, from the policy's own note,
    // and the line is there once, not twice, when both speak.
    assert_eq!(
        explain(&skeleton(merged_facts()), BaselineTrust::Merged),
        FULL
    );
    assert_eq!(
        explain(&skeleton(merged_facts()), BaselineTrust::Exact),
        FULL
    );
    assert_eq!(FULL.matches("Not preselected").count(), 1);

    // The backstop on evidence that says nothing about its trust: no exact wording survives, and the
    // capped proof is not called a proof "about a different kind of item".
    let bare = skeleton(Facts::new().with(BASELINE_KEY, "Professional-26340.9882"));
    assert_eq!(
        explain(&bare, BaselineTrust::Local),
        "Everything in it belonged to App · now empty · not in this PC's Windows component list · \
         Not preselected: there is no verified clean-install list for this Windows build"
    );
    // With an exact baseline the M1b text, to the letter.
    assert_eq!(
        explain(&bare, BaselineTrust::Exact),
        "Everything in it belonged to App · now empty · not on clean Windows Professional-26340.9882"
    );
    assert_eq!(
        explain(&bare, BaselineTrust::None),
        explain(&bare, BaselineTrust::Exact)
    );

    // A kind without a baseline line of its own gets the cap line only.
    let token = cand(
        key(r"HKLM\SOFTWARE\Classes\FirefoxHTML-308046B0AF4A39CB"),
        vec![
            ev(EvidenceKind::HarvestedToken, Scope::Key, ADMIN, "tokens").with_detail(
                Facts::new()
                    .with("token", "308046B0AF4A39CB")
                    .with(WINDOWS_BUILD_KEY, "26300.9974"),
            ),
            time(Scope::Key),
        ],
    );
    assert_eq!(
        explain(&token, BaselineTrust::Merged),
        "Carries App's identifier 308046B0AF4A39CB · Created or changed while App was being \
         installed or removed · Not preselected: there is no verified clean-install list for \
         Windows build 26300.9974"
    );
    assert_eq!(
        explain(&token, BaselineTrust::Exact),
        "Carries App's identifier 308046B0AF4A39CB · Created or changed while App was being \
         installed or removed"
    );

    // An item that is Safe on its other evidence is not told it is "not preselected".
    let safe = cand(
        key(HKLM_KEY),
        vec![
            ev(
                EvidenceKind::AppNamedKeyWithRootRef,
                Scope::Key,
                ADMIN,
                "software",
            ),
            time(Scope::Key),
            ev(EvidenceKind::HarvestedToken, Scope::Key, ADMIN, "tokens"),
        ],
    );
    let d = decide(&safe, &post(BaselineTrust::Merged));
    assert_eq!((d.band, d.preselected), (Band::Safe, true));
    assert!(
        !d.explanation.contains("Not preselected"),
        "{}",
        d.explanation
    );
    // A Blocked item is explained by its hard blocker only.
    let mut blocked = carrier.clone();
    blocked.blockers.push(Blocker::WindowsBaseline);
    assert_eq!(
        explain(&blocked, BaselineTrust::Merged),
        "Kept: part of a clean Windows installation"
    );
}

// ---------------------------------------------------------------------------------------------------
// Property checks

/// xorshift64*: small, deterministic, good enough to vary test inputs.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % (n as u64)).unwrap()
    }
    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
    fn pick<T: Clone>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())].clone()
    }
}

fn random_evidence(rng: &mut Rng) -> Evidence {
    let mut kinds = EvidenceKind::ALL.to_vec();
    kinds.push(EvidenceKind::InstallerManifest(ManifestKind::Msi));
    kinds.push(EvidenceKind::InstallerManifest(ManifestKind::Burn));
    // The kinds this file is about, more often.
    for _ in 0..3 {
        kinds.extend([
            EvidenceKind::ProvenOwnedSkeleton,
            EvidenceKind::ComKeyOwnership,
            EvidenceKind::HarvestedToken,
            EvidenceKind::ChainedRef,
            EvidenceKind::AppNamedKeyWithRootRef,
            EvidenceKind::UninstallerArtifact,
            EvidenceKind::TimeWindow,
        ]);
    }
    let kind = rng.pick(&kinds);
    let allowed: Vec<Scope> = kind.scope().iter().collect();
    let scope = if rng.chance(85) {
        rng.pick(&allowed)
    } else {
        rng.pick(&Scope::ALL)
    };
    let mut e = Evidence {
        kind,
        tier: kind.default_tier(),
        weight: kind.default_weight(),
        scope,
        trust: if rng.chance(75) { ADMIN } else { USER },
        source: rng.pick(&["a", "b", "c", "d"]).into(),
        detail: Facts::new(),
    };
    if rng.chance(10) {
        e.tier = rng.pick(&[Tier::A, Tier::B, Tier::C, Tier::Ai]);
    }
    if rng.chance(10) {
        e.weight = i8::try_from(rng.below(18)).unwrap() - 7;
    }
    if rng.chance(6) {
        let fact = rng.pick(&["exact", "merged", "local", "none", "?"]);
        e.detail = Facts::new().with(BASELINE_TRUST_KEY, fact);
    }
    e
}

fn random_candidate(rng: &mut Rng) -> Candidate {
    let target = rng.pick(&[
        key(HKLM_KEY),
        key(HKLM_KEY),
        key(CLSID_KEY),
        key(HKU_KEY),
        value(HKLM_KEY, "v"),
        value(HKU_KEY, "v"),
        path(r"C:\Program Files\App"),
        Target::Service {
            name: "AppSvc".into(),
        },
    ]);
    let evidence = (0..rng.below(6)).map(|_| random_evidence(rng)).collect();
    let mut c = cand(target, evidence);
    if rng.chance(15) {
        c.action = rng.pick(&[
            Action::Quarantine,
            Action::DeleteKey,
            Action::DeleteValue,
            Action::RemoveDirIfEmpty,
            Action::ReportOnly,
        ]);
    }
    if rng.chance(25) {
        c.category = rng.pick(&[
            Category::Association,
            Category::ShellCom,
            Category::UserData,
            Category::System,
        ]);
    }
    c.harm = rng.pick(&[Harm::None, Harm::Low, Harm::Low, Harm::Low, Harm::Medium]);
    c.origin = rng.pick(&[
        Origin::Scanner,
        Origin::Scanner,
        Origin::Scanner,
        Origin::Signature,
        Origin::ProbeAgent,
    ]);
    if rng.chance(8) {
        c.reversibility = rng.pick(&[Reversibility::Partial, Reversibility::None]);
    }
    if rng.chance(12) {
        c.blockers.push(rng.pick(&[
            Blocker::BaselineInferred,
            Blocker::BaselineInferred,
            Blocker::UnmatchedChildren { n: 1 },
            Blocker::InUse,
        ]));
    }
    if rng.chance(5) {
        c.blockers.push(rng.pick(&[
            Blocker::WindowsBaseline,
            Blocker::TrustedInstallerOwned,
            Blocker::ExistedBeforeInstall,
        ]));
    }
    c
}

/// A context with everything but the baseline trust drawn at random; the trust is set by each check.
fn random_ctx(rng: &mut Rng) -> PolicyCtx {
    PolicyCtx {
        mode: rng.pick(&[
            ScanMode::Post,
            ScanMode::Post,
            ScanMode::Post,
            ScanMode::External,
            ScanMode::Forced,
        ]),
        verify_gone: VerifyGone::new(rng.chance(95), rng.chance(97), rng.chance(97)),
        target_scope: rng.pick(&[TargetScope::Machine, TargetScope::PerUser]),
        baseline_trust: BaselineTrust::Exact,
    }
}

const ROUNDS: u64 = 40_000;

fn for_all(mut check: impl FnMut(&Candidate, &PolicyCtx, u64)) {
    for seed in 1..=ROUNDS {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let candidate = random_candidate(&mut rng);
        let ctx = random_ctx(&mut rng);
        check(&candidate, &ctx, seed);
    }
}

fn at(ctx: &PolicyCtx, trust: BaselineTrust) -> PolicyCtx {
    PolicyCtx {
        baseline_trust: trust,
        ..*ctx
    }
}

/// The candidate as it would be had no inferred absence been answered: without the evidence P-BL-1
/// caps at `trust`.
fn without_capped(c: &Candidate, trust: BaselineTrust) -> Candidate {
    let mut stripped = c.clone();
    stripped
        .evidence
        .retain(|e| !is_capped(e, &c.target, trust));
    stripped
}

/// The generator reaches what the checks below are about, often enough to mean something.
#[test]
fn generator_reaches_the_cap() {
    let (mut capped, mut safe_exact, mut lowered, mut safe_inferred) = (0u32, 0u32, 0u32, 0u32);
    for_all(|c, ctx, _| {
        let exact = decide(c, &at(ctx, BaselineTrust::Exact));
        let merged = decide(c, &at(ctx, BaselineTrust::Merged));
        capped += u32::from(
            c.evidence
                .iter()
                .any(|e| is_capped(e, &c.target, BaselineTrust::Merged)),
        );
        safe_exact += u32::from(exact.band == Band::Safe);
        lowered += u32::from(exact.band == Band::Safe && merged.band != Band::Safe);
        safe_inferred +=
            u32::from(merged.band == Band::Safe && matches!(c.target, Target::RegKey { .. }));
    });
    assert!(capped > 5_000, "capped: {capped}");
    assert!(safe_exact > 2_000, "safe with exact: {safe_exact}");
    assert!(lowered > 500, "lowered by the cap: {lowered}");
    assert!(
        safe_inferred > 200,
        "keys safe on other evidence: {safe_inferred}"
    );
}

/// L4, the invariant itself: with an inferred trust, an item is Safe or preselected only if it is so
/// **without** every piece of evidence that rests on inferred absence. Inferred absence never makes an
/// item Safe or preselected; it is at most along for the ride.
#[test]
fn inferred_absence_never_makes_an_item_safe_or_preselected() {
    for_all(|c, ctx, seed| {
        for trust in [BaselineTrust::Merged, BaselineTrust::Local] {
            let ctx = at(ctx, trust);
            let d = decide(c, &ctx);
            if d.band != Band::Safe && !d.preselected {
                continue;
            }
            let stripped = without_capped(c, trust);
            assert!(
                !stripped.has_absence_dependent_evidence(),
                "seed {seed}: at an inferred trust every absence-dependent piece is capped"
            );
            let alone = decide(&stripped, &ctx);
            assert_eq!(
                (alone.band, alone.preselected),
                (d.band, d.preselected),
                "seed {seed} {trust:?}"
            );
            // And it is Safe with no baseline at all, where the scanner would not have produced the
            // absence-dependent evidence (L5: preselected(non-exact view) is a subset).
            let none = decide(&stripped, &at(&ctx, BaselineTrust::None));
            assert_eq!(
                (none.band, none.preselected),
                (d.band, d.preselected),
                "seed {seed} {trust:?}"
            );
        }
    });
}

/// The same for evidence that declares its own absence inferred, at the trusts that cap nothing by
/// themselves.
#[test]
fn declared_inferred_absence_never_makes_an_item_safe_or_preselected() {
    for_all(|c, ctx, seed| {
        for trust in [BaselineTrust::Exact, BaselineTrust::None] {
            let ctx = at(ctx, trust);
            let d = decide(c, &ctx);
            if d.band != Band::Safe && !d.preselected {
                continue;
            }
            let alone = decide(&without_capped(c, trust), &ctx);
            assert_eq!(
                (alone.band, alone.preselected),
                (d.band, d.preselected),
                "seed {seed} {trust:?}"
            );
        }
    });
}

/// The carrier: `BaselineInferred` on any target, at any trust, in any mode, is never Safe and never
/// preselected, and it never blocks by itself.
#[test]
fn the_carrier_alone_is_enough() {
    for_all(|c, ctx, seed| {
        let with_carrier = carried(c.clone());
        for trust in TRUSTS {
            let ctx = at(ctx, trust);
            let d = decide(&with_carrier, &ctx);
            assert!(
                d.band != Band::Safe && !d.preselected,
                "seed {seed} {trust:?}"
            );
            let before = decide(c, &ctx);
            assert_eq!(
                d.band == Band::Blocked,
                before.band == Band::Blocked,
                "seed {seed} {trust:?}"
            );
            assert_eq!(d.score, before.score, "seed {seed} {trust:?}");
        }
    });
}

/// The trust only ever lowers: an inferred trust never gives a better band than Exact, never
/// preselects what Exact does not, and never changes the score or what is Blocked.
#[test]
fn an_inferred_trust_never_raises_a_band() {
    for_all(|c, ctx, seed| {
        let exact = decide(c, &at(ctx, BaselineTrust::Exact));
        for trust in [BaselineTrust::Merged, BaselineTrust::Local] {
            let d = decide(c, &at(ctx, trust));
            assert!(rank(d.band) <= rank(exact.band), "seed {seed} {trust:?}");
            assert!(!d.preselected || exact.preselected, "seed {seed} {trust:?}");
            assert_eq!(d.score, exact.score, "seed {seed} {trust:?}");
            assert_eq!(
                d.band == Band::Blocked,
                exact.band == Band::Blocked,
                "seed {seed} {trust:?}"
            );
            // The cap takes Safe away and nothing else: a band below Safe does not move. (An item
            // with a negative Ai note is left out: rule 7 moves it one band down from wherever the
            // other rules put it, so Safe-then-Likely with Exact is Likely-then-Weak under the cap.)
            let ai_negative = c
                .evidence
                .iter()
                .any(|e| e.tier == Tier::Ai && e.weight < 0);
            if exact.band != Band::Safe && !ai_negative {
                assert_eq!(d.band, exact.band, "seed {seed} {trust:?}");
            }
        }
    });
}

/// Exact and None decide alike, to the letter; so do Merged and Local. And where nothing is
/// absence-dependent and nothing carries the cap, all four agree: the trust is inert for every file,
/// value, package and typed object, and for every key without such evidence.
#[test]
fn the_trust_is_inert_where_no_absence_is_used() {
    for_all(|c, ctx, seed| {
        let [exact, merged, local, none] = TRUSTS.map(|t| decide(c, &at(ctx, t)));
        assert_eq!(exact, none, "seed {seed}");
        assert_eq!(merged, local, "seed {seed}");
        if !c.has_absence_dependent_evidence() {
            assert_eq!(exact, merged, "seed {seed}");
        }
        if !matches!(c.target, Target::RegKey { .. }) {
            assert!(!c.has_absence_dependent_evidence(), "seed {seed}");
        }
    });
}
