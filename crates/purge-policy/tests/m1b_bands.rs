//! M1b band tests: the C-POLICY rules of policy `m1b.1` (docs/M1B_DESIGN.json, package M1B-POLICY).
//!
//! One test per rule:
//! - P-OBJ-1: a typed object (service, task, firewall rule) is Safe only with `OwnedSystemObject`, no soft
//!   blocker, harm <= Low and `Reversibility::Full`; `Category::System` is Safe only for such an object.
//! - P-OBJ-2: `ReversibilityPartial` and `ProgramUnresolved` are soft; a typed object with
//!   `Reversibility::Partial` is treated as carrying `ReversibilityPartial` even when the scanner left it out.
//! - P-MSI-1: `InstallerManifest` (Msi, Burn) is Tier A with matching scope for Key, Value and Path targets.
//! - P-PATH-1: `PointsIntoInstallRoot` + `DanglingRef` on a path-keyed-store value is Safe; the first alone
//!   is Likely.
//! - The M1b hard blockers (`Driver`, `HasDependents`, `ObjectChangedSinceHarvest`) protect.
//! - The M1a golden table is unchanged apart from its version key.

use purge_model::{
    Action, AppRef, Band, Blocker, Candidate, CandidateId, Category, Evidence, EvidenceKind, Harm,
    ManifestKind, Origin, ProgramId, Reversibility, ScanMode, Scope, SourceTrust, Target, Tier,
    VerifyGone, View,
};
use purge_policy::band::{POLICY_VERSION, PolicyCtx, TargetScope, decide, effective_tier};
use purge_policy::score::SAFE_MIN;

const ADMIN: SourceTrust = SourceTrust::AdminOnly;
const USER: SourceTrust = SourceTrust::UserWritable;
const OSO: EvidenceKind = EvidenceKind::OwnedSystemObject;
const MSI: EvidenceKind = EvidenceKind::InstallerManifest(ManifestKind::Msi);
const BURN: EvidenceKind = EvidenceKind::InstallerManifest(ManifestKind::Burn);
const PARTIAL_LINE: &str = "Undo cannot bring back all of it";

// ---------------------------------------------------------------------------------------------------
// Builders

fn ev(kind: EvidenceKind, scope: Scope, trust: SourceTrust, source: &str) -> Evidence {
    Evidence::new(kind, scope, trust, source)
        .unwrap_or_else(|| panic!("{kind:?} cannot have scope {scope:?}"))
}

fn cand(target: Target, action: Action, category: Category, evidence: Vec<Evidence>) -> Candidate {
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
        category,
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
        display_name: None,
        owner_program: None,
    }
}

fn post(target_scope: TargetScope) -> PolicyCtx {
    PolicyCtx {
        baseline_trust: purge_model::BaselineTrust::Exact,
        mode: ScanMode::Post,
        verify_gone: VerifyGone::new(true, true, true),
        target_scope,
    }
}
fn post_machine() -> PolicyCtx {
    post(TargetScope::Machine)
}

fn service() -> Target {
    Target::Service {
        name: "AppUpdateSvc".into(),
    }
}
fn task() -> Target {
    Target::Task {
        path: r"\Vendor\App Updater".into(),
    }
}
fn firewall_rule() -> Target {
    Target::FirewallRule {
        id: "{6A3B1C2D-0000-4000-8000-00000000F00D}".into(),
    }
}

/// The three typed objects with the category their scanners give them (C-MODEL-SCOPE).
fn typed_objects() -> [(Target, Category); 3] {
    [
        (service(), Category::System),
        (task(), Category::Startup),
        (firewall_rule(), Category::System),
    ]
}

/// A typed object as its scanner emits it when the harvest recorded it and its program is gone.
fn owned_object(target: Target, category: Category) -> Candidate {
    cand(
        target,
        Action::DeleteKey,
        category,
        vec![ev(OSO, Scope::Object, ADMIN, "harvest-sysobj")],
    )
}

/// `(band, preselected, score)` of `c` in `ctx`.
fn verdict(c: &Candidate, ctx: &PolicyCtx) -> (Band, bool, i32) {
    let d = decide(c, ctx);
    (d.band, d.preselected, d.score)
}

fn explanation(c: &Candidate) -> String {
    decide(c, &post_machine()).explanation
}

// ---------------------------------------------------------------------------------------------------
// P-OBJ-1

#[test]
fn object_safe_needs_owned_system_object() {
    for (target, category) in typed_objects() {
        let name = format!("{target:?}");

        // With OwnedSystemObject, no blocker, harm Low, full undo: Safe and preselected.
        let owned = owned_object(target.clone(), category);
        assert_eq!(
            verdict(&owned, &post_machine()),
            (Band::Safe, true, 8),
            "{name}"
        );
        // Also when the caller classified the target as per-user: typed objects are machine scope.
        assert_eq!(
            verdict(&owned, &post(TargetScope::PerUser)),
            (Band::Safe, true, 8),
            "{name}"
        );

        // Without it: the strongest other evidence, even recorded with Object scope, is not enough.
        let manifest = cand(
            target.clone(),
            Action::DeleteKey,
            category,
            vec![
                ev(MSI, Scope::Object, ADMIN, "msi-serviceinstall"),
                ev(EvidenceKind::TimeWindow, Scope::Object, ADMIN, "t"),
            ],
        );
        let (band, preselected, score) = verdict(&manifest, &post_machine());
        assert!(score >= SAFE_MIN, "{name}: {score}");
        assert_eq!((band, preselected), (Band::Likely, false), "{name}");
        assert!(
            effective_tier(&manifest.evidence[0], TargetScope::Machine) == Tier::A,
            "{name}: the manifest itself is Tier A; only P-OBJ-1 keeps it from Safe"
        );

        // OwnedSystemObject that does not count as Tier A for a machine-wide object does not either.
        let mut from_user = owned.clone();
        from_user.evidence[0].trust = USER; // Rule T
        assert_eq!(
            verdict(&from_user, &post_machine()).0,
            Band::Likely,
            "{name}"
        );
        let mut ai = owned.clone();
        ai.evidence[0].tier = Tier::Ai;
        assert_ne!(verdict(&ai, &post_machine()).0, Band::Safe, "{name}");
        let mut weightless = owned.clone().with(ev(MSI, Scope::Object, ADMIN, "msi"));
        weightless.evidence[0].weight = 0;
        assert_eq!(
            verdict(&weightless, &post_machine()),
            (Band::Likely, false, 8),
            "{name}"
        );
        let mut wrong_scope = owned.clone();
        wrong_scope.evidence[0].scope = Scope::Key; // a stored scope the table does not allow
        assert_ne!(
            verdict(&wrong_scope, &post_machine()).0,
            Band::Safe,
            "{name}"
        );

        // The other conditions of P-OBJ-1 and of Safe still apply.
        let mut medium = owned.clone();
        medium.harm = Harm::Medium;
        assert_eq!(verdict(&medium, &post_machine()).0, Band::Likely, "{name}");
        let mut soft = owned.clone();
        soft.blockers.push(Blocker::InUse);
        assert_eq!(verdict(&soft, &post_machine()).0, Band::Likely, "{name}");
        let mut none = owned.clone();
        none.reversibility = Reversibility::None;
        assert_eq!(verdict(&none, &post_machine()).0, Band::Likely, "{name}");
        let mut user_data = owned.clone();
        user_data.category = Category::UserData;
        assert_eq!(
            verdict(&user_data, &post_machine()).0,
            Band::Likely,
            "{name}"
        );
        for action in [
            Action::ReportOnly,
            Action::Quarantine,
            Action::DeleteValue,
            Action::RemoveDirIfEmpty,
        ] {
            let mut other = owned.clone();
            other.action = action;
            assert_eq!(
                verdict(&other, &post_machine()).0,
                Band::Likely,
                "{name} {action:?}"
            );
        }
        // Mode rules: forced mode and a failed verify-gone never preselect; external mode needs the
        // OwnedSystemObject itself from an admin-only source.
        let forced = PolicyCtx {
            mode: ScanMode::Forced,
            ..post_machine()
        };
        assert_eq!(verdict(&owned, &forced).0, Band::Likely, "{name}");
        let not_gone = PolicyCtx {
            verify_gone: VerifyGone::new(false, true, true),
            ..post_machine()
        };
        assert_eq!(verdict(&owned, &not_gone).0, Band::Likely, "{name}");
        let external = PolicyCtx {
            mode: ScanMode::External,
            ..post_machine()
        };
        assert_eq!(verdict(&owned, &external).0, Band::Safe, "{name}");
        let mut external_user =
            owned
                .clone()
                .with(ev(MSI, Scope::Object, ADMIN, "msi-serviceinstall"));
        external_user.evidence[0].trust = USER;
        assert_eq!(
            verdict(&external_user, &external).0,
            Band::Likely,
            "{name}: admin-only manifest does not stand in for a user-writable OwnedSystemObject"
        );
    }
}

#[test]
fn object_with_high_score_but_value_scoped_evidence_is_likely() {
    // Hostile: a scanner that attributes a service by what its ImagePath points to, with a token match on
    // top. 6 + 7 = 13 is well above the Safe score, but none of it is about the service as an object.
    let hostile = cand(
        service(),
        Action::DeleteKey,
        Category::System,
        vec![
            ev(
                EvidenceKind::PointsIntoInstallRoot,
                Scope::Value,
                ADMIN,
                "imagepath",
            ),
            ev(EvidenceKind::HarvestedToken, Scope::Value, ADMIN, "tokens"),
        ],
    );
    assert_eq!(
        verdict(&hostile, &post_machine()),
        (Band::Likely, false, 13)
    );

    // The same evidence relabelled with Object scope by a broken producer: the table does not allow that
    // scope for these kinds, so they drop to Tier B and still cannot support the service.
    let mut relabelled = hostile.clone();
    for e in &mut relabelled.evidence {
        e.scope = Scope::Object;
    }
    assert_eq!(
        verdict(&relabelled, &post_machine()),
        (Band::Likely, false, 13)
    );

    // And with an installer record of the object on top (Tier A, Object scope, S = 21): still not Safe
    // without OwnedSystemObject.
    let with_manifest = hostile.clone().with(ev(MSI, Scope::Object, ADMIN, "msi"));
    assert_eq!(
        verdict(&with_manifest, &post_machine()),
        (Band::Likely, false, 21)
    );

    for (target, category) in typed_objects() {
        let mut c = hostile.clone();
        c.target = target.clone();
        c.category = category;
        assert_eq!(
            verdict(&c, &post_machine()),
            (Band::Likely, false, 13),
            "{target:?}"
        );
    }
}

#[test]
fn system_category_regvalue_still_never_safe() {
    let services_key = r"HKLM\SYSTEM\CurrentControlSet\Services\AppUpdateSvc";
    let strong_value = |category: Category| {
        cand(
            Target::RegValue {
                path: services_key.into(),
                name: "ImagePath".into(),
            },
            Action::DeleteValue,
            category,
            vec![
                ev(MSI, Scope::Value, ADMIN, "msi-registry"),
                ev(EvidenceKind::DanglingRef, Scope::Value, ADMIN, "imagepath"),
            ],
        )
    };
    // Control: the same proof under another category is Safe, so only the category holds it back.
    assert_eq!(
        verdict(&strong_value(Category::Registration), &post_machine()).0,
        Band::Safe
    );
    let system = strong_value(Category::System);
    assert_eq!(verdict(&system, &post_machine()), (Band::Likely, false, 15));
    assert!(
        explanation(&system).contains("Items of this category are never ticked for you"),
        "{}",
        explanation(&system)
    );

    // The key form, with an installer key record and a proven skeleton (S = 16).
    let key = cand(
        Target::RegKey {
            path: services_key.into(),
        },
        Action::DeleteKey,
        Category::System,
        vec![
            ev(MSI, Scope::Key, ADMIN, "msi-registry"),
            ev(
                EvidenceKind::ProvenOwnedSkeleton,
                Scope::Key,
                ADMIN,
                "subtree",
            ),
        ],
    );
    assert_eq!(verdict(&key, &post_machine()), (Band::Likely, false, 16));

    // A path in System is not Safe either (M1a behaviour).
    let path = cand(
        Target::Path {
            path: r"C:\Windows\System32\drivers\app.sys".into(),
        },
        Action::Quarantine,
        Category::System,
        vec![ev(
            EvidenceKind::InsideInstallRoot,
            Scope::Path,
            ADMIN,
            "arp",
        )],
    );
    assert_eq!(verdict(&path, &post_machine()).0, Band::Likely);
}

// ---------------------------------------------------------------------------------------------------
// P-OBJ-2

#[test]
fn partial_reversibility_never_safe_even_without_blocker() {
    for (target, category) in typed_objects() {
        let name = format!("{target:?}");
        // A scanner that set Partial but forgot the blocker.
        let mut unstated = owned_object(target.clone(), category);
        unstated.reversibility = Reversibility::Partial;
        assert_eq!(
            verdict(&unstated, &post_machine()),
            (Band::Likely, false, 8),
            "{name}"
        );
        assert!(
            explanation(&unstated).contains(PARTIAL_LINE),
            "{name}: {}",
            explanation(&unstated)
        );

        // Treated exactly as if the blocker were present.
        let stated = unstated.clone().blocker(Blocker::ReversibilityPartial);
        assert_eq!(
            verdict(&stated, &post_machine()),
            verdict(&unstated, &post_machine()),
            "{name}"
        );
        assert_eq!(explanation(&stated), explanation(&unstated), "{name}");
        assert_eq!(
            explanation(&stated).matches(PARTIAL_LINE).count(),
            1,
            "{name}: {}",
            explanation(&stated)
        );

        // Even Likely-by-Tier-A survives a low score: the soft blocker keeps it shown.
        let mut weak = unstated.clone();
        weak.evidence[0].weight = 3;
        assert_eq!(
            verdict(&weak, &post_machine()),
            (Band::Likely, false, 3),
            "{name}"
        );
    }

    // M1a scope: for files, keys and values `Partial` alone has never stopped Safe (golden row "partially
    // reversible removal can still be safe"); C-POLICY does not change that.
    let mut file = cand(
        Target::Path {
            path: r"C:\Program Files\App".into(),
        },
        Action::Quarantine,
        Category::AppFiles,
        vec![ev(
            EvidenceKind::InsideInstallRoot,
            Scope::Path,
            ADMIN,
            "arp",
        )],
    );
    file.reversibility = Reversibility::Partial;
    assert_eq!(verdict(&file, &post_machine()), (Band::Safe, true, 9));
}

#[test]
fn program_unresolved_is_soft() {
    for (target, category) in typed_objects() {
        let name = format!("{target:?}");
        for soft in [Blocker::ProgramUnresolved, Blocker::ReversibilityPartial] {
            assert!(!soft.is_hard(), "{soft:?}");
            let c = owned_object(target.clone(), category).blocker(soft.clone());
            let d = decide(&c, &post_machine());
            assert_eq!(
                (d.band, d.preselected, d.score),
                (Band::Likely, false, 8),
                "{name} {soft:?}"
            );
            assert!(
                !d.explanation.starts_with("Kept: "),
                "{name}: {}",
                d.explanation
            );
        }
        // The scanner's form for an unresolved program: a recorded object without OwnedSystemObject
        // (S-SERVICE, S-TASK) is still offered, unticked.
        let c = cand(
            target.clone(),
            Action::DeleteKey,
            category,
            vec![ev(
                EvidenceKind::PointsIntoInstallRoot,
                Scope::Value,
                ADMIN,
                "imagepath",
            )],
        )
        .blocker(Blocker::ProgramUnresolved);
        assert_eq!(
            verdict(&c, &post_machine()),
            (Band::Likely, false, 6),
            "{name}"
        );
        assert!(
            explanation(&c).contains("Its program could not be pinned to one file"),
            "{name}: {}",
            explanation(&c)
        );
    }
}

#[test]
fn driver_and_has_dependents_are_protected() {
    let hard = [
        Blocker::Driver,
        Blocker::HasDependents {
            names: vec!["AppHelperSvc".into()],
        },
        Blocker::ObjectChangedSinceHarvest,
    ];
    for (target, category) in typed_objects() {
        for blocker in &hard {
            assert!(blocker.is_hard(), "{blocker:?}");
            let c = owned_object(target.clone(), category).blocker(blocker.clone());
            let d = decide(&c, &post_machine());
            assert_eq!(
                (d.band, d.preselected),
                (Band::Blocked, false),
                "{target:?} {blocker:?}"
            );
            assert!(d.explanation.starts_with("Kept: "), "{}", d.explanation);
        }
    }
    let c = owned_object(service(), Category::System).blocker(Blocker::HasDependents {
        names: vec!["AppHelperSvc".into(), "Other\nSvc".into()],
    });
    assert_eq!(
        explanation(&c),
        "Kept: other services depend on it (AppHelperSvc, OtherSvc)"
    );
    let c = owned_object(service(), Category::System).blocker(Blocker::Driver);
    assert_eq!(explanation(&c), "Kept: it is a driver");
}

// ---------------------------------------------------------------------------------------------------
// P-MSI-1

#[test]
fn msi_manifest_is_tier_a_for_key_value_path() {
    let targets = [
        (
            Target::RegKey {
                path: r"HKLM\SOFTWARE\Classes\CLSID\{11111111-2222-3333-4444-555555555555}".into(),
            },
            Action::DeleteKey,
            Scope::Key,
        ),
        (
            Target::RegValue {
                path: r"HKLM\SOFTWARE\Vendor\App".into(),
                name: "InstallDir".into(),
            },
            Action::DeleteValue,
            Scope::Value,
        ),
        (
            Target::Path {
                path: r"C:\ProgramData\Vendor\App".into(),
            },
            Action::Quarantine,
            Scope::Path,
        ),
    ];
    for kind in [MSI, BURN] {
        for (target, action, scope) in &targets {
            let e = ev(kind, *scope, ADMIN, "installer-record");
            for target_scope in [TargetScope::Machine, TargetScope::PerUser] {
                assert_eq!(
                    effective_tier(&e, target_scope),
                    Tier::A,
                    "{kind:?} {scope:?}"
                );
            }
            assert_eq!(e.weight, 8, "{kind:?}");
            let c = cand(
                target.clone(),
                *action,
                Category::Registration,
                vec![e.clone()],
            );
            assert_eq!(
                verdict(&c, &post_machine()),
                (Band::Safe, true, 8),
                "{kind:?} {target:?}"
            );
            assert!(
                explanation(&c).contains("Named in App's installer record"),
                "{}",
                explanation(&c)
            );
            // Matching scope still matters: the record of another kind of item does not support this one.
            for other in [Scope::Key, Scope::Value, Scope::Path] {
                if other == *scope {
                    continue;
                }
                let mismatched = cand(
                    target.clone(),
                    *action,
                    Category::Registration,
                    vec![ev(kind, other, ADMIN, "installer-record")],
                );
                assert_eq!(
                    verdict(&mismatched, &post_machine()),
                    (Band::Likely, false, 8),
                    "{kind:?} {other:?} on {target:?}"
                );
            }
            // Rule T still applies to a record the user can write.
            let mut user = c.clone();
            user.evidence[0].trust = USER;
            assert_eq!(verdict(&user, &post_machine()).0, Band::Likely, "{kind:?}");
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// P-PATH-1

#[test]
fn path_store_value_points_plus_dangling_is_safe_points_alone_is_likely() {
    // A value of a path-keyed store whose name is the path (MuiCache-like) in a user's hive, and one in
    // HKLM (a machine store), as S-PRIVACY's builder.path_named_value emits them.
    let stores = [
        (
            Target::RegValue {
                path: r"HKU\S-1-5-21-1-2-3-1001_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache".into(),
                name: r"C:\Program Files\App\app.exe.FriendlyAppName".into(),
            },
            TargetScope::PerUser,
        ),
        (
            Target::RegValue {
                path: r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers".into(),
                name: r"C:\Program Files\App\app.exe".into(),
            },
            TargetScope::Machine,
        ),
    ];
    for (target, scope) in stores {
        let points = ev(
            EvidenceKind::PointsIntoInstallRoot,
            Scope::Value,
            ADMIN,
            "value-name",
        );
        let dangling = ev(EvidenceKind::DanglingRef, Scope::Value, ADMIN, "value-name");
        assert_eq!(points.weight, 6);
        assert_eq!(dangling.weight, 7);
        let alone = cand(
            target.clone(),
            Action::DeleteValue,
            Category::Privacy,
            vec![points.clone()],
        );
        assert_eq!(
            verdict(&alone, &post(scope)),
            (Band::Likely, false, 6),
            "{target:?}"
        );
        let both = alone.clone().with(dangling);
        assert_eq!(
            verdict(&both, &post(scope)),
            (Band::Safe, true, 13),
            "{target:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------------
// Version and the M1a table

/// The rules of this file came with policy `m1b.1`. Policy `bl.1` (BL-POLICY, the baseline trust cap)
/// keeps every one of them: with trust Exact, as every context here has, it decides as `m1b.1` did.
#[test]
fn policy_version_is_bl_1() {
    assert_eq!(POLICY_VERSION, "bl.1");
}

/// FNV-1a over the text with line endings normalised, so a checkout with CRLF gives the same value.
fn fnv1a(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.bytes().filter(|b| *b != b'\r') {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// The fingerprint of `tests/golden.rs` at the m1a.6 rows (commit 04d58c9), with its one
/// `const GOLDEN_VERSION` line left out: the only line policy m1b.1 was allowed to touch. Policy bl.1
/// (BL-POLICY) did not change this value: besides the version key it added only
/// [`BL_CONTEXT_LINE`], which is left out the same way.
const M1A_GOLDEN_FINGERPRINT: u64 = 0xa367_5f14_bf46_703b;

/// The one line policy bl.1 added to `tests/golden.rs`, in the two places that build a `PolicyCtx` in
/// full (`ctx` and `random_ctx`): the new context field, at the trust under which nothing is capped.
/// The rows and property checks of the table therefore run with trust Exact, and the rows of the
/// baseline trust cap are in tests/bl_bands.rs.
const BL_CONTEXT_LINE: &str = "baseline_trust: purge_model::BaselineTrust::Exact,";

#[test]
fn m1a_band_table_unchanged() {
    // The rows of the M1a golden table (and its property checks) are not edited for m1b.1 or bl.1: only
    // the version key moved, and bl.1 gave the two contexts their new field. `golden_table` itself still
    // runs and passes in tests/golden.rs.
    let golden = include_str!("golden.rs");
    let version_lines: Vec<&str> = golden
        .lines()
        .filter(|l| l.starts_with("const GOLDEN_VERSION"))
        .collect();
    assert_eq!(version_lines, [r#"const GOLDEN_VERSION: &str = "bl.1";"#]);
    assert_eq!(
        golden
            .lines()
            .filter(|l| l.trim() == BL_CONTEXT_LINE)
            .count(),
        2,
        "the context field is set in `ctx` and `random_ctx` only"
    );
    assert!(
        !golden
            .replace(BL_CONTEXT_LINE, "")
            .contains("BaselineTrust"),
        "tests/golden.rs names a baseline trust outside the two context lines"
    );
    let rows: String = golden
        .lines()
        .filter(|l| !l.starts_with("const GOLDEN_VERSION") && l.trim() != BL_CONTEXT_LINE)
        .map(|l| format!("{l}\n"))
        .collect();
    assert_eq!(
        fnv1a(&rows),
        M1A_GOLDEN_FINGERPRINT,
        "tests/golden.rs changed beyond its version key: an M1a band moved under m1b.1 or bl.1"
    );

    // What m1b.1 added is inert for every M1a target: on a file, key or value, Partial alone still
    // allows Safe, System still never does, and DeleteKey still fits only keys (and typed objects).
    let file = |category: Category, reversibility: Reversibility| {
        let mut c = cand(
            Target::Path {
                path: r"C:\Program Files\App".into(),
            },
            Action::Quarantine,
            category,
            vec![ev(
                EvidenceKind::InsideInstallRoot,
                Scope::Path,
                ADMIN,
                "arp",
            )],
        );
        c.reversibility = reversibility;
        c
    };
    assert_eq!(
        verdict(
            &file(Category::AppFiles, Reversibility::Partial),
            &post_machine()
        )
        .0,
        Band::Safe
    );
    assert_eq!(
        verdict(
            &file(Category::System, Reversibility::Full),
            &post_machine()
        )
        .0,
        Band::Likely
    );
    let mut on_path = file(Category::AppFiles, Reversibility::Full);
    on_path.action = Action::DeleteKey;
    assert_eq!(verdict(&on_path, &post_machine()).0, Band::Likely);
}

// ---------------------------------------------------------------------------------------------------
// Properties over generated typed objects

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
    fn pick<T: Clone>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())].clone()
    }
}

fn random_object(rng: &mut Rng) -> (Candidate, PolicyCtx) {
    let (target, category) = rng.pick(&typed_objects());
    let category = if rng.chance(80) {
        category
    } else {
        rng.pick(&[
            Category::System,
            Category::Startup,
            Category::UserData,
            Category::Registration,
        ])
    };
    let action = if rng.chance(80) {
        Action::DeleteKey
    } else {
        rng.pick(&[Action::ReportOnly, Action::Quarantine, Action::DeleteValue])
    };
    let kinds = [
        OSO,
        OSO,
        MSI,
        BURN,
        EvidenceKind::PointsIntoInstallRoot,
        EvidenceKind::DanglingRef,
        EvidenceKind::HarvestedToken,
        EvidenceKind::InsideInstallRoot,
        EvidenceKind::TimeWindow,
        EvidenceKind::ExecutablesPresent,
    ];
    let evidence = (0..rng.below(4))
        .map(|_| {
            let kind = rng.pick(&kinds);
            let allowed: Vec<Scope> = kind.scope().iter().collect();
            let mut e = ev(
                kind,
                rng.pick(&allowed),
                if rng.chance(80) { ADMIN } else { USER },
                rng.pick(&["a", "b", "c"]),
            );
            if rng.chance(15) {
                e.scope = rng.pick(&Scope::ALL);
            }
            if rng.chance(10) {
                e.tier = rng.pick(&[Tier::A, Tier::B, Tier::C, Tier::Ai]);
            }
            e
        })
        .collect();
    let mut c = cand(target, action, category, evidence);
    c.harm = rng.pick(&[Harm::None, Harm::Low, Harm::Low, Harm::Medium, Harm::High]);
    c.reversibility = rng.pick(&[
        Reversibility::Full,
        Reversibility::Full,
        Reversibility::Partial,
        Reversibility::None,
    ]);
    c.origin = rng.pick(&[
        Origin::Scanner,
        Origin::Scanner,
        Origin::Signature,
        Origin::ProbeAgent,
    ]);
    if rng.chance(20) {
        c.blockers.push(rng.pick(&[
            Blocker::ProgramUnresolved,
            Blocker::ReversibilityPartial,
            Blocker::InUse,
            Blocker::Driver,
            Blocker::HasDependents {
                names: vec!["x".into()],
            },
            Blocker::ObjectChangedSinceHarvest,
        ]));
    }
    let ctx = PolicyCtx {
        baseline_trust: purge_model::BaselineTrust::Exact,
        mode: rng.pick(&[
            ScanMode::Post,
            ScanMode::Post,
            ScanMode::External,
            ScanMode::Forced,
        ]),
        verify_gone: VerifyGone::new(rng.chance(90), true, true),
        target_scope: rng.pick(&[TargetScope::Machine, TargetScope::PerUser]),
    };
    (c, ctx)
}

#[test]
fn every_safe_typed_object_meets_p_obj_1() {
    let mut safe = 0u32;
    for seed in 1..=20_000u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let (c, ctx) = random_object(&mut rng);
        let d = decide(&c, &ctx);
        if d.band != Band::Safe {
            assert!(!d.preselected, "seed {seed}");
            continue;
        }
        safe += 1;
        assert!(
            c.evidence.iter().any(|e| e.kind == OSO
                && e.scope == Scope::Object
                && e.tier != Tier::Ai
                && effective_tier(e, TargetScope::Machine) == Tier::A),
            "seed {seed}: {c:?}"
        );
        assert!(c.blockers.is_empty(), "seed {seed}");
        assert_eq!(c.reversibility, Reversibility::Full, "seed {seed}");
        assert!(c.harm <= Harm::Low, "seed {seed}");
        assert_eq!(c.action, Action::DeleteKey, "seed {seed}");
        assert_ne!(c.category, Category::UserData, "seed {seed}");
        assert_eq!(
            c.origin == Origin::ProbeAgent,
            !d.preselected,
            "seed {seed}"
        );
        assert!(d.score >= SAFE_MIN, "seed {seed}");
        // Taking the OwnedSystemObject away always drops it out of Safe.
        let mut stripped = c.clone();
        stripped.evidence.retain(|e| e.kind != OSO);
        assert_ne!(decide(&stripped, &ctx).band, Band::Safe, "seed {seed}");
    }
    assert!(safe > 100, "only {safe} Safe typed objects generated");
}

trait CandidateExt {
    fn with(self, evidence: Evidence) -> Self;
    fn blocker(self, blocker: Blocker) -> Self;
}

impl CandidateExt for Candidate {
    fn with(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }
    fn blocker(mut self, blocker: Blocker) -> Self {
        self.blockers.push(blocker);
        self
    }
}
