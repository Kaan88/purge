//! M1b planner tests (M1B-PLAN): the exemption lists come from system facts only, typed objects merge on
//! their identity digest and never nest, the stage order is fixed, Windows Installer client lists are not
//! offered as containers, and plans without typed objects keep their M1a output.

use std::cell::RefCell;

use purge_guard::canon::GuardEnv;
use purge_guard::deny::DenyList;
use purge_model::{
    Action, AppRef, Band, Blocker, BurnFacts, BurnPackage, Candidate, CandidateId, Category,
    Evidence, EvidenceKind, Facts, Fingerprint, FirewallIdentity, Harm, ManifestKind, MsiContext,
    MsiFacts, ObjectFp, ObjectKind, Origin, ProgramId, Reversibility, ScanMode, Scope,
    ServiceIdentity, SourceTrust, Target, TaskAction, TaskIdentity, VerifyGone, View,
};
use purge_plan::decide::{DecideCtx, M1bDecide, decide, exemptions};
use purge_plan::emit::{ScanDoc, build};
use purge_plan::empty_after::{Child, mark_pending};
use purge_plan::hash::plan_hash;
use purge_plan::order::{Stage, sort};
use purge_policy::band::POLICY_VERSION;
use serde_json::json;
use sha2::{Digest, Sha256};

const SID: &str = GuardEnv::SAMPLE_SID;

// Two MSI products: their ProductCodes and the packed forms Windows Installer stores.
const GONE_CODE: &str = "{12345678-ABCD-EF01-2345-6789ABCDEF01}";
const GONE_PACKED: &str = "87654321DCBA10FE32547698BADCFE10";
const KEPT_CODE: &str = "{AAAAAAAA-1111-2222-3333-444455556666}";
const KEPT_PACKED: &str = "AAAAAAAA111122223333444455556666";

const BUNDLE: &str = "{B0B0B0B0-0000-0000-0000-000000000001}";
const BUNDLE_PROVIDER: &str = "Vendor.App.Bundle";
const BUNDLE_CACHE: &str = r"C:\ProgramData\Package Cache\{B0B0B0B0-0000-0000-0000-000000000001}";
const PKG_CODE: &str = "{C0C0C0C0-0000-0000-0000-000000000002}";
const PKG_PROVIDER: &str = "{C0C0C0C0-0000-0000-0000-000000000002}";
const PKG_CACHE: &str = r"C:\ProgramData\Package Cache\{C0C0C0C0-0000-0000-0000-000000000002}v1.0";
const SHARED_CODE: &str = "{D0D0D0D0-0000-0000-0000-000000000003}";
const SHARED_PROVIDER: &str = "Microsoft.VS.VC_Runtime";
const SHARED_CACHE: &str =
    r"C:\ProgramData\Package Cache\{D0D0D0D0-0000-0000-0000-000000000003}v14";

fn ev(kind: EvidenceKind, scope: Scope, source: &str) -> Evidence {
    Evidence::new(kind, scope, SourceTrust::AdminOnly, source).expect("scope fits the kind")
}

fn cand(id: &str, target: Target, scanner: &str) -> Candidate {
    let action = match &target {
        Target::Path { .. } => Action::Quarantine,
        Target::RegKey { .. }
        | Target::Service { .. }
        | Target::Task { .. }
        | Target::FirewallRule { .. } => Action::DeleteKey,
        Target::RegMultiSzSegment { .. } => Action::EditSegment,
        Target::AppxPackage { .. } => Action::RemovePackage,
        _ => Action::DeleteValue,
    };
    Candidate {
        id: CandidateId(id.into()),
        target,
        action,
        owner: AppRef {
            program_id: ProgramId::machine(View::K64, "App_is1").expect("valid key name"),
            display_name: "App".into(),
        },
        origin: Origin::Scanner,
        scanner: scanner.into(),
        category: Category::Registration,
        evidence: Vec::new(),
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

fn path(p: &str) -> Target {
    Target::Path { path: p.into() }
}
fn key(p: &str) -> Target {
    Target::RegKey { path: p.into() }
}
fn value(p: &str, name: &str) -> Target {
    Target::RegValue {
        path: p.into(),
        name: name.into(),
    }
}

fn deny() -> DenyList {
    DenyList::compile(&GuardEnv::sample())
}

/// Post mode, verify-gone passed, the sample user, long names resolved, empty M1b lists.
fn ctx(deny: &DenyList) -> DecideCtx<'_> {
    DecideCtx {
        user_sid: Some(SID),
        long_names_resolved: true,
        ..DecideCtx::new(deny, ScanMode::Post, VerifyGone::new(true, true, true))
    }
}

fn with_m1b(deny: &DenyList, m1b: M1bDecide) -> DecideCtx<'_> {
    DecideCtx { m1b, ..ctx(deny) }
}

/// A candidate with MSI-manifest evidence (Tier A for every scope, P-MSI-1).
fn msi_owned(id: &str, target: Target, scanner: &str) -> Candidate {
    let scope = Scope::of(&target).expect("a scoped target");
    let mut c = cand(id, target, scanner);
    c.evidence.push(ev(
        EvidenceKind::InstallerManifest(ManifestKind::Msi),
        scope,
        "msi",
    ));
    c
}

fn one(c: Candidate, ctx: &DecideCtx<'_>) -> Candidate {
    let mut out = decide(vec![c], ctx);
    assert_eq!(out.len(), 1);
    out.remove(0)
}

fn deny_rule(c: &Candidate) -> Option<&str> {
    c.blockers.iter().find_map(|b| match b {
        Blocker::DenyListed { rule } => Some(rule.as_str()),
        _ => None,
    })
}

fn band(c: &Candidate) -> Band {
    c.decision.as_ref().expect("decided").band
}

/// A fingerprint with no M1b facts.
fn bare_fp() -> Fingerprint {
    serde_json::from_value(json!({
        "schema": "purge.fp/0",
        "app": {"program_id": "HKLM|64|App_is1", "display_name": "App"},
        "identity": {"names": [], "vendors": [], "tokens": [], "mega_vendor": false},
        "os": {"edition": "Professional", "build": 26340, "ubr": 9882},
        "user_sid": SID,
        "verify_gone": null
    }))
    .expect("a valid fingerprint")
}

fn msi(code: &str, packed: &str) -> MsiFacts {
    MsiFacts {
        product_code: code.into(),
        packed_code: packed.into(),
        upgrade_code: None,
        context: MsiContext::Machine,
        user_sid: None,
        local_package: None,
        package_readable: false,
        components: Vec::new(),
        registry_rows: Vec::new(),
        services: Vec::new(),
        source_dirs: Vec::new(),
        custom_actions: 0,
        unresolved_rows: 0,
    }
}

fn burn_fp() -> Fingerprint {
    let mut fp = bare_fp();
    fp.burn = Some(BurnFacts {
        bundle_id: BUNDLE.into(),
        provider_key: Some(BUNDLE_PROVIDER.into()),
        cache_path: Some(BUNDLE_CACHE.into()),
        packages: vec![
            BurnPackage {
                provider_key: PKG_PROVIDER.into(),
                product_code: Some(PKG_CODE.into()),
                cache_dir: Some(PKG_CACHE.into()),
                other_dependents: Vec::new(),
            },
            BurnPackage {
                provider_key: SHARED_PROVIDER.into(),
                product_code: Some(SHARED_CODE.into()),
                cache_dir: Some(SHARED_CACHE.into()),
                other_dependents: vec!["{E0E0E0E0-0000-0000-0000-000000000004}".into()],
            },
        ],
        dependents_at_harvest: Vec::new(),
    });
    fp
}

/// A product state source answering from a fixed table; anything not listed is unknown.
fn table(entries: &[(&str, Option<bool>)]) -> impl Fn(&str) -> Option<bool> + use<> {
    let entries: Vec<(String, Option<bool>)> =
        entries.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect();
    move |code: &str| {
        entries
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(code))
            .and_then(|(_, v)| *v)
    }
}

fn unknown(_: &str) -> Option<bool> {
    None
}

fn classes_product(packed: &str) -> Target {
    key(&format!(
        r"HKLM\SOFTWARE\Classes\Installer\Products\{packed}"
    ))
}

fn userdata_product(packed: &str) -> Target {
    key(&format!(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\{packed}"
    ))
}

fn dependency(provider: &str) -> Target {
    key(&format!(
        r"HKLM\SOFTWARE\Classes\Installer\Dependencies\{provider}"
    ))
}

// ---------------------------------------------------------------------------------------------------
// The exemption lists
// ---------------------------------------------------------------------------------------------------

#[test]
fn m1b_decide_default_is_closed() {
    let empty = M1bDecide::default();
    assert!(empty.is_empty());
    assert!(empty.gone_msi_products().is_empty());
    assert!(empty.gone_cache_dirs().is_empty());
    assert!(empty.gone_burn().is_empty());
    let deny = deny();
    assert_eq!(
        DecideCtx::new(&deny, ScanMode::Post, VerifyGone::new(true, true, true)).m1b,
        empty
    );
    // A fingerprint without M1b facts gives nothing, whatever the sources say.
    let all_gone = |_: &str| Some(false);
    assert!(M1bDecide::from_facts(&bare_fp(), &all_gone, &all_gone).is_empty());

    // With the default every exempted shape stays denied, however good the evidence.
    let ctx = ctx(&deny);
    for target in [
        classes_product(GONE_PACKED),
        userdata_product(GONE_PACKED),
        dependency(BUNDLE_PROVIDER),
        path(PKG_CACHE),
        path(BUNDLE_CACHE),
    ] {
        let c = msi_owned("c", target.clone(), "S");
        let ex = exemptions(&c, &ctx);
        assert!(ex.gone_msi_products.is_empty() && ex.gone_burn.is_empty());
        assert!(ex.gone_cache_dirs.is_empty());
        let c = one(c, &ctx);
        assert!(deny_rule(&c).is_some(), "{target:?}: {:?}", c.blockers);
        assert_eq!(band(&c), Band::Blocked, "{target:?}");
    }
}

#[test]
fn gone_products_only_when_known_absent() {
    let mut fp = bare_fp();
    fp.msi = vec![
        msi(GONE_CODE, GONE_PACKED),
        msi(KEPT_CODE, KEPT_PACKED),
        // Lower-case on record: still the same product, listed in the packed form Windows uses.
        msi(
            "{abcdef01-2345-6789-abcd-ef0123456789}",
            "10fedcba54329876badcfe1032547698",
        ),
    ];
    let products = table(&[
        (GONE_CODE, Some(false)),
        (KEPT_CODE, Some(true)),
        ("{ABCDEF01-2345-6789-ABCD-EF0123456789}", Some(false)),
    ]);
    let m1b = M1bDecide::from_facts(&fp, &products, &unknown);
    assert_eq!(
        m1b.gone_msi_products(),
        [
            "10FEDCBA54329876BADCFE1032547698".to_owned(),
            GONE_PACKED.to_owned()
        ]
    );
    assert!(m1b.gone_burn().is_empty() && m1b.gone_cache_dirs().is_empty());

    let deny = deny();
    let ctx = with_m1b(&deny, m1b);
    for target in [classes_product(GONE_PACKED), userdata_product(GONE_PACKED)] {
        let c = one(msi_owned("gone", target.clone(), "S"), &ctx);
        assert_eq!(deny_rule(&c), None, "{target:?}");
        assert_ne!(band(&c), Band::Blocked, "{target:?}");
    }
    // The installed product's registration stays denied in the same plan.
    let c = one(msi_owned("kept", classes_product(KEPT_PACKED), "S"), &ctx);
    assert_eq!(deny_rule(&c), Some("reg.installer"));
    assert_eq!(band(&c), Band::Blocked);
}

/// Hostile: the product state cannot be read (a source error), or the fingerprint's packed code is not the
/// packed form of its ProductCode. Nothing is opened.
#[test]
fn gone_products_unknown_state_stays_closed() {
    let mut fp = burn_fp();
    fp.msi = vec![msi(GONE_CODE, GONE_PACKED), msi(KEPT_CODE, KEPT_PACKED)];
    let asked = RefCell::new(Vec::<String>::new());
    let failing = |code: &str| {
        asked.borrow_mut().push(code.to_owned());
        None
    };
    let m1b = M1bDecide::from_facts(&fp, &failing, &failing);
    assert!(m1b.is_empty(), "{m1b:?}");
    // The sources were really asked, with the ProductCodes and the bundle id.
    let asked = asked.into_inner();
    for code in [GONE_CODE, KEPT_CODE, BUNDLE, PKG_CODE] {
        assert!(
            asked.iter().any(|a| a == code),
            "{code} not asked: {asked:?}"
        );
    }

    // A record whose packed code names another product than its ProductCode is ignored, even when the
    // ProductCode is gone: the packed code is what the guard would open.
    let mut forged = bare_fp();
    forged.msi = vec![
        msi(GONE_CODE, KEPT_PACKED),
        msi("not a guid", GONE_PACKED),
        msi(GONE_CODE, "87654321DCBA10FE32547698BADCFE1"),
    ];
    let all_gone = |_: &str| Some(false);
    assert!(M1bDecide::from_facts(&forged, &all_gone, &all_gone).is_empty());

    let deny = deny();
    let ctx = with_m1b(&deny, M1bDecide::from_facts(&fp, &unknown, &unknown));
    let c = one(msi_owned("p", classes_product(GONE_PACKED), "S"), &ctx);
    assert_eq!(deny_rule(&c), Some("reg.installer"));
}

/// Hostile: a scanner writes "this product is gone" into its candidate's facts, evidence detail and id.
/// The lists come from the plan's system facts only, so the target stays denied.
#[test]
fn gone_products_not_taken_from_candidate_facts() {
    let forged_facts = Facts::new()
        .with("product_gone", "true")
        .with("gone_msi_products", GONE_PACKED)
        .with("packed_code", GONE_PACKED)
        .with("gone_burn", BUNDLE_PROVIDER)
        .with("gone_cache_dirs", PKG_CACHE);
    let forge = |target: Target| {
        let mut c = msi_owned(GONE_PACKED, target, "M1B-PLAN");
        for e in &mut c.evidence {
            *e = e.clone().with_detail(forged_facts.clone());
        }
        let scope = c.evidence[0].scope;
        c.evidence.push(
            ev(
                EvidenceKind::InstallerManifest(ManifestKind::Burn),
                scope,
                GONE_PACKED,
            )
            .with_detail(forged_facts.clone()),
        );
        c
    };
    let deny = deny();
    // Closed lists, and lists for a plan in which the product is still installed.
    let mut fp = burn_fp();
    fp.msi = vec![msi(GONE_CODE, GONE_PACKED)];
    let present = |_: &str| Some(true);
    let installed = M1bDecide::from_facts(&fp, &present, &present);
    assert!(installed.is_empty());
    for m1b in [M1bDecide::default(), installed] {
        let ctx = with_m1b(&deny, m1b);
        for target in [
            classes_product(GONE_PACKED),
            userdata_product(GONE_PACKED),
            dependency(BUNDLE_PROVIDER),
            path(PKG_CACHE),
        ] {
            let c = forge(target.clone());
            let ex = exemptions(&c, &ctx);
            assert!(
                ex.gone_msi_products.is_empty()
                    && ex.gone_burn.is_empty()
                    && ex.gone_cache_dirs.is_empty()
            );
            let c = one(c, &ctx);
            assert!(deny_rule(&c).is_some(), "{target:?}");
            assert_eq!(band(&c), Band::Blocked, "{target:?}");
        }
    }
    // The same candidates pass once the system says the product is gone: the test above is not vacuous.
    let gone = |_: &str| Some(false);
    let ctx = with_m1b(&deny, M1bDecide::from_facts(&fp, &gone, &gone));
    let c = one(forge(classes_product(GONE_PACKED)), &ctx);
    assert_eq!(deny_rule(&c), None);
}

#[test]
fn gone_cache_dirs_need_no_other_dependents() {
    let fp = burn_fp();
    let products = table(&[(PKG_CODE, Some(false)), (SHARED_CODE, Some(false))]);
    let bundles = table(&[(BUNDLE, Some(false))]);
    let m1b = M1bDecide::from_facts(&fp, &products, &bundles);
    // The shared runtime has another dependent: its folder stays, although its product is gone.
    assert_eq!(
        m1b.gone_cache_dirs(),
        [BUNDLE_CACHE.to_owned(), PKG_CACHE.to_owned()]
    );

    // A package without a product code, or whose product is installed or unknown, keeps its folder.
    let mut fp2 = burn_fp();
    if let Some(burn) = fp2.burn.as_mut() {
        burn.packages[0].product_code = None;
        burn.packages[1].other_dependents.clear();
    }
    let m1b2 = M1bDecide::from_facts(&fp2, &table(&[(SHARED_CODE, Some(true))]), &unknown);
    assert!(m1b2.gone_cache_dirs().is_empty(), "{m1b2:?}");

    let deny = deny();
    let ctx = with_m1b(&deny, m1b);
    let mut inside = msi_owned("pkg-file", path(&format!(r"{PKG_CACHE}\app.msi")), "S");
    inside.category = Category::Package;
    let inside = one(inside, &ctx);
    assert_eq!(deny_rule(&inside), None, "{:?}", inside.blockers);
    let dir = one(msi_owned("pkg", path(PKG_CACHE), "S"), &ctx);
    assert_eq!(deny_rule(&dir), None, "{:?}", dir.blockers);
    let shared = one(msi_owned("shared", path(SHARED_CACHE), "S"), &ctx);
    assert!(deny_rule(&shared).is_some());
    assert_eq!(band(&shared), Band::Blocked);
}

#[test]
fn gone_burn_needs_bundle_known_absent() {
    let fp = burn_fp();
    let none_gone = table(&[]);
    for bundle_state in [Some(true), None] {
        let bundles = table(&[(BUNDLE, bundle_state)]);
        let m1b = M1bDecide::from_facts(&fp, &none_gone, &bundles);
        assert!(m1b.is_empty(), "{bundle_state:?}: {m1b:?}");
    }
    let m1b = M1bDecide::from_facts(&fp, &none_gone, &table(&[(BUNDLE, Some(false))]));
    assert_eq!(
        m1b.gone_burn(),
        [BUNDLE_PROVIDER.to_owned(), BUNDLE.to_owned()]
    );
    assert_eq!(m1b.gone_cache_dirs(), [BUNDLE_CACHE.to_owned()]);

    // A bundle that other bundles depended on at harvest keeps its dependency key; its own
    // registrations as a dependent (named by its id) may go.
    let mut depended = burn_fp();
    if let Some(burn) = depended.burn.as_mut() {
        burn.dependents_at_harvest = vec!["Other.Bundle".into()];
    }
    let m1b_dep = M1bDecide::from_facts(&depended, &none_gone, &table(&[(BUNDLE, Some(false))]));
    assert_eq!(m1b_dep.gone_burn(), [BUNDLE.to_owned()]);

    let deny = deny();
    let gone_ctx = with_m1b(&deny, m1b);
    let closed = ctx(&deny);
    let own_dependent = key(&format!(
        r"HKLM\SOFTWARE\Classes\Installer\Dependencies\{SHARED_PROVIDER}\Dependents\{BUNDLE}"
    ));
    for target in [dependency(BUNDLE_PROVIDER), own_dependent] {
        let c = one(msi_owned("c", target.clone(), "S"), &gone_ctx);
        assert_eq!(deny_rule(&c), None, "{target:?}");
        let c = one(msi_owned("c", target.clone(), "S"), &closed);
        assert!(deny_rule(&c).is_some(), "{target:?}");
    }
}

#[test]
fn gone_burn_package_with_other_dependent_excluded() {
    let fp = burn_fp();
    // Both package products are gone, the bundle is still registered.
    let products = table(&[(PKG_CODE, Some(false)), (SHARED_CODE, Some(false))]);
    let bundles = table(&[(BUNDLE, Some(true))]);
    let m1b = M1bDecide::from_facts(&fp, &products, &bundles);
    assert_eq!(m1b.gone_burn(), [PKG_PROVIDER.to_owned()]);
    assert!(!m1b.gone_burn().contains(&SHARED_PROVIDER.to_owned()));

    let deny = deny();
    let ctx = with_m1b(&deny, m1b);
    let own = one(msi_owned("own", dependency(PKG_PROVIDER), "S"), &ctx);
    assert_eq!(deny_rule(&own), None, "{:?}", own.blockers);
    let shared = one(msi_owned("shared", dependency(SHARED_PROVIDER), "S"), &ctx);
    assert_eq!(deny_rule(&shared), Some("reg.installer"));
    assert_eq!(band(&shared), Band::Blocked);
}

#[test]
fn m1b_lists_are_sorted_and_free_of_duplicates() {
    let mut fp = burn_fp();
    fp.msi = vec![
        msi(GONE_CODE, GONE_PACKED),
        msi(GONE_CODE, &GONE_PACKED.to_ascii_lowercase()),
    ];
    if let Some(burn) = fp.burn.as_mut() {
        burn.packages.push(burn.packages[0].clone());
        burn.packages.reverse();
    }
    let gone = |_: &str| Some(false);
    let a = M1bDecide::from_facts(&fp, &gone, &gone);
    assert_eq!(a.gone_msi_products(), [GONE_PACKED.to_owned()]);
    if let Some(burn) = fp.burn.as_mut() {
        burn.packages.reverse();
    }
    fp.msi.reverse();
    assert_eq!(M1bDecide::from_facts(&fp, &gone, &gone), a);
    let mut sorted = a.gone_burn().to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(a.gone_burn(), sorted);
}

// ---------------------------------------------------------------------------------------------------
// Typed objects
// ---------------------------------------------------------------------------------------------------

fn service_identity(image: &str) -> ServiceIdentity {
    ServiceIdentity {
        name: "AppSvc".into(),
        image_path: Some(image.into()),
        service_dll: None,
        service_type: 0x10,
        start: 2,
        object_name: Some("LocalSystem".into()),
    }
}

fn typed(id: &str, target: Target, fp: Option<ObjectFp>, scanner: &str) -> Candidate {
    let mut c = cand(id, target, scanner);
    c.category = match ObjectKind::of(&c.target) {
        Some(kind) => kind.category(),
        None => Category::System,
    };
    c.evidence
        .push(ev(EvidenceKind::OwnedSystemObject, Scope::Object, scanner));
    c.object_fp = fp;
    c
}

fn service(id: &str, name: &str, fp: Option<ObjectFp>, scanner: &str) -> Candidate {
    typed(id, Target::Service { name: name.into() }, fp, scanner)
}

#[test]
fn merge_equal_object_fp() {
    let fp = service_identity(r"C:\Program Files\Vendor\App\svc.exe").fp();
    let deny = deny();
    let ctx = ctx(&deny);
    let a = service("a", "AppSvc", Some(fp.clone()), "SYS-SERVICE");
    let b = service("b", "appsvc", Some(fp.clone()), "MSI-REG");
    let out = decide(vec![a, b], &ctx);
    assert_eq!(out.len(), 1, "one service, one item");
    let m = &out[0];
    assert_eq!(m.id.0, "a");
    assert_eq!(m.object_fp.as_ref(), Some(&fp));
    assert!(
        !m.blockers.contains(&Blocker::ObjectChangedSinceHarvest),
        "{:?}",
        m.blockers
    );
    assert_eq!(m.evidence.len(), 2, "both scanners' evidence is kept");
    assert_ne!(band(m), Band::Blocked);

    // The same for tasks and firewall rules.
    let task_fp = TaskIdentity {
        path: r"\Vendor\Update".into(),
        actions: vec![TaskAction::Exec {
            path: r"C:\Program Files\Vendor\App\update.exe".into(),
            arguments: None,
            working_dir: None,
        }],
    }
    .fp();
    let rule_fp = FirewallIdentity {
        id: "{11111111-2222-3333-4444-555555555555}".into(),
        rule:
            r"v2.31|Action=Allow|Active=TRUE|Dir=In|App=C:\Program Files\Vendor\App\a.exe|Name=App|"
                .into(),
    }
    .fp();
    let task = |id: &str| {
        typed(
            id,
            Target::Task {
                path: r"\Vendor\Update".into(),
            },
            Some(task_fp.clone()),
            "SYS-TASK",
        )
    };
    let rule = |id: &str| {
        typed(
            id,
            Target::FirewallRule {
                id: "{11111111-2222-3333-4444-555555555555}".into(),
            },
            Some(rule_fp.clone()),
            "SYS-FIREWALL",
        )
    };
    let out = decide(vec![task("t1"), rule("r1"), task("t2"), rule("r2")], &ctx);
    assert_eq!(out.len(), 2);
    assert!(
        out.iter()
            .all(|c| !c.blockers.contains(&Blocker::ObjectChangedSinceHarvest))
    );
    assert_eq!(out[0].object_fp.as_ref(), Some(&task_fp));
    assert_eq!(out[1].object_fp.as_ref(), Some(&rule_fp));
}

#[test]
fn merge_different_object_fp_blocks() {
    let deny = deny();
    let ctx = ctx(&deny);
    let ours = service_identity(r"C:\Program Files\Vendor\App\svc.exe").fp();
    let theirs = service_identity(r"C:\Program Files\Other\svc.exe").fp();
    assert_ne!(ours, theirs);
    let cases = [
        (Some(ours.clone()), Some(theirs.clone())),
        (Some(ours.clone()), None),
        (None, Some(ours.clone())),
    ];
    for (first, second) in cases {
        let a = service("a", "AppSvc", first.clone(), "SYS-SERVICE");
        let b = service("b", "APPSVC", second.clone(), "MSI-REG");
        let out = decide(vec![a, b], &ctx);
        assert_eq!(out.len(), 1);
        let m = &out[0];
        assert!(
            m.blockers.contains(&Blocker::ObjectChangedSinceHarvest),
            "{first:?} / {second:?}"
        );
        let d = m.decision.as_ref().unwrap();
        assert_eq!((d.band, d.preselected), (Band::Blocked, false));
        assert_eq!(m.object_fp, first, "the first candidate's digest is kept");
    }
    // A third candidate that disagrees with the first two blocks too.
    let out = decide(
        vec![
            service("a", "AppSvc", Some(ours.clone()), "S1"),
            service("b", "AppSvc", Some(ours.clone()), "S2"),
            service("c", "AppSvc", Some(theirs), "S3"),
        ],
        &ctx,
    );
    assert!(
        out[0]
            .blockers
            .contains(&Blocker::ObjectChangedSinceHarvest)
    );
    // Different objects are never merged: two services, two items, neither blocked for it.
    let out = decide(
        vec![
            service("a", "AppSvc", Some(ours.clone()), "S1"),
            service("b", "AppSvc2", None, "S2"),
        ],
        &ctx,
    );
    assert_eq!(out.len(), 2);
    assert!(
        out.iter()
            .all(|c| !c.blockers.contains(&Blocker::ObjectChangedSinceHarvest))
    );
}

#[test]
fn typed_candidate_never_nested() {
    let deny = deny();
    let ctx = ctx(&deny);
    let svc_fp = service_identity(r"C:\Program Files\Vendor\App\svc.exe").fp();
    // A scanner lists children under typed objects; one of them is a real plan item.
    let mut svc = service("svc", "AppSvc", Some(svc_fp.clone()), "SYS-SERVICE");
    svc.children.push(CandidateId("exe".into()));
    let mut svc_dup = service("svc-dup", "AppSvc", Some(svc_fp), "MSI-REG");
    svc_dup.children.push(CandidateId("ghost".into()));
    let mut task = typed(
        "task",
        Target::Task {
            path: r"\Vendor\App".into(),
        },
        None,
        "SYS-TASK",
    );
    task.action = Action::ReportOnly;
    task.children.push(CandidateId("root".into()));
    let rule = typed(
        "rule",
        Target::FirewallRule {
            id: r"C:\Program Files\Vendor\App".into(),
        },
        None,
        "SYS-FIREWALL",
    );
    // File and key items whose spelling begins like the objects' names and paths.
    let mut root = cand(
        "root",
        path(r"C:\Program Files\Vendor\App"),
        "FS-INSTALLDIR",
    );
    root.category = Category::AppFiles;
    root.evidence
        .push(ev(EvidenceKind::InsideInstallRoot, Scope::Path, "arp"));
    let mut exe = root.clone();
    exe.id = CandidateId("exe".into());
    exe.target = path(r"C:\Program Files\Vendor\App\svc.exe");
    let built = build(
        "vendor-app",
        vec![svc, task, rule, root, exe, svc_dup],
        &ctx,
    );
    let scan = &built.scan;
    let ids: Vec<&str> = scan.items.iter().map(|c| c.id.0.as_str()).collect();
    for id in ["svc", "task", "rule", "root"] {
        assert!(ids.contains(&id), "{id} is a top-level item: {ids:?}");
    }
    let absorbed: Vec<&str> = scan.absorbed.iter().map(|c| c.id.0.as_str()).collect();
    assert_eq!(absorbed, ["exe"], "only the file nests, under its folder");
    for c in scan.items.iter().chain(&scan.absorbed) {
        if ObjectKind::of(&c.target).is_some() {
            assert!(
                c.children.is_empty(),
                "{} has children {:?}",
                c.id.0,
                c.children
            );
        }
    }
    let root = scan.items.iter().find(|c| c.id.0 == "root").unwrap();
    assert_eq!(root.children, [CandidateId("exe".into())]);
}

#[test]
fn stage_order_fixed() {
    let expected = [
        Stage::Task,
        Stage::FirewallRule,
        Stage::RegistryValue,
        Stage::RegistryKey,
        Stage::FileSystem,
        Stage::Service,
        Stage::Package,
    ];
    let mut sorted = expected.to_vec();
    sorted.sort();
    assert_eq!(sorted, expected);

    // One item of each stage, in reverse: the plan order is the stage order.
    let mut items = vec![
        cand(
            "pkg",
            Target::AppxPackage {
                full_name: "Vendor.App_1.0.0.0_x64__abcdefghijklm".into(),
            },
            "SYS-APPX",
        ),
        service("svc", "AppSvc", None, "SYS-SERVICE"),
        cand("file", path(r"C:\Program Files\Vendor\App\a.exe"), "FS"),
        cand("key", key(r"HKLM\SOFTWARE\Vendor\App"), "REG"),
        cand("value", value(r"HKLM\SOFTWARE\Vendor\App", "x"), "REG"),
        typed("fw", Target::FirewallRule { id: "{1}".into() }, None, "FW"),
        typed(
            "task",
            Target::Task {
                path: r"\Vendor\T".into(),
            },
            None,
            "TASK",
        ),
    ];
    sort(&mut items);
    let stages: Vec<Stage> = items.iter().map(|c| Stage::of(&c.target)).collect();
    assert_eq!(stages, expected);
    let ids: Vec<&str> = items.iter().map(|c| c.id.0.as_str()).collect();
    assert_eq!(ids, ["task", "fw", "value", "key", "file", "svc", "pkg"]);
}

// ---------------------------------------------------------------------------------------------------
// Windows Installer client lists
// ---------------------------------------------------------------------------------------------------

const COMPONENTS: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\0123456789ABCDEF0123456789ABCDEF";
const UPGRADE: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\FEDCBA9876543210FEDCBA9876543210";

fn client_list(id: &str, key_path: &str, values: &[&str]) -> Candidate {
    let mut c = cand(id, key(key_path), "MSI-REG");
    c.action = Action::RemoveDirIfEmpty;
    c.evidence.push(
        ev(EvidenceKind::VendorContainer, Scope::Key, "msi").with_detail(mark_pending(
            Facts::new(),
            values.iter().map(|v| Child::Leaf(v)),
        )),
    );
    c
}

#[test]
fn empty_after_plan_not_created_for_partially_planned_components_key() {
    let mut fp = bare_fp();
    fp.msi = vec![msi(GONE_CODE, GONE_PACKED)];
    let gone = table(&[(GONE_CODE, Some(false))]);
    let deny = deny();
    let ctx = with_m1b(&deny, M1bDecide::from_facts(&fp, &gone, &unknown));

    for list in [COMPONENTS, UPGRADE] {
        // The gone product's value is an allowed, Safe item of the plan.
        let own_value = msi_owned("own", value(list, GONE_PACKED), "MSI-REG");
        let decided = one(own_value.clone(), &ctx);
        assert_eq!(deny_rule(&decided), None, "{list}: {:?}", decided.blockers);
        assert_eq!(band(&decided), Band::Safe, "{list}");

        // Partially planned: another product's value stays, so the key is not offered at all.
        let partial = decide(
            vec![
                client_list("list", list, &[GONE_PACKED, KEPT_PACKED]),
                own_value.clone(),
            ],
            &ctx,
        );
        let ids: Vec<&str> = partial.iter().map(|c| c.id.0.as_str()).collect();
        assert_eq!(ids, ["own"], "{list}");
        assert!(partial.iter().all(|c| {
            c.evidence
                .iter()
                .all(|e| e.kind != EvidenceKind::EmptyAfterPlan)
        }));

        // Every value planned: the guard still denies the key itself, so it is not offered either.
        let full = build(
            "vendor-app",
            vec![client_list("list", list, &[GONE_PACKED]), own_value],
            &ctx,
        );
        let ids: Vec<&str> = full.scan.items.iter().map(|c| c.id.0.as_str()).collect();
        assert_eq!(ids, ["own"], "{list}");
        assert!(full.plan.items.iter().all(|i| i.target != key(list)));
    }

    // Other spellings of the same lists: the Classes copy, the 32-bit view, a user's Installer data and
    // Classes.
    let closed = with_m1b(&deny, M1bDecide::default());
    let user = format!(
        r"HKU\{SID}\Software\Microsoft\Installer\UpgradeCodes\FEDCBA9876543210FEDCBA9876543210"
    );
    for list in [
        r"HKLM\SOFTWARE\Classes\Installer\UpgradeCodes\FEDCBA9876543210FEDCBA9876543210",
        r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\FEDCBA9876543210FEDCBA9876543210",
        user.as_str(),
        r"HKCU\Software\Classes\Installer\Components\0123456789ABCDEF0123456789ABCDEF",
    ] {
        let out = decide(vec![client_list("list", list, &[KEPT_PACKED])], &closed);
        assert!(out.is_empty(), "{list}: {out:?}");
    }

    // A vendor's own container with the same leaf names is unaffected: listed (Weak) as before.
    let out = decide(
        vec![client_list(
            "list",
            r"HKLM\SOFTWARE\Vendor\Installer\Data\Components\X",
            &[KEPT_PACKED],
        )],
        &closed,
    );
    assert_eq!(out.len(), 1);
}

// ---------------------------------------------------------------------------------------------------
// Emission
// ---------------------------------------------------------------------------------------------------

/// One candidate of each shape the M1a scanners produce (the emit tests' scan output).
fn m1a_shapes() -> Vec<Candidate> {
    let owned_path = |id: &str, p: &str| {
        let mut c = cand(id, path(p), "FS-INSTALLDIR");
        c.category = Category::AppFiles;
        c.evidence
            .push(ev(EvidenceKind::InsideInstallRoot, Scope::Path, "arp"));
        c
    };
    let owned_key = |id: &str, p: &str| {
        let mut c = cand(id, key(p), "REG-SOFTWARE");
        c.evidence.push(ev(
            EvidenceKind::InstallerManifest(ManifestKind::Inno),
            Scope::Key,
            "inno",
        ));
        c
    };
    let owned_value = |id: &str, p: &str, name: &str| {
        let mut c = cand(id, value(p, name), "REF-ANY");
        c.evidence.push(ev(
            EvidenceKind::InPreUninstallRefSnapshot,
            Scope::Value,
            "refsnap",
        ));
        c
    };
    let mut vendor = cand("vendor", key(r"HKLM\SOFTWARE\Vendor"), "REG-SOFTWARE");
    vendor.action = Action::RemoveDirIfEmpty;
    vendor.evidence.push(
        ev(EvidenceKind::VendorContainer, Scope::Key, "vendor")
            .with_detail(mark_pending(Facts::new(), [Child::Container("App")])),
    );
    let mut segment = cand(
        "segment",
        Target::RegMultiSzSegment {
            path: r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment".into(),
            name: "Path".into(),
            segment: r"C:\Program Files\Vendor\App\bin".into(),
            index: None,
        },
        "REG-ENV",
    );
    segment.evidence.push(ev(
        EvidenceKind::InstallerManifest(ManifestKind::Inno),
        Scope::Value,
        "inno",
    ));
    let mut weak = cand("weak", path(r"C:\ProgramData\Vendor"), "FS-APPDATA");
    weak.evidence
        .push(ev(EvidenceKind::NameTokenExact, Scope::Path, "name"));
    let mut package = cand(
        "pkg",
        Target::AppxPackage {
            full_name: "Vendor.App_1.0.0.0_x64__abcdefghijklm".into(),
        },
        "SYS-APPX",
    );
    package.category = Category::Package;
    package.blockers.push(Blocker::ReversibilityNone);
    package.evidence.push(ev(
        EvidenceKind::AppxExternalLocation,
        Scope::Package,
        "appx",
    ));
    let mut dup = cand(
        "dup",
        value(r"HKLM\Software\Vendor\App", "InstallDir"),
        "REG-SOFTWARE",
    );
    dup.evidence.push(ev(
        EvidenceKind::PointsIntoInstallRoot,
        Scope::Value,
        "live",
    ));
    vec![
        package,
        owned_path("root", r"C:\Program Files\Vendor\App"),
        weak,
        owned_path("exe", r"C:\Program Files\Vendor\App\app.exe"),
        vendor,
        owned_key("app-key", r"HKLM\SOFTWARE\Vendor\App"),
        owned_value("dir", r"HKLM\SOFTWARE\Vendor\App", "InstallDir"),
        dup,
        owned_value("default", &format!(r"HKU\{SID}\Software\Classes\.vnd"), ""),
        owned_key(
            "denied",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        segment,
    ]
}

fn sha256(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Captured from the planner before M1B-PLAN (commit dd3a22b, policy m1b.1) for `m1a_shapes`: the plan
/// hash, and SHA-256 of the compact JSON of the plan and of the scan document.
const GOLDEN_PLAN_HASH: &str = "3ea67656d0bcc442e8b931fe5ccd0b6ad659ed4c6269ad90bd1c7d02505a7b78";
const GOLDEN_PLAN_JSON: &str = "3c4854025920d672fbe93df779e7428fd9bdea0393dbe734ac5bfbd167080604";
const GOLDEN_SCAN_JSON: &str = "8eeb28506b28687df093d9002fdfa655b9db958268d693a47d7ddf125c7fc7ed";

#[test]
fn plan_hash_golden_unchanged() {
    let deny = deny();
    // Closed lists, and lists that name products, bundles and caches the plan does not touch.
    let mut fp = burn_fp();
    fp.msi = vec![msi(GONE_CODE, GONE_PACKED)];
    let gone = |_: &str| Some(false);
    let open = M1bDecide::from_facts(&fp, &gone, &gone);
    assert!(!open.is_empty());
    for m1b in [M1bDecide::default(), open] {
        let built = build("vendor-app", m1a_shapes(), &with_m1b(&deny, m1b));
        assert_eq!(POLICY_VERSION, "m1b.1");
        assert_eq!(built.scan.plan_hash, GOLDEN_PLAN_HASH);
        assert_eq!(
            sha256(&serde_json::to_string(&built.plan).unwrap()),
            GOLDEN_PLAN_JSON
        );
        assert_eq!(
            sha256(&serde_json::to_string(&built.scan).unwrap()),
            GOLDEN_SCAN_JSON
        );
    }
}

#[test]
fn object_fp_emitted_and_read_back() {
    let deny = deny();
    let ctx = ctx(&deny);
    let svc_fp = service_identity(r"C:\Program Files\Vendor\App\svc.exe").fp();
    let rule_fp = FirewallIdentity {
        id: "{11111111-2222-3333-4444-555555555555}".into(),
        rule: "v2.31|Action=Allow|Dir=In|Name=App|".into(),
    }
    .fp();
    let with_fp = || {
        let mut list = m1a_shapes();
        list.push(service(
            "svc",
            "AppSvc",
            Some(svc_fp.clone()),
            "SYS-SERVICE",
        ));
        list.push(typed(
            "rule",
            Target::FirewallRule {
                id: "{11111111-2222-3333-4444-555555555555}".into(),
            },
            Some(rule_fp.clone()),
            "SYS-FIREWALL",
        ));
        list
    };
    let built = build("vendor-app", with_fp(), &ctx);
    let text = serde_json::to_string_pretty(&built.scan).unwrap();
    let back: ScanDoc = serde_json::from_str(&text).unwrap();
    assert_eq!(back, built.scan);
    let get = |doc: &ScanDoc, id: &str| -> Option<ObjectFp> {
        doc.items
            .iter()
            .find(|c| c.id.0 == id)
            .and_then(|c| c.object_fp.clone())
    };
    assert_eq!(get(&back, "svc"), Some(svc_fp.clone()));
    assert_eq!(get(&back, "rule"), Some(rule_fp.clone()));
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let items = v["items"].as_array().unwrap();
    let svc_json = items.iter().find(|c| c["id"] == json!("svc")).unwrap();
    assert_eq!(svc_json["object_fp"]["kind"], json!("service"));
    assert_eq!(svc_json["object_fp"]["sha256"], json!(svc_fp.sha256));
    // Only the typed items carry the member.
    let carriers = items
        .iter()
        .filter(|c| c.get("object_fp").is_some())
        .count();
    assert_eq!(carriers, 2);

    // The digest is outside the plan hash: the same plan with other digests has the same hash and
    // plan. (Without any digest a typed item is `object.no-fp`, R2a S2, so the digests are replaced,
    // not removed.)
    let other: Vec<Candidate> = with_fp()
        .into_iter()
        .map(|mut c| {
            if let Some(fp) = c.object_fp.as_mut() {
                fp.sha256 = "0".repeat(64);
            }
            c
        })
        .collect();
    let plain = build("vendor-app", other, &ctx);
    assert_eq!(plain.plan, built.plan);
    assert_eq!(plain.scan.plan_hash, built.scan.plan_hash);
    // Without a digest, a typed item is Blocked by the plan itself.
    let stripped: Vec<Candidate> = with_fp()
        .into_iter()
        .map(|mut c| {
            c.object_fp = None;
            c
        })
        .collect();
    let unbound = build("vendor-app", stripped, &ctx);
    for item in unbound.plan.items.iter().filter(|i| {
        matches!(
            i.target,
            Target::Service { .. } | Target::FirewallRule { .. }
        )
    }) {
        assert_eq!(item.band, Band::Blocked, "{:?}", item.target);
    }
    assert_eq!(
        plan_hash(&back.items, &back.policy_version, back.mode),
        built.scan.plan_hash
    );
}

/// R2a S10: a whole-value delete under a shared COM key is let through when admin-trust Value-scope
/// evidence ties the value's data to the app; without it, or for a key, the shared-COM rule holds.
#[test]
fn shared_com_value_is_earned_by_the_values_own_evidence() {
    let deny = deny();
    let ctx = ctx(&deny);
    let data = purge_guard::deny::shared_iids().unwrap();
    let iid = format!(r"HKLM\SOFTWARE\Classes\Interface\{}", data.iids[0].iid);
    let stub = format!(r"{iid}\ProxyStubClsid32");
    let with = |target: Target, evidence: Vec<Evidence>| {
        let mut c = cand("c", target, "COM-INTERFACE");
        c.evidence = evidence;
        one(c, &ctx)
    };
    for kind in [
        EvidenceKind::InPreUninstallRefSnapshot,
        EvidenceKind::PointsIntoInstallRoot,
        EvidenceKind::DanglingRef,
    ] {
        assert_eq!(
            deny_rule(&with(value(&stub, ""), vec![ev(kind, Scope::Value, "x")])),
            None,
            "{kind:?}"
        );
    }
    // No such evidence: denied.
    assert_eq!(
        deny_rule(&with(value(&stub, ""), Vec::new())),
        Some("com.shared-iid")
    );
    // User-writable evidence for a machine value is not admin trust: denied.
    let mut user = ev(
        EvidenceKind::InPreUninstallRefSnapshot,
        Scope::Value,
        "refsnap",
    );
    user.trust = SourceTrust::UserWritable;
    assert_eq!(
        deny_rule(&with(value(&stub, ""), vec![user])),
        Some("com.shared-iid")
    );
    // A key is never lifted, whatever its evidence.
    let k = msi_owned("k", key(&stub), "COM-INTERFACE");
    assert_eq!(deny_rule(&one(k, &ctx)), Some("com.shared-iid"));
}

/// R2a S9: `bundle_known` reads the fresh inventory and is unknown unless the bundle's hive was read.
#[test]
fn bundle_known_rule() {
    use purge_model::{InstallScope, InstallerKind, InventoryEntry, RawFlags, WritableBy};
    use purge_plan::decide::bundle_known;
    let bundle = "{B0B0B0B0-0000-0000-0000-000000000001}";
    let machine = ProgramId::machine(View::K64, bundle).unwrap();
    let entry = |id: ProgramId| InventoryEntry {
        key_path: id.key_path(),
        program_id: id,
        hive_sid: None,
        view: View::K32,
        display_name: "Bundle".into(),
        version: None,
        publisher: None,
        flags: RawFlags::default(),
        installer_kind: InstallerKind::Burn,
        scope: InstallScope::Machine,
        product_code: None,
        upgrade_code: None,
        inno_app_id: None,
        writable_by: WritableBy::Admin,
        install_location: None,
        uninstall_string: None,
        quiet_uninstall_string: None,
        display_icon: None,
        install_time_evidence: Vec::new(),
        msi: None,
    };
    let read = |_: Option<&str>| true;
    let unread = |_: Option<&str>| false;
    let present = [entry(
        ProgramId::machine(View::K32, bundle.to_ascii_lowercase()).unwrap(),
    )];
    assert_eq!(
        bundle_known(bundle, &machine, &present, &unread),
        Some(true)
    );
    assert_eq!(bundle_known(bundle, &machine, &[], &read), Some(false));
    assert_eq!(bundle_known(bundle, &machine, &[], &unread), None);
    assert_eq!(bundle_known("not-a-guid", &machine, &[], &read), None);
    // A per-user bundle asks for its own hive.
    let user = ProgramId::user(SID.to_owned(), View::K64, bundle).unwrap();
    let only_user = |sid: Option<&str>| sid == Some(SID);
    assert_eq!(bundle_known(bundle, &user, &[], &only_user), Some(false));
    assert_eq!(bundle_known(bundle, &machine, &[], &only_user), None);
}
