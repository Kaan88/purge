//! Golden table and property checks for the policy (ENGINE_PLAN.md §5.3 Rule T, §5.8).
//!
//! The table is keyed by `POLICY_VERSION`: a change to the rules that alters any row must bump the version
//! and update [`GOLDEN_VERSION`] together with the rows, so a silent policy change fails here first.
//!
//! The property checks draw candidates from a small deterministic generator (no external crates), so a
//! failure reproduces from the printed seed.

use purge_model::{
    Action, AppRef, Band, Blocker, Candidate, CandidateId, Category, Evidence, EvidenceKind, Facts,
    Harm, ManifestKind, Origin, ProgramId, Reversibility, ScanMode, Scope, SourceTrust, Target,
    Tier, VerifyGone, View,
};
use purge_policy::band::{POLICY_VERSION, PolicyCtx, TargetScope, decide, effective_tier, rank};

/// The policy version the rows below were written for.
const GOLDEN_VERSION: &str = "m1a.6";

const ADMIN: SourceTrust = SourceTrust::AdminOnly;
const USER: SourceTrust = SourceTrust::UserWritable;
const INNO: EvidenceKind = EvidenceKind::InstallerManifest(ManifestKind::Inno);

// ---------------------------------------------------------------------------------------------------
// Builders

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
fn segment(p: &str, seg: &str) -> Target {
    Target::RegMultiSzSegment {
        path: p.into(),
        name: "Path".into(),
        segment: seg.into(),
        index: None,
    }
}
fn package(name: &str) -> Target {
    Target::AppxPackage {
        full_name: name.into(),
    }
}

const HKLM_KEY: &str = r"HKLM\SOFTWARE\Vendor\App";
const HKU_KEY: &str = r"HKU\S-1-5-21-1-2-3-1001\Software\Vendor\App";
const HKLM_ENV: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment";
const HKU_ENV: &str = r"HKU\S-1-5-21-1-2-3-1001\Environment";
const PF_DIR: &str = r"C:\Program Files\App";
const USER_DIR: &str = r"C:\Users\u\AppData\Local\Programs\App";

fn ev(kind: EvidenceKind, scope: Scope, trust: SourceTrust, source: &str) -> Evidence {
    Evidence::new(kind, scope, trust, source)
        .unwrap_or_else(|| panic!("{kind:?} cannot have scope {scope:?}"))
}

/// A candidate with the usual defaults: scanner origin, harm Low, fully reversible.
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
    }
}

trait CandidateExt {
    fn harm(self, harm: Harm) -> Self;
    fn blocker(self, blocker: Blocker) -> Self;
    fn origin(self, origin: Origin) -> Self;
    fn more(self, evidence: Evidence) -> Self;
}

impl CandidateExt for Candidate {
    fn harm(mut self, harm: Harm) -> Self {
        self.harm = harm;
        self
    }
    fn blocker(mut self, blocker: Blocker) -> Self {
        self.blockers.push(blocker);
        self
    }
    fn origin(mut self, origin: Origin) -> Self {
        self.origin = origin;
        self
    }
    fn more(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }
}

fn gone() -> VerifyGone {
    VerifyGone::new(true, true, true)
}
fn ctx(mode: ScanMode, target_scope: TargetScope) -> PolicyCtx {
    PolicyCtx {
        mode,
        verify_gone: gone(),
        target_scope,
    }
}
fn post_machine() -> PolicyCtx {
    ctx(ScanMode::Post, TargetScope::Machine)
}
fn post_user() -> PolicyCtx {
    ctx(ScanMode::Post, TargetScope::PerUser)
}

/// Files under the install root: the plainest Safe item.
fn app_files(trust: SourceTrust, dir: &str) -> Candidate {
    cand(
        path(dir),
        Action::Quarantine,
        Category::AppFiles,
        vec![ev(
            EvidenceKind::InsideInstallRoot,
            Scope::Path,
            trust,
            "arp",
        )],
    )
}

/// A registry value recorded in the pre-uninstall reference snapshot.
fn snap_value(target: Target) -> Candidate {
    cand(
        target,
        Action::DeleteValue,
        Category::Registration,
        vec![ev(
            EvidenceKind::InPreUninstallRefSnapshot,
            Scope::Value,
            ADMIN,
            "refsnap",
        )],
    )
}

fn ai(weight: i8) -> Evidence {
    let mut e = Evidence::chained(Tier::Ai, Scope::Value, ADMIN, "agent").unwrap();
    e.weight = weight;
    e
}

// ---------------------------------------------------------------------------------------------------
// Golden table

struct Case {
    name: &'static str,
    candidate: Candidate,
    ctx: PolicyCtx,
    band: Band,
    preselected: bool,
    score: i32,
}

fn case(
    name: &'static str,
    candidate: Candidate,
    ctx: PolicyCtx,
    band: Band,
    preselected: bool,
    score: i32,
) -> Case {
    Case {
        name,
        candidate,
        ctx,
        band,
        preselected,
        score,
    }
}

#[allow(clippy::too_many_lines)]
fn golden() -> Vec<Case> {
    use Band::{Blocked, Likely, Safe, Weak};
    use EvidenceKind::*;
    let reg = Category::Registration;
    let mut cases = Vec::new();
    let mut add = |name, candidate, ctx, band, preselected, score| {
        cases.push(case(name, candidate, ctx, band, preselected, score));
    };

    // --- Safe: Tier A with matching scope, S >= 8 -------------------------------------------------
    add(
        "files inside the install root",
        app_files(ADMIN, PF_DIR),
        post_machine(),
        Safe,
        true,
        9,
    );
    add(
        "inno key-create record on that key",
        cand(
            key(HKLM_KEY),
            Action::DeleteKey,
            reg,
            vec![ev(INNO, Scope::Key, ADMIN, "inno")],
        ),
        post_machine(),
        Safe,
        true,
        8,
    );
    add(
        "snapshot value on a value target",
        snap_value(value(HKLM_KEY, "InstallDir")),
        post_machine(),
        Safe,
        true,
        8,
    );
    add(
        "proven owned skeleton key",
        cand(
            key(r"HKLM\SOFTWARE\Classes\sh_auto_file"),
            Action::DeleteKey,
            Category::Association,
            vec![ev(ProvenOwnedSkeleton, Scope::Key, ADMIN, "subtree")],
        ),
        post_machine(),
        Safe,
        true,
        8,
    );
    add(
        "harvested token key plus time window reaches 8",
        cand(
            key(r"HKLM\SOFTWARE\Classes\FirefoxHTML-308046B0AF4A39CB"),
            Action::DeleteKey,
            Category::Association,
            vec![
                ev(HarvestedToken, Scope::Key, ADMIN, "tokens"),
                ev(TimeWindow, Scope::Key, ADMIN, "time"),
            ],
        ),
        post_machine(),
        Safe,
        true,
        8,
    );
    add(
        "com key ownership plus time window",
        cand(
            key(r"HKLM\SOFTWARE\Classes\CLSID\{11111111-2222-3333-4444-555555555555}"),
            Action::DeleteKey,
            Category::ShellCom,
            vec![
                ev(ComKeyOwnership, Scope::Key, ADMIN, "com"),
                ev(TimeWindow, Scope::Key, ADMIN, "time"),
            ],
        ),
        post_machine(),
        Safe,
        true,
        8,
    );
    add(
        "dangling value into the root",
        cand(
            value(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "App"),
            Action::DeleteValue,
            Category::Startup,
            vec![
                ev(PointsIntoInstallRoot, Scope::Value, ADMIN, "roots"),
                ev(DanglingRef, Scope::Value, ADMIN, "fs"),
            ],
        ),
        post_machine(),
        Safe,
        true,
        13,
    );
    add(
        "chained ref to a tier A progid, also in the snapshot",
        snap_value(value(
            r"HKLM\SOFTWARE\Classes\.txt\OpenWithProgids",
            "App.txt",
        ))
        .more(Evidence::chained(Tier::A, Scope::Value, ADMIN, "assoc").unwrap()),
        post_machine(),
        Safe,
        true,
        13,
    );
    add(
        "app-named key with a root reference plus time window",
        cand(
            key(HKLM_KEY),
            Action::DeleteKey,
            reg,
            vec![
                ev(AppNamedKeyWithRootRef, Scope::Key, ADMIN, "software"),
                ev(TimeWindow, Scope::Key, ADMIN, "time"),
            ],
        ),
        post_machine(),
        Safe,
        true,
        8,
    );

    // --- Score: independent sources ---------------------------------------------------------------
    let points = |sources: &[&str]| {
        cand(
            value(HKLM_KEY, "Path"),
            Action::DeleteValue,
            reg,
            sources
                .iter()
                .map(|s| ev(PointsIntoInstallRoot, Scope::Value, ADMIN, s))
                .collect(),
        )
    };
    add(
        "points into root, one source",
        points(&["a"]),
        post_machine(),
        Likely,
        false,
        6,
    );
    add(
        "points into root, same source twice",
        points(&["a", "a"]),
        post_machine(),
        Likely,
        false,
        6,
    );
    add(
        "points into root, two sources",
        points(&["a", "b"]),
        post_machine(),
        Likely,
        false,
        7,
    );
    add(
        "points into root, three sources",
        points(&["a", "b", "c"]),
        post_machine(),
        Safe,
        true,
        8,
    );
    add(
        "points into root, bonus capped at +2",
        points(&["a", "b", "c", "d", "e"]),
        post_machine(),
        Safe,
        true,
        8,
    );

    // --- Scope mismatch ---------------------------------------------------------------------------
    add(
        "value-only tier A on a key target is never Safe",
        cand(
            key(HKLM_KEY),
            Action::DeleteKey,
            reg,
            vec![
                ev(InPreUninstallRefSnapshot, Scope::Value, ADMIN, "refsnap"),
                ev(PointsIntoInstallRoot, Scope::Value, ADMIN, "roots"),
                ev(DanglingRef, Scope::Value, ADMIN, "fs"),
            ],
        ),
        post_machine(),
        Likely,
        false,
        21,
    );
    add(
        "inno value record on a key target",
        cand(
            key(HKLM_KEY),
            Action::DeleteKey,
            reg,
            vec![ev(INNO, Scope::Value, ADMIN, "inno")],
        ),
        post_machine(),
        Likely,
        false,
        8,
    );
    add(
        "key evidence on a value target",
        cand(
            value(HKLM_KEY, "v"),
            Action::DeleteValue,
            reg,
            vec![ev(ProvenOwnedSkeleton, Scope::Key, ADMIN, "subtree")],
        ),
        post_machine(),
        Likely,
        false,
        8,
    );
    add(
        "path evidence on a package target",
        cand(
            package("Vendor.App_1.0.0.0_x64__abc"),
            Action::RemovePackage,
            Category::Package,
            vec![ev(InsideInstallRoot, Scope::Path, ADMIN, "arp")],
        ),
        post_machine(),
        Likely,
        false,
        9,
    );
    add(
        "a service has no M1a evidence scope",
        cand(
            Target::Service {
                name: "AppSvc".into(),
            },
            Action::ReportOnly,
            Category::System,
            vec![ev(HarvestedToken, Scope::Key, ADMIN, "tokens")],
        ),
        post_machine(),
        Likely,
        false,
        7,
    );

    // --- Rule T -----------------------------------------------------------------------------------
    add(
        "rule T: user-writable record, machine path",
        app_files(USER, PF_DIR),
        post_machine(),
        Likely,
        false,
        9,
    );
    add(
        "rule T: user-writable record, per-user path",
        app_files(USER, USER_DIR),
        post_user(),
        Safe,
        true,
        9,
    );
    add(
        "rule T: HKLM key stays machine scope whatever the caller says",
        cand(
            key(HKLM_KEY),
            Action::DeleteKey,
            reg,
            vec![ev(INNO, Scope::Key, USER, "inno")],
        ),
        post_user(),
        Likely,
        false,
        8,
    );
    add(
        "rule T: user-writable record, HKU key",
        cand(
            key(HKU_KEY),
            Action::DeleteKey,
            reg,
            vec![ev(INNO, Scope::Key, USER, "inno")],
        ),
        post_user(),
        Safe,
        true,
        8,
    );
    add(
        "rule T: one admin record is enough beside a user-writable one",
        app_files(USER, PF_DIR).more(ev(InsideInstallRoot, Scope::Path, ADMIN, "msi")),
        post_machine(),
        Safe,
        true,
        10,
    );

    // --- ChainedRef takes its anchor's tier -------------------------------------------------------
    let chained = |tier| {
        cand(
            value(r"HKLM\SOFTWARE\Classes\.txt\OpenWithProgids", "App.txt"),
            Action::DeleteValue,
            Category::Association,
            vec![Evidence::chained(tier, Scope::Value, ADMIN, "assoc").unwrap()],
        )
    };
    add(
        "chained ref to a tier A anchor alone",
        chained(Tier::A),
        post_machine(),
        Likely,
        false,
        5,
    );
    add(
        "chained ref to a tier B anchor with a time window and a name",
        chained(Tier::B)
            .more(ev(TimeWindow, Scope::Value, ADMIN, "time"))
            .more(ev(TimeWindow, Scope::Value, ADMIN, "time2"))
            .more(ev(TimeWindow, Scope::Value, ADMIN, "time3")),
        post_machine(),
        Likely,
        false,
        8,
    );

    // --- Category, harm ---------------------------------------------------------------------------
    add(
        "user data category is never preselected",
        {
            let mut c = app_files(ADMIN, PF_DIR);
            c.category = Category::UserData;
            c
        },
        post_machine(),
        Likely,
        false,
        9,
    );
    add(
        "user data soft blocker",
        app_files(ADMIN, PF_DIR).blocker(Blocker::UserData),
        post_machine(),
        Likely,
        false,
        9,
    );
    add(
        "system category",
        {
            let mut c = app_files(ADMIN, PF_DIR);
            c.category = Category::System;
            c
        },
        post_machine(),
        Likely,
        false,
        9,
    );
    add(
        "harm medium (configuration)",
        {
            let mut c = app_files(ADMIN, PF_DIR).harm(Harm::Medium);
            c.category = Category::AppData;
            c
        },
        post_machine(),
        Likely,
        false,
        9,
    );
    add(
        "harm high",
        app_files(ADMIN, PF_DIR).harm(Harm::High),
        post_machine(),
        Likely,
        false,
        9,
    );
    add(
        "harm none is fine",
        app_files(ADMIN, PF_DIR).harm(Harm::None),
        post_machine(),
        Safe,
        true,
        9,
    );
    add(
        "referenced data dir: tier B, user data",
        {
            let mut c = cand(
                path(r"C:\Users\u\Documents\AppProjects"),
                Action::Quarantine,
                Category::UserData,
                vec![ev(ReferencedByApp, Scope::Path, USER, "config")],
            )
            .harm(Harm::High)
            .blocker(Blocker::UserData);
            c.reversibility = Reversibility::Full;
            c
        },
        post_user(),
        Likely,
        false,
        4,
    );

    // --- PATH segment edits (declared-segment exception) ------------------------------------------
    let seg = |target: Target, evidence: Vec<Evidence>| {
        cand(target, Action::EditSegment, reg, evidence).harm(Harm::Medium)
    };
    add(
        "PATH segment declared by the inno log",
        seg(
            segment(HKLM_ENV, r"C:\Program Files\Git\cmd"),
            vec![ev(INNO, Scope::Value, ADMIN, "inno")],
        ),
        post_machine(),
        Safe,
        true,
        8,
    );
    add(
        "PATH segment under a root, directory gone",
        seg(
            segment(HKLM_ENV, r"C:\Program Files\App\bin"),
            vec![
                ev(PointsIntoInstallRoot, Scope::Value, ADMIN, "roots"),
                ev(DanglingRef, Scope::Value, ADMIN, "fs"),
            ],
        ),
        post_machine(),
        Safe,
        true,
        13,
    );
    add(
        "PATH segment neither declared nor under a root stays medium",
        seg(
            segment(HKLM_ENV, r"C:\Tools\308046B0AF4A39CB"),
            vec![
                ev(DanglingRef, Scope::Value, ADMIN, "fs"),
                ev(HarvestedToken, Scope::Value, ADMIN, "tokens"),
            ],
        ),
        post_machine(),
        Likely,
        false,
        14,
    );
    add(
        "user PATH segment declared by a user-writable record",
        seg(
            segment(HKU_ENV, r"C:\Users\u\AppData\Roaming\npm"),
            vec![ev(INNO, Scope::Value, USER, "inno")],
        ),
        post_user(),
        Safe,
        true,
        8,
    );
    add(
        "machine PATH segment declared only by a user-writable record",
        seg(
            segment(HKLM_ENV, r"C:\Program Files\App\bin"),
            vec![ev(INNO, Scope::Value, USER, "inno")],
        ),
        post_machine(),
        Likely,
        false,
        8,
    );
    add(
        "declared PATH segment marked high harm keeps its harm",
        seg(
            segment(HKLM_ENV, r"C:\Program Files\Git\cmd"),
            vec![ev(INNO, Scope::Value, ADMIN, "inno")],
        )
        .harm(Harm::High),
        post_machine(),
        Likely,
        false,
        8,
    );
    add(
        "whole-value delete of PATH gets no exception",
        cand(
            value(HKLM_ENV, "Path"),
            Action::DeleteValue,
            reg,
            vec![ev(INNO, Scope::Value, ADMIN, "inno")],
        )
        .harm(Harm::Medium),
        post_machine(),
        Likely,
        false,
        8,
    );

    // --- AppX -------------------------------------------------------------------------------------
    let appx = || {
        cand(
            package("Vendor.App_1.0.0.0_x64__abc"),
            Action::RemovePackage,
            Category::Package,
            vec![ev(AppxExternalLocation, Scope::Package, ADMIN, "appx")],
        )
    };
    add(
        "appx package with ReversibilityNone is Likely",
        {
            let mut c = appx().blocker(Blocker::ReversibilityNone);
            c.reversibility = Reversibility::None;
            c
        },
        post_machine(),
        Likely,
        false,
        8,
    );
    add(
        "appx package at default harm (medium) is Likely",
        appx().harm(Harm::Medium),
        post_machine(),
        Likely,
        false,
        8,
    );

    // --- Likely / Weak by score and name ----------------------------------------------------------
    let named = |kinds: &[EvidenceKind]| {
        cand(
            path(r"C:\Users\u\AppData\Roaming\App"),
            Action::Quarantine,
            Category::AppData,
            kinds
                .iter()
                .map(|k| ev(*k, Scope::Path, USER, "name"))
                .collect(),
        )
        .harm(Harm::Medium)
    };
    add(
        "exact full name alone",
        named(&[ExactFullName]),
        post_user(),
        Likely,
        false,
        4,
    );
    add(
        "exact full name stays Likely below S 4",
        named(&[ExactFullName, GenericName, ManyFiles]),
        post_user(),
        Likely,
        false,
        -1,
    );
    // The app's own data folder, `<Vendor>\<Product>`: shown whatever is in it, never ticked.
    let profile = |category: Category, kinds: &[EvidenceKind]| {
        cand(
            path(r"C:\Users\u\AppData\Roaming\Vendor\App"),
            Action::Quarantine,
            category,
            kinds
                .iter()
                .map(|k| ev(*k, Scope::Path, USER, "name"))
                .collect(),
        )
    };
    add(
        "product data folder with programs in it is shown",
        profile(
            Category::UserData,
            &[ProductSubfolderOfVendor, ExecutablesPresent],
        )
        .blocker(Blocker::UserData),
        post_user(),
        Likely,
        false,
        -1,
    );
    add(
        "product data folder alone is shown",
        profile(Category::UserData, &[ProductSubfolderOfVendor]).blocker(Blocker::UserData),
        post_user(),
        Likely,
        false,
        3,
    );
    add(
        "product data folder with a generic name stays weak",
        profile(Category::UserData, &[ProductSubfolderOfVendor, GenericName])
            .blocker(Blocker::UserData),
        post_user(),
        Weak,
        false,
        0,
    );
    add(
        "product subfolder that is not user data stays weak",
        profile(Category::AppData, &[ProductSubfolderOfVendor]).blocker(Blocker::UserData),
        post_user(),
        Weak,
        false,
        3,
    );
    add(
        "product data folder without the user-data blocker stays weak",
        profile(Category::UserData, &[ProductSubfolderOfVendor]),
        post_user(),
        Weak,
        false,
        3,
    );
    add(
        "product data folder is lowered by an assistant's note like any other",
        profile(Category::UserData, &[ProductSubfolderOfVendor])
            .blocker(Blocker::UserData)
            .more(ai(-1)),
        post_user(),
        Weak,
        false,
        3,
    );
    add(
        "product data folder named by an assistant only stays weak",
        {
            let mut c =
                profile(Category::UserData, &[ProductSubfolderOfVendor]).blocker(Blocker::UserData);
            c.evidence[0].tier = Tier::Ai;
            c
        },
        post_user(),
        Weak,
        false,
        0,
    );
    add(
        "product-named key is not lifted",
        cand(
            key(r"HKLM\SOFTWARE\Vendor\App"),
            Action::DeleteKey,
            Category::UserData,
            vec![ev(ProductSubfolderOfVendor, Scope::Key, ADMIN, "name")],
        )
        .blocker(Blocker::UserData),
        post_machine(),
        Weak,
        false,
        3,
    );
    add(
        "vendor container next to a product data folder stays weak",
        cand(
            path(r"C:\Users\u\AppData\Roaming\Vendor"),
            Action::RemoveDirIfEmpty,
            Category::AppData,
            vec![ev(VendorContainer, Scope::Path, USER, "vendor")],
        ),
        post_user(),
        Weak,
        false,
        2,
    );
    add(
        "name token alone is weak",
        named(&[NameTokenExact]),
        post_user(),
        Weak,
        false,
        3,
    );
    add(
        "name token plus time window",
        named(&[NameTokenExact, TimeWindow]),
        post_user(),
        Likely,
        false,
        4,
    );
    add(
        "product under vendor alone is weak",
        named(&[ProductSubfolderOfVendor]),
        post_user(),
        Weak,
        false,
        3,
    );
    add(
        "product under vendor plus name token",
        named(&[ProductSubfolderOfVendor, NameTokenExact]),
        post_user(),
        Likely,
        false,
        6,
    );
    add(
        "fuzzy name with executables is weak",
        named(&[NameTokenExact, TimeWindow, NameFuzzy, ExecutablesPresent]),
        post_user(),
        Weak,
        false,
        -2,
    );
    add(
        "no evidence at all",
        named(&[]),
        post_user(),
        Weak,
        false,
        0,
    );
    add(
        "tier B and C evidence never reaches Safe however much there is",
        named(&[
            ExactFullName,
            ProductSubfolderOfVendor,
            NameTokenExact,
            VendorContainer,
            TimeWindow,
        ])
        .harm(Harm::Low),
        post_user(),
        Likely,
        false,
        13,
    );

    // --- Vendor containers ------------------------------------------------------------------------
    let vendor = |action: Action, extra: Vec<Evidence>| {
        let mut evidence = vec![ev(VendorContainer, Scope::Path, ADMIN, "vendor")];
        evidence.extend(extra);
        cand(
            path(r"C:\Program Files\Vendor"),
            action,
            Category::AppFiles,
            evidence,
        )
        .harm(Harm::None)
    };
    add(
        "vendor container alone is weak",
        vendor(Action::RemoveDirIfEmpty, vec![]),
        post_machine(),
        Weak,
        false,
        2,
    );
    add(
        "vendor container empty after the plan",
        vendor(
            Action::RemoveDirIfEmpty,
            vec![ev(EmptyAfterPlan, Scope::Path, ADMIN, "plan")],
        ),
        post_machine(),
        Safe,
        true,
        10,
    );
    add(
        "EmptyAfterPlan supports delete-if-empty only",
        vendor(
            Action::Quarantine,
            vec![ev(EmptyAfterPlan, Scope::Path, ADMIN, "plan")],
        ),
        post_machine(),
        Likely,
        false,
        10,
    );
    add(
        "mega-vendor container weighs nothing",
        {
            let mut c = vendor(Action::RemoveDirIfEmpty, vec![]);
            c.evidence[0].weight = EvidenceKind::MEGA_VENDOR_WEIGHT;
            c
        },
        post_machine(),
        Weak,
        false,
        0,
    );

    // --- Negatives --------------------------------------------------------------------------------
    add(
        "modified after uninstall pulls a root item below 8",
        app_files(ADMIN, PF_DIR).more(ev(ModifiedAfterUninstall, Scope::Path, ADMIN, "fs")),
        post_machine(),
        Likely,
        false,
        5,
    );
    add(
        "tier A with S below 4 and nothing else is weak",
        points(&["a"]).more(ev(ModifiedAfterUninstall, Scope::Value, ADMIN, "fs")),
        post_machine(),
        Weak,
        false,
        2,
    );
    add(
        "tier A with S below 4 and a soft blocker is Likely",
        points(&["a"])
            .more(ev(ModifiedAfterUninstall, Scope::Value, ADMIN, "fs"))
            .blocker(Blocker::InUse),
        post_machine(),
        Likely,
        false,
        2,
    );

    // --- Soft blockers ----------------------------------------------------------------------------
    for (name, blocker) in [
        (
            "soft: unmatched children",
            Blocker::UnmatchedChildren { n: 2 },
        ),
        ("soft: too large", Blocker::TooLarge),
        ("soft: older than install", Blocker::OlderThanInstall),
        ("soft: multi-target owner", Blocker::MultiTargetOwner),
        ("soft: in use", Blocker::InUse),
        (
            "soft: msi package unreadable",
            Blocker::MsiPackageUnreadable,
        ),
        ("soft: changed since scan", Blocker::ChangedSinceScan),
    ] {
        add(
            name,
            app_files(ADMIN, PF_DIR).blocker(blocker),
            post_machine(),
            Likely,
            false,
            9,
        );
    }

    // --- Hard blockers ----------------------------------------------------------------------------
    for (name, blocker) in [
        (
            "hard: referenced by another app",
            Blocker::ReferencedByOtherApp {
                app: "Mozilla Thunderbird".into(),
            },
        ),
        ("hard: windows baseline", Blocker::WindowsBaseline),
        (
            "hard: deny-listed",
            Blocker::DenyListed {
                rule: "windir".into(),
            },
        ),
        ("hard: not gone", Blocker::NotGone),
        ("hard: shared iid", Blocker::SharedIid),
    ] {
        add(
            name,
            app_files(ADMIN, PF_DIR).blocker(blocker),
            post_machine(),
            Blocked,
            false,
            9,
        );
    }
    add(
        "hard beats soft and weak evidence alike",
        named(&[NameTokenExact])
            .blocker(Blocker::UserData)
            .blocker(Blocker::StructuralContainer),
        post_user(),
        Blocked,
        false,
        3,
    );

    // --- Mode rules -------------------------------------------------------------------------------
    add(
        "forced mode shows Safe as Likely",
        app_files(ADMIN, PF_DIR),
        ctx(ScanMode::Forced, TargetScope::Machine),
        Likely,
        false,
        9,
    );
    add(
        "forced mode leaves a weak item weak",
        named(&[NameTokenExact]),
        ctx(ScanMode::Forced, TargetScope::PerUser),
        Weak,
        false,
        3,
    );
    add(
        "verify-gone failed in post mode",
        app_files(ADMIN, PF_DIR),
        PolicyCtx {
            verify_gone: VerifyGone::new(true, true, false),
            ..post_machine()
        },
        Likely,
        false,
        9,
    );
    add(
        "verify-gone with an inconsistent passed flag",
        app_files(ADMIN, PF_DIR),
        PolicyCtx {
            verify_gone: VerifyGone {
                arp_gone: false,
                msi_unknown_all_ctx: true,
                main_exes_gone: true,
                passed: true,
            },
            ..post_machine()
        },
        Likely,
        false,
        9,
    );
    add(
        "external mode, admin-only evidence",
        app_files(ADMIN, PF_DIR),
        ctx(ScanMode::External, TargetScope::Machine),
        Safe,
        true,
        9,
    );
    add(
        "external mode, user-writable evidence on a per-user target",
        app_files(USER, USER_DIR),
        ctx(ScanMode::External, TargetScope::PerUser),
        Likely,
        false,
        9,
    );
    add(
        "external mode, admin evidence alone is below 8",
        cand(
            value(HKU_KEY, "Path"),
            Action::DeleteValue,
            reg,
            vec![
                ev(PointsIntoInstallRoot, Scope::Value, ADMIN, "roots"),
                ev(DanglingRef, Scope::Value, USER, "fs"),
            ],
        ),
        ctx(ScanMode::External, TargetScope::PerUser),
        Likely,
        false,
        13,
    );
    add(
        "external mode, verify-gone failed",
        app_files(ADMIN, PF_DIR),
        PolicyCtx {
            verify_gone: VerifyGone::new(false, true, true),
            ..ctx(ScanMode::External, TargetScope::Machine)
        },
        Likely,
        false,
        9,
    );

    // --- Caps by origin ---------------------------------------------------------------------------
    add(
        "signature origin is at most Likely",
        app_files(ADMIN, PF_DIR).origin(Origin::Signature),
        post_machine(),
        Likely,
        false,
        9,
    );
    add(
        "agent probe with engine tier A: Safe but unticked",
        app_files(ADMIN, PF_DIR).origin(Origin::ProbeAgent),
        post_machine(),
        Safe,
        false,
        9,
    );
    add(
        "agent probe without tier A is at most Likely",
        named(&[
            ExactFullName,
            NameTokenExact,
            ProductSubfolderOfVendor,
            TimeWindow,
        ])
        .harm(Harm::Low)
        .origin(Origin::ProbeAgent),
        post_user(),
        Likely,
        false,
        11,
    );
    add(
        "manual user origin follows the ordinary rules",
        app_files(ADMIN, PF_DIR).origin(Origin::ManualUser),
        post_machine(),
        Safe,
        true,
        9,
    );

    // --- Ai evidence ------------------------------------------------------------------------------
    add(
        "positive AI note changes nothing",
        named(&[NameTokenExact]).more(ai(2)),
        post_user(),
        Weak,
        false,
        3,
    );
    add(
        "negative AI note moves Safe down to Likely",
        app_files(ADMIN, PF_DIR).more(ai(-1)),
        post_machine(),
        Likely,
        false,
        9,
    );
    add(
        "negative AI note moves Likely down to Weak",
        named(&[NameTokenExact, TimeWindow]).more(ai(-1)),
        post_user(),
        Weak,
        false,
        4,
    );
    add(
        "negative AI note cannot hide an exact full name",
        named(&[ExactFullName]).more(ai(-3)),
        post_user(),
        Likely,
        false,
        4,
    );

    // --- Actions and untrusted numbers ------------------------------------------------------------
    add(
        "report-only is never ticked",
        {
            let mut c = app_files(ADMIN, PF_DIR);
            c.action = Action::ReportOnly;
            c
        },
        post_machine(),
        Likely,
        false,
        9,
    );
    add(
        "an action that does not fit the target",
        {
            let mut c = snap_value(value(HKLM_KEY, "v"));
            c.action = Action::DeleteKey;
            c
        },
        post_machine(),
        Likely,
        false,
        8,
    );
    add(
        "a stored tier and weight above the table are not believed",
        {
            let mut c = named(&[NameTokenExact]).harm(Harm::Low);
            c.category = Category::Cache;
            c.evidence[0].tier = Tier::A;
            c.evidence[0].weight = 100;
            c
        },
        post_user(),
        Weak,
        false,
        3,
    );
    add(
        "evidence with a scope its kind cannot have is not tier A",
        {
            let mut c = cand(
                key(HKLM_KEY),
                Action::DeleteKey,
                reg,
                vec![ev(
                    InPreUninstallRefSnapshot,
                    Scope::Value,
                    ADMIN,
                    "refsnap",
                )],
            );
            c.evidence[0].scope = Scope::Key;
            c
        },
        post_machine(),
        Likely,
        false,
        8,
    );
    add(
        "truth-only RegValueChanged is never Safe",
        cand(
            Target::RegValueChanged {
                path: HKLM_ENV.into(),
                name: "Path".into(),
                before: String::new(),
                after: String::new(),
            },
            Action::DeleteValue,
            reg,
            vec![ev(
                InPreUninstallRefSnapshot,
                Scope::Value,
                ADMIN,
                "refsnap",
            )],
        ),
        post_machine(),
        Likely,
        false,
        8,
    );

    // --- Review regressions (m1a.2) ---------------------------------------------------------------
    add(
        "appx package is never ticked, even at harm low with no blocker attached",
        appx(),
        post_machine(),
        Likely,
        false,
        8,
    );
    add(
        "an irreversible removal is never ticked without the blocker either",
        {
            let mut c = app_files(ADMIN, PF_DIR);
            c.reversibility = Reversibility::None;
            c
        },
        post_machine(),
        Likely,
        false,
        9,
    );
    add(
        "partially reversible removal can still be safe",
        {
            let mut c = app_files(ADMIN, PF_DIR);
            c.reversibility = Reversibility::Partial;
            c
        },
        post_machine(),
        Safe,
        true,
        9,
    );
    let system_hive_key = |hive_key: &str| {
        cand(
            key(hive_key),
            Action::DeleteKey,
            reg,
            vec![
                ev(HarvestedToken, Scope::Key, USER, "tokens"),
                ev(TimeWindow, Scope::Key, USER, "t"),
            ],
        )
    };
    add(
        "user-writable proof of a user account's hive key",
        system_hive_key(HKU_KEY),
        post_user(),
        Safe,
        true,
        8,
    );
    add(
        "LocalSystem's hive is machine scope whatever the caller says",
        system_hive_key(r"HKU\S-1-5-18\Software\Vendor\App"),
        post_user(),
        Likely,
        false,
        8,
    );
    add(
        "the .DEFAULT hive is machine scope whatever the caller says",
        system_hive_key(r"HKU\.DEFAULT\Software\Vendor\App"),
        post_user(),
        Likely,
        false,
        8,
    );
    add(
        "a manifest record about the key does not declare a PATH segment",
        seg(
            segment(HKLM_ENV, r"C:\Tools\bin"),
            vec![
                ev(INNO, Scope::Key, ADMIN, "inno"),
                ev(DanglingRef, Scope::Value, ADMIN, "fs"),
            ],
        ),
        post_machine(),
        Likely,
        false,
        15,
    );
    add(
        "tier A evidence that weighs nothing proves nothing",
        {
            let mut c = app_files(ADMIN, PF_DIR)
                .more(ev(ExactFullName, Scope::Path, ADMIN, "name"))
                .more(ev(NameTokenExact, Scope::Path, ADMIN, "name"))
                .more(ev(TimeWindow, Scope::Path, ADMIN, "t"));
            c.evidence[0].weight = 0;
            c
        },
        post_machine(),
        Likely,
        false,
        8,
    );

    cases
}

#[test]
fn golden_table() {
    assert_eq!(
        POLICY_VERSION, GOLDEN_VERSION,
        "the policy version changed: review every golden row, then update GOLDEN_VERSION"
    );
    let cases = golden();
    assert!(cases.len() >= 40, "only {} golden cases", cases.len());
    let mut names: Vec<_> = cases.iter().map(|c| c.name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), cases.len(), "a golden case name is used twice");

    let mut failures = Vec::new();
    for c in &cases {
        let d = decide(&c.candidate, &c.ctx);
        if (d.band, d.preselected, d.score) != (c.band, c.preselected, c.score) {
            failures.push(format!(
                "{}: got ({:?}, {}, {}), expected ({:?}, {}, {}) [{}]",
                c.name,
                d.band,
                d.preselected,
                d.score,
                c.band,
                c.preselected,
                c.score,
                d.explanation
            ));
        }
        assert!(!d.explanation.is_empty(), "{}: empty explanation", c.name);
        // Same input, same output; a stored decision is ignored.
        let mut again = c.candidate.clone();
        again.decision = Some(purge_model::Decision {
            band: Band::Safe,
            preselected: true,
            score: 99,
            explanation: "stale".into(),
        });
        assert_eq!(decide(&again, &c.ctx), d, "{}", c.name);
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn golden_explanations() {
    assert_eq!(POLICY_VERSION, GOLDEN_VERSION);
    let explain = |c: &Candidate, ctx: PolicyCtx| decide(c, &ctx).explanation;

    let mut git = cand(
        key(r"HKLM\SOFTWARE\Classes\sh_auto_file"),
        Action::DeleteKey,
        Category::Association,
        vec![
            ev(INNO, Scope::Key, ADMIN, "inno"),
            ev(
                EvidenceKind::ProvenOwnedSkeleton,
                Scope::Key,
                ADMIN,
                "subtree",
            )
            .with_detail(Facts::new().with("baseline", "11 Pro 26300")),
        ],
    );
    git.owner.display_name = "Git".into();
    assert_eq!(
        explain(&git, post_machine()),
        "Named in Git's uninstall log · Everything in it belonged to Git · now empty · \
         not on clean Windows 11 Pro 26300"
    );

    let blocked = app_files(ADMIN, PF_DIR).blocker(Blocker::UserData).blocker(
        Blocker::ReferencedByOtherApp {
            app: "Mozilla Thunderbird".into(),
        },
    );
    assert_eq!(
        explain(&blocked, post_machine()),
        "Kept: still used by Mozilla Thunderbird"
    );

    let path_segment = cand(
        segment(HKLM_ENV, r"C:\Program Files\Git\cmd"),
        Action::EditSegment,
        Category::Registration,
        vec![ev(INNO, Scope::Value, ADMIN, "inno")],
    )
    .harm(Harm::Medium);
    assert_eq!(
        explain(&path_segment, post_machine()),
        "Named in App's uninstall log · Only this one entry is taken out of the list; the installer added it"
    );

    assert_eq!(
        explain(
            &app_files(ADMIN, PF_DIR),
            ctx(ScanMode::Forced, TargetScope::Machine)
        ),
        "Inside App's install folder · Not ticked: the uninstaller did not run, so nothing is preselected"
    );
    assert_eq!(
        explain(&app_files(USER, PF_DIR), post_machine()),
        "Inside App's install folder · A record the user can change does not prove a machine-wide item"
    );
    let mismatch = cand(
        key(HKLM_KEY),
        Action::DeleteKey,
        Category::Registration,
        vec![ev(
            EvidenceKind::InPreUninstallRefSnapshot,
            Scope::Value,
            ADMIN,
            "refsnap",
        )],
    );
    assert_eq!(
        explain(&mismatch, post_machine()),
        "Pointed to App before uninstall · The proof is about a different kind of item than this one"
    );
    // AI evidence is never rendered, only its effect.
    let lowered = app_files(ADMIN, PF_DIR).more(ai(-1));
    assert_eq!(
        explain(&lowered, post_machine()),
        "Inside App's install folder · Moved down after an assistant's note"
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
    let kind = rng.pick(&EvidenceKind::ALL);
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
        trust: if rng.chance(70) { ADMIN } else { USER },
        source: rng.pick(&["a", "b", "c", "d"]).into(),
        detail: Facts::new(),
    };
    if rng.chance(10) {
        e.tier = rng.pick(&[Tier::A, Tier::B, Tier::C, Tier::Ai]);
    }
    if rng.chance(10) {
        e.weight = i8::try_from(rng.below(18)).unwrap() - 7;
    }
    e
}

fn random_ai(rng: &mut Rng) -> Evidence {
    let mut e = random_evidence(rng);
    e.tier = Tier::Ai;
    e.weight = i8::try_from(rng.below(8)).unwrap() - 5;
    e
}

fn random_blocker(rng: &mut Rng, hard: bool) -> Blocker {
    if hard {
        rng.pick(&[
            Blocker::DenyListed { rule: "r".into() },
            Blocker::StructuralContainer,
            Blocker::WindowsBaseline,
            Blocker::ReferencedByOtherApp {
                app: "Other".into(),
            },
            Blocker::ExistedBeforeInstall,
            Blocker::CannotBackUp,
            Blocker::NotGone,
        ])
    } else {
        rng.pick(&[
            Blocker::UnmatchedChildren { n: 1 },
            Blocker::UserData,
            Blocker::TooLarge,
            Blocker::ReversibilityNone,
            Blocker::InUse,
        ])
    }
}

fn random_candidate(rng: &mut Rng) -> Candidate {
    let target = rng.pick(&[
        path(PF_DIR),
        path(USER_DIR),
        key(HKLM_KEY),
        key(HKU_KEY),
        value(HKLM_KEY, "v"),
        value(HKU_KEY, "v"),
        segment(HKLM_ENV, r"C:\Program Files\App\bin"),
        segment(HKU_ENV, r"C:\Users\u\AppData\Roaming\npm"),
        package("Vendor.App_1.0.0.0_x64__abc"),
        Target::Service {
            name: "AppSvc".into(),
        },
    ]);
    let action = rng.pick(&[
        Action::Quarantine,
        Action::DeleteKey,
        Action::DeleteValue,
        Action::EditSegment,
        Action::RemoveDirIfEmpty,
        Action::RemovePackage,
        Action::ReportOnly,
    ]);
    // Mostly a fitting action, so that Safe is reached often enough to be tested.
    let action = if rng.chance(75) {
        match &target {
            Target::Path { .. } => Action::Quarantine,
            Target::RegKey { .. } => Action::DeleteKey,
            Target::RegValue { .. } => Action::DeleteValue,
            Target::RegMultiSzSegment { .. } => Action::EditSegment,
            Target::AppxPackage { .. } => Action::RemovePackage,
            _ => action,
        }
    } else {
        action
    };
    let category = rng.pick(&[
        Category::AppFiles,
        Category::AppData,
        Category::UserData,
        Category::Cache,
        Category::Registration,
        Category::Association,
        Category::ShellCom,
        Category::Startup,
        Category::System,
        Category::Privacy,
        Category::Package,
    ]);
    let category = if rng.chance(60) {
        Category::Registration
    } else {
        category
    };
    let evidence = (0..rng.below(6)).map(|_| random_evidence(rng)).collect();
    let mut c = cand(target, action, category, evidence);
    c.harm = rng.pick(&[
        Harm::None,
        Harm::Low,
        Harm::Low,
        Harm::Medium,
        Harm::High,
        Harm::Critical,
    ]);
    c.origin = rng.pick(&[
        Origin::Scanner,
        Origin::Scanner,
        Origin::Scanner,
        Origin::Signature,
        Origin::ProbeAgent,
        Origin::ManualUser,
    ]);
    if rng.chance(15) {
        c.blockers.push(random_blocker(rng, false));
    }
    if rng.chance(8) {
        c.blockers.push(random_blocker(rng, true));
    }
    c
}

fn random_ctx(rng: &mut Rng) -> PolicyCtx {
    PolicyCtx {
        mode: rng.pick(&[
            ScanMode::Post,
            ScanMode::Post,
            ScanMode::External,
            ScanMode::Forced,
        ]),
        verify_gone: VerifyGone::new(rng.chance(90), rng.chance(95), rng.chance(95)),
        target_scope: rng.pick(&[TargetScope::Machine, TargetScope::PerUser]),
    }
}

const ROUNDS: u64 = 20_000;

/// Runs `check` on many generated (candidate, context) pairs.
fn for_all(mut check: impl FnMut(&mut Rng, &Candidate, &PolicyCtx, u64)) {
    for seed in 1..=ROUNDS {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let candidate = random_candidate(&mut rng);
        let ctx = random_ctx(&mut rng);
        check(&mut rng, &candidate, &ctx, seed);
    }
}

#[test]
fn generator_reaches_every_band() {
    let mut seen = [0u32; 4];
    let mut preselected = 0u32;
    for_all(|_, c, ctx, _| {
        let d = decide(c, ctx);
        seen[usize::from(rank(d.band))] += 1;
        preselected += u32::from(d.preselected);
    });
    assert!(seen.iter().all(|n| *n > 100), "bands seen: {seen:?}");
    assert!(preselected > 100, "preselected: {preselected}");
}

#[test]
fn decisions_are_deterministic_and_consistent() {
    for_all(|_, c, ctx, seed| {
        let d = decide(c, ctx);
        assert_eq!(decide(c, ctx), d, "seed {seed}");
        assert!(!d.explanation.is_empty(), "seed {seed}");
        if d.preselected {
            assert_eq!(d.band, Band::Safe, "seed {seed}");
        }
        if d.band == Band::Safe {
            assert!(
                d.preselected || c.origin == Origin::ProbeAgent,
                "seed {seed}"
            );
            assert!(d.score >= 8, "seed {seed}");
            assert!(c.blockers.is_empty(), "seed {seed}");
            assert!(
                !matches!(c.category, Category::UserData | Category::System),
                "seed {seed}"
            );
            assert!(c.harm <= Harm::Medium, "seed {seed}");
            assert_ne!(c.origin, Origin::Signature, "seed {seed}");
            assert_ne!(c.action, Action::ReportOnly, "seed {seed}");
            assert_ne!(ctx.mode, ScanMode::Forced, "seed {seed}");
            assert!(ctx.verify_gone.is_passed(), "seed {seed}");
            // Some evidence is Tier A for this target and speaks about this type of target.
            let scope = ctx.target_scope.or_machine_for(&c.target);
            let needed = Scope::of(&c.target);
            assert!(
                c.evidence
                    .iter()
                    .any(|e| effective_tier(e, scope) == Tier::A && Some(e.scope) == needed),
                "seed {seed}"
            );
        }
        assert_eq!(d.band == Band::Blocked, c.has_hard_blocker(), "seed {seed}");
    });
}

#[test]
fn adding_a_hard_blocker_always_blocks() {
    for_all(|rng, c, ctx, seed| {
        let mut blocked = c.clone();
        let at = rng.below(blocked.blockers.len() + 1);
        blocked.blockers.insert(at, random_blocker(rng, true));
        let d = decide(&blocked, ctx);
        assert_eq!(
            (d.band, d.preselected),
            (Band::Blocked, false),
            "seed {seed}"
        );
        assert!(d.explanation.starts_with("Kept: "), "seed {seed}");
    });
}

#[test]
fn adding_a_soft_blocker_never_raises_and_never_preselects() {
    for_all(|rng, c, ctx, seed| {
        let before = decide(c, ctx);
        let mut softened = c.clone();
        softened.blockers.push(random_blocker(rng, false));
        let after = decide(&softened, ctx);
        assert!(!after.preselected, "seed {seed}");
        assert_ne!(after.band, Band::Safe, "seed {seed}");
        // A soft blocker can make a Tier A item visible (Weak to Likely), but nothing more.
        assert!(
            rank(after.band) <= rank(before.band).max(rank(Band::Likely)),
            "seed {seed}"
        );
        assert_eq!(
            after.band == Band::Blocked,
            before.band == Band::Blocked,
            "seed {seed}"
        );
    });
}

#[test]
fn adding_ai_evidence_never_raises_a_band() {
    for_all(|rng, c, ctx, seed| {
        let before = decide(c, ctx);
        let mut with_ai = c.clone();
        let at = rng.below(with_ai.evidence.len() + 1);
        with_ai.evidence.insert(at, random_ai(rng));
        let after = decide(&with_ai, ctx);
        assert!(rank(after.band) <= rank(before.band), "seed {seed}");
        assert_eq!(after.score, before.score, "seed {seed}");
        assert!(!after.preselected || before.preselected, "seed {seed}");
    });
}

/// Removing supporting evidence never raises a band. "Supporting" excludes the two kinds of evidence whose
/// whole purpose is to lower: the negative rows of §5.3 and AI notes; removing one of those never lowers.
#[test]
fn removing_evidence_never_raises_a_band() {
    for_all(|_, c, ctx, seed| {
        let before = decide(c, ctx);
        for i in 0..c.evidence.len() {
            let mut fewer = c.clone();
            let removed = fewer.evidence.remove(i);
            let after = decide(&fewer, ctx);
            let lowering = removed.kind.is_negative() || removed.tier == Tier::Ai;
            if lowering {
                assert!(
                    rank(after.band) >= rank(before.band),
                    "seed {seed}: removing {removed:?} lowered the band"
                );
            } else {
                assert!(
                    rank(after.band) <= rank(before.band),
                    "seed {seed}: removing {removed:?} raised the band"
                );
                assert!(after.score <= before.score, "seed {seed}");
            }
        }
    });
}

#[test]
fn forced_mode_and_failed_verify_gone_never_preselect() {
    for_all(|_, c, ctx, seed| {
        let forced = PolicyCtx {
            mode: ScanMode::Forced,
            ..*ctx
        };
        let d = decide(c, &forced);
        assert!(!d.preselected && d.band != Band::Safe, "seed {seed}");
        let not_gone = PolicyCtx {
            verify_gone: VerifyGone::new(false, true, true),
            ..*ctx
        };
        let d = decide(c, &not_gone);
        assert!(!d.preselected && d.band != Band::Safe, "seed {seed}");
        // Neither rule ever improves on the ordinary post-uninstall decision.
        let post = PolicyCtx {
            mode: ScanMode::Post,
            verify_gone: gone(),
            ..*ctx
        };
        let best = decide(c, &post);
        for other in [forced, not_gone, *ctx] {
            assert!(
                rank(decide(c, &other).band) <= rank(best.band),
                "seed {seed}"
            );
        }
    });
}

/// A removal that cannot be undone is never Safe, with or without the `ReversibilityNone` blocker, and
/// says so exactly once.
#[test]
fn irreversible_removals_are_never_safe() {
    for_all(|_, c, ctx, seed| {
        let mut gone_for_good = c.clone();
        gone_for_good.reversibility = Reversibility::None;
        let d = decide(&gone_for_good, ctx);
        assert_ne!(d.band, Band::Safe, "seed {seed}");
        assert!(!d.preselected, "seed {seed}");
        // Like a stated soft blocker, it can make a Tier A item visible (Weak to Likely), nothing more.
        assert!(
            rank(d.band) <= rank(decide(c, ctx).band).max(rank(Band::Likely)),
            "seed {seed}"
        );
        if d.band != Band::Blocked {
            assert_eq!(
                d.explanation
                    .matches("Removing it cannot be undone")
                    .count(),
                1,
                "seed {seed}: {}",
                d.explanation
            );
        }
        let mut package = c.clone();
        package.action = Action::RemovePackage;
        let d = decide(&package, ctx);
        assert_ne!(d.band, Band::Safe, "seed {seed}");
        assert!(!d.preselected, "seed {seed}");
    });
}

/// Evidence from a user-writable source never makes a key in a system account's hive Safe, whatever scope
/// the caller passes.
#[test]
fn system_account_hives_follow_rule_t() {
    for_all(|rng, c, ctx, seed| {
        let mut system = c.clone();
        let hive_key = rng.pick(&[
            r"HKU\S-1-5-18\Software\Vendor\App",
            r"HKU\S-1-5-19\Software\Vendor\App",
            r"HKU\S-1-5-20_Classes\App.Doc",
            r"HKU\.DEFAULT\Software\Vendor\App",
            r"HKCU\Software\Vendor\App",
        ]);
        system.target = key(hive_key);
        system.action = Action::DeleteKey;
        for e in &mut system.evidence {
            e.trust = USER;
        }
        let d = decide(&system, ctx);
        assert_ne!(d.band, Band::Safe, "seed {seed}");
        assert!(!d.preselected, "seed {seed}");
    });
}

#[test]
fn user_data_is_never_preselected() {
    for_all(|_, c, ctx, seed| {
        let mut data = c.clone();
        data.category = Category::UserData;
        assert!(!decide(&data, ctx).preselected, "seed {seed}");
        let mut flagged = c.clone();
        flagged.blockers.push(Blocker::UserData);
        assert!(!decide(&flagged, ctx).preselected, "seed {seed}");
    });
}

#[test]
fn value_only_evidence_never_makes_a_key_safe() {
    for_all(|rng, c, ctx, seed| {
        let mut on_key = c.clone();
        on_key.target = rng.pick(&[key(HKLM_KEY), key(HKU_KEY)]);
        on_key.action = Action::DeleteKey;
        on_key.blockers.clear();
        on_key.evidence.retain(|e| e.scope == Scope::Value);
        for kind in [
            EvidenceKind::InPreUninstallRefSnapshot,
            EvidenceKind::DanglingRef,
            EvidenceKind::PointsIntoInstallRoot,
            INNO,
        ] {
            on_key.evidence.push(ev(kind, Scope::Value, ADMIN, "x"));
        }
        let d = decide(&on_key, ctx);
        assert!(d.band != Band::Safe && !d.preselected, "seed {seed}");
    });
}

#[test]
fn rule_t_blocks_user_writable_proof_of_machine_targets() {
    for_all(|rng, c, ctx, seed| {
        let mut machine = c.clone();
        machine.target = rng.pick(&[key(HKLM_KEY), value(HKLM_KEY, "v"), path(PF_DIR)]);
        for e in &mut machine.evidence {
            e.trust = USER;
        }
        let machine_ctx = PolicyCtx {
            target_scope: TargetScope::Machine,
            ..*ctx
        };
        let d = decide(&machine, &machine_ctx);
        assert!(d.band != Band::Safe && !d.preselected, "seed {seed}");
    });
}

#[test]
fn external_mode_needs_admin_only_proof() {
    for_all(|_, c, ctx, seed| {
        let mut user_only = c.clone();
        for e in &mut user_only.evidence {
            e.trust = USER;
        }
        let external = PolicyCtx {
            mode: ScanMode::External,
            ..*ctx
        };
        assert_ne!(
            decide(&user_only, &external).band,
            Band::Safe,
            "seed {seed}"
        );
        // External mode is never more generous than post-uninstall mode.
        let post = PolicyCtx {
            mode: ScanMode::Post,
            ..*ctx
        };
        assert!(
            rank(decide(c, &external).band) <= rank(decide(c, &post).band),
            "seed {seed}"
        );
    });
}
