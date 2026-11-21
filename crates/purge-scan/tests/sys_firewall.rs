//! SYS-FIREWALL tests (M1B-S-FIREWALL). Every source is a fixture (`tests/data/sys_firewall`); no real
//! firewall rule is read or touched.
//!
//! The machine holds the app "Tool" (InstallRoot `C:\Program Files\Tool`, uninstalled: `tool.exe` is
//! gone, `helper.exe` is still there) and a set of rules, some of them traps: a rule of another program
//! with the app's display name, a port-only rule named after the app, package-bound and resource-named
//! rules for the app's program, a `svchost.exe` service rule, a rule the executor cannot re-create.

use std::collections::BTreeMap;
use std::path::Path;

use purge_guard::canon::GuardEnv;
use purge_index::baseline::Baseline;
use purge_index::sysobj::{self, FirewallFacts, ProgramRef};
use purge_model::{
    Action, Anchors, AppFileOutsideRoot, AppRef, Band, Blocker, Candidate, Category, EvidenceKind,
    ExeFile, Fingerprint, FingerprintSchema, Harm, IdentitySnapshot, ObjectWhy, OsInfo, ProgramId,
    Reversibility, Root, RootKind, RootSource, ScanMode, Scope, SourceTrust, SysFirewallRule,
    Target, Tier, TimeWindow, VerifyGone, View,
};
use purge_policy::band::{PolicyCtx, TargetScope, decide};
use purge_scan::framework::{AppIdentityView, OtherApp, OtherApps, ScanCtx, ScanExt, ScanLimits};
use purge_scan::sys_firewall::{SysFirewall, recreate_refusal};
use purge_source::fixture::Fixture;
use purge_source::metered::{Meter, MeteredRegistry, Op};
use purge_source::types::RegData;

const ROOT: &str = r"C:\Program Files\Tool";
const FW: &str =
    r"HKLM\SYSTEM\ControlSet001\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

/// The app's own rule: `App=` its (gone) main exe.
const OWNED: &str = "{0000F1F1-0000-0000-0000-000000000001}";
/// Another program's rule with the same display name `Tool`.
const SAME_NAME_OTHER: &str = "{0000F1F1-0000-0000-0000-000000000002}";
/// A port-only rule named `Tool` whose `Svc=` names a service called like the app.
const PORT_ONLY: &str = "{0000F1F1-0000-0000-0000-000000000003}";
/// `App=System`, named `Tool`.
const APP_SYSTEM: &str = "{0000F1F1-0000-0000-0000-000000000004}";
/// The app's program, bound to a package (`PFN=`).
const PKG_PFN: &str = "{0000F1F1-0000-0000-0000-000000000005}";
/// The app's program, bound to an AppContainer (`LUOwn=S-1-15-...`).
const PKG_LUOWN: &str = "{0000F1F1-0000-0000-0000-000000000006}";
/// The app's program, `Name=@resource`.
const RES_NAME: &str = "{0000F1F1-0000-0000-0000-000000000007}";
/// The app's program, `EmbedCtxt=@resource`.
const RES_GROUP: &str = "{0000F1F1-0000-0000-0000-000000000008}";
/// `App=%ProgramFiles%\Tool\tool.exe`.
const ENV_APP: &str = "{0000F1F1-0000-0000-0000-000000000009}";
/// A service rule: `App=%SystemRoot%\System32\svchost.exe`, `Svc=ToolSvc`.
const SVCHOST: &str = "{0000F1F1-0000-0000-0000-00000000000A}";
/// The app's program with `LPort=RPC`, which the executor cannot re-create.
const UNMAPPED: &str = "{0000F1F1-0000-0000-0000-00000000000B}";
/// `App=` a program of the app that is still present.
const HELPER: &str = "{0000F1F1-0000-0000-0000-00000000000C}";
/// A Windows prompt rule: id in mixed case with blanks, braces and a path.
const PROMPT: &str =
    r"TCP Query User{aBcD0001-0000-0000-0000-00000000000d}C:\program files\tool\tool.exe";
/// `App=` a file the app's installer declares outside its roots.
const OUTSIDE: &str = "{0000F1F1-0000-0000-0000-00000000000E}";

fn machine() -> Fixture {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/sys_firewall/machine.json");
    Fixture::from_json_file(&path).expect("machine.json loads")
}

fn fingerprint() -> Fingerprint {
    Fingerprint {
        baseline_view: None,
        schema: FingerprintSchema,
        app: AppRef {
            program_id: ProgramId::machine(View::K64, "Tool").unwrap(),
            display_name: "Tool".into(),
        },
        identity: IdentitySnapshot {
            names: vec!["Tool".into()],
            vendors: vec!["Tool Vendor".into()],
            tokens: Vec::new(),
            mega_vendor: false,
        },
        roots: vec![Root {
            path: ROOT.into(),
            kind: RootKind::InstallRoot,
            source: RootSource::ArpInstallLocation,
            trust: SourceTrust::AdminOnly,
            volume_serial: Some(0x1234_5678),
            parent_existed: true,
        }],
        exes: vec![
            ExeFile {
                path: format!(r"{ROOT}\tool.exe"),
                main: true,
            },
            ExeFile {
                path: format!(r"{ROOT}\helper.exe"),
                main: false,
            },
        ],
        outside_root_files: vec![AppFileOutsideRoot {
            path: r"C:\ProgramData\Tool\agent.exe".into(),
            source: "test".into(),
        }],
        uninstallers: Vec::new(),
        older_keys: Vec::new(),
        anchors: Anchors::default(),
        tokens: Vec::new(),
        inno: Vec::new(),
        ref_snapshot: Vec::new(),
        subtrees: Vec::new(),
        ext_journal: Vec::new(),
        co_removed: Vec::new(),
        msi: Vec::new(),
        burn: None,
        sys: Default::default(),
        os: OsInfo {
            edition: "Professional".into(),
            build: 26340,
            ubr: 9882,
        },
        user_sid: GuardEnv::SAMPLE_SID.into(),
        window: TimeWindow::default(),
        verify_gone: None,
        warnings: Vec::new(),
    }
}

/// Everything a [`ScanCtx`] borrows.
struct World {
    fixture: Fixture,
    fp: Fingerprint,
    baseline: Option<Baseline>,
    env: BTreeMap<String, String>,
    guard: GuardEnv,
    other_apps: OtherApps,
    ext: ScanExt,
}

impl World {
    fn new() -> Self {
        Self::over(machine())
    }

    /// A world over `fixture`, the system objects read from it as the pipeline reads them.
    fn over(fixture: Fixture) -> Self {
        let ext = ScanExt::new(Default::default(), sysobj::build(&fixture, &fixture));
        let baseline_text = "#purge-baseline 1\tT\tPC\tProfessional\t26340.9882\n";
        Self {
            fixture,
            fp: fingerprint(),
            baseline: Some(Baseline::from_bytes(baseline_text.as_bytes()).unwrap()),
            env: BTreeMap::new(),
            guard: GuardEnv::sample(),
            other_apps: OtherApps::default(),
            ext,
        }
    }

    /// The rule `id` as the index read it.
    fn rule(&self, id: &str) -> &FirewallFacts {
        self.ext
            .sysobj
            .firewall
            .iter()
            .find(|r| r.identity.id == id)
            .unwrap_or_else(|| panic!("rule {id} is in the index"))
    }

    /// Records the rule `id` as the harvest would (the identity read now, its program, `why`), whether
    /// or not the harvest would really have recorded it (hostile fingerprints).
    fn record(&mut self, id: &str, why: ObjectWhy) {
        let rule = self.rule(id).clone();
        let program = match &rule.program {
            ProgramRef::File(file) => Some(file.clone()),
            _ => None,
        };
        self.fp.sys.firewall_rules.push(SysFirewallRule {
            identity: rule.identity,
            program,
            why,
        });
    }

    fn ctx(&self) -> ScanCtx<'_> {
        ScanCtx {
            reg: &self.fixture,
            fs: &self.fixture,
            sys: &self.fixture,
            fp: &self.fp,
            baseline: self.baseline.as_ref(),
            mode: ScanMode::Post,
            verify_gone: Some(VerifyGone::new(true, true, true)),
            env: &self.env,
            guard: &self.guard,
            other_apps: &self.other_apps,
            limits: ScanLimits::default(),
            ext: &self.ext,
        }
    }

    /// Runs the scanner through the sealing driver.
    fn run_with(&self, scanner: SysFirewall) -> Vec<Candidate> {
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
        self.ctx().run(&scanner, &app)
    }

    fn run(&self) -> Vec<Candidate> {
        self.run_with(SysFirewall::default())
    }

    /// The whole InstallRoot is gone (the uninstaller removed `helper.exe` and the folder too).
    fn root_gone(&mut self) {
        assert!(self.fixture.remove_path(ROOT));
    }
}

/// R3a S1: a recorded rule whose program file is absent while its InstallRoot still exists (`helper.exe`
/// is left) is not proven gone: the dangling rule asks for the whole root. Likely, Tier B.
#[test]
fn program_absent_but_root_present_is_likely() {
    let mut w = World::new();
    w.record(OWNED, ObjectWhy::ProgramInRoot);
    let out = w.run();
    let c = find(&out, OWNED);
    assert_eq!(owned_object_tier(c), Some(Tier::B));
    assert_eq!(band(c), (Band::Likely, false));
    w.root_gone();
    let out = w.run();
    assert_eq!(owned_object_tier(find(&out, OWNED)), Some(Tier::A));
}

fn ids(candidates: &[Candidate]) -> Vec<&str> {
    candidates
        .iter()
        .map(|c| match &c.target {
            Target::FirewallRule { id } => id.as_str(),
            other => panic!("not a firewall rule: {other:?}"),
        })
        .collect()
}

fn find<'a>(candidates: &'a [Candidate], id: &str) -> &'a Candidate {
    candidates
        .iter()
        .find(|c| c.target == Target::FirewallRule { id: id.to_owned() })
        .unwrap_or_else(|| panic!("rule {id} offered; offered: {:?}", ids(candidates)))
}

fn offered(candidates: &[Candidate], id: &str) -> bool {
    ids(candidates).contains(&id)
}

fn band(c: &Candidate) -> (Band, bool) {
    let d = decide(
        c,
        &PolicyCtx {
            baseline_trust: purge_model::BaselineTrust::Exact,
            mode: ScanMode::Post,
            verify_gone: VerifyGone::new(true, true, true),
            target_scope: TargetScope::Machine,
        },
    );
    (d.band, d.preselected)
}

fn owned_object_tier(c: &Candidate) -> Option<Tier> {
    c.evidence
        .iter()
        .find(|e| e.kind == EvidenceKind::OwnedSystemObject)
        .map(|e| e.tier)
}

// ---------------------------------------------------------------------------------------------------------
// Required tests
// ---------------------------------------------------------------------------------------------------------

#[test]
fn owned_recorded_dangling_rule_safe() {
    let mut w = World::new();
    w.record(OWNED, ObjectWhy::ProgramInRoot);
    w.root_gone();
    let out = w.run();
    let c = find(&out, OWNED);
    assert_eq!(c.action, Action::DeleteKey);
    assert_eq!(c.category, Category::System);
    assert_eq!(c.harm, Harm::Low);
    assert_eq!(c.reversibility, Reversibility::Full);
    assert_eq!(c.scanner, "SYS-FIREWALL");
    assert_eq!(owned_object_tier(c), Some(Tier::A));
    assert!(
        c.evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::OwnedSystemObject && e.scope == Scope::Object)
    );
    assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    assert_eq!(band(c), (Band::Safe, true));
}

/// Hostile (trap fw-same-display-name): another program's rule carries the app's display name.
#[test]
fn two_rules_same_display_name_only_owned_id_offered() {
    let mut w = World::new();
    assert_eq!(
        w.ext
            .sysobj
            .rules_named("Tool")
            .iter()
            .map(|r| r.identity.id.as_str())
            .collect::<Vec<_>>(),
        [OWNED, SAME_NAME_OTHER, PORT_ONLY, APP_SYSTEM]
    );
    w.record(OWNED, ObjectWhy::ProgramInRoot);
    let out = w.run();
    assert!(offered(&out, OWNED));
    assert!(!offered(&out, SAME_NAME_OTHER));
    // Each rule is its own candidate: nothing groups the rules named `Tool`.
    let named_tool: Vec<&str> = ids(&out)
        .into_iter()
        .filter(|id| {
            w.rule(id)
                .fields
                .get("Name")
                .is_some_and(|n| n.eq_ignore_ascii_case("Tool"))
        })
        .collect();
    assert_eq!(named_tool, [OWNED]);
    assert!(find(&out, OWNED).children.is_empty());
}

/// Hostile (trap fw-no-app): a port-only rule named after the app, whose `Svc=` names the app's
/// service, is never offered, even when a fingerprint records its id; nor is `App=System`.
#[test]
fn port_only_rule_named_after_app_no_candidate() {
    let mut w = World::new();
    assert_eq!(w.rule(PORT_ONLY).program, ProgramRef::None);
    assert_eq!(w.rule(PORT_ONLY).service.as_deref(), Some("ToolSvc"));
    assert_eq!(w.rule(APP_SYSTEM).program, ProgramRef::None);
    let out = w.run();
    assert!(!offered(&out, PORT_ONLY) && !offered(&out, APP_SYSTEM));
    w.record(PORT_ONLY, ObjectWhy::ProgramInRoot);
    w.record(APP_SYSTEM, ObjectWhy::ProgramInRoot);
    let out = w.run();
    assert!(!offered(&out, PORT_ONLY) && !offered(&out, APP_SYSTEM));
}

#[test]
fn package_bound_rule_never() {
    let mut w = World::new();
    assert!(w.rule(PKG_PFN).package_bound && w.rule(PKG_LUOWN).package_bound);
    w.record(PKG_PFN, ObjectWhy::ProgramInRoot);
    w.record(PKG_LUOWN, ObjectWhy::ProgramInRoot);
    let out = w.run();
    assert!(!offered(&out, PKG_PFN));
    assert!(!offered(&out, PKG_LUOWN));
    // The same program's plain rule is offered: the program is the app's, the binding is the reason.
    assert!(offered(&out, OWNED));
}

#[test]
fn resource_name_rule_never() {
    let mut w = World::new();
    w.record(RES_NAME, ObjectWhy::ProgramInRoot);
    w.record(RES_GROUP, ObjectWhy::ProgramInRoot);
    let out = w.run();
    assert!(!offered(&out, RES_NAME), "Name=@...");
    assert!(!offered(&out, RES_GROUP), "EmbedCtxt=@...");
}

#[test]
fn app_env_var_expanded() {
    let mut w = World::new();
    assert_eq!(
        w.rule(ENV_APP).program,
        ProgramRef::File(format!(r"{ROOT}\tool.exe"))
    );
    // Not recorded: the program alone makes it the app's, never above Likely.
    let out = w.run();
    let c = find(&out, ENV_APP);
    assert_eq!(c.reversibility, Reversibility::Full);
    assert_eq!(band(c), (Band::Likely, false));
    // Recorded: the expanded program is gone (with its whole root) and undo can re-create it, so it
    // is Safe.
    w.record(ENV_APP, ObjectWhy::ProgramInRoot);
    w.root_gone();
    let out = w.run();
    let c = find(&out, ENV_APP);
    assert_eq!(owned_object_tier(c), Some(Tier::A));
    assert_eq!(band(c), (Band::Safe, true));
}

#[test]
fn rule_edited_since_harvest_blocks() {
    let mut w = World::new();
    w.record(OWNED, ObjectWhy::ProgramInRoot);
    // The rule is changed after the harvest (same id, same program, Block instead of Allow).
    let mut fixture = machine();
    fixture.set_value(
        FW,
        OWNED,
        RegData::from_sz(
            r"v2.33|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Private|App=C:\Program Files\Tool\tool.exe|Name=Tool|",
        ),
    );
    let fp = w.fp.clone();
    let mut w = World::over(fixture);
    w.fp = fp;
    let out = w.run();
    let c = find(&out, OWNED);
    assert!(c.blockers.contains(&Blocker::ObjectChangedSinceHarvest));
    assert_ne!(owned_object_tier(c), Some(Tier::A));
    assert_eq!(band(c).0, Band::Blocked);
}

#[test]
fn program_present_likely() {
    let mut w = World::new();
    w.record(HELPER, ObjectWhy::ProgramIsAppExe);
    let out = w.run();
    let c = find(&out, HELPER);
    assert_eq!(owned_object_tier(c), Some(Tier::B));
    assert_eq!(band(c), (Band::Likely, false));
    // Not recorded and its program gone: still only Likely (D10).
    let c = find(&out, OWNED);
    assert_eq!(owned_object_tier(c), None);
    assert_eq!(band(c), (Band::Likely, false));
}

#[test]
fn restore_not_exact_makes_partial() {
    let mut w = World::new();
    w.record(OWNED, ObjectWhy::ProgramInRoot);
    let out = w.run_with(SysFirewall::with_restore_exact(false));
    assert!(!out.is_empty());
    for c in &out {
        assert_eq!(c.reversibility, Reversibility::Partial, "{:?}", c.target);
        assert!(c.blockers.contains(&Blocker::ReversibilityPartial));
        assert!(!band(c).1);
    }
    assert_eq!(band(find(&out, OWNED)), (Band::Likely, false));
}

#[test]
fn id_spelled_exactly_as_stored() {
    let mut w = World::new();
    w.record(PROMPT, ObjectWhy::ProgramInRoot);
    w.root_gone();
    let out = w.run();
    let c = find(&out, PROMPT);
    assert_eq!(
        c.target,
        Target::FirewallRule {
            id: PROMPT.to_owned()
        }
    );
    assert_eq!(band(c), (Band::Safe, true));
    // No other spelling of it is offered.
    assert_eq!(
        ids(&out)
            .iter()
            .filter(|id| id.eq_ignore_ascii_case(PROMPT))
            .count(),
        1
    );
}

#[test]
fn object_fp_present() {
    let mut w = World::new();
    w.record(OWNED, ObjectWhy::ProgramInRoot);
    let out = w.run();
    assert!(out.len() >= 4, "{:?}", ids(&out));
    for c in &out {
        let Target::FirewallRule { id } = &c.target else {
            unreachable!()
        };
        assert_eq!(
            c.object_fp.as_ref(),
            Some(&w.rule(id).identity.fp()),
            "{id}"
        );
    }
    // The sealing dropped nothing.
    assert!(w.ext.take_faults().is_empty());
}

#[test]
fn budget_no_key_opens() {
    let mut w = World::new();
    w.record(OWNED, ObjectWhy::ProgramInRoot);
    let meter = Meter::new();
    let metered = MeteredRegistry::new(&w.fixture, &meter);
    let ctx = ScanCtx {
        reg: &metered,
        ..w.ctx()
    };
    let app = AppIdentityView::from_fingerprint(&w.fp, &w.env);
    let out = ctx.run(&SysFirewall::default(), &app);
    assert!(offered(&out, OWNED));
    let snap = meter.snapshot();
    for op in [
        Op::RegKeyInfo,
        Op::RegSubkeys,
        Op::RegValues,
        Op::RegValue,
        Op::RegOther,
    ] {
        assert_eq!(snap.get(op).calls, 0, "{op:?}");
    }
}

// ---------------------------------------------------------------------------------------------------------
// What the executor and its undo can do
// ---------------------------------------------------------------------------------------------------------

/// A service rule runs `svchost.exe`: a host is no program of the app's, and undo would refuse to
/// re-create it (`ProgramOutsideRoot`). Never offered, even when recorded.
#[test]
fn svchost_service_rule_never_offered() {
    let mut w = World::new();
    assert!(matches!(
        w.rule(SVCHOST).program,
        ProgramRef::Unresolved { .. }
    ));
    let out = w.run();
    assert!(!offered(&out, SVCHOST));
    w.record(SVCHOST, ObjectWhy::ProgramInRoot);
    let out = w.run();
    assert!(!offered(&out, SVCHOST));
}

/// A rule the executor cannot re-create exactly is report-only.
#[test]
fn unmapped_rule_cannot_back_up() {
    let mut w = World::new();
    assert!(recreate_refusal(&w.rule(UNMAPPED).fields).is_some());
    assert!(recreate_refusal(&w.rule(OWNED).fields).is_none());
    w.record(UNMAPPED, ObjectWhy::ProgramInRoot);
    let out = w.run();
    let c = find(&out, UNMAPPED);
    assert!(c.blockers.contains(&Blocker::CannotBackUp));
    assert_eq!(band(c), (Band::Blocked, false));
}

/// Undo re-creates a rule only for a program inside the run's roots: an outside-root file of the app
/// can be offered, never as undoable, never preselected.
#[test]
fn program_outside_roots_not_undoable() {
    let mut w = World::new();
    w.record(OUTSIDE, ObjectWhy::ProgramIsAppExe);
    let out = w.run();
    let c = find(&out, OUTSIDE);
    assert_eq!(c.reversibility, Reversibility::None);
    assert!(c.blockers.contains(&Blocker::ReversibilityNone));
    assert_eq!(band(c), (Band::Likely, false));
}

/// An unreadable rule list offers nothing.
#[test]
fn unreadable_rule_list_offers_nothing() {
    let mut w = World::new();
    w.record(OWNED, ObjectWhy::ProgramInRoot);
    w.ext
        .sysobj
        .errors
        .push("sysobj: firewall rules: not captured".into());
    assert!(w.run().is_empty());
}

/// A rule whose program another installed app references is that app's too: blocked.
#[test]
fn program_of_another_app_blocked() {
    let mut w = World::new();
    w.record(OWNED, ObjectWhy::ProgramInRoot);
    w.other_apps = OtherApps::new(vec![OtherApp {
        name: "Suite".into(),
        roots: Vec::new(),
        files: vec![format!(r"{ROOT}\tool.exe")],
        keys: Vec::new(),
        anchors: Vec::new(),
    }]);
    let out = w.run();
    let c = find(&out, OWNED);
    assert!(
        c.blockers
            .iter()
            .any(|b| matches!(b, Blocker::ReferencedByOtherApp { .. }))
    );
    assert_eq!(band(c).0, Band::Blocked);
}

/// A recorded id now used for a rule of another program is not offered.
#[test]
fn recorded_id_reused_for_another_program_not_offered() {
    let mut w = World::new();
    w.record(OWNED, ObjectWhy::ProgramInRoot);
    let mut fixture = machine();
    fixture.set_value(
        FW,
        OWNED,
        RegData::from_sz(
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|App=C:\Program Files\Other\tool.exe|Name=Tool|",
        ),
    );
    let fp = w.fp.clone();
    let mut w = World::over(fixture);
    w.fp = fp;
    assert!(!offered(&w.run(), OWNED));
}

/// The whole set, with every owned rule recorded: exactly the app's rules are offered.
#[test]
fn offered_set_is_exactly_the_apps() {
    let mut w = World::new();
    for id in [OWNED, ENV_APP, UNMAPPED, HELPER, PROMPT, OUTSIDE] {
        w.record(id, ObjectWhy::ProgramInRoot);
    }
    let mut got = ids(&w.run())
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    got.sort();
    let mut want = [OWNED, ENV_APP, UNMAPPED, HELPER, PROMPT, OUTSIDE].map(str::to_owned);
    want.sort();
    assert_eq!(got, want);
}

/// A recorded rule whose `App=` the scan cannot expand now keeps the harvest's attribution, but only
/// as `ProgramUnresolved` (soft) and never undoable: undo could not place its program either.
#[test]
fn recorded_rule_unresolved_now_is_not_preselected() {
    const UNEXPANDED: &str = "{0000F1F1-0000-0000-0000-00000000000F}";
    let mut fixture = machine();
    fixture.set_value(
        FW,
        UNEXPANDED,
        RegData::from_sz(
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|App=%TOOLHOME%\tool.exe|Name=Tool Home|",
        ),
    );
    let mut w = World::over(fixture);
    assert!(matches!(
        w.rule(UNEXPANDED).program,
        ProgramRef::Unresolved { .. }
    ));
    assert!(
        !offered(&w.run(), UNEXPANDED),
        "not recorded: not the app's"
    );
    // The harvest saw it expanded into the app's root.
    let identity = w.rule(UNEXPANDED).identity.clone();
    w.fp.sys.firewall_rules.push(SysFirewallRule {
        identity,
        program: Some(format!(r"{ROOT}\tool.exe")),
        why: ObjectWhy::ProgramInRoot,
    });
    let out = w.run();
    let c = find(&out, UNEXPANDED);
    assert!(c.blockers.contains(&Blocker::ProgramUnresolved));
    assert_eq!(c.reversibility, Reversibility::None);
    assert_eq!(band(c), (Band::Likely, false));
    // A forged record pointing outside the app is no attribution.
    w.fp.sys.firewall_rules.last_mut().unwrap().program =
        Some(r"C:\Program Files\Other\tool.exe".into());
    assert!(!offered(&w.run(), UNEXPANDED));
}
