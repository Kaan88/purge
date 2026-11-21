//! SYS-TASK tests (M1B-S-TASK). Every source is a fixture: `tests/data/sys_task/machine.json` is a machine
//! after the uninstall of "Contoso Widget", with the app's own tasks and the trap tasks of the rig
//! (`task-similar-name`, `task-interpreter`) next to each other. No real task is read or changed.

use std::collections::BTreeMap;
use std::path::Path;

use purge_guard::canon::GuardEnv;
use purge_index::baseline::Baseline;
use purge_index::ownership::OwnershipIndex;
use purge_index::sysobj;
use purge_model::object::{TaskAction, TaskIdentity};
use purge_model::{
    Action, Anchors, AppRef, Band, Blocker, Candidate, Category, EvidenceKind, ExeFile,
    Fingerprint, FingerprintSchema, Harm, IdentitySnapshot, ObjectWhy, OsInfo, ProgramId,
    Reversibility, Root, RootKind, RootSource, ScanMode, Scope, SourceTrust, SysTask as Recorded,
    Target, Tier, TimeWindow, VerifyGone, View,
};
use purge_policy::band::{PolicyCtx, TargetScope, decide};
use purge_scan::framework::{AppIdentityView, OtherApp, OtherApps, ScanCtx, ScanExt, ScanLimits};
use purge_scan::sys_task::{ID, SysTask};
use purge_source::fixture::Fixture;
use purge_source::metered::{Meter, MeteredFileSystem, MeteredRegistry, MeteredSystem, Op};
use purge_source::sysobj::TaskInfo;
use purge_source::system::SystemSource;

const ROOT: &str = r"C:\Program Files\Contoso\Widget";
const USER_ROOT: &str = r"C:\Users\tester\AppData\Local\Contoso\Widget";
const SERIAL: u32 = 0x1234_5678;
const OWN_CLSID: &str = "{C0C0C0C0-0000-4000-8000-000000000001}";

const UPDATE: &str = r"\Contoso\Widget Update";
const TRAY: &str = r"\Contoso Widget Tray";
const SIMILAR: &str = r"\Contoso\Widget Updater";
const CMD: &str = r"\Contoso\Widget Cleanup";
const PYTHON: &str = r"\Contoso\Widget Script";
const SYNC: &str = r"\Contoso\Widget Sync";
const NOTIFY: &str = r"\Contoso\Widget Notify";
const SHELL: &str = r"\Contoso\Widget Shell";
const WINDOWS: &str = r"\Microsoft\Windows\Contoso\Widget Telemetry";
const LOCKED: &str = r"\Contoso\Widget Locked";
const MAIL: &str = r"\Contoso\Widget Mail";
const PROFILE: &str = r"\Contoso\Widget Profile";

// -------------------------------------------------------------------------------------------------------
// Test world
// -------------------------------------------------------------------------------------------------------

fn machine() -> Fixture {
    let file = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/sys_task/machine.json");
    Fixture::from_json_file(&file).expect("the sys_task fixture loads")
}

/// The machine with only the named tasks of the fixture.
fn machine_with(paths: &[&str]) -> Fixture {
    let mut fx = machine();
    let tasks: Vec<TaskInfo> = fx
        .tasks()
        .expect("the fixture captures tasks")
        .into_iter()
        .filter(|t| paths.contains(&t.identity.path.as_str()))
        .collect();
    assert_eq!(
        tasks.len(),
        paths.len(),
        "every named task is in the fixture"
    );
    fx.set_tasks(Some(tasks));
    fx
}

/// The fixture task at `path`.
fn task(path: &str) -> TaskInfo {
    machine()
        .tasks()
        .unwrap()
        .into_iter()
        .find(|t| t.identity.path == path)
        .expect("task in fixture")
}

/// "Contoso Widget", machine-wide: one admin-only InstallRoot whose parent still exists, its exes, and
/// one COM class of its own.
fn fingerprint() -> Fingerprint {
    Fingerprint {
        baseline_view: None,
        schema: FingerprintSchema,
        app: AppRef {
            program_id: ProgramId::machine(View::K64, "Contoso Widget").unwrap(),
            display_name: "Contoso Widget".into(),
        },
        identity: IdentitySnapshot {
            names: vec!["Contoso Widget".into()],
            vendors: vec!["Contoso".into()],
            tokens: Vec::new(),
            mega_vendor: false,
        },
        roots: vec![Root {
            path: ROOT.into(),
            kind: RootKind::InstallRoot,
            source: RootSource::ArpInstallLocation,
            trust: SourceTrust::AdminOnly,
            volume_serial: Some(SERIAL),
            parent_existed: true,
        }],
        exes: vec![
            ExeFile {
                path: format!(r"{ROOT}\widget.exe"),
                main: true,
            },
            ExeFile {
                path: format!(r"{ROOT}\update.exe"),
                main: false,
            },
        ],
        outside_root_files: Vec::new(),
        uninstallers: Vec::new(),
        older_keys: Vec::new(),
        anchors: Anchors {
            clsids: vec![OWN_CLSID.into()],
            ..Anchors::default()
        },
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

/// The harvest's record of `identity` (as `purge_harvest::sysobj::record` writes it).
fn record(identity: &TaskIdentity, why: ObjectWhy) -> Recorded {
    let program = identity.actions.iter().find_map(|a| match a {
        TaskAction::Exec { path, .. } => Some(path.trim_matches('"').to_owned()),
        _ => None,
    });
    Recorded {
        identity: identity.clone(),
        program,
        why,
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
    fn new(fixture: Fixture) -> Self {
        let env = fixture.env().expect("the fixture has an environment");
        // The pipeline builds the system objects once, before the first scanner.
        let ext = ScanExt::new(OwnershipIndex::default(), sysobj::build(&fixture, &fixture));
        Self {
            fixture,
            fp: fingerprint(),
            baseline: None,
            env,
            guard: GuardEnv::sample(),
            other_apps: OtherApps::default(),
            ext,
        }
    }

    /// Records the fixture task at `path` in the fingerprint, as the harvest would have.
    fn recorded(mut self, path: &str, why: ObjectWhy) -> Self {
        self.fp.sys.tasks.push(record(&task(path).identity, why));
        self
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

    /// Runs SYS-TASK through the sealing driver, as the engine does.
    fn run(&self) -> Vec<Candidate> {
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
        let found = self.ctx().run(&SysTask, &app);
        assert!(
            self.ext.take_faults().is_empty(),
            "the sealing dropped a candidate"
        );
        found
    }
}

fn find<'c>(found: &'c [Candidate], path: &str) -> Option<&'c Candidate> {
    found
        .iter()
        .find(|c| matches!(&c.target, Target::Task { path: p } if p == path))
}

fn only<'c>(found: &'c [Candidate], path: &str) -> &'c Candidate {
    assert_eq!(found.len(), 1, "{found:#?}");
    find(found, path).unwrap_or_else(|| panic!("no candidate for {path}: {found:#?}"))
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

fn has(c: &Candidate, kind: EvidenceKind, tier: Tier) -> bool {
    c.evidence.iter().any(|e| e.kind == kind && e.tier == tier)
}

fn deny_rule(c: &Candidate) -> Option<&str> {
    c.blockers.iter().find_map(|b| match b {
        Blocker::DenyListed { rule } => Some(rule.as_str()),
        _ => None,
    })
}

// -------------------------------------------------------------------------------------------------------
// Tests named by the package
// -------------------------------------------------------------------------------------------------------

/// Recorded at harvest, the same task now, its program gone with the whole root: Safe and ticked.
#[test]
fn owned_recorded_dangling_task_safe() {
    let world = World::new(machine_with(&[UPDATE])).recorded(UPDATE, ObjectWhy::ProgramIsAppExe);
    let found = world.run();
    let c = only(&found, UPDATE);
    assert_eq!(c.scanner, ID);
    assert_eq!(c.action, Action::DeleteKey);
    assert_eq!(c.category, Category::Startup);
    assert_eq!(c.harm, Harm::Low);
    assert_eq!(c.reversibility, Reversibility::Full);
    assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    assert!(
        c.evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::OwnedSystemObject
                && e.tier == Tier::A
                && e.scope == Scope::Object),
        "{:#?}",
        c.evidence
    );
    assert_eq!(band(c), (Band::Safe, true));
}

/// R3a S1: the program file is absent but its InstallRoot still holds a file: not proven gone (the
/// dangling rule asks for the whole root), so the record stays at Tier B and the task Likely.
#[test]
fn program_absent_root_present_not_safe() {
    let mut fx = machine_with(&[UPDATE]);
    fx.add_file(&format!(r"{ROOT}\left-behind.dll"), 10);
    let world = World::new(fx).recorded(UPDATE, ObjectWhy::ProgramIsAppExe);
    let found = world.run();
    let c = only(&found, UPDATE);
    assert!(
        !has(c, EvidenceKind::OwnedSystemObject, Tier::A),
        "{:#?}",
        c.evidence
    );
    assert_eq!(band(c), (Band::Likely, false));
}

/// R3a S6 (hostile): the app's program with a relative argument in a working directory outside the
/// app's roots runs another product's code: not offered unrecorded, at most Tier B recorded. The same in
/// the app's root is the app's.
#[test]
fn relative_argument_in_foreign_working_dir_not_the_apps() {
    let with_dir = |dir: &str| {
        let mut fx = machine_with(&[UPDATE]);
        let mut tasks = fx.tasks().unwrap();
        for action in &mut tasks[0].identity.actions {
            if let TaskAction::Exec {
                arguments,
                working_dir,
                ..
            } = action
            {
                *arguments = Some("run start".to_owned());
                *working_dir = Some(dir.to_owned());
            }
        }
        fx.set_tasks(Some(tasks));
        fx
    };
    let foreign = r"C:\Other\proj";
    assert!(World::new(with_dir(foreign)).run().is_empty());

    let mut world = World::new(with_dir(foreign));
    let recorded = world.ext.sysobj.tasks[0].identity.clone();
    world
        .fp
        .sys
        .tasks
        .push(record(&recorded, ObjectWhy::ProgramIsAppExe));
    let found = world.run();
    let c = only(&found, UPDATE);
    assert!(!has(c, EvidenceKind::OwnedSystemObject, Tier::A));
    assert_eq!(band(c), (Band::Likely, false));

    // The app's own root as the working directory: the app's.
    assert_eq!(World::new(with_dir(ROOT)).run().len(), 1);
}

/// Hostile (trap `task-similar-name`): a task named after the app, in a folder named after its vendor,
/// authored "Contoso Widget", that runs another installed product's program. Not offered, whatever its
/// names say.
#[test]
fn similar_name_other_product_no_candidate() {
    let world = World::new(machine());
    let found = world.run();
    assert!(find(&found, SIMILAR).is_none(), "{found:#?}");
    // The same with the app's other tasks recorded: a record of other tasks proves nothing about it.
    let world = World::new(machine())
        .recorded(UPDATE, ObjectWhy::ProgramIsAppExe)
        .recorded(TRAY, ObjectWhy::ProgramIsAppExe);
    assert!(find(&world.run(), SIMILAR).is_none());
}

/// Hostile (trap `task-interpreter`): a task that runs an interpreter with a file of the app as its
/// argument is not the app's program. Not recorded: no candidate at all (Windows' `cmd.exe` and a
/// Python of the machine alike).
#[test]
fn interpreter_action_with_app_argument_not_safe() {
    let world = World::new(machine_with(&[CMD, PYTHON]));
    assert!(world.run().is_empty());

    // Had the harvest recorded them (a forged or mistaken record), neither could be Safe: the system
    // interpreter is the guard's, the other one leaves the program unresolved.
    let world = World::new(machine_with(&[CMD, PYTHON]))
        .recorded(CMD, ObjectWhy::ProgramInRoot)
        .recorded(PYTHON, ObjectWhy::ProgramInRoot);
    let found = world.run();
    let cmd = find(&found, CMD).expect("recorded interpreter task listed");
    assert_eq!(deny_rule(cmd), Some("sys.task.windows"));
    assert_eq!(band(cmd).0, Band::Blocked);
    let py = find(&found, PYTHON).expect("recorded interpreter task listed");
    assert!(py.blockers.contains(&Blocker::ProgramUnresolved));
    assert_eq!(band(py), (Band::Likely, false));
}

/// R2a S5 (hostile): the app's program with an argument naming another product's code is not the
/// app's task: not offered unrecorded, and at most Tier B when recorded.
#[test]
fn foreign_argument_path_not_the_apps() {
    let with_args = |args: &str| {
        let mut fx = machine_with(&[UPDATE]);
        let mut tasks = fx.tasks().unwrap();
        for action in &mut tasks[0].identity.actions {
            if let TaskAction::Exec { arguments, .. } = action {
                *arguments = Some(args.to_owned());
            }
        }
        fx.set_tasks(Some(tasks));
        fx
    };
    let foreign = r#"-load "C:\Program Files\Other Vendor\plugin.dll""#;
    assert!(World::new(with_args(foreign)).run().is_empty());

    let world = World::new(with_args(foreign));
    let recorded = world.ext.sysobj.tasks[0].identity.clone();
    let mut world = world;
    world
        .fp
        .sys
        .tasks
        .push(record(&recorded, ObjectWhy::ProgramIsAppExe));
    let found = world.run();
    let c = only(&found, UPDATE);
    assert!(
        !has(c, EvidenceKind::OwnedSystemObject, Tier::A),
        "{:?}",
        c.evidence
    );
    assert_ne!(band(c).0, Band::Safe);

    // An argument inside the app's own root keeps it the app's.
    let own = format!(r#"-config "{ROOT}\update.ini""#);
    assert!(find(&World::new(with_args(&own)).run(), UPDATE).is_some());
}

/// Two exec actions, one the app's updater, one another product's program: not the app's task.
#[test]
fn multi_action_one_foreign_no_candidate() {
    let world = World::new(machine_with(&[SYNC]));
    assert!(world.run().is_empty());
}

/// A COM-handler task whose class is one of the app's, not recorded at harvest: offered, never ticked
/// (the class's word alone is no harvest record), with the class as its reason.
#[test]
fn com_handler_owned_clsid() {
    let world = World::new(machine_with(&[NOTIFY]));
    let found = world.run();
    let c = only(&found, NOTIFY);
    assert!(c.object_fp.is_some());
    assert!(
        !c.evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::OwnedSystemObject && e.tier == Tier::A)
    );
    assert_eq!(band(c), (Band::Likely, false));
}

/// The fixture with the scan user's Classes hive loaded (empty): what a logged-on user has.
fn with_user_classes(mut fx: Fixture) -> Fixture {
    fx.add_key(&format!(r"HKU\{}_Classes", GuardEnv::SAMPLE_SID));
    fx
}

/// R4 B2: a task whose only action is a COM handler of the app's class, recorded at harvest
/// (`AppComClass`), the same now, and the class registered in no view of the machine's or a loaded
/// user's Classes: Safe and ticked, like an exec task whose program is gone.
#[test]
fn com_handler_recorded_class_gone_safe() {
    let world = World::new(with_user_classes(machine_with(&[NOTIFY])))
        .recorded(NOTIFY, ObjectWhy::AppComClass);
    let found = world.run();
    let c = only(&found, NOTIFY);
    assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    assert!(
        c.evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::OwnedSystemObject
                && e.tier == Tier::A
                && e.scope == Scope::Object),
        "{:#?}",
        c.evidence
    );
    assert_eq!(band(c), (Band::Safe, true));
}

/// R4 B2 (hostile): the class still registered in any view, or a Classes hive that cannot be seen, keeps
/// the recorded COM-handler task at Tier B: Likely, never ticked.
#[test]
fn com_handler_recorded_class_present_or_unknown_likely() {
    let other_user = "S-1-5-21-1111111111-2222222222-3333333333-1002";
    let class_key = |root: &str| format!(r"{root}\CLSID\{OWN_CLSID}");
    let cases: Vec<(&str, Fixture)> = vec![
        (
            "the scan user's Classes not loaded",
            machine_with(&[NOTIFY]),
        ),
        ("64-bit machine class", {
            let mut fx = with_user_classes(machine_with(&[NOTIFY]));
            fx.add_key(&class_key(r"HKLM\SOFTWARE\Classes"));
            fx
        }),
        ("32-bit machine class, key without a server", {
            let mut fx = with_user_classes(machine_with(&[NOTIFY]));
            fx.add_key(&class_key(r"HKLM\SOFTWARE\Classes\WOW6432Node"));
            fx
        }),
        ("the scan user's class", {
            let mut fx = with_user_classes(machine_with(&[NOTIFY]));
            fx.add_key(&class_key(&format!(
                r"HKU\{}_Classes",
                GuardEnv::SAMPLE_SID
            )));
            fx
        }),
        ("another logged-on user's class", {
            let mut fx = with_user_classes(machine_with(&[NOTIFY]));
            fx.add_key(&format!(r"HKU\{other_user}\Software"));
            fx.add_key(&class_key(&format!(
                r"HKU\{other_user}_Classes\WOW6432Node"
            )));
            fx
        }),
        ("another logged-on user's Classes not loaded", {
            let mut fx = with_user_classes(machine_with(&[NOTIFY]));
            fx.add_key(&format!(r"HKU\{other_user}\Software"));
            fx
        }),
    ];
    for (why, fx) in cases {
        let world = World::new(fx).recorded(NOTIFY, ObjectWhy::AppComClass);
        let found = world.run();
        let c = only(&found, NOTIFY);
        assert!(
            !has(c, EvidenceKind::OwnedSystemObject, Tier::A),
            "{why}: {:#?}",
            c.evidence
        );
        assert_eq!(band(c), (Band::Likely, false), "{why}");
    }
}

/// R4 B2: an exec action of the app and a COM handler of its class, both gone: Safe; the class still
/// registered: Likely.
#[test]
fn exec_and_own_com_handler_recorded_gone_safe() {
    const MIXED: &str = r"\Contoso\Widget Mixed";
    let mixed_fixture = || {
        let mut fx = with_user_classes(machine_with(&[]));
        let mut mixed = task(UPDATE);
        mixed.identity.path = MIXED.into();
        mixed.identity.actions.push(TaskAction::ComHandler {
            clsid: OWN_CLSID.into(),
            data: None,
        });
        fx.add_task(mixed);
        fx
    };
    let mut world = World::new(mixed_fixture());
    let identity = world.ext.sysobj.tasks[0].identity.clone();
    world
        .fp
        .sys
        .tasks
        .push(record(&identity, ObjectWhy::ProgramIsAppExe));
    let found = world.run();
    assert_eq!(band(only(&found, MIXED)), (Band::Safe, true));

    let mut fx = mixed_fixture();
    fx.add_key(&format!(r"HKLM\SOFTWARE\Classes\CLSID\{OWN_CLSID}"));
    let mut world = World::new(fx);
    world
        .fp
        .sys
        .tasks
        .push(record(&identity, ObjectWhy::ProgramIsAppExe));
    let found = world.run();
    assert_eq!(band(only(&found, MIXED)), (Band::Likely, false));
}

/// Budget (R4 B2): a recorded COM-handler task opens only the class keys of its handlers (two views
/// of the machine's Classes, the user's Classes hive and its two views) and lists the loaded hives once.
#[test]
fn budget_com_handler_class_keys_only() {
    let world = World::new(with_user_classes(machine_with(&[NOTIFY])))
        .recorded(NOTIFY, ObjectWhy::AppComClass);
    let meter = Meter::new();
    let reg = MeteredRegistry::new(&world.fixture, &meter);
    let fs = MeteredFileSystem::new(&world.fixture, &meter);
    let sys = MeteredSystem::new(&world.fixture, &meter);
    let ctx = ScanCtx {
        reg: &reg,
        fs: &fs,
        sys: &sys,
        ..world.ctx()
    };
    let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
    let found = ctx.run(&SysTask, &app);
    assert_eq!(band(only(&found, NOTIFY)), (Band::Safe, true));
    let calls = meter.snapshot();
    assert!(
        calls.get(Op::RegKeyInfo).calls <= 5,
        "{}",
        calls.get(Op::RegKeyInfo).calls
    );
    assert!(
        calls.get(Op::RegOther).calls <= 1,
        "{}",
        calls.get(Op::RegOther).calls
    );
    for op in [
        Op::RegSubkeys,
        Op::RegValues,
        Op::RegValue,
        Op::SysTasks,
        Op::SysMsiTables,
        Op::FsListDir,
    ] {
        assert_eq!(calls.get(op).calls, 0, "{}", op.name());
    }
}

/// A COM-handler task of a class that is not the app's runs somebody else's code.
#[test]
fn com_handler_foreign_clsid_no_candidate() {
    let world = World::new(machine_with(&[SHELL]));
    assert!(world.run().is_empty());
    // Mixed with an action of the app, still not the app's task.
    let mut fx = machine_with(&[]);
    let mut mixed = task(UPDATE);
    mixed.identity.path = r"\Contoso\Widget Mixed".into();
    mixed.identity.actions.push(TaskAction::ComHandler {
        clsid: "{F0F0F0F0-0000-4000-8000-000000000001}".into(),
        data: None,
    });
    fx.add_task(mixed);
    assert!(World::new(fx).run().is_empty());
}

/// A task under `\Microsoft\Windows\` is Windows': never offered. Recorded (it could not have been), it is
/// listed with the guard's rule and blocked.
#[test]
fn windows_task_path_never() {
    let world = World::new(machine_with(&[WINDOWS]));
    assert!(world.run().is_empty());
    let world = World::new(machine_with(&[WINDOWS])).recorded(WINDOWS, ObjectWhy::ProgramIsAppExe);
    let found = world.run();
    let c = only(&found, WINDOWS);
    assert_eq!(deny_rule(c), Some("sys.task.windows"));
    assert_eq!(band(c), (Band::Blocked, false));
}

/// A hidden task is judged like any other.
#[test]
fn hidden_task_seen() {
    assert!(task(TRAY).hidden);
    let world = World::new(machine_with(&[TRAY]));
    let found = world.run();
    let c = only(&found, TRAY);
    // Not recorded: the program speaks for it, the harvest does not.
    assert!(has(c, EvidenceKind::PointsIntoInstallRoot, Tier::A));
    assert_eq!(band(c), (Band::Likely, false));
}

/// A task the scanning user cannot read has no actions: nothing shows whose it is.
#[test]
fn unreadable_task_not_recorded_no_candidate() {
    let world = World::new(machine_with(&[LOCKED]));
    assert!(world.run().is_empty());
    // Recorded (readable at harvest), it is listed but never ticked.
    let mut world = World::new(machine_with(&[LOCKED]));
    let mut harvested = task(UPDATE).identity;
    harvested.path = LOCKED.into();
    world
        .fp
        .sys
        .tasks
        .push(record(&harvested, ObjectWhy::ProgramIsAppExe));
    let found = world.run();
    let c = only(&found, LOCKED);
    assert!(c.blockers.contains(&Blocker::ProgramUnresolved));
    assert!(!has(c, EvidenceKind::OwnedSystemObject, Tier::A));
    assert_eq!(band(c), (Band::Likely, false));
}

/// Hostile: the task at the recorded path was changed after the harvest (another program, other
/// arguments). Listed and blocked: the record no longer describes it.
#[test]
fn digest_changed_blocks() {
    let mut world = World::new(machine_with(&[UPDATE]));
    let mut harvested = task(UPDATE).identity;
    if let TaskAction::Exec { arguments, .. } = &mut harvested.actions[0] {
        *arguments = Some("/silent".into());
    }
    world
        .fp
        .sys
        .tasks
        .push(record(&harvested, ObjectWhy::ProgramIsAppExe));
    let found = world.run();
    let c = only(&found, UPDATE);
    assert!(c.blockers.contains(&Blocker::ObjectChangedSinceHarvest));
    assert!(!has(c, EvidenceKind::OwnedSystemObject, Tier::A));
    assert_eq!(band(c), (Band::Blocked, false));

    // Re-pointed at another product's program under the recorded path: blocked as well.
    let mut fx = machine_with(&[]);
    let mut repointed = task(SIMILAR);
    repointed.identity.path = UPDATE.into();
    fx.add_task(repointed);
    let world = World::new(fx).recorded(UPDATE, ObjectWhy::ProgramIsAppExe);
    let found = world.run();
    assert_eq!(band(only(&found, UPDATE)).0, Band::Blocked);
}

/// A task with a stored password cannot be registered again without it: partial undo, never ticked.
#[test]
fn stored_password_partial() {
    let mut fx = machine_with(&[]);
    let mut t = task(UPDATE);
    t.stored_password = true;
    t.run_as = Some("CONTOSO\\svc-widget".into());
    fx.add_task(t);
    let world = World::new(fx).recorded(UPDATE, ObjectWhy::ProgramIsAppExe);
    let found = world.run();
    let c = only(&found, UPDATE);
    assert_eq!(c.reversibility, Reversibility::Partial);
    assert!(c.blockers.contains(&Blocker::ReversibilityPartial));
    assert_eq!(band(c), (Band::Likely, false));
}

/// Recorded and unchanged, but the program file is still there: offered, not ticked (D10).
#[test]
fn action_file_present_likely() {
    let mut fx = machine_with(&[UPDATE]);
    fx.add_file(&format!(r"{ROOT}\update.exe"), 1024);
    let world = World::new(fx).recorded(UPDATE, ObjectWhy::ProgramIsAppExe);
    let found = world.run();
    let c = only(&found, UPDATE);
    assert!(has(c, EvidenceKind::OwnedSystemObject, Tier::B));
    assert!(!has(c, EvidenceKind::OwnedSystemObject, Tier::A));
    assert_eq!(band(c), (Band::Likely, false));
}

/// Every candidate carries the digest of the task as read now, which is what the executor checks.
#[test]
fn object_fp_present() {
    let world = World::new(machine())
        .recorded(UPDATE, ObjectWhy::ProgramIsAppExe)
        .recorded(WINDOWS, ObjectWhy::ProgramIsAppExe)
        .recorded(PYTHON, ObjectWhy::ProgramInRoot);
    let found = world.run();
    assert!(found.len() >= 4, "{found:#?}");
    for c in &found {
        let Target::Task { path } = &c.target else {
            panic!("not a task: {c:?}");
        };
        let fp = c.object_fp.as_ref().expect("object_fp on every candidate");
        assert!(fp.is_well_formed());
        assert_eq!(*fp, task(path).identity.fp(), "{path}");
    }
}

// -------------------------------------------------------------------------------------------------------
// Further rules
// -------------------------------------------------------------------------------------------------------

/// The whole fixture, nothing recorded: only the tasks all of whose actions are the app's are offered,
/// and none of them is ticked.
#[test]
fn whole_machine_offers_only_owned_tasks() {
    let world = World::new(machine());
    let found = world.run();
    let mut paths: Vec<&str> = found
        .iter()
        .map(|c| match &c.target {
            Target::Task { path } => path.as_str(),
            other => panic!("{other:?}"),
        })
        .collect();
    paths.sort_unstable();
    assert_eq!(paths, [TRAY, NOTIFY, UPDATE]);
    for c in &found {
        assert!(!band(c).1, "{c:#?}");
    }
    for never in [
        SIMILAR, CMD, PYTHON, SYNC, SHELL, WINDOWS, LOCKED, MAIL, PROFILE,
    ] {
        assert!(find(&found, never).is_none(), "{never}");
    }
}

/// An action of a kind other than exec or COM handler: not recorded, nothing; recorded, never ticked.
#[test]
fn other_action_kind_unresolved() {
    let world = World::new(machine_with(&[MAIL]));
    assert!(world.run().is_empty());
    let world = World::new(machine_with(&[MAIL])).recorded(MAIL, ObjectWhy::ProgramInRoot);
    let found = world.run();
    let c = only(&found, MAIL);
    assert!(c.blockers.contains(&Blocker::ProgramUnresolved));
    assert_eq!(band(c), (Band::Likely, false));
}

/// An exec path written with a per-user token cannot be checked by the executor's gate (it
/// canonicalises without a profile and refuses it as `sys.task.windows`). The scanner says so instead
/// of offering what the executor refuses: listed blocked when recorded, nothing otherwise.
#[test]
fn profile_token_path_is_what_the_executor_refuses() {
    let per_user = |world: World| {
        let mut world = world;
        world.fp.roots.push(Root {
            path: USER_ROOT.into(),
            kind: RootKind::InstallRoot,
            source: RootSource::ArpInstallLocation,
            trust: SourceTrust::AdminOnly,
            volume_serial: Some(SERIAL),
            parent_existed: true,
        });
        world
    };
    let world = per_user(World::new(machine_with(&[PROFILE])));
    assert!(world.run().is_empty());
    let world =
        per_user(World::new(machine_with(&[PROFILE]))).recorded(PROFILE, ObjectWhy::ProgramInRoot);
    let found = world.run();
    let c = only(&found, PROFILE);
    assert_eq!(deny_rule(c), Some("sys.task.windows"));
    assert_eq!(band(c).0, Band::Blocked);
}

/// A task in the Windows baseline is Windows' own.
#[test]
fn baseline_task_never() {
    let tree_key = format!(
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree{UPDATE}"
    );
    let baseline = || {
        let text = format!(
            "#purge-baseline 1\tT\tPC\tProfessional\t26340.9882\nK\t{}\t0\t0\t0\n",
            tree_key.replace('\\', "\\\\")
        );
        Baseline::from_bytes(text.as_bytes()).expect("baseline parses")
    };
    let mut world = World::new(machine_with(&[UPDATE]));
    world.baseline = Some(baseline());
    assert!(
        world.ctx().in_baseline(&Target::RegKey {
            path: tree_key.clone()
        }),
        "the test baseline holds the task's tree key"
    );
    assert!(world.run().is_empty());
    let mut world =
        World::new(machine_with(&[UPDATE])).recorded(UPDATE, ObjectWhy::ProgramIsAppExe);
    world.baseline = Some(baseline());
    let found = world.run();
    assert!(
        only(&found, UPDATE)
            .blockers
            .contains(&Blocker::WindowsBaseline)
    );
}

/// A program file that another installed app's records name is that app's too.
#[test]
fn program_named_by_another_app_blocks() {
    let mut world =
        World::new(machine_with(&[UPDATE])).recorded(UPDATE, ObjectWhy::ProgramIsAppExe);
    world.other_apps = OtherApps::new(vec![OtherApp {
        name: "Fabrikam Gadget".into(),
        files: vec![format!(r"{ROOT}\update.exe")],
        ..OtherApp::default()
    }]);
    let found = world.run();
    let c = only(&found, UPDATE);
    assert!(
        c.blockers
            .iter()
            .any(|b| matches!(b, Blocker::ReferencedByOtherApp { .. }))
    );
    assert_eq!(band(c).0, Band::Blocked);
}

/// The task list could not be read: nothing is offered, not even a recorded task.
#[test]
fn tasks_not_captured_offers_nothing() {
    let mut fx = machine();
    fx.set_tasks(None);
    let world = World::new(fx).recorded(UPDATE, ObjectWhy::ProgramIsAppExe);
    assert!(
        world.ext.sysobj.errors.iter().any(|e| e.contains("tasks")),
        "{:?}",
        world.ext.sysobj.errors
    );
    assert!(world.run().is_empty());
}

/// A recorded task that is gone now gives nothing: the uninstaller removed it.
#[test]
fn recorded_task_gone_no_candidate() {
    let world = World::new(machine_with(&[])).recorded(UPDATE, ObjectWhy::ProgramIsAppExe);
    assert!(world.run().is_empty());
}

/// One candidate per task path, however the list spells it twice.
#[test]
fn one_candidate_per_path() {
    let mut fx = machine_with(&[UPDATE]);
    let mut twin = task(UPDATE);
    twin.identity.path = UPDATE.to_uppercase();
    fx.add_task(twin);
    let found = World::new(fx).run();
    assert_eq!(found.len(), 1, "{found:#?}");
}

/// Budget (C-SCANEXT, budgets): SYS-TASK opens no registry key and does not ask the task list again;
/// the pipeline's `ScanExt` holds it.
#[test]
fn budget_no_key_opens() {
    let world = World::new(machine()).recorded(UPDATE, ObjectWhy::ProgramIsAppExe);
    let meter = Meter::new();
    let reg = MeteredRegistry::new(&world.fixture, &meter);
    let fs = MeteredFileSystem::new(&world.fixture, &meter);
    let sys = MeteredSystem::new(&world.fixture, &meter);
    let ctx = ScanCtx {
        reg: &reg,
        fs: &fs,
        sys: &sys,
        ..world.ctx()
    };
    let app = AppIdentityView::from_fingerprint(&world.fp, &world.env);
    let found = ctx.run(&SysTask, &app);
    assert!(!found.is_empty());
    let calls = meter.snapshot();
    for op in [
        Op::RegKeyInfo,
        Op::RegSubkeys,
        Op::RegValues,
        Op::RegValue,
        Op::RegOther,
        Op::SysTasks,
        Op::SysMsiTables,
        Op::FsListDir,
    ] {
        assert_eq!(calls.get(op).calls, 0, "{}", op.name());
    }
}
