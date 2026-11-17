//! SYS-SERVICE tests (M1B-S-SERVICE). Every source is a fixture: `tests/data/sys_service/machine.json`
//! holds the services (the app's, another product's, Windows' own, and the trap shapes), and each test
//! changes what it needs and records what the harvest would have recorded.

use std::collections::BTreeMap;
use std::path::Path;

use purge_guard::canon::GuardEnv;
use purge_index::baseline::Baseline;
use purge_index::sysobj::{self, ServiceFacts};
use purge_model::{
    Action, AppRef, Band, Blocker, Candidate, Category, EvidenceKind, ExeFile, Fingerprint,
    FingerprintSchema, Harm, IdentitySnapshot, ObjectKind, ObjectWhy, OsInfo, ProgramId,
    Reversibility, Root, RootKind, RootSource, ScanMode, Scope, SourceTrust, SysService, Target,
    Tier, TimeWindow, VerifyGone, View,
};
use purge_policy::band::{PolicyCtx, TargetScope, decide};
use purge_scan::framework::{AppIdentityView, OtherApps, ScanCtx, ScanExt, ScanLimits};
use purge_scan::sys_service::SysService as Scanner;
use purge_source::fixture::Fixture;
use purge_source::metered::{Meter, MeteredFileSystem, MeteredRegistry, MeteredSystem, Op};
use purge_source::system::SystemSource;
use purge_source::types::RegData;

const ROOT: &str = r"C:\Program Files\App";
const SERIAL: u32 = 0x1234_5678;
const SVC: &str = r"HKLM\SYSTEM\ControlSet001\Services";

fn machine() -> Fixture {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/sys_service/machine.json");
    Fixture::from_json_file(&path).expect("machine.json loads")
}

/// The app "App": one admin-only InstallRoot and its main exe.
fn fingerprint(fx: &Fixture) -> Fingerprint {
    Fingerprint {
        schema: FingerprintSchema,
        app: AppRef {
            program_id: ProgramId::machine(View::K64, "App").unwrap(),
            display_name: "App".into(),
        },
        identity: IdentitySnapshot {
            names: vec!["App".into(), "App Service".into()],
            vendors: vec!["App Vendor".into()],
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
        exes: vec![ExeFile {
            path: format!(r"{ROOT}\app.exe"),
            main: true,
        }],
        outside_root_files: Vec::new(),
        uninstallers: Vec::new(),
        older_keys: Vec::new(),
        anchors: Default::default(),
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
        user_sid: fx.user_sid().expect("fixture user"),
        window: TimeWindow::default(),
        verify_gone: None,
        warnings: Vec::new(),
    }
}

/// Everything a [`ScanCtx`] borrows. The system objects are read from the fixture when the world is
/// made ([`World::reindex`] after a change), as the pipeline reads them once before the scanners.
struct World {
    fixture: Fixture,
    fp: Fingerprint,
    baseline: Baseline,
    env: BTreeMap<String, String>,
    guard: GuardEnv,
    other_apps: OtherApps,
    ext: ScanExt,
}

impl World {
    fn new() -> Self {
        Self::with(machine())
    }

    fn with(fixture: Fixture) -> Self {
        let fp = fingerprint(&fixture);
        let env = fixture.env().expect("fixture env");
        let ext = ScanExt::new(Default::default(), sysobj::build(&fixture, &fixture));
        let header = "#purge-baseline 1\tT\tPC\tProfessional\t26340.9882\n";
        Self {
            fixture,
            fp,
            baseline: Baseline::from_bytes(header.as_bytes()).expect("baseline parses"),
            env,
            guard: GuardEnv::sample(),
            other_apps: OtherApps::default(),
            ext,
        }
    }

    /// Reads the system objects again after the fixture changed.
    fn reindex(&mut self) {
        self.ext = ScanExt::new(
            Default::default(),
            sysobj::build(&self.fixture, &self.fixture),
        );
    }

    fn facts(&self, name: &str) -> &ServiceFacts {
        self.ext
            .sysobj
            .services
            .iter()
            .find(|s| s.identity.name == name)
            .unwrap_or_else(|| panic!("service {name} in the index"))
    }

    /// Records the service as the harvest does: its identity as read now, its resolved program.
    fn record(&mut self, name: &str, why: ObjectWhy) {
        let facts = self.facts(name).clone();
        self.fp.sys.services.push(SysService {
            program: facts.program.file().map(str::to_owned),
            identity: facts.identity,
            why,
        });
    }

    fn remove_file(&mut self, file: &str) {
        assert!(self.fixture.remove_path(file), "{file} was in the fixture");
    }

    /// The whole InstallRoot is gone: what the dangling rule asks for before a program file in it is
    /// proven gone (R3a S1).
    fn remove_root(&mut self) {
        assert!(self.fixture.remove_path(ROOT), "{ROOT} was in the fixture");
    }

    fn ctx(&self) -> ScanCtx<'_> {
        ScanCtx {
            reg: &self.fixture,
            fs: &self.fixture,
            sys: &self.fixture,
            fp: &self.fp,
            baseline: Some(&self.baseline),
            mode: ScanMode::Post,
            verify_gone: Some(VerifyGone::new(true, true, true)),
            env: &self.env,
            guard: &self.guard,
            other_apps: &self.other_apps,
            limits: ScanLimits::default(),
            ext: &self.ext,
        }
    }

    /// The scanner through the sealing driver.
    fn run(&self) -> Vec<Candidate> {
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
        let out = self.ctx().run(&Scanner, &app);
        assert!(self.ext.take_faults().is_empty(), "no scanner fault");
        out
    }

    fn find(&self, name: &str) -> Option<Candidate> {
        let mut found: Vec<Candidate> = self
            .run()
            .into_iter()
            .filter(|c| matches!(&c.target, Target::Service { name: n } if n.eq_ignore_ascii_case(name)))
            .collect();
        assert!(found.len() <= 1, "one candidate per service: {found:?}");
        found.pop()
    }

    fn get(&self, name: &str) -> Candidate {
        self.find(name)
            .unwrap_or_else(|| panic!("a candidate for {name}"))
    }
}

fn band(c: &Candidate) -> (Band, bool) {
    let d = decide(
        c,
        &PolicyCtx {
            mode: ScanMode::Post,
            verify_gone: VerifyGone::new(true, true, true),
            target_scope: TargetScope::Machine,
        },
    );
    (d.band, d.preselected)
}

fn has_owned_object(c: &Candidate) -> bool {
    c.evidence.iter().any(|e| {
        e.kind == EvidenceKind::OwnedSystemObject && e.tier == Tier::A && e.scope == Scope::Object
    })
}

fn deny(rule: &str) -> Blocker {
    Blocker::DenyListed {
        rule: rule.to_owned(),
    }
}

fn file(name: &str) -> String {
    format!(r"{ROOT}\{name}")
}

// ---------------------------------------------------------------------------------------------------------
// Ownership and bands
// ---------------------------------------------------------------------------------------------------------

#[test]
fn owned_recorded_dangling_service_safe() {
    let mut w = World::new();
    w.record("AppSvc", ObjectWhy::ProgramInRoot);
    w.remove_root();
    let c = w.get("AppSvc");
    assert_eq!(
        c.target,
        Target::Service {
            name: "AppSvc".into()
        }
    );
    assert_eq!(c.action, Action::DeleteKey);
    assert_eq!(c.category, Category::System);
    assert_eq!(c.harm, Harm::Low);
    assert_eq!(c.reversibility, Reversibility::Full);
    assert_eq!(c.scanner, "SYS-SERVICE");
    assert!(has_owned_object(&c), "{:?}", c.evidence);
    assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    assert_eq!(band(&c), (Band::Safe, true));
}

/// R3a S1: the program file is absent but its InstallRoot is still there (other files left): not proven
/// gone, so the record is not Tier A.
#[test]
fn owned_recorded_program_absent_root_present_likely() {
    let mut w = World::new();
    w.record("AppSvc", ObjectWhy::ProgramInRoot);
    w.remove_file(&file("svc.exe"));
    let c = w.get("AppSvc");
    assert!(!has_owned_object(&c), "{:?}", c.evidence);
    assert_eq!(band(&c), (Band::Likely, false));
}

#[test]
fn owned_recorded_program_present_likely() {
    let mut w = World::new();
    w.record("AppSvc", ObjectWhy::ProgramInRoot);
    let c = w.get("AppSvc");
    assert!(!has_owned_object(&c), "{:?}", c.evidence);
    assert!(
        c.evidence
            .iter()
            .any(|e| e.kind == EvidenceKind::PointsIntoInstallRoot)
    );
    assert_eq!(band(&c), (Band::Likely, false));

    // An MSI ServiceInstall record does not stand in for "the program is gone".
    let mut w = World::new();
    w.record("AppSvc", ObjectWhy::MsiServiceRow);
    let c = w.get("AppSvc");
    assert!(!has_owned_object(&c), "{:?}", c.evidence);
    assert_eq!(band(&c), (Band::Likely, false));
}

/// R2a S5 (hostile): the app's program with an argument naming another product's code, or a path that
/// is not one local file, is not the app's service. An argument inside the app's root is.
#[test]
fn foreign_argument_path_makes_no_candidate() {
    for (args, offered) in [
        (r#""C:\Program Files\Other Vendor\plugin.dll""#, false),
        (r"-load=D:\x\y.dll", false),
        (r"\\server\share\y.dll", false),
        (r#"-config "C:\Program Files\App\svc.ini""#, true),
        ("-run", true),
    ] {
        let mut w = World::new();
        w.fixture.set_value(
            &format!(r"{SVC}\AppSvc"),
            "ImagePath",
            RegData::from_expand_sz(&format!(r#""{ROOT}\svc.exe" {args}"#)),
        );
        w.reindex();
        assert_eq!(w.find("AppSvc").is_some(), offered, "{args}");
    }
}

#[test]
fn not_recorded_program_in_root_likely() {
    let mut w = World::new();
    w.remove_file(&file("update.exe"));
    let c = w.get("AppUpdate");
    // Gone or not, without the harvest's record the program's word is all there is.
    assert!(!has_owned_object(&c), "{:?}", c.evidence);
    assert_eq!(band(&c), (Band::Likely, false));

    // A program on an unproven volume is not "gone" either.
    let mut w = World::new();
    w.record("AppUpdate", ObjectWhy::ProgramInRoot);
    w.remove_file(&file("update.exe"));
    w.fixture.add_volume(
        r"C:\",
        purge_source::types::VolumeInfo {
            serial: Some(SERIAL + 1),
            fixed: true,
            fs: "NTFS".into(),
        },
    );
    let c = w.get("AppUpdate");
    assert!(!has_owned_object(&c), "other disk under the same letter");
    assert_eq!(band(&c), (Band::Likely, false));
}

/// Hostile (trap svc-shared): a service whose name, display name and description carry the app's
/// name but whose program belongs to another product is never the app's.
#[test]
fn name_contains_app_name_program_elsewhere_no_candidate() {
    let mut w = World::new();
    w.remove_file(r"C:\Program Files\Other Vendor\helper.exe");
    assert!(w.find("App Shared Helper").is_none());
    assert!(w.run().iter().all(|c| !matches!(
        &c.target,
        Target::Service { name } if name.contains("Shared")
    )));
}

#[test]
fn svchost_service_with_app_dll_in_root() {
    let mut w = World::new();
    let facts = w.facts("AppHost");
    assert!(facts.svchost);
    assert_eq!(facts.program.file(), Some(file("apphost.dll").as_str()));
    // Smoke trap svc-svchost (escape at 3b17232: listed Likely): a service hosted by svchost shares a
    // Windows process and is judged by its host, svchost.exe under %SystemRoot%, not by its DLL. Not
    // recorded, it is not listed at all.
    assert!(w.find("AppHost").is_none());
    w.remove_root();
    assert!(w.find("AppHost").is_none());

    // A forged (or pre-fix) harvest record lists it, protected by the guard: never offered, even with
    // the DLL proven gone.
    w.record("AppHost", ObjectWhy::ProgramInRoot);
    let c = w.get("AppHost");
    assert!(
        c.blockers.contains(&deny("sys.service.windows")),
        "{:?}",
        c.blockers
    );
    assert_eq!(band(&c).0, Band::Blocked);
}

/// Hostile (trap svc-svchost): a svchost service of the app's name whose DLL is in System32.
#[test]
fn svchost_service_dll_in_system32_no_candidate() {
    let mut w = World::new();
    assert!(w.find("AppNet").is_none());
    // Even a forged harvest record does not make it offerable: Windows' program is denied.
    w.record("AppNet", ObjectWhy::ProgramInRoot);
    w.remove_file(r"C:\WINDOWS\System32\appnet.dll");
    let c = w.get("AppNet");
    assert!(
        c.blockers.contains(&deny("sys.service.windows")),
        "{:?}",
        c.blockers
    );
    assert_eq!(band(&c).0, Band::Blocked);
}

#[test]
fn driver_recorded_is_protected_listed() {
    let mut w = World::new();
    assert!(w.facts("appdrv").is_driver);
    // Not recorded: not listed.
    assert!(w.find("appdrv").is_none());
    // Recorded: listed with the guard's blocker, so the user sees why it stays.
    w.record("appdrv", ObjectWhy::ProgramInRoot);
    w.remove_file(&file("appdrv.sys"));
    let c = w.get("appdrv");
    assert!(c.blockers.contains(&deny("sys.driver")), "{:?}", c.blockers);
    assert!(c.blockers.contains(&Blocker::Driver));
    assert_eq!(band(&c), (Band::Blocked, false));
}

#[test]
fn per_user_instance_never() {
    let mut w = World::new();
    assert!(w.facts("AppUserSvc").per_user_template);
    assert!(w.facts("AppUserSvc_4a5b1").per_user_template);
    assert!(w.find("AppUserSvc").is_none());
    assert!(w.find("AppUserSvc_4a5b1").is_none());
    // A forged record lists it, blocked.
    w.record("AppUserSvc_4a5b1", ObjectWhy::ProgramInRoot);
    let c = w.get("AppUserSvc_4a5b1");
    assert!(
        c.blockers.contains(&deny("sys.service.peruser")),
        "{:?}",
        c.blockers
    );
    assert_eq!(band(&c), (Band::Blocked, false));
}

/// Trap svc-dependent: a service another service depends on is blocked, even when the dependent is the
/// app's own.
#[test]
fn dependent_service_blocks() {
    let mut w = World::new();
    w.record("AppCore", ObjectWhy::ProgramInRoot);
    w.record("AppAgent", ObjectWhy::ProgramInRoot);
    w.remove_root();
    let core = w.get("AppCore");
    assert!(
        core.blockers.contains(&Blocker::HasDependents {
            names: vec!["AppAgent".into()]
        }),
        "{:?}",
        core.blockers
    );
    assert_eq!(band(&core), (Band::Blocked, false));
    // The dependent itself goes first.
    let agent = w.get("AppAgent");
    assert!(agent.blockers.is_empty(), "{:?}", agent.blockers);
    assert_eq!(band(&agent), (Band::Safe, true));
}

#[test]
fn unreadable_service_counts_as_dependent() {
    let mut w = World::new();
    w.fixture
        .set_value(&format!(r"{SVC}\Odd"), "ImagePath", RegData::from_dword(7));
    w.reindex();
    assert!(w.ext.sysobj.errors.iter().any(|e| e.contains("Odd")));
    w.record("AppSvc", ObjectWhy::ProgramInRoot);
    w.remove_file(&file("svc.exe"));
    let c = w.get("AppSvc");
    assert!(
        c.blockers.contains(&Blocker::HasDependents {
            names: vec!["Odd".into()]
        }),
        "{:?}",
        c.blockers
    );
    assert_eq!(band(&c).0, Band::Blocked);
}

/// Hostile: the service's ImagePath was repointed after the harvest (to another product's program, or
/// to another file of the root).
#[test]
fn digest_changed_since_harvest_blocks() {
    for repointed in [
        r#""C:\Program Files\Other Vendor\helper.exe""#,
        r#""C:\Program Files\App\update.exe""#,
    ] {
        let mut w = World::new();
        w.record("AppSvc", ObjectWhy::ProgramInRoot);
        w.remove_file(&file("svc.exe"));
        w.fixture.set_value(
            &format!(r"{SVC}\AppSvc"),
            "ImagePath",
            RegData::from_expand_sz(repointed),
        );
        w.reindex();
        let c = w.get("AppSvc");
        assert!(
            c.blockers.contains(&Blocker::ObjectChangedSinceHarvest),
            "{repointed}: {:?}",
            c.blockers
        );
        assert!(!has_owned_object(&c));
        assert_eq!(band(&c), (Band::Blocked, false), "{repointed}");
    }
    // A change of the account is a change of the identity too.
    let mut w = World::new();
    w.record("AppSvc", ObjectWhy::ProgramInRoot);
    w.remove_file(&file("svc.exe"));
    w.fixture.set_value(
        &format!(r"{SVC}\AppSvc"),
        "ObjectName",
        RegData::from_sz(r".\x"),
    );
    w.reindex();
    assert!(
        w.get("AppSvc")
            .blockers
            .contains(&Blocker::ObjectChangedSinceHarvest)
    );
}

#[test]
fn password_account_partial_never_safe() {
    let mut w = World::new();
    w.record("AppAccount", ObjectWhy::ProgramInRoot);
    w.remove_root();
    let c = w.get("AppAccount");
    assert!(has_owned_object(&c), "owned, and still not Safe");
    assert_eq!(c.reversibility, Reversibility::Partial);
    assert!(c.blockers.contains(&Blocker::ReversibilityPartial));
    assert_eq!(band(&c), (Band::Likely, false));
}

#[test]
fn unresolved_program_likely() {
    let mut w = World::new();
    assert!(w.facts("AppScript").program.file().is_none());
    // Not recorded: an interpreter's arguments are never ownership.
    assert!(w.find("AppScript").is_none());
    // Recorded (an older harvest, another environment): offered, never preselected.
    w.record("AppScript", ObjectWhy::ProgramInRoot);
    w.fp.sys.services.last_mut().unwrap().program = Some(file("run.cmd"));
    w.remove_file(&file("run.cmd"));
    let c = w.get("AppScript");
    assert!(
        c.blockers.contains(&Blocker::ProgramUnresolved),
        "{:?}",
        c.blockers
    );
    assert!(!has_owned_object(&c));
    assert_eq!(band(&c), (Band::Likely, false));
}

#[test]
fn delete_flag_no_candidate() {
    let mut w = World::new();
    assert!(w.find("AppMarked").is_none());
    w.record("AppMarked", ObjectWhy::ProgramInRoot);
    w.remove_file(&file("marked.exe"));
    assert!(w.find("AppMarked").is_none());
}

#[test]
fn recorded_service_gone_no_candidate() {
    let mut w = World::new();
    w.record("AppSvc", ObjectWhy::ProgramInRoot);
    assert!(w.fixture.remove_key(&format!(r"{SVC}\AppSvc")));
    w.reindex();
    assert!(w.find("AppSvc").is_none());
}

// ---------------------------------------------------------------------------------------------------------
// Form
// ---------------------------------------------------------------------------------------------------------

#[test]
fn object_fp_present_on_every_candidate() {
    let mut w = World::new();
    for name in [
        "AppSvc",
        "AppUpdate",
        "AppHost",
        "AppNet",
        "appdrv",
        "AppCore",
        "AppAgent",
        "AppAccount",
        "AppScript",
    ] {
        w.record(name, ObjectWhy::ProgramInRoot);
    }
    let all = w.run();
    assert_eq!(
        all.len(),
        9,
        "{:#?}",
        all.iter().map(|c| &c.target).collect::<Vec<_>>()
    );
    for c in &all {
        let Target::Service { name } = &c.target else {
            panic!("{:?}", c.target);
        };
        let fp = c.object_fp.as_ref().expect("object_fp");
        assert_eq!(fp.kind, ObjectKind::Service);
        assert!(fp.is_well_formed());
        assert_eq!(*fp, w.facts(name).identity.fp(), "{name}");
    }
}

#[test]
fn controlset_spelling_does_not_duplicate() {
    let mut fx = machine();
    // A second, non-current control set with its own copy of the service.
    fx.set_value(
        r"HKLM\SYSTEM\ControlSet002\Services\AppSvc",
        "ImagePath",
        RegData::from_expand_sz(r#""C:\Program Files\App\old.exe""#),
    );
    let mut w = World::with(fx);
    w.record("AppSvc", ObjectWhy::ProgramInRoot);
    // The same service recorded twice, once spelled in other case.
    let mut again = w.fp.sys.services[0].clone();
    again.identity.name = "APPSVC".into();
    w.fp.sys.services.push(again);
    w.remove_root();
    let all: Vec<Candidate> = w
        .run()
        .into_iter()
        .filter(|c| matches!(&c.target, Target::Service { name } if name.eq_ignore_ascii_case("AppSvc")))
        .collect();
    assert_eq!(all.len(), 1, "{all:?}");
    assert_eq!(
        all[0].target,
        Target::Service {
            name: "AppSvc".into()
        }
    );
    assert_eq!(
        all[0].object_fp.as_ref(),
        Some(&w.facts("AppSvc").identity.fp())
    );
    assert_eq!(band(&all[0]), (Band::Safe, true));
}

/// The key-open budget of SYS-SERVICE is 0 beyond what ScanExt already holds (budgets).
#[test]
fn budget_no_key_opens() {
    let mut w = World::new();
    for name in ["AppSvc", "AppCore", "AppAgent", "appdrv"] {
        w.record(name, ObjectWhy::ProgramInRoot);
    }
    w.remove_file(&file("svc.exe"));
    let meter = Meter::new();
    let reg = MeteredRegistry::new(&w.fixture, &meter);
    let fs = MeteredFileSystem::new(&w.fixture, &meter);
    let sys = MeteredSystem::new(&w.fixture, &meter);
    let ctx = ScanCtx {
        reg: &reg,
        fs: &fs,
        sys: &sys,
        ..w.ctx()
    };
    let app = AppIdentityView::from_fingerprint(&w.fp, &w.env);
    let out = ctx.run(&Scanner, &app);
    assert!(!out.is_empty());
    let calls = meter.snapshot();
    for op in [
        Op::RegKeyInfo,
        Op::RegSubkeys,
        Op::RegValues,
        Op::RegValue,
        Op::RegOther,
        Op::SysTasks,
        Op::SysMsiTables,
    ] {
        assert_eq!(calls.get(op).calls, 0, "{}: {}", op.name(), calls.summary());
    }
    // The file system is asked only about the programs of offered services.
    assert!(calls.get(Op::FsListDir).calls == 0, "{}", calls.summary());
}
