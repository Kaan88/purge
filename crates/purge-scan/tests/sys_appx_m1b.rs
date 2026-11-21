//! SYS-APPX M1b tests (M1B-S-APPX): the guards M1b adds to the M1a scanner. Every source is a fixture:
//! the Notepad++ app of the M1a tests, its sparse context-menu package, and packages that look like it.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use purge_guard::canon::GuardEnv;
use purge_index::baseline::Baseline;
use purge_model::{
    Action, AppRef, Band, Blocker, Candidate, Category, EvidenceKind, ExeFile, Fingerprint,
    FingerprintSchema, IdentitySnapshot, OsInfo, ProgramId, Reversibility, Root, RootKind,
    RootSource, ScanMode, Scope, SourceTrust, Target, Tier, TimeWindow, VerifyGone, View,
};
use purge_policy::band::{PolicyCtx, TargetScope, decide};
use purge_scan::framework::{AppIdentityView, OtherApps, ScanCtx, ScanExt, ScanLimits};
use purge_scan::sys_appx::{OTHER_USERS, OTHER_USERS_UNKNOWN, SysAppx};
use purge_source::fixture::{Fixture, FixtureBuilder};
use purge_source::metered::{Meter, MeteredFileSystem, MeteredRegistry, MeteredSystem, Op};
use purge_source::types::{PackageInfo, PackageSignatureKind};

const ROOT: &str = r"C:\Program Files\Notepad++";
const SERIAL: u32 = 0x1234_5678;
/// The scanning user.
const ME: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";
/// Another user of the machine.
const OTHER: &str = "S-1-5-21-1004336348-1177238915-682003330-1002";
const FAMILY: &str = "NotepadPlusPlus_2247w0b46hfww";
const PACKAGE: &str = "NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww";

/// The four AppX rows of the M1a Notepad++ run (`tests/fs/fixtures/lists-npp-2-appx.json`).
const LISTS: &str = include_str!("fs/fixtures/lists-npp-2-appx.json");

/// Notepad++: an NSIS app in `C:\Program Files\Notepad++` whose sparse package the harvest linked.
fn npp_fp() -> Fingerprint {
    let mut fp = Fingerprint {
        baseline_view: None,
        schema: FingerprintSchema,
        app: AppRef {
            program_id: ProgramId::machine(View::K64, "Notepad++").unwrap(),
            display_name: "Notepad++ (64-bit x64)".into(),
        },
        identity: IdentitySnapshot {
            names: vec!["Notepad++ (64-bit x64)".into(), "Notepad++".into()],
            vendors: vec!["Notepad++ Team".into()],
            tokens: vec!["notepad++".into()],
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
            path: format!(r"{ROOT}\notepad++.exe"),
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
        user_sid: ME.into(),
        window: TimeWindow::default(),
        verify_gone: Some(VerifyGone::new(true, true, true)),
        warnings: Vec::new(),
    };
    fp.anchors.package_full_names = vec![PACKAGE.into()];
    fp.anchors.package_families = vec![FAMILY.into()];
    fp
}

/// A sparse developer-signed package whose content is in the app's directory, registered for `users`.
fn package(full_name: &str, family: &str, users: &[&str]) -> PackageInfo {
    PackageInfo {
        full_name: full_name.into(),
        family: family.into(),
        install_location: Some(format!(r"C:\Program Files\WindowsApps\{full_name}")),
        external_location: Some(format!(r"{ROOT}\contextMenu")),
        sparse: true,
        users: users.iter().map(|s| (*s).to_owned()).collect(),
        is_framework: false,
        is_resource: false,
        signature_kind: PackageSignatureKind::Developer,
    }
}

/// An elevated machine whose interactive user is [`ME`].
fn machine() -> FixtureBuilder {
    Fixture::builder()
        .volume("C:\\", Some(SERIAL), true, "NTFS")
        .dir(r"C:\Program Files")
        .dir(r"C:\Windows\System32")
        .user_sid(ME)
        .elevated(true)
}

/// Everything a [`ScanCtx`] borrows.
struct World {
    fixture: Fixture,
    fp: Fingerprint,
    baseline: Baseline,
    env: BTreeMap<String, String>,
    guard: GuardEnv,
    other_apps: OtherApps,
}

impl World {
    fn new(fixture: Fixture) -> Self {
        let env = [
            ("SYSTEMDRIVE", "C:"),
            ("WINDIR", r"C:\Windows"),
            ("SYSTEMROOT", r"C:\Windows"),
            ("PROGRAMFILES", r"C:\Program Files"),
            ("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            ("PROGRAMDATA", r"C:\ProgramData"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let header = "#purge-baseline 1\tT\tPC\tProfessional\t26340.9882\n";
        Self {
            fixture,
            fp: npp_fp(),
            baseline: Baseline::from_bytes(header.as_bytes()).expect("baseline parses"),
            env,
            guard: GuardEnv::sample(),
            other_apps: OtherApps::default(),
        }
    }

    /// A world over an elevated machine with these packages registered.
    fn with_packages(packages: Vec<PackageInfo>) -> Self {
        let mut b = machine();
        for p in packages {
            b = b.package(p);
        }
        Self::new(b.build())
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
            ext: ScanExt::none(),
        }
    }

    /// The scanner through the sealing driver, with what every scanner must hold.
    fn run(&self) -> Vec<Candidate> {
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
        let found = self.ctx().run(&SysAppx, &app);
        for (i, c) in found.iter().enumerate() {
            assert_eq!(c.scanner, "SYS-APPX");
            assert!(c.decision.is_none(), "a scanner never decides: {c:?}");
            assert!(found[..i].iter().all(|o| o.id != c.id), "duplicate: {c:?}");
        }
        found
    }

    /// The one candidate there is.
    fn one(&self) -> Candidate {
        let mut found = self.run();
        assert_eq!(found.len(), 1, "one package: {found:#?}");
        found.pop().unwrap()
    }
}

fn full_name(c: &Candidate) -> &str {
    match &c.target {
        Target::AppxPackage { full_name } => full_name,
        other => panic!("not a package: {other:?}"),
    }
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

/// The `other_users` fact of the candidate's link evidence.
fn other_users(c: &Candidate) -> Option<String> {
    let link: Vec<_> = c
        .evidence
        .iter()
        .filter(|e| e.kind == EvidenceKind::AppxExternalLocation)
        .collect();
    assert_eq!(link.len(), 1, "one link evidence: {:?}", c.evidence);
    link[0].detail.get(OTHER_USERS).map(str::to_owned)
}

// ---------------------------------------------------------------------------------------------------------
// Never a candidate
// ---------------------------------------------------------------------------------------------------------

#[test]
fn framework_package_never() {
    let offered = |edit: &dyn Fn(&mut PackageInfo)| {
        let mut p = package(PACKAGE, FAMILY, &[ME]);
        edit(&mut p);
        World::with_packages(vec![p]).run().len()
    };
    // The control: the linked package as it is.
    assert_eq!(offered(&|_| {}), 1);
    assert_eq!(offered(&|p| p.is_framework = true), 0);
    assert_eq!(offered(&|p| p.is_resource = true), 0);
    // A bundle of the linked family (resource id `~`): the source has no bundle flag, so a bundle of
    // frameworks is caught here as well.
    assert_eq!(
        offered(&|p| p.full_name = "NotepadPlusPlus_1.0.0.0_neutral_~_2247w0b46hfww".into()),
        0
    );
    assert_eq!(
        offered(&|p| {
            p.full_name = "NotepadPlusPlus_1.0.0.0_neutral_~_2247w0b46hfww".into();
            p.is_framework = true;
        }),
        0
    );
    // Whatever the registration, a framework stays out (not even ReportOnly).
    assert_eq!(
        offered(&|p| {
            p.is_framework = true;
            p.users = vec![ME.into(), OTHER.into()];
        }),
        0
    );
    // The fingerprint recording the framework's full name changes nothing.
    let mut w = World::with_packages(vec![PackageInfo {
        is_framework: true,
        ..package(PACKAGE, FAMILY, &[ME])
    }]);
    w.fp.anchors.package_full_names = vec![PACKAGE.into()];
    assert!(w.run().is_empty());
}

/// Hostile: a package of the same publisher with a similar name, its content in the app's directory.
/// Only a family the harvest linked counts; a recorded full name alone does not.
#[test]
fn family_not_in_fingerprint_never() {
    let similar = [
        (
            "NotepadPlusPlus.Shell_1.0.0.0_neutral__2247w0b46hfww",
            "NotepadPlusPlus.Shell_2247w0b46hfww",
        ),
        (
            "NotepadPlusPlus2_1.0.0.0_neutral__2247w0b46hfww",
            "NotepadPlusPlus2_2247w0b46hfww",
        ),
        (
            "Notepadplusplus_1.0.0.0_neutral__2247w0b46hfwx",
            "Notepadplusplus_2247w0b46hfwx",
        ),
    ];
    for (full, family) in similar {
        let w = World::with_packages(vec![package(full, family, &[ME])]);
        assert!(w.run().is_empty(), "{full} is not the app's");
    }

    // The harvest recorded the full name, but its family is not among the linked families (an
    // inconsistent or hand-edited fingerprint): not offered.
    let mut w = World::with_packages(vec![package(PACKAGE, FAMILY, &[ME])]);
    w.fp.anchors.package_families = vec!["NotepadPlusPlus.Shell_2247w0b46hfww".into()];
    assert!(w.run().is_empty(), "a full name alone is not a link");
    w.fp.anchors.package_families.clear();
    assert!(w.run().is_empty(), "no family linked, nothing offered");

    // A listing that reports the linked family for a full name of another family is not trusted.
    let w = World::with_packages(vec![package(
        "Evil_1.0.0.0_neutral__2247w0b46hfww",
        FAMILY,
        &[ME],
    )]);
    assert!(w.run().is_empty(), "family and full name disagree");

    // The family compares case-insensitively and exactly: the linked one is still offered next to
    // the look-alikes, and only it.
    let mut packages: Vec<PackageInfo> = similar
        .iter()
        .map(|(full, family)| package(full, family, &[ME]))
        .collect();
    packages.push(package(
        "notepadplusplus_1.0.2.0_x64__2247W0B46HFWW",
        "NOTEPADPLUSPLUS_2247W0B46HFWW",
        &[ME],
    ));
    let c = World::with_packages(packages).one();
    assert_eq!(full_name(&c), "notepadplusplus_1.0.2.0_x64__2247W0B46HFWW");
}

// ---------------------------------------------------------------------------------------------------------
// Which action
// ---------------------------------------------------------------------------------------------------------

#[test]
fn other_users_registered_is_report_only() {
    let cases: [(&[&str], &str); 4] = [
        (&[ME, OTHER], "1"),
        // Registered for another user only: nothing to remove for the scanning user.
        (&[OTHER], "1"),
        // SYSTEM's registration counts as another user's.
        (&[ME, "S-1-5-18", OTHER], "2"),
        // The same user twice, in another case, is one user.
        (
            &[ME, OTHER, "s-1-5-21-1004336348-1177238915-682003330-1002"],
            "1",
        ),
    ];
    for (users, n) in cases {
        let c = World::with_packages(vec![package(PACKAGE, FAMILY, users)]).one();
        assert_eq!(c.action, Action::ReportOnly, "{users:?}");
        assert_eq!(other_users(&c).as_deref(), Some(n), "{users:?}");
        assert_eq!(c.reversibility, Reversibility::None);
        assert!(c.blockers.contains(&Blocker::ReversibilityNone));
        assert!(!band(&c).1, "never preselected: {users:?}");
    }

    // Who the package is registered for cannot be known: ReportOnly, `other_users = unknown`.
    let unknown = |fixture: Fixture| {
        let c = World::new(fixture).one();
        assert_eq!(c.action, Action::ReportOnly);
        assert_eq!(other_users(&c).as_deref(), Some(OTHER_USERS_UNKNOWN));
        assert!(!band(&c).1);
    };
    // Not elevated: the listing holds the engine account's own registrations only.
    unknown(
        machine()
            .elevated(false)
            .package(package(PACKAGE, FAMILY, &[ME]))
            .build(),
    );
    // The scanning user's SID cannot be read.
    unknown(
        Fixture::builder()
            .volume("C:\\", Some(SERIAL), true, "NTFS")
            .elevated(true)
            .package(package(PACKAGE, FAMILY, &[ME]))
            .build(),
    );
    // The listing names no user, or an empty one.
    unknown(machine().package(package(PACKAGE, FAMILY, &[])).build());
    unknown(
        machine()
            .package(package(PACKAGE, FAMILY, &[ME, " "]))
            .build(),
    );
}

#[test]
fn current_user_only_package_likely_remove() {
    // The SID as the live source spells it (upper case) and as a snapshot may (lower case).
    for me in [ME, &ME.to_ascii_lowercase()] {
        let c = World::with_packages(vec![package(PACKAGE, FAMILY, &[me])]).one();
        assert_eq!(
            c.target,
            Target::AppxPackage {
                full_name: PACKAGE.into()
            }
        );
        assert_eq!(
            (c.action, c.category, c.reversibility),
            (
                Action::RemovePackage,
                Category::Package,
                Reversibility::None
            )
        );
        assert_eq!(c.blockers, [Blocker::ReversibilityNone]);
        assert_eq!(other_users(&c), None, "no fact on a current-user package");
        let link = c
            .evidence
            .iter()
            .find(|e| e.kind == EvidenceKind::AppxExternalLocation)
            .expect("the link");
        assert_eq!((link.tier, link.scope), (Tier::A, Scope::Package));
        assert_eq!(band(&c), (Band::Likely, false));
    }
}

// ---------------------------------------------------------------------------------------------------------
// M1a behaviour and budget
// ---------------------------------------------------------------------------------------------------------

/// The candidate list as the M1a golden files render it (`tests/fs/main.rs` `render`).
fn render(found: &[Candidate]) -> String {
    let mut out = String::new();
    for c in found {
        writeln!(
            out,
            "{} {:?} {:?} package:{}",
            c.scanner,
            c.action,
            c.category,
            full_name(c)
        )
        .unwrap();
        writeln!(
            out,
            "  harm={:?} reversibility={:?} size=- files=-",
            c.harm, c.reversibility
        )
        .unwrap();
        for e in &c.evidence {
            let detail: Vec<String> = e.detail.0.iter().map(|(k, v)| format!("{k}={v}")).collect();
            writeln!(
                out,
                "  + {:?} {:?}/{} {:?} {:?} [{}] {{{}}}",
                e.kind,
                e.tier,
                e.weight,
                e.scope,
                e.trust,
                e.source.0,
                detail.join(", ")
            )
            .unwrap();
        }
        for b in &c.blockers {
            writeln!(out, "  ! {b:?}").unwrap();
        }
    }
    out
}

/// The M1a Notepad++ run gives exactly the M1a golden candidate (`tests/fs/golden/appx_npp.txt`), through
/// the sealing driver as well; the M1a tests themselves (`tests/fs/appx.rs`) are unchanged.
#[test]
fn m1a_sys_appx_tests_unchanged() {
    let fixture = Fixture::from_snap_parts(&b""[..], Some(LISTS), None).expect("the lists load");
    let mut w = World::new(fixture);
    // The M1a fingerprint's user is not the run's; the scanning user comes from the system source.
    w.fp.user_sid = GuardEnv::SAMPLE_SID.into();
    let found = w.run();
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fs/golden/appx_npp.txt");
    let want = std::fs::read_to_string(golden)
        .expect("the M1a golden file")
        .replace("\r\n", "\n");
    assert_eq!(render(&found), want);

    // Edge's own sparse package and the inbox apps of the same listing stay out with every family
    // of the listing linked.
    w.fp.anchors.package_families = vec![
        FAMILY.into(),
        "Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe".into(),
        "Microsoft.MicrosoftEdgeDevToolsClient_8wekyb3d8bbwe".into(),
    ];
    w.other_apps = OtherApps::new(vec![purge_scan::framework::OtherApp {
        name: "Microsoft Edge".into(),
        roots: vec![r"C:\Program Files (x86)\Microsoft\Edge\Application".into()],
        ..Default::default()
    }]);
    let names: Vec<String> = w.run().iter().map(|c| full_name(c).to_owned()).collect();
    assert_eq!(names, [PACKAGE]);
}

/// The scanner opens no registry key and touches no file: one package listing and the two facts of who
/// is scanning.
#[test]
fn budget_no_key_opens() {
    let w = World::with_packages(vec![
        package(PACKAGE, FAMILY, &[ME]),
        package(
            "NotepadPlusPlus_1.0.1.0_neutral__2247w0b46hfww",
            FAMILY,
            &[ME, OTHER],
        ),
    ]);
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
    let out = ctx.run(&SysAppx, &app);
    assert_eq!(out.len(), 2);
    let calls = meter.snapshot();
    for op in [
        Op::RegKeyInfo,
        Op::RegSubkeys,
        Op::RegValues,
        Op::RegValue,
        Op::RegOther,
        Op::FsListDir,
        Op::FsMetadata,
        Op::FsExists,
        Op::SysTasks,
        Op::SysMsiTables,
    ] {
        assert_eq!(calls.get(op).calls, 0, "{}: {}", op.name(), calls.summary());
    }
    // `packages` once, then `elevated` and `user_sid` (the metered source counts all three as System).
    assert!(calls.get(Op::System).calls <= 3, "{}", calls.summary());
}
