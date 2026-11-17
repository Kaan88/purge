//! The fixture world of the Burn tests.

use std::collections::BTreeMap;
use std::path::Path;

use purge_guard::canon::GuardEnv;
use purge_index::baseline::Baseline;
use purge_index::ownership::{OwnershipIndex, OwnershipInput};
use purge_index::sysobj::SysObjectIndex;
use purge_model::{
    AppRef, Band, BurnFacts, BurnPackage, Candidate, Fingerprint, FingerprintSchema,
    IdentitySnapshot, OsInfo, ProgramId, ScanMode, Target, TimeWindow, VerifyGone, View,
};
use purge_policy::band::{PolicyCtx, TargetScope, decide};
use purge_scan::framework::{
    AppIdentityView, OtherApp, OtherApps, ScanCtx, ScanExt, ScanLimits, Scanner,
};
use purge_source::fixture::Fixture;
use purge_source::system::SystemSource;

pub const SID: &str = GuardEnv::SAMPLE_SID;
pub const BUNDLE: &str = "{B0B0B0B0-1111-2222-3333-444444444444}";
pub const BUNDLE_PROVIDER: &str = "AppBundle";
pub const OTHER_BUNDLE: &str = "{8F55F023-DF9B-4357-8AE7-2C820D0150CA}";
pub const CORE: &str = "{C0C0C0C0-1111-2222-3333-444444444444}";
pub const LAUNCHER: &str = "{73831AC2-F0E1-4173-9FDB-D07463D7EB80}";
pub const VC: &str = "{D0D0D0D0-1111-2222-3333-444444444444}";
pub const VC_PROVIDER: &str = "Microsoft.VS.VC_RuntimeMinimumVSU_amd64,v14";
pub const TRAP: &str = "{E0E0E0E0-1111-2222-3333-444444444444}";
pub const TRAP_PROVIDER: &str = "PurgeTrapPkg";
pub const USER_PART: &str = "{F0F0F0F0-1111-2222-3333-444444444444}";
pub const USER_PROVIDER: &str = "AppBundle_User";
pub const FOREIGN: &str = "{5A5A5A5A-1111-2222-3333-444444444444}";

pub const DEPS: &str = r"HKLM\SOFTWARE\Classes\Installer\Dependencies";
pub const CACHE: &str = r"C:\ProgramData\Package Cache";
pub const USER_CACHE: &str = r"C:\Users\tester\AppData\Local\Package Cache";
pub const UNINSTALL: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

/// `HKU\<sid>_Classes\Installer\Dependencies`, the guard's spelling of the user's dependencies.
pub fn user_deps() -> String {
    format!(r"HKU\{SID}_Classes\Installer\Dependencies")
}

pub fn machine() -> Fixture {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/burn/machine.json");
    Fixture::from_json_file(&path).expect("machine.json loads")
}

pub fn package(provider: &str, product: &str, cache_dir: Option<&str>) -> BurnPackage {
    BurnPackage {
        provider_key: provider.into(),
        product_code: Some(product.into()),
        cache_dir: cache_dir.map(Into::into),
        other_dependents: Vec::new(),
    }
}

/// The bundle as the harvest recorded it, before its uninstall.
pub fn burn_facts() -> BurnFacts {
    BurnFacts {
        bundle_id: BUNDLE.into(),
        provider_key: Some(BUNDLE_PROVIDER.into()),
        cache_path: Some(format!(r"{CACHE}\{BUNDLE}")),
        packages: vec![
            package(
                "AppBundle_Core",
                CORE,
                Some(&format!(r"{CACHE}\{CORE}v1.0.0.0")),
            ),
            package(
                LAUNCHER,
                LAUNCHER,
                Some(&format!(r"{CACHE}\{LAUNCHER}v3.12.7150.0")),
            ),
            package(VC_PROVIDER, VC, Some(&format!(r"{CACHE}\{VC}v14.44.35211"))),
            package(
                TRAP_PROVIDER,
                TRAP,
                Some(&format!(r"{CACHE}\{TRAP_PROVIDER}")),
            ),
            package(
                USER_PROVIDER,
                USER_PART,
                Some(&format!(r"{USER_CACHE}\{USER_PART}v1.0.0.0")),
            ),
        ],
        dependents_at_harvest: Vec::new(),
    }
}

/// The fingerprint of the bundle "App Bundle".
pub fn fingerprint() -> Fingerprint {
    Fingerprint {
        schema: FingerprintSchema,
        app: AppRef {
            program_id: ProgramId::machine(View::K64, BUNDLE).unwrap(),
            display_name: "App Bundle".into(),
        },
        identity: IdentitySnapshot {
            names: vec!["App Bundle".into()],
            vendors: vec!["App Vendor".into()],
            tokens: Vec::new(),
            mega_vendor: false,
        },
        roots: Vec::new(),
        exes: Vec::new(),
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
        burn: Some(burn_facts()),
        sys: Default::default(),
        os: OsInfo {
            edition: "Professional".into(),
            build: 26340,
            ubr: 9882,
        },
        user_sid: SID.into(),
        window: TimeWindow::default(),
        verify_gone: None,
        warnings: Vec::new(),
    }
}

/// The other apps of the fresh inventory: the two products that stay installed.
pub fn other_apps() -> Vec<OtherApp> {
    vec![
        OtherApp {
            name: "Python Launcher".into(),
            keys: vec![format!(r"{UNINSTALL}\{LAUNCHER}")],
            ..OtherApp::default()
        },
        OtherApp {
            name: "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.44.35211".into(),
            keys: vec![format!(r"{UNINSTALL}\{VC}")],
            ..OtherApp::default()
        },
    ]
}

/// Everything a [`ScanCtx`] borrows. The ownership index is read from the fixture when the world is
/// made ([`World::reindex`] after a change), as the pipeline reads it once before the scanners.
pub struct World {
    pub fixture: Fixture,
    pub fp: Fingerprint,
    pub baseline: Baseline,
    pub env: BTreeMap<String, String>,
    pub guard: GuardEnv,
    pub other_apps: OtherApps,
    pub verify_gone: Option<VerifyGone>,
    pub ext: ScanExt,
}

fn index(fixture: &Fixture) -> OwnershipIndex {
    OwnershipIndex::build(&OwnershipInput {
        reg: fixture,
        fs: fixture,
        sys: fixture,
        products: &[],
        msi_only: &[],
        cache: None,
        threads: 1,
    })
}

impl World {
    pub fn new() -> Self {
        let fixture = machine();
        let env = fixture.env().expect("fixture env");
        let ext = ScanExt::new(index(&fixture), SysObjectIndex::default());
        let header = "#purge-baseline 1\tT\tPC\tProfessional\t26340.9882\n";
        Self {
            fixture,
            fp: fingerprint(),
            baseline: Baseline::from_bytes(header.as_bytes()).expect("baseline parses"),
            env,
            guard: GuardEnv::sample(),
            other_apps: OtherApps::new(other_apps()),
            verify_gone: Some(VerifyGone::new(true, true, true)),
            ext,
        }
    }

    /// Reads the ownership index again after the fixture changed.
    pub fn reindex(&mut self) {
        self.ext = ScanExt::new(index(&self.fixture), SysObjectIndex::default());
    }

    /// The bundle as a per-user one of the user `SID` (its ARP entry in that user's hive).
    pub fn per_user(mut self) -> Self {
        self.fp.app.program_id = ProgramId::user(SID, View::K64, BUNDLE).unwrap();
        self
    }

    pub fn burn_mut(&mut self) -> &mut BurnFacts {
        self.fp.burn.as_mut().expect("the fingerprint has a bundle")
    }

    pub fn ctx(&self) -> ScanCtx<'_> {
        ScanCtx {
            reg: &self.fixture,
            fs: &self.fixture,
            sys: &self.fixture,
            fp: &self.fp,
            baseline: Some(&self.baseline),
            mode: ScanMode::Post,
            verify_gone: self.verify_gone,
            env: &self.env,
            guard: &self.guard,
            other_apps: &self.other_apps,
            limits: ScanLimits::default(),
            ext: &self.ext,
        }
    }

    /// `scanner` through the sealing driver.
    pub fn run(&self, scanner: &dyn Scanner) -> Vec<Candidate> {
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
        let out = self.ctx().run(scanner, &app);
        assert!(self.ext.take_faults().is_empty(), "no scanner fault");
        let mut targets: Vec<&Target> = out.iter().map(|c| &c.target).collect();
        targets.dedup();
        assert_eq!(
            targets.len(),
            out.len(),
            "one candidate per target: {out:?}"
        );
        out
    }
}

/// The candidate on `target` (compared ignoring case), if any.
pub fn find<'c>(found: &'c [Candidate], target: &Target) -> Option<&'c Candidate> {
    let fold = |t: &Target| format!("{t:?}").to_lowercase();
    found.iter().find(|c| fold(&c.target) == fold(target))
}

pub fn key(path: impl Into<String>) -> Target {
    Target::RegKey { path: path.into() }
}

pub fn dir(path: impl Into<String>) -> Target {
    Target::Path { path: path.into() }
}

/// The band and preselection the policy gives `c` after a verified uninstall.
pub fn band(c: &Candidate) -> (Band, bool) {
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
