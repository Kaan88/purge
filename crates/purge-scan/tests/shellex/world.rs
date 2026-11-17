//! The world the COM-SHELLEX tests run in: a fixture machine with drive `C:`, an app whose InstallRoot
//! `C:\Program Files\App` is gone, the shared data the pipeline reads once (the reference walk, the MSI
//! ownership index), and the policy that bands what the scanner returns. Built like the COM scanners'
//! world (`tests/com/world.rs`).

use std::collections::BTreeMap;

use purge_guard::canon::GuardEnv;
use purge_index::baseline::Baseline;
use purge_index::ownership::{MACHINE_SID, OwnershipLimits, USERDATA};
use purge_model::{
    Anchors, AppRef, Band, Candidate, EvidenceKind, ExeFile, Fingerprint, FingerprintSchema,
    IdentitySnapshot, InventoryEntry, OsInfo, ProgramId, Root, RootKind, RootSource, ScanMode,
    SourceTrust, Target, Tier, TimeWindow, VerifyGone, View,
};
use purge_policy::band::{PolicyCtx, TargetScope, decide};
use purge_scan::com_shellex::ComShellex;
use purge_scan::framework::{
    AppIdentityView, OtherApp, OtherApps, ScanCtx, ScanExt, ScanLimits, Scanner,
};
use purge_source::fixture::Fixture;
use purge_source::registry::RegistrySource;
use purge_source::types::{KnownFolder, RegData};

pub const SID: &str = GuardEnv::SAMPLE_SID;
pub const EDITION: &str = "Professional";
pub const BUILD: u32 = 26340;
pub const UBR: u32 = 9882;
pub const SERIAL: u32 = 0x1234_5678;

/// The app's InstallRoot, gone after the uninstall.
pub const ROOT: &str = r"C:\Program Files\App";
/// Another product's folder, present.
pub const OTHER_ROOT: &str = r"C:\Program Files\Other";
/// The other product's name.
pub const OTHER: &str = "Other Product";

pub const HKLM_CLASSES: &str = r"HKLM\SOFTWARE\Classes";
pub const HKLM_CLASSES32: &str = r"HKLM\SOFTWARE\Classes\WOW6432Node";

/// The app's classes.
pub const CLS_A: &str = "{A0A0A0A0-0000-4000-8000-0000000000A1}";
pub const CLS_B: &str = "{B0B0B0B0-0000-4000-8000-0000000000B1}";
/// A class of another product.
pub const FOREIGN: &str = "{F0F0F0F0-0000-4000-8000-0000000000F1}";
/// The interface id the shell keys thumbnail handlers by.
pub const IID_THUMB: &str = "{E357FCCD-A995-4576-B01F-234630154E96}";

/// `...\Microsoft\Windows\CurrentVersion` of the machine, 64-bit.
pub const CV: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion";
/// The same, 32-bit.
pub const CV32: &str = r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion";

/// The user's classes.
pub fn user_classes() -> String {
    format!(r"HKU\{SID}_Classes")
}

/// The user's `...\Microsoft\Windows\CurrentVersion`.
pub fn user_cv() -> String {
    format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion")
}

/// `<root>\CLSID\{id}`.
pub fn clsid_key(root: &str, id: &str) -> String {
    format!(r"{root}\CLSID\{id}")
}

/// `<root>\<object>\shellex\<list>\<name>`.
pub fn handler_key(root: &str, object: &str, list: &str, name: &str) -> String {
    format!(r"{root}\{object}\shellex\{list}\{name}")
}

/// `<cv>\Shell Extensions\Approved`.
pub fn approved(cv: &str) -> String {
    format!(r"{cv}\Shell Extensions\Approved")
}

/// A file of the app's (gone) InstallRoot.
pub fn app_file(name: &str) -> String {
    format!(r"{ROOT}\{name}")
}

/// The app: machine-wide, one admin-only InstallRoot that existed at harvest.
pub fn fingerprint() -> Fingerprint {
    Fingerprint {
        schema: FingerprintSchema,
        app: AppRef {
            program_id: ProgramId::machine(View::K64, "App").unwrap(),
            display_name: "App".into(),
        },
        identity: IdentitySnapshot {
            names: vec!["App".into()],
            vendors: vec!["Vendor".into()],
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
            path: app_file("app.exe"),
            main: true,
        }],
        outside_root_files: Vec::new(),
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
            edition: EDITION.into(),
            build: BUILD,
            ubr: UBR,
        },
        user_sid: SID.into(),
        window: TimeWindow::default(),
        verify_gone: None,
        warnings: Vec::new(),
    }
}

/// A baseline of this Windows holding `keys`.
pub fn baseline(keys: &[&str]) -> Baseline {
    let mut text = format!("#purge-baseline 1\tT\tPC\t{EDITION}\t{BUILD}.{UBR}\n");
    for key in keys {
        text.push_str(&format!("K\t{}\t0\t0\t0\n", key.replace('\\', "\\\\")));
    }
    Baseline::from_bytes(text.as_bytes()).expect("the baseline parses")
}

/// The machine after the uninstall: drive `C:`, `C:\Program Files` without the app's folder, the
/// other product's folder, Windows' own files, the Classes roots of the machine and the user.
pub fn machine() -> Fixture {
    let mut fx = Fixture::builder()
        .os(EDITION, BUILD, UBR)
        .user_sid(SID)
        .volume(r"C:\", Some(SERIAL), true, "NTFS")
        .dir(r"C:\Program Files")
        .dir(r"C:\Program Files (x86)")
        .dir(OTHER_ROOT)
        .file(&format!(r"{OTHER_ROOT}\other.dll"), 10)
        .dir(r"C:\Windows\System32")
        .file(r"C:\Windows\System32\rundll32.exe", 10)
        .file(r"C:\Windows\System32\oleaut32.dll", 10)
        .known_folder(KnownFolder::ProgramFiles, r"C:\Program Files")
        .known_folder(KnownFolder::ProgramFilesX86, r"C:\Program Files (x86)")
        .known_folder(KnownFolder::Windows, r"C:\Windows")
        .key(&format!(r"HKU\{SID}\Software"))
        .key(&user_classes())
        .key(HKLM_CLASSES)
        .build();
    fx.set_current_control_set(1);
    fx.add_key(&format!(r"{USERDATA}\{MACHINE_SID}\Components"));
    fx.set_msi_tables_captured(true);
    fx
}

/// Writes a default string value.
pub fn sz(fx: &mut Fixture, key: &str, data: &str) {
    fx.set_value(key, "", RegData::from_sz(data));
}

/// Registers class `id` in `root` with `server` (`InprocServer32`, `LocalServer32`...) = `data`.
pub fn class(fx: &mut Fixture, root: &str, id: &str, server: &str, data: &str) {
    sz(fx, &clsid_key(root, id), "a class");
    sz(fx, &format!(r"{}\{server}", clsid_key(root, id)), data);
}

/// Everything a [`ScanCtx`] borrows.
pub struct World {
    pub fixture: Fixture,
    pub fp: Fingerprint,
    pub baseline: Option<Baseline>,
    pub env: BTreeMap<String, String>,
    pub guard: GuardEnv,
    pub other_apps: OtherApps,
    pub ext: ScanExt,
}

impl World {
    /// A world over `fixture` with the app's fingerprint and an empty baseline of this Windows. The
    /// shared data is read by [`World::ready`].
    pub fn new(fixture: Fixture) -> Self {
        Self {
            fixture,
            fp: fingerprint(),
            baseline: Some(baseline(&[])),
            env: BTreeMap::new(),
            guard: GuardEnv::sample(),
            other_apps: OtherApps::new(vec![OtherApp {
                name: OTHER.into(),
                roots: vec![OTHER_ROOT.into()],
                ..OtherApp::default()
            }]),
            ext: ScanExt::new(Default::default(), Default::default()),
        }
    }

    /// Reads the shared data as the pipeline does: the one reference walk and the ownership index over
    /// `inventory`.
    pub fn ready(mut self, inventory: &[InventoryEntry]) -> Self {
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
        self.ext = ScanExt::build(
            &self.fixture,
            &self.fixture,
            &self.fixture,
            &self.fp,
            &app,
            inventory,
            None,
            OwnershipLimits::default(),
        );
        self
    }

    /// The context, reading the registry through `reg`.
    pub fn ctx_with<'a>(&'a self, reg: &'a dyn RegistrySource) -> ScanCtx<'a> {
        ScanCtx {
            reg,
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

    pub fn ctx(&self) -> ScanCtx<'_> {
        self.ctx_with(&self.fixture)
    }

    /// Runs `scanner` through the sealing driver, as the pipeline does.
    pub fn run(&self, scanner: &dyn Scanner) -> Vec<Candidate> {
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
        let found = self.ctx().run(scanner, &app);
        for c in &found {
            assert_eq!(c.scanner, scanner.id());
            assert!(c.decision.is_none(), "scanners never decide a band");
        }
        found
    }

    /// What COM-SHELLEX returns, sealed.
    pub fn shellex(&self) -> Vec<Candidate> {
        self.run(&ComShellex)
    }
}

/// The band the policy gives `c` after a passed verify-gone.
pub fn band(c: &Candidate) -> Band {
    decide(
        c,
        &PolicyCtx {
            mode: ScanMode::Post,
            verify_gone: VerifyGone::new(true, true, true),
            target_scope: TargetScope::PerUser,
        },
    )
    .band
}

/// Where a candidate is: the key of a key candidate, `key|name` for a value.
pub fn spot(c: &Candidate) -> String {
    match &c.target {
        Target::RegKey { path } => path.clone(),
        Target::RegValue { path, name } => value_spot(path, name),
        other => panic!("not a key or value: {other:?}"),
    }
}

/// The spot of value `name` of `key`.
pub fn value_spot(key: &str, name: &str) -> String {
    format!("{key}|{name}")
}

/// The candidate at `spot` ([`spot`]), if any (compared ignoring case).
pub fn find<'c>(found: &'c [Candidate], at: &str) -> Option<&'c Candidate> {
    found.iter().find(|c| spot(c).eq_ignore_ascii_case(at))
}

/// The candidate at `spot`; panics with the list when there is none.
pub fn get<'c>(found: &'c [Candidate], at: &str) -> &'c Candidate {
    find(found, at).unwrap_or_else(|| {
        let spots: Vec<String> = found.iter().map(spot).collect();
        panic!("no candidate at {at}; found {spots:#?}")
    })
}

/// A world over `fx` whose app owns `CLS_A` and `CLS_B`.
pub fn app_world(fx: Fixture) -> World {
    let mut world = World::new(fx);
    world.fp.anchors.clsids = vec![CLS_A.into(), CLS_B.into()];
    world
}

/// Registers `CLS_A` in the machine's 64-bit Classes, served from the app's (gone) `a.dll`.
pub fn dangling_class(fx: &mut Fixture) {
    class(
        fx,
        HKLM_CLASSES,
        CLS_A,
        "InprocServer32",
        &app_file("a.dll"),
    );
}

/// Whether `c` carries evidence of `kind` at `tier`.
pub fn has(c: &Candidate, kind: EvidenceKind, tier: Tier) -> bool {
    c.evidence.iter().any(|e| e.kind == kind && e.tier == tier)
}

/// Whether `c` carries evidence of `kind` at any tier.
pub fn has_kind(c: &Candidate, kind: EvidenceKind) -> bool {
    c.evidence.iter().any(|e| e.kind == kind)
}
