//! The world the REG-DIAG and FS-WER tests run in: a fixture machine with drive `C:`, an app whose
//! InstallRoot `C:\Program Files\App` is gone, another product with a folder of its own, the event logs,
//! the `Tracing` keys and the WER report stores, the shared data the pipeline reads once (the reference
//! walk) and the policy that bands what the scanners return. Built like the COM-SHELLEX world.

use std::collections::BTreeMap;

use purge_guard::canon::GuardEnv;
use purge_index::baseline::Baseline;
use purge_index::ownership::{OwnershipLimits, pack_guid};
use purge_model::{
    Anchors, AppRef, Band, Candidate, EvidenceKind, ExeFile, Fingerprint, FingerprintSchema,
    IdentitySnapshot, InventoryEntry, MsiContext, MsiFacts, MsiRegRow, OsInfo, ProgramId, Root,
    RootKind, RootSource, ScanMode, SourceTrust, Target, Tier, TimeWindow, VerifyGone, View,
};
use purge_policy::band::{PolicyCtx, TargetScope, decide};
use purge_scan::framework::{
    AppIdentityView, OtherApp, OtherApps, ScanCtx, ScanExt, ScanLimits, Scanner,
};
use purge_scan::fs_wer::FsWer;
use purge_scan::reg_diag::RegDiag;
use purge_source::filesystem::FileSystemSource;
use purge_source::fixture::Fixture;
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;
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

/// The app's main exe and its stem.
pub const MAIN_EXE: &str = "AppMain.exe";
pub const MAIN_STEM: &str = "AppMain";

/// The `Tracing` keys.
pub const TRACING: &str = r"HKLM\SOFTWARE\Microsoft\Tracing";
pub const TRACING32: &str = r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Tracing";

/// The event logs, as the scanner spells them, and as the fixture stores them.
pub const EVENTLOG: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\EventLog";
pub const EVENTLOG_SET: &str = r"HKLM\SYSTEM\ControlSet001\Services\EventLog";

/// The WER report stores of the machine and of the user.
pub const PD_ARCHIVE: &str = r"C:\ProgramData\Microsoft\Windows\WER\ReportArchive";
pub const PD_QUEUE: &str = r"C:\ProgramData\Microsoft\Windows\WER\ReportQueue";
pub const PD_TEMP: &str = r"C:\ProgramData\Microsoft\Windows\WER\Temp";
pub const USER_ARCHIVE: &str = r"C:\Users\tester\AppData\Local\Microsoft\Windows\WER\ReportArchive";
pub const USER_QUEUE: &str = r"C:\Users\tester\AppData\Local\Microsoft\Windows\WER\ReportQueue";

/// The app's MSI product.
pub const PRODUCT: &str = "{A1B2C3D4-0000-4000-8000-00000000A001}";

/// A file of the app's (gone) InstallRoot.
pub fn app_file(name: &str) -> String {
    format!(r"{ROOT}\{name}")
}

/// `EventLog\<log>\<source>` as the scanner spells it.
pub fn source_key(log: &str, source: &str) -> String {
    format!(r"{EVENTLOG}\{log}\{source}")
}

/// The app: machine-wide, one admin-only InstallRoot that existed at harvest, its main exe and a
/// `setup.exe`.
pub fn fingerprint() -> Fingerprint {
    Fingerprint {
        baseline_view: None,
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
        exes: vec![
            ExeFile {
                path: app_file(MAIN_EXE),
                main: true,
            },
            ExeFile {
                path: app_file("setup.exe"),
                main: false,
            },
        ],
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

/// The app's MSI product with one whole-key `Registry` row on `key`.
pub fn msi_with_whole_key(key: &str, row: &str) -> MsiFacts {
    MsiFacts {
        product_code: PRODUCT.into(),
        packed_code: pack_guid(PRODUCT).expect("a GUID"),
        upgrade_code: None,
        context: MsiContext::Machine,
        user_sid: None,
        local_package: None,
        package_readable: true,
        components: Vec::new(),
        registry_rows: vec![MsiRegRow {
            key: key.into(),
            name: None,
            whole_key: true,
            component: "Main".into(),
            row: row.into(),
        }],
        services: Vec::new(),
        source_dirs: Vec::new(),
        custom_actions: 0,
        unresolved_rows: 0,
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

/// The machine after the uninstall: drive `C:`, `C:\Program Files` without the app's folder, the other
/// product's folder, Windows' own files, the `Tracing` keys with one Windows program, the three classic
/// logs with Windows' own sources, and empty WER stores.
pub fn machine() -> Fixture {
    let mut fx = Fixture::builder()
        .os(EDITION, BUILD, UBR)
        .user_sid(SID)
        .volume(r"C:\", Some(SERIAL), true, "NTFS")
        .dir(r"C:\Program Files")
        .dir(r"C:\Program Files (x86)")
        .dir(OTHER_ROOT)
        .file(&format!(r"{OTHER_ROOT}\{MAIN_EXE}"), 10)
        .file(r"C:\Windows\System32\wevtapi.dll", 10)
        .file(r"C:\Windows\System32\kernel32.dll", 10)
        .file(
            r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll",
            10,
        )
        .dir(PD_ARCHIVE)
        .dir(PD_QUEUE)
        .dir(PD_TEMP)
        .dir(USER_ARCHIVE)
        .dir(USER_QUEUE)
        .known_folder(KnownFolder::ProgramFiles, r"C:\Program Files")
        .known_folder(KnownFolder::ProgramFilesX86, r"C:\Program Files (x86)")
        .known_folder(KnownFolder::Windows, r"C:\Windows")
        .env("SystemRoot", r"C:\Windows")
        .key(&format!(r"HKU\{SID}\Software"))
        .key(&format!(r"HKU\{SID}_Classes"))
        .key(r"HKLM\SOFTWARE\Classes")
        .build();
    fx.set_current_control_set(1);
    fx.add_key(&format!(r"{TRACING}\svchost_RASAPI32"));
    fx.add_key(&format!(r"{TRACING32}\svchost_RASMANCS"));
    for log in ["Application", "System", "Security"] {
        fx.add_key(&format!(r"{EVENTLOG_SET}\{log}"));
    }
    fx.set_value(
        &format!(r"{EVENTLOG_SET}\Application\Application Error"),
        "EventMessageFile",
        RegData::from_expand_sz(r"%SystemRoot%\System32\wevtapi.dll"),
    );
    fx
}

/// Adds the event source `log\source` with `EventMessageFile` = `files` (`REG_EXPAND_SZ`).
pub fn event_source(fx: &mut Fixture, log: &str, source: &str, files: &str) {
    let key = format!(r"{EVENTLOG_SET}\{log}\{source}");
    fx.set_value(&key, "EventMessageFile", RegData::from_expand_sz(files));
    fx.set_value(&key, "TypesSupported", RegData::from_dword(7));
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
    /// A world over `fixture` with the app's fingerprint and an empty baseline of this Windows; the
    /// shared data is read by [`World::ready`].
    pub fn new(fixture: Fixture) -> Self {
        let env = fixture.env().unwrap_or_default();
        Self {
            fixture,
            fp: fingerprint(),
            baseline: Some(baseline(&[])),
            env,
            guard: GuardEnv::sample(),
            other_apps: OtherApps::new(vec![OtherApp {
                name: OTHER.into(),
                roots: vec![OTHER_ROOT.into()],
                ..OtherApp::default()
            }]),
            ext: ScanExt::new(Default::default(), Default::default()),
        }
    }

    /// Reads the shared data as the pipeline does: the one reference walk and the indexes.
    pub fn ready(mut self) -> Self {
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
        let inventory: &[InventoryEntry] = &[];
        self.ext = ScanExt::build(
            &self.fixture,
            &self.fixture,
            &self.fixture,
            &self.fp,
            &app,
            inventory,
            &[],
            None,
            OwnershipLimits::default(),
        );
        self
    }

    /// The context, reading through `reg` and `fs`.
    pub fn ctx_with<'a>(
        &'a self,
        reg: &'a dyn RegistrySource,
        fs: &'a dyn FileSystemSource,
    ) -> ScanCtx<'a> {
        ScanCtx {
            reg,
            fs,
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
        self.ctx_with(&self.fixture, &self.fixture)
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

    /// What REG-DIAG returns, sealed.
    pub fn diag(&self) -> Vec<Candidate> {
        self.run(&RegDiag)
    }

    /// What FS-WER returns, sealed.
    pub fn wer(&self) -> Vec<Candidate> {
        self.run(&FsWer)
    }
}

/// The band the policy gives `c` after a passed verify-gone, for a machine-wide target.
pub fn band(c: &Candidate) -> Band {
    decide(
        c,
        &PolicyCtx {
            baseline_trust: purge_model::BaselineTrust::Exact,
            mode: ScanMode::Post,
            verify_gone: VerifyGone::new(true, true, true),
            target_scope: TargetScope::Machine,
        },
    )
    .band
}

/// Where a candidate is: the key or the path.
pub fn spot(c: &Candidate) -> String {
    match &c.target {
        Target::RegKey { path } | Target::Path { path } => path.clone(),
        other => panic!("not a key or path: {other:?}"),
    }
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

/// The spots of all candidates.
pub fn spots(found: &[Candidate]) -> Vec<String> {
    found.iter().map(spot).collect()
}

/// Whether `c` carries evidence of `kind` at `tier`.
pub fn has(c: &Candidate, kind: EvidenceKind, tier: Tier) -> bool {
    c.evidence.iter().any(|e| e.kind == kind && e.tier == tier)
}

/// Whether any positive evidence of `c` is Tier A.
pub fn any_tier_a(c: &Candidate) -> bool {
    c.evidence.iter().any(|e| e.weight > 0 && e.tier == Tier::A)
}
