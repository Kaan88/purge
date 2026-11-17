//! The world the REG-PRIVACY tests run in: a fixture machine with drive `C:`, an app whose InstallRoot
//! `C:\Program Files\App` is gone, another installed product in `C:\Program Files\Other`, the shared
//! data the pipeline reads once, and the policy that bands what the scanner returns. Built like the
//! COM-SHELLEX world (`tests/shellex/world.rs`).

use std::collections::BTreeMap;

use purge_guard::canon::GuardEnv;
use purge_index::baseline::Baseline;
use purge_index::ownership::{MACHINE_SID, OwnershipLimits, USERDATA};
use purge_model::{
    Anchors, AppRef, Band, Candidate, Category, EvidenceKind, ExeFile, Fingerprint,
    FingerprintSchema, IdentitySnapshot, OsInfo, ProgramId, Root, RootKind, RootSource, ScanMode,
    SourceTrust, Target, Tier, TimeWindow, VerifyGone, View,
};
use purge_policy::band::{PolicyCtx, TargetScope, decide};
use purge_scan::framework::{
    AppIdentityView, OtherApp, OtherApps, ScanCtx, ScanExt, ScanLimits, Scanner,
};
use purge_scan::reg_privacy::RegPrivacy;
use purge_source::fixture::Fixture;
use purge_source::registry::RegistrySource;
use purge_source::types::{KnownFolder, RegData};

/// The interactive user (the fingerprint's user).
pub const SID: &str = GuardEnv::SAMPLE_SID;
/// A second user whose hive is loaded.
pub const SID2: &str = "S-1-5-21-1-2-3-1002";
pub const EDITION: &str = "Professional";
pub const BUILD: u32 = 26340;
pub const UBR: u32 = 9882;
pub const SERIAL: u32 = 0x1234_5678;

/// The app's InstallRoot, gone after the uninstall.
pub const ROOT: &str = r"C:\Program Files\App";
/// Another installed product's folder, present.
pub const OTHER_ROOT: &str = r"C:\Program Files\Other";
/// The other product's name.
pub const OTHER: &str = "Other Product";

/// `FOLDERID_ProgramFilesX64`.
pub const PF_X64: &str = "{6D809377-6AF0-444B-8957-A3773F02200E}";
/// `FOLDERID_LocalAppData`.
pub const LOCAL_APPDATA: &str = "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}";
/// The UserAssist GUID Windows files executables under.
pub const UA_EXE: &str = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}";
/// The UserAssist GUID Windows files shortcuts under.
pub const UA_LNK: &str = "{F4E57C4B-2036-45F0-A9AB-1BAAB5C3A2EE}";

/// The machine's `AppCompatFlags\Layers`.
pub const HKLM_LAYERS: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers";

/// A file of the app's (gone) InstallRoot.
pub fn app_file(rel: &str) -> String {
    format!(r"{ROOT}\{rel}")
}

/// The app's main program.
pub fn app_exe() -> String {
    app_file("app.exe")
}

/// A file of the other product.
pub fn other_file(rel: &str) -> String {
    format!(r"{OTHER_ROOT}\{rel}")
}

fn user(sid: &str) -> String {
    format!(r"HKU\{sid}")
}

/// `...\AppCompatFlags\Layers` of `sid`.
pub fn layers(sid: &str) -> String {
    format!(
        r"{}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers",
        user(sid)
    )
}

/// `...\Compatibility Assistant\Store` of `sid`.
pub fn pca_store(sid: &str) -> String {
    format!(
        r"{}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store",
        user(sid)
    )
}

/// `...\Compatibility Assistant\Persisted` of `sid`.
pub fn pca_persisted(sid: &str) -> String {
    format!(
        r"{}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted",
        user(sid)
    )
}

/// `MuiCache` of `sid`, spelled through the Classes hive (`HKU\<sid>_Classes`).
pub fn muicache(sid: &str) -> String {
    format!(
        r"{}_Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
        user(sid)
    )
}

/// `MuiCache` of `sid`, spelled through `HKU\<sid>\Software\Classes`.
pub fn muicache_alias(sid: &str) -> String {
    format!(
        r"{}\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
        user(sid)
    )
}

/// `UserAssist\<guid>\Count` of `sid`.
pub fn user_assist(sid: &str, guid: &str) -> String {
    format!(
        r"{}\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{guid}\Count",
        user(sid)
    )
}

/// `FeatureUsage\<store>` of `sid`.
pub fn feature_usage(sid: &str, store: &str) -> String {
    format!(
        r"{}\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\{store}",
        user(sid)
    )
}

/// `UFH\SHC` of `sid`.
pub fn shc(sid: &str) -> String {
    format!(
        r"{}\Software\Microsoft\Windows\CurrentVersion\UFH\SHC",
        user(sid)
    )
}

/// ROT13 of the ASCII letters (how UserAssist spells its names).
pub fn rot13(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='z' => char::from((c as u8 - b'a' + 13) % 26 + b'a'),
            'A'..='Z' => char::from((c as u8 - b'A' + 13) % 26 + b'A'),
            _ => c,
        })
        .collect()
}

/// The UserAssist data of one entry: 72 bytes of counters, as Windows writes them.
pub fn ua_counters() -> RegData {
    let mut bytes = vec![0u8; 72];
    bytes[4] = 3;
    RegData::from_binary(bytes)
}

/// PCA data: a `SACP` header, as the Compatibility Assistant writes it.
pub fn pca_blob() -> RegData {
    let mut bytes = vec![0x53, 0x41, 0x43, 0x50, 0x01, 0, 0, 0];
    bytes.extend([0u8; 16]);
    RegData::from_binary(bytes)
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
        exes: vec![
            ExeFile {
                path: app_exe(),
                main: true,
            },
            ExeFile {
                path: app_file(r"bin\helper.exe"),
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

/// An empty baseline of this Windows.
pub fn baseline() -> Baseline {
    let text = format!("#purge-baseline 1\tT\tPC\t{EDITION}\t{BUILD}.{UBR}\n");
    Baseline::from_bytes(text.as_bytes()).expect("the baseline parses")
}

/// The machine after the uninstall: drive `C:`, `C:\Program Files` without the app's folder, the other
/// product's folder with its program, the user's hives (Software and Classes) and the known folders.
pub fn machine() -> Fixture {
    let mut fx = Fixture::builder()
        .os(EDITION, BUILD, UBR)
        .user_sid(SID)
        .volume(r"C:\", Some(SERIAL), true, "NTFS")
        .dir(r"C:\Program Files")
        .dir(OTHER_ROOT)
        .file(&other_file("app.exe"), 10)
        .file(&other_file("other.exe"), 10)
        .dir(r"C:\Windows\System32")
        .file(r"C:\Windows\System32\cmd.exe", 10)
        .known_folder(KnownFolder::ProgramFiles, r"C:\Program Files")
        .known_folder(KnownFolder::ProgramFilesX86, r"C:\Program Files (x86)")
        .known_folder(KnownFolder::Windows, r"C:\Windows")
        .known_folder(KnownFolder::System, r"C:\Windows\System32")
        .known_folder(KnownFolder::LocalAppData, r"C:\Users\tester\AppData\Local")
        .key(&format!(r"HKU\{SID}\Software"))
        .key(&format!(r"HKU\{SID}_Classes"))
        .key(r"HKLM\SOFTWARE\Classes")
        .build();
    fx.set_current_control_set(1);
    fx.add_key(&format!(r"{USERDATA}\{MACHINE_SID}\Components"));
    fx.set_msi_tables_captured(true);
    fx
}

/// Writes a string value.
pub fn sz(fx: &mut Fixture, key: &str, name: &str, data: &str) {
    fx.set_value(key, name, RegData::from_sz(data));
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
    /// A world over `fixture` with the app's fingerprint, an empty baseline of this Windows and the
    /// shared data read as the pipeline reads it (empty inventory).
    pub fn new(fixture: Fixture) -> Self {
        let mut env = BTreeMap::new();
        env.insert(
            "LOCALAPPDATA".to_owned(),
            r"C:\Users\tester\AppData\Local".to_owned(),
        );
        Self {
            fixture,
            fp: fingerprint(),
            baseline: Some(baseline()),
            env,
            guard: GuardEnv::sample(),
            other_apps: OtherApps::new(vec![OtherApp {
                name: OTHER.into(),
                roots: vec![OTHER_ROOT.into()],
                ..OtherApp::default()
            }]),
            ext: ScanExt::new(Default::default(), Default::default()),
        }
        .ready()
    }

    /// Reads the shared data as the pipeline does: the one reference walk and the ownership index.
    pub fn ready(mut self) -> Self {
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
        self.ext = ScanExt::build(
            &self.fixture,
            &self.fixture,
            &self.fixture,
            &self.fp,
            &app,
            &[],
            &[],
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

    /// What REG-PRIVACY returns through the sealing driver, as the pipeline runs it.
    pub fn privacy(&self) -> Vec<Candidate> {
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
        let found = self.ctx().run(&RegPrivacy, &app);
        for c in &found {
            assert_eq!(c.scanner, RegPrivacy.id());
            assert!(c.decision.is_none(), "scanners never decide a band");
            assert!(
                matches!(c.target, Target::RegValue { .. }),
                "only single values are offered: {:?}",
                c.target
            );
            assert_eq!(c.action, purge_model::Action::DeleteValue);
        }
        found
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

/// `key|name` of a value candidate.
pub fn spot(c: &Candidate) -> String {
    match &c.target {
        Target::RegValue { path, name } => value_spot(path, name),
        other => panic!("not a value: {other:?}"),
    }
}

/// The spot of value `name` of `key`.
pub fn value_spot(key: &str, name: &str) -> String {
    format!("{key}|{name}")
}

/// The candidate at `spot`, if any (compared ignoring case).
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

/// Asserts that nothing at all was offered.
pub fn assert_none(found: &[Candidate]) {
    let spots: Vec<String> = found.iter().map(spot).collect();
    assert!(
        spots.is_empty(),
        "nothing must be offered; found {spots:#?}"
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

/// Asserts that `c` is a privacy trace of a gone file: both path-store facts at Tier A, Safe.
pub fn assert_safe_trace(c: &Candidate) {
    assert_eq!(c.category, Category::Privacy, "{}", spot(c));
    assert!(
        has(c, EvidenceKind::PointsIntoInstallRoot, Tier::A),
        "{c:#?}"
    );
    assert!(has(c, EvidenceKind::DanglingRef, Tier::A), "{c:#?}");
    assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    assert_eq!(band(c), Band::Safe, "{c:#?}");
}
