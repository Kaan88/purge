//! Shared fixtures: a world a [`ScanCtx`] can borrow from, fingerprints, baselines and the renderer the
//! goldens are written in.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::OnceLock;

use purge_guard::canon::GuardEnv;
use purge_index::baseline::Baseline;
use purge_model::{
    AnchorKind, AnchorRef, Anchors, AppRef, Blocker, Candidate, Evidence, EvidenceKind, ExeFile,
    Fingerprint, FingerprintSchema, IdentitySnapshot, InnoRecord, InnoRecordKind, OsInfo,
    ProgramId, RefCarrier, RefSnapEntry, Root, RootKind, RootSource, ScanMode, SourceTrust, Target,
    TimeWindow, VerifyGone, View,
};
use purge_scan::framework::{
    AppIdentityView, OtherApp, OtherApps, ScanCtx, ScanExt, ScanLimits, Scanner,
};
use purge_source::fixture::{Fixture, FixtureBuilder};

/// The interactive user of every fixture.
pub const SID: &str = GuardEnv::SAMPLE_SID;
/// The Windows of the synthetic baseline.
pub const EDITION: &str = "Professional";
pub const BUILD: u32 = 26340;
pub const UBR: u32 = 9882;
/// The serial of drive `C:` at harvest and now.
pub const SERIAL: u32 = 0x1234_5678;

pub const HKLM_CLASSES: &str = r"HKLM\SOFTWARE\Classes";

/// The user's physical Classes root.
pub fn user_classes() -> String {
    format!(r"HKU\{SID}_Classes")
}

/// Everything a [`ScanCtx`] borrows, owned in one place.
pub struct World {
    pub fixture: Fixture,
    pub fp: Fingerprint,
    pub baseline: Option<Baseline>,
    pub env: BTreeMap<String, String>,
    pub guard: GuardEnv,
    pub other_apps: OtherApps,
}

impl World {
    /// A world over `fixture` for the app of `fp`, with an empty baseline of the fixture's Windows.
    pub fn new(fixture: Fixture, fp: Fingerprint) -> Self {
        Self {
            fixture,
            fp,
            baseline: Some(baseline(&[])),
            env: BTreeMap::new(),
            guard: GuardEnv::sample(),
            other_apps: OtherApps::default(),
        }
    }

    pub fn ctx(&self) -> ScanCtx<'_> {
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
            ext: ScanExt::none(),
        }
    }

    /// Runs one scanner.
    pub fn run(&self, scanner: &dyn Scanner) -> Vec<Candidate> {
        let ctx = self.ctx();
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
        let candidates = scanner.scan(&ctx, &app);
        for c in &candidates {
            assert_eq!(c.scanner, scanner.id());
            assert!(c.decision.is_none(), "scanners never decide a band");
        }
        candidates
    }

    /// Runs one scanner and renders its candidates.
    pub fn golden(&self, scanner: &dyn Scanner) -> Vec<String> {
        render(&self.run(scanner))
    }
}

/// A fixture builder with the synthetic Windows, drive `C:` and the Program Files directory.
pub fn machine() -> FixtureBuilder {
    Fixture::builder()
        .os(EDITION, BUILD, UBR)
        .user_sid(SID)
        .volume(r"C:\", Some(SERIAL), true, "NTFS")
        .dir(r"C:\Program Files")
        .key(HKLM_CLASSES)
}

/// A baseline of the synthetic Windows holding `keys`.
pub fn baseline(keys: &[&str]) -> Baseline {
    baseline_for(EDITION, keys)
}

/// A baseline of `edition` (same build) holding `keys`.
pub fn baseline_for(edition: &str, keys: &[&str]) -> Baseline {
    let mut text = format!("#purge-baseline 1\tT\tPC\t{edition}\t{BUILD}.{UBR}\n");
    for key in keys {
        text.push_str(&format!("K\t{}\t0\t0\t0\n", key.replace('\\', "\\\\")));
    }
    Baseline::from_bytes(text.as_bytes()).expect("the baseline parses")
}

/// The committed clean-Windows baseline of the LTSC corpus VM (`EnterpriseSEval` 26100.1742).
pub fn ltsc_baseline() -> Baseline {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    let bytes = BYTES.get_or_init(|| {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../kb/baselines/EnterpriseSEval-26100.1742.tsv.gz");
        std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    });
    Baseline::from_bytes(bytes).expect("the LTSC baseline parses")
}

pub const LTSC_EDITION: &str = "EnterpriseSEval";
pub const LTSC_BUILD: u32 = 26100;
pub const LTSC_UBR: u32 = 1742;

/// A machine-wide app with one admin-only InstallRoot at `root`, harvested on the synthetic Windows.
pub fn machine_fp(key_name: &str, display_name: &str, root: &str) -> Fingerprint {
    fingerprint(
        ProgramId::machine(View::K64, key_name).unwrap(),
        display_name,
        root,
        SourceTrust::AdminOnly,
    )
}

/// A per-user app of [`SID`] with one user-writable InstallRoot at `root`.
pub fn user_fp(key_name: &str, display_name: &str, root: &str) -> Fingerprint {
    fingerprint(
        ProgramId::user(SID, View::K64, key_name).unwrap(),
        display_name,
        root,
        SourceTrust::UserWritable,
    )
}

fn fingerprint(
    program_id: ProgramId,
    display_name: &str,
    root: &str,
    trust: SourceTrust,
) -> Fingerprint {
    Fingerprint {
        schema: FingerprintSchema,
        app: AppRef {
            program_id,
            display_name: display_name.into(),
        },
        identity: IdentitySnapshot {
            names: vec![display_name.into()],
            vendors: Vec::new(),
            tokens: Vec::new(),
            mega_vendor: false,
        },
        roots: vec![Root {
            path: root.into(),
            kind: RootKind::InstallRoot,
            source: RootSource::ArpInstallLocation,
            trust,
            volume_serial: Some(SERIAL),
            parent_existed: true,
        }],
        exes: Vec::new(),
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

/// A main exe of the exe set.
pub fn exe(path: &str) -> ExeFile {
    ExeFile {
        path: path.into(),
        main: true,
    }
}

/// An Inno record that deletes (and so created) the whole key.
pub fn inno_key(key: &str) -> InnoRecord {
    InnoRecord {
        kind: InnoRecordKind::RegDeleteEntireKey,
        target: Target::RegKey { path: key.into() },
        view: Some(View::K64),
        user_hive: false,
        existed_before: false,
        shared: false,
        key_create: true,
    }
}

/// A reference-snapshot entry for a value whose name is one of the app's ProgIDs.
pub fn snap_progid_value(key: &str, progid: &str) -> RefSnapEntry {
    RefSnapEntry {
        target: Target::RegValue {
            path: key.into(),
            name: progid.into(),
        },
        carrier: RefCarrier::ValueName,
        anchor: AnchorRef {
            kind: AnchorKind::ProgId,
            text: progid.into(),
        },
        parent_values: 1,
        parent_subkeys: 0,
        data_hash: None,
    }
}

/// A reference-snapshot entry for a value whose data pointed at `anchor` (a root or an exe path).
pub fn snap_data_value(key: &str, name: &str, kind: AnchorKind, anchor: &str) -> RefSnapEntry {
    RefSnapEntry {
        target: Target::RegValue {
            path: key.into(),
            name: name.into(),
        },
        carrier: RefCarrier::Data,
        anchor: AnchorRef {
            kind,
            text: anchor.into(),
        },
        parent_values: 1,
        parent_subkeys: 0,
        data_hash: None,
    }
}

/// Another installed app with one root and some ProgID / AUMID anchors.
pub fn other_app(name: &str, root: &str, anchors: &[(AnchorKind, &str)]) -> OtherApp {
    OtherApp {
        name: name.into(),
        roots: vec![root.into()],
        files: Vec::new(),
        keys: Vec::new(),
        anchors: anchors
            .iter()
            .map(|(kind, text)| AnchorRef {
                kind: *kind,
                text: (*text).into(),
            })
            .collect(),
    }
}

// ---- rendering ------------------------------------------------------------------------------------------

fn kind_name(kind: EvidenceKind) -> String {
    match kind {
        EvidenceKind::InstallerManifest(_) => "InstallerManifest".into(),
        other => format!("{other:?}"),
    }
}

fn evidence(e: &Evidence) -> String {
    format!("{}/{:?}/{:?}", kind_name(e.kind), e.tier, e.scope)
}

fn blocker(b: &Blocker) -> String {
    match b {
        Blocker::ReferencedByOtherApp { app } => format!("ReferencedByOtherApp({app})"),
        Blocker::InsideOtherApp { app } => format!("InsideOtherApp({app})"),
        Blocker::ContainsOtherApp { app } => format!("ContainsOtherApp({app})"),
        other => format!("{other:?}"),
    }
}

/// The target as `key <path>` or `value <path>|<name>`.
pub fn target(c: &Candidate) -> String {
    match &c.target {
        Target::RegKey { path } => format!("key {path}"),
        Target::RegValue { path, name } => format!("value {path}|{name}"),
        other => format!("{other:?}"),
    }
}

/// One line per candidate, sorted: `<target> <action> [evidence kind/tier/scope, …]` and, when there are
/// any, ` !<blocker>` per blocker.
pub fn render(candidates: &[Candidate]) -> Vec<String> {
    let mut lines: Vec<String> = candidates
        .iter()
        .map(|c| {
            let mut ev: Vec<String> = c.evidence.iter().map(evidence).collect();
            ev.sort();
            let mut line = format!("{} {:?} [{}]", target(c), c.action, ev.join(", "));
            for b in &c.blockers {
                line.push_str(" !");
                line.push_str(&blocker(b));
            }
            line
        })
        .collect();
    lines.sort();
    lines
}

/// The candidate on the key `key`, if one was produced.
pub fn on_key<'c>(candidates: &'c [Candidate], key: &str) -> Option<&'c Candidate> {
    candidates
        .iter()
        .find(|c| matches!(&c.target, Target::RegKey { path } if path.eq_ignore_ascii_case(key)))
}

/// Asserts the rendered candidates equal `expected` (given in any order).
#[track_caller]
pub fn assert_golden(actual: Vec<String>, expected: &[&str]) {
    let mut expected: Vec<String> = expected.iter().map(|s| (*s).to_owned()).collect();
    expected.sort();
    assert_eq!(
        actual,
        expected,
        "\nactual:\n{}\n",
        actual
            .iter()
            .map(|l| format!("  {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
