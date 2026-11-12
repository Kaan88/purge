//! The world the association tests scan: a VS Code-shaped system install after its uninstaller ran.

use std::collections::BTreeMap;

use purge_guard::canon::GuardEnv;
use purge_index::baseline::Baseline;
use purge_model::{
    AnchorKind, AnchorRef, Anchors, AppRef, Candidate, ExeFile, ExtJournalEntry, Fingerprint,
    FingerprintSchema, IdentitySnapshot, OsInfo, ProgramId, RefCarrier, RefSnapEntry, Root,
    RootKind, RootSource, ScanMode, SourceTrust, Target, TimeWindow, VerifyGone, View,
};
use purge_scan::framework::{AppIdentityView, OtherApps, ScanCtx, ScanLimits, Scanner};
use purge_source::fixture::Fixture;

/// The edition of the LTSC rig image.
pub const EDITION: &str = "EnterpriseSEval";
/// Its build.
pub const BUILD: u32 = 26100;
/// Its update build revision.
pub const UBR: u32 = 1742;

/// The interactive user.
pub const SID: &str = GuardEnv::SAMPLE_SID;
/// The machine's Classes root.
pub const CLASSES: &str = r"HKLM\SOFTWARE\Classes";
/// The install root.
pub const CODE_ROOT: &str = r"C:\Program Files\Microsoft VS Code";

/// `<CLASSES>\<rest>`.
pub fn classes(rest: &str) -> String {
    format!(r"{CLASSES}\{rest}")
}

/// The user's `FileExts\<ext>` key.
pub fn file_exts(ext: &str) -> String {
    format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\{ext}")
}

/// The user's `ApplicationAssociationToasts` key.
pub fn user_toasts() -> String {
    format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\ApplicationAssociationToasts")
}

/// A fingerprint of a machine-wide VS Code with the given ProgID set and no journal.
pub fn fingerprint(progids: &[&str]) -> Fingerprint {
    Fingerprint {
        schema: FingerprintSchema,
        app: AppRef {
            program_id: ProgramId::machine(View::K64, "{EA457B21-F73E-494C-ACAB-524FDE069978}_is1")
                .expect("a valid program id"),
            display_name: "Microsoft Visual Studio Code".into(),
        },
        identity: IdentitySnapshot {
            names: vec!["Microsoft Visual Studio Code".into()],
            vendors: vec!["Microsoft Corporation".into()],
            tokens: vec!["visual".into(), "studio".into(), "code".into()],
            mega_vendor: true,
        },
        roots: vec![Root {
            path: CODE_ROOT.into(),
            kind: RootKind::InstallRoot,
            source: RootSource::InnoApp,
            trust: SourceTrust::AdminOnly,
            volume_serial: Some(0x1234_5678),
            parent_existed: true,
        }],
        exes: vec![ExeFile {
            path: format!(r"{CODE_ROOT}\Code.exe"),
            main: true,
        }],
        outside_root_files: Vec::new(),
        anchors: Anchors {
            progids: progids.iter().map(|p| (*p).to_owned()).collect(),
            ..Anchors::default()
        },
        tokens: Vec::new(),
        inno: Vec::new(),
        ref_snapshot: Vec::new(),
        subtrees: Vec::new(),
        ext_journal: Vec::new(),
        co_removed: Vec::new(),
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

/// A journal entry for `<CLASSES>\<ext>` in which only `ours` lived in `OpenWithProgids` and the key held
/// nothing else: the shape of an extension the app brought to the machine.
pub fn journal(ext: &str, ours: &[&str]) -> ExtJournalEntry {
    ExtJournalEntry {
        ext: ext.into(),
        key: classes(ext),
        openwith_ours: ours.iter().map(|p| (*p).to_owned()).collect(),
        openwith_others: Vec::new(),
        subkey_count: 1,
        default: None,
        previous_default: None,
        other_values: Vec::new(),
        other_subkeys: Vec::new(),
        ti_owned: false,
        vendor_backup: None,
        file_exts_key: None,
        toast_values: Vec::new(),
    }
}

/// A reference-snapshot entry for a value whose name is the ProgID `progid`.
pub fn ref_snap(key: &str, name: &str, progid: &str) -> RefSnapEntry {
    RefSnapEntry {
        target: Target::RegValue {
            path: key.into(),
            name: name.into(),
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

/// A baseline of the test Windows (or of `edition`) holding `keys` and `values` (key, name, type, hash).
pub fn baseline(edition: &str, keys: &[&str], values: &[(&str, &str, u32, u64)]) -> Baseline {
    let escape = |s: &str| s.replace('\\', "\\\\");
    let mut text = format!("#purge-baseline 1\tT\tPC\t{edition}\t{BUILD}.{UBR}\n");
    for key in keys {
        text.push_str(&format!("K\t{}\t0\t0\t0\n", escape(key)));
    }
    for (key, name, ty, hash) in values {
        text.push_str(&format!("V\t{}\t{name}\t{ty}\t{hash:016x}\n", escape(key)));
    }
    Baseline::from_bytes(text.as_bytes()).expect("the baseline parses")
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
    /// A world over `fixture` and `fp` with an empty matching baseline.
    pub fn new(fixture: Fixture, fp: Fingerprint) -> Self {
        Self {
            fixture,
            fp,
            baseline: Some(baseline(EDITION, &[], &[])),
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
        }
    }

    /// Runs one scanner over the world.
    pub fn scan(&self, scanner: &dyn Scanner) -> Vec<Candidate> {
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
        scanner.scan(&self.ctx(), &app)
    }
}
