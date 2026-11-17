//! Golden fixture tests of the file-system scanners and SYS-APPX (M1a package P32).
//!
//! Each test builds an in-memory machine ([`Fixture`]) and a fingerprint, runs one scanner and compares
//! the rendered candidate list with a golden file under `tests/fs/golden`. Set `PURGE_BLESS=1` to rewrite
//! the golden files from the current output, then review the diff.

mod appdata;
mod appx;
mod installdir;
mod property;
mod shortcuts;
mod uninstaller;
mod vendorparent;

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use purge_guard::canon::GuardEnv;
use purge_index::baseline::Baseline;
use purge_model::{
    Anchors, AppRef, Candidate, Fingerprint, FingerprintSchema, HarvestedToken, IdentitySnapshot,
    InnoRecord, InnoRecordKind, OsInfo, ProgramId, Root, RootKind, RootSource, ScanMode, SourceId,
    SourceTrust, Target, TimeWindow, VerifyGone, View,
};
use purge_scan::framework::{
    AppIdentityView, OtherApp, OtherApps, ScanCtx, ScanExt, ScanLimits, Scanner,
};
use purge_source::fixture::{Fixture, FixtureBuilder};
use purge_source::types::FileTimes;

/// The interactive user of every fixture: the profile of [`GuardEnv::sample`].
pub const SID: &str = GuardEnv::SAMPLE_SID;
/// The serial of the fixtures' `C:` volume.
pub const SERIAL: u32 = 0x1234_5678;
/// The user's profile directory.
pub const PROFILE: &str = r"C:\Users\tester";
/// `%APPDATA%`.
pub const ROAMING: &str = r"C:\Users\tester\AppData\Roaming";
/// `%LOCALAPPDATA%`.
pub const LOCAL: &str = r"C:\Users\tester\AppData\Local";
/// LocalLow.
pub const LOCAL_LOW: &str = r"C:\Users\tester\AppData\LocalLow";
/// The user's `Start Menu\Programs`.
pub const USER_PROGRAMS: &str =
    r"C:\Users\tester\AppData\Roaming\Microsoft\Windows\Start Menu\Programs";
/// The all-users `Start Menu\Programs`.
pub const COMMON_PROGRAMS: &str = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs";

const DAY: u64 = 24 * 60 * 60 * 10_000_000;
/// When the test apps were installed.
pub const T_INSTALL: u64 = 134_000_000_000_000_000;
/// When their uninstaller started.
pub const T_START: u64 = T_INSTALL + 30 * DAY;
/// When it ended.
pub const T_END: u64 = T_START + DAY / 24;

/// Everything a [`ScanCtx`] borrows, owned in one place.
pub struct World {
    /// The machine.
    pub fixture: Fixture,
    /// The fingerprint of the app being cleaned.
    pub fp: Fingerprint,
    /// The clean-Windows baseline.
    pub baseline: Option<Baseline>,
    /// The interactive user's environment.
    pub env: BTreeMap<String, String>,
    /// The machine layout.
    pub guard: GuardEnv,
    /// The other installed apps.
    pub other_apps: OtherApps,
    /// The verify-gone result of the uninstall.
    pub verify_gone: Option<VerifyGone>,
}

impl World {
    /// A world over `fixture` for the app of `fp`, uninstalled and verified gone, with an empty baseline
    /// of the fixture's Windows and no other apps.
    pub fn new(fixture: Fixture, fp: Fingerprint) -> Self {
        let env = [
            ("SYSTEMDRIVE", "C:"),
            ("WINDIR", r"C:\Windows"),
            ("SYSTEMROOT", r"C:\Windows"),
            ("PROGRAMFILES", r"C:\Program Files"),
            ("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
            ("PROGRAMDATA", r"C:\ProgramData"),
            ("PUBLIC", r"C:\Users\Public"),
            ("USERPROFILE", PROFILE),
            ("APPDATA", ROAMING),
            ("LOCALAPPDATA", LOCAL),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let baseline =
            Baseline::from_bytes(b"#purge-baseline 1\tT\tPC\tProfessional\t26340.9882\n")
                .expect("the baseline parses");
        Self {
            fixture,
            fp,
            baseline: Some(baseline),
            env,
            guard: GuardEnv::sample(),
            other_apps: OtherApps::default(),
            verify_gone: Some(VerifyGone::new(true, true, true)),
        }
    }

    /// Adds another installed app with these roots and referenced files.
    pub fn with_other_app(mut self, name: &str, roots: &[&str], files: &[&str]) -> Self {
        let mut apps = self.other_apps.apps().to_vec();
        apps.push(OtherApp {
            name: name.to_owned(),
            roots: roots.iter().map(|s| (*s).to_owned()).collect(),
            files: files.iter().map(|s| (*s).to_owned()).collect(),
            ..OtherApp::default()
        });
        self.other_apps = OtherApps::new(apps);
        self
    }

    /// The scan context over this world.
    pub fn ctx(&self) -> ScanCtx<'_> {
        ScanCtx {
            reg: &self.fixture,
            fs: &self.fixture,
            sys: &self.fixture,
            fp: &self.fp,
            baseline: self.baseline.as_ref(),
            mode: ScanMode::Post,
            verify_gone: self.verify_gone,
            env: &self.env,
            guard: &self.guard,
            other_apps: &self.other_apps,
            limits: ScanLimits::default(),
            ext: ScanExt::none(),
        }
    }

    /// Runs one scanner and checks what every scanner must hold: its own id on each candidate, no
    /// decision, no duplicate target.
    pub fn scan(&self, scanner: &dyn Scanner) -> Vec<Candidate> {
        let ctx = self.ctx();
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
        let found = scanner.scan(&ctx, &app);
        for (i, c) in found.iter().enumerate() {
            assert_eq!(c.scanner, scanner.id(), "{c:?}");
            assert!(c.decision.is_none(), "a scanner never decides: {c:?}");
            assert!(
                c.evidence.iter().any(|e| e.weight > 0),
                "no positive evidence: {c:?}"
            );
            assert!(
                found[..i].iter().all(|other| other.id != c.id),
                "duplicate target: {c:?}"
            );
        }
        found
    }
}

/// A builder with the fixtures' `C:` volume and the directories every Windows has.
pub fn machine() -> FixtureBuilder {
    Fixture::builder()
        .volume("C:\\", Some(SERIAL), true, "NTFS")
        .dir(r"C:\Program Files")
        .dir(r"C:\Program Files (x86)")
        .dir(r"C:\ProgramData")
        .dir(r"C:\Windows\System32")
        .dir(ROAMING)
        .dir(LOCAL)
        .dir(LOCAL_LOW)
        .dir(USER_PROGRAMS)
        .dir(COMMON_PROGRAMS)
        .dir(r"C:\Users\tester\Desktop")
        .dir(r"C:\Users\Public\Desktop")
}

/// File times of something written at `when`.
pub fn at(when: u64) -> FileTimes {
    FileTimes {
        created: Some(purge_model::FileTime(when)),
        modified: Some(purge_model::FileTime(when)),
        accessed: None,
    }
}

/// An InstallRoot read from `source`, admin-only, on the fixtures' volume.
pub fn install_root(path: &str, source: RootSource) -> Root {
    Root {
        path: path.to_owned(),
        kind: RootKind::InstallRoot,
        source,
        trust: SourceTrust::AdminOnly,
        volume_serial: Some(SERIAL),
        parent_existed: true,
    }
}

/// An Inno path record.
pub fn inno_path(kind: InnoRecordKind, path: &str) -> InnoRecord {
    InnoRecord {
        kind,
        target: Target::Path {
            path: path.to_owned(),
        },
        view: None,
        user_hive: false,
        existed_before: false,
        shared: false,
        key_create: false,
    }
}

/// A harvested token.
pub fn token(text: &str) -> HarvestedToken {
    HarvestedToken {
        token: text.to_owned(),
        source: SourceId("anchor:test".to_owned()),
    }
}

/// A machine-wide fingerprint with this identity and nothing else, uninstalled in the test window.
pub fn fingerprint(
    key_name: &str,
    display_name: &str,
    names: &[&str],
    vendors: &[&str],
    tokens: &[&str],
) -> Fingerprint {
    let strings = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    Fingerprint {
        schema: FingerprintSchema,
        app: AppRef {
            program_id: ProgramId::machine(View::K64, key_name).expect("a valid key name"),
            display_name: display_name.to_owned(),
        },
        identity: IdentitySnapshot {
            names: strings(names),
            vendors: strings(vendors),
            tokens: strings(tokens),
            mega_vendor: false,
        },
        roots: Vec::new(),
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
            edition: "Professional".into(),
            build: 26340,
            ubr: 9882,
        },
        user_sid: SID.into(),
        window: TimeWindow {
            install_time: Some(purge_model::FileTime(T_INSTALL)),
            t_start: Some(purge_model::FileTime(T_START)),
            t_end: Some(purge_model::FileTime(T_END)),
        },
        verify_gone: Some(VerifyGone::new(true, true, true)),
        warnings: Vec::new(),
    }
}

/// Git for Windows: an Inno Setup app in `C:\Program Files\Git`.
pub fn git_fp() -> Fingerprint {
    let mut fp = fingerprint(
        "Git_is1",
        "Git",
        &["Git"],
        &["The Git Development Community"],
        &["git"],
    );
    fp.roots = vec![install_root(r"C:\Program Files\Git", RootSource::InnoApp)];
    fp
}

/// Mozilla Firefox: an NSIS app in `C:\Program Files\Mozilla Firefox` with its install hash as a token.
pub fn firefox_fp() -> Fingerprint {
    let mut fp = fingerprint(
        "Mozilla Firefox 144.0 (x64 en-US)",
        "Mozilla Firefox (x64 en-US)",
        &["Mozilla Firefox (x64 en-US)", "Mozilla Firefox", "Firefox"],
        &["Mozilla", "Mozilla Corporation"],
        &["firefox"],
    );
    fp.roots = vec![install_root(
        r"C:\Program Files\Mozilla Firefox",
        RootSource::ArpInstallLocation,
    )];
    fp.tokens = vec![token(FIREFOX_HASH)];
    fp.anchors.aumids = vec![FIREFOX_HASH.to_owned()];
    fp
}

/// The install hash of the Firefox fixture.
pub const FIREFOX_HASH: &str = "308046B0AF4A39CB";

/// Notepad++: an NSIS app in `C:\Program Files\Notepad++` with a sparse context-menu package.
pub fn npp_fp() -> Fingerprint {
    let mut fp = fingerprint(
        "Notepad++",
        "Notepad++ (64-bit x64)",
        &["Notepad++ (64-bit x64)", "Notepad++"],
        &["Notepad++ Team"],
        &["notepad++"],
    );
    fp.roots = vec![install_root(
        r"C:\Program Files\Notepad++",
        RootSource::ArpInstallLocation,
    )];
    fp.exes = vec![purge_model::ExeFile {
        path: r"C:\Program Files\Notepad++\notepad++.exe".into(),
        main: true,
    }];
    fp.anchors.package_full_names = vec![NPP_PACKAGE.to_owned()];
    fp.anchors.package_families = vec!["NotepadPlusPlus_2247w0b46hfww".to_owned()];
    fp
}

/// The full name of Notepad++'s sparse package.
pub const NPP_PACKAGE: &str = "NotepadPlusPlus_1.0.0.0_neutral__2247w0b46hfww";

/// The target of a candidate as one line.
pub fn target_text(target: &Target) -> String {
    match target {
        Target::Path { path } => path.clone(),
        Target::AppxPackage { full_name } => format!("package:{full_name}"),
        other => format!("{other:?}"),
    }
}

/// The path targets of `found`.
pub fn paths(found: &[Candidate]) -> Vec<String> {
    found.iter().map(|c| target_text(&c.target)).collect()
}

/// The candidate for `path`.
pub fn by_path<'a>(found: &'a [Candidate], path: &str) -> &'a Candidate {
    found
        .iter()
        .find(|c| target_text(&c.target).eq_ignore_ascii_case(path))
        .unwrap_or_else(|| panic!("no candidate for {path}; have {:#?}", paths(found)))
}

/// The candidate list as text: one block per candidate with its evidence (`+`), blockers (`!`) and
/// nested candidates (`>`).
pub fn render(found: &[Candidate]) -> String {
    let mut out = String::new();
    for c in found {
        writeln!(
            out,
            "{} {:?} {:?} {}",
            c.scanner,
            c.action,
            c.category,
            target_text(&c.target)
        )
        .unwrap();
        let count = |n: Option<u32>| n.map_or("-".to_owned(), |n| n.to_string());
        let size = c.size_bytes.map_or("-".to_owned(), |n| n.to_string());
        writeln!(
            out,
            "  harm={:?} reversibility={:?} size={size} files={}",
            c.harm,
            c.reversibility,
            count(c.child_count)
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
        for id in &c.children {
            let child = found
                .iter()
                .find(|other| other.id == *id)
                .map_or_else(|| id.0.clone(), |other| target_text(&other.target));
            writeln!(out, "  > {child}").unwrap();
        }
    }
    if found.is_empty() {
        out.push_str("(nothing)\n");
    }
    out
}

/// Compares the rendered candidates with `tests/fs/golden/<name>.txt`, or rewrites the file when
/// `PURGE_BLESS` is set.
pub fn golden(name: &str, found: &[Candidate]) {
    let text = render(found);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fs")
        .join("golden")
        .join(format!("{name}.txt"));
    if std::env::var_os("PURGE_BLESS").is_some() {
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the golden directory");
        std::fs::write(&path, &text).expect("the golden file is writable");
        return;
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| {
            panic!(
                "{}: {e} (run with PURGE_BLESS=1 to create it)",
                path.display()
            )
        })
        .replace("\r\n", "\n");
    assert_eq!(text, want, "golden {name} differs");
}
