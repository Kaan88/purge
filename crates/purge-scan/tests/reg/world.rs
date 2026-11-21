//! The worlds the registry-scanner tests scan: machines after an uninstaller ran, with the fingerprint
//! the harvest took before.

use std::collections::BTreeMap;

use purge_guard::canon::GuardEnv;
use purge_index::baseline::Baseline;
use purge_model::{
    AnchorKind, AnchorRef, Anchors, AppRef, Candidate, CoRemovedProduct, ExeFile, FileTime,
    Fingerprint, FingerprintSchema, HarvestedToken, IdentitySnapshot, InnoRecord, InnoRecordKind,
    OsInfo, ProgramId, RefCarrier, RefSnapEntry, Root, RootKind, RootSource, ScanMode, SourceTrust,
    Target, TimeWindow, VerifyGone, View,
};
use purge_scan::framework::{AppIdentityView, OtherApps, ScanCtx, ScanExt, ScanLimits, Scanner};
use purge_source::fixture::{Fixture, FixtureBuilder};

/// The edition of the rig image the baseline is for.
pub const EDITION: &str = "Professional";
/// Its build.
pub const BUILD: u32 = 26340;
/// Its update build revision.
pub const UBR: u32 = 9882;
/// The serial of drive `C:`.
pub const SERIAL: u32 = 0x1234_5678;

/// The interactive user.
pub const SID: &str = GuardEnv::SAMPLE_SID;

/// Firefox's install root.
pub const FIREFOX: &str = r"C:\Program Files\Mozilla Firefox";
/// Firefox's install hash.
pub const HASH: &str = "308046B0AF4A39CB";
/// The Maintenance Service's install root.
pub const MAINTENANCE: &str = r"C:\Program Files (x86)\Mozilla Maintenance Service";
/// Git's install root.
pub const GIT: &str = r"C:\Program Files\Git";
/// Notepad++'s install root.
pub const NPP: &str = r"C:\Program Files\Notepad++";

/// `Microsoft\Windows\CurrentVersion` below a `Software` key.
pub const CV: &str = r"Microsoft\Windows\CurrentVersion";
/// The machine `Environment` key as the registry spells it.
pub const MACHINE_ENV: &str = r"HKLM\SYSTEM\ControlSet001\Control\Session Manager\Environment";
/// The machine `Environment` key as plans spell it.
pub const MACHINE_ENV_PLAN: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

/// The user's `Software` key.
pub fn hkcu() -> String {
    format!(r"HKU\{SID}\Software")
}

pub fn key(path: impl Into<String>) -> Target {
    Target::RegKey { path: path.into() }
}

pub fn value(path: impl Into<String>, name: &str) -> Target {
    Target::RegValue {
        path: path.into(),
        name: name.into(),
    }
}

pub fn segment(path: impl Into<String>, name: &str, segment: &str) -> Target {
    Target::RegMultiSzSegment {
        path: path.into(),
        name: name.into(),
        segment: segment.into(),
        index: None,
    }
}

/// An InstallRoot read from an admin-only record.
pub fn install_root(path: &str, source: RootSource) -> Root {
    Root {
        path: path.into(),
        kind: RootKind::InstallRoot,
        source,
        trust: SourceTrust::AdminOnly,
        volume_serial: Some(SERIAL),
        parent_existed: true,
    }
}

/// A machine-wide fingerprint with one InstallRoot and one main exe, and nothing else.
pub fn fingerprint(
    arp_key: &str,
    display_name: &str,
    identity: IdentitySnapshot,
    root: Root,
    main_exe: &str,
) -> Fingerprint {
    let exe = format!(r"{}\{main_exe}", root.path);
    Fingerprint {
        baseline_view: None,
        schema: FingerprintSchema,
        app: AppRef {
            program_id: ProgramId::machine(View::K64, arp_key).expect("a valid program id"),
            display_name: display_name.into(),
        },
        identity,
        roots: vec![root],
        exes: vec![ExeFile {
            path: exe,
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

pub fn identity(names: &[&str], vendors: &[&str], tokens: &[&str]) -> IdentitySnapshot {
    let own = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect();
    IdentitySnapshot {
        names: own(names),
        vendors: own(vendors),
        tokens: own(tokens),
        mega_vendor: false,
    }
}

/// A reference-snapshot entry: `target` referred to `anchor` through `carrier`.
pub fn snap(target: Target, carrier: RefCarrier, kind: AnchorKind, anchor: &str) -> RefSnapEntry {
    RefSnapEntry {
        target,
        carrier,
        anchor: AnchorRef {
            kind,
            text: anchor.into(),
        },
        parent_values: 1,
        parent_subkeys: 0,
        data_hash: None,
    }
}

/// An Inno record on a registry target that did not exist before the install.
pub fn inno(kind: InnoRecordKind, target: Target) -> InnoRecord {
    let key_create = matches!(target, Target::RegKey { .. })
        && matches!(
            kind,
            InnoRecordKind::RegDeleteEntireKey | InnoRecordKind::RegDeleteKeyIfEmpty
        );
    InnoRecord {
        kind,
        target,
        view: Some(View::K64),
        user_hive: false,
        existed_before: false,
        shared: false,
        key_create,
    }
}

/// The Mozilla Maintenance Service as it was pre-harvested next to Firefox.
pub fn maintenance_service() -> Fingerprint {
    fingerprint(
        "MozillaMaintenanceService",
        "Mozilla Maintenance Service",
        identity(
            &["Mozilla Maintenance Service", "maintenanceservice.exe"],
            &["Mozilla"],
            &["maintenance", "service", "maintenanceservice"],
        ),
        install_root(MAINTENANCE, RootSource::ArpInstallLocation),
        "maintenanceservice.exe",
    )
}

/// The `Launcher` key of the user's Firefox settings.
pub fn launcher_key() -> String {
    format!(r"{}\Mozilla\Firefox\Launcher", hkcu())
}

/// Firefox, harvested while installed: its install hash, the values that named its root, and the
/// Maintenance Service that goes with it.
pub fn firefox() -> Fingerprint {
    let mut fp = fingerprint(
        "Mozilla Firefox 147.0 (x64 en-US)",
        "Mozilla Firefox (x64 en-US)",
        identity(
            &["Mozilla Firefox (x64 en-US)", "Mozilla Firefox", "Firefox"],
            &["Mozilla", "Mozilla Corporation", "mozilla.org"],
            &["firefox"],
        ),
        install_root(FIREFOX, RootSource::ArpInstallLocation),
        "firefox.exe",
    );
    fp.tokens = vec![HarvestedToken {
        token: HASH.into(),
        source: "progid:FirefoxHTML-308046B0AF4A39CB".into(),
    }];
    let exe = format!(r"{FIREFOX}\firefox.exe");
    fp.ref_snapshot = vec![
        snap(
            value(r"HKLM\SOFTWARE\Mozilla\Firefox\TaskBarIDs", FIREFOX),
            RefCarrier::ValueName,
            AnchorKind::Root,
            FIREFOX,
        ),
        snap(
            value(launcher_key(), &format!("{exe}|Launcher")),
            RefCarrier::ValueName,
            AnchorKind::Exe,
            &exe,
        ),
        snap(
            value(launcher_key(), &format!("{exe}|Browser")),
            RefCarrier::ValueName,
            AnchorKind::Exe,
            &exe,
        ),
    ];
    fp.co_removed = vec![CoRemovedProduct {
        app: maintenance_service().app,
        fingerprint: Some(Box::new(maintenance_service())),
    }];
    fp.window = TimeWindow {
        install_time: Some(FileTime(1_000_000_000_000)),
        t_start: Some(FileTime(1_000_500_000_000)),
        t_end: Some(FileTime(1_000_600_000_000)),
    };
    fp
}

/// Git for Windows (Inno Setup, machine-wide).
pub fn git() -> Fingerprint {
    fingerprint(
        "Git_is1",
        "Git",
        identity(&["Git"], &["The Git Development Community"], &["git"]),
        install_root(GIT, RootSource::InnoApp),
        "git-bash.exe",
    )
}

/// Notepad++ (NSIS, machine-wide).
pub fn notepadpp() -> Fingerprint {
    fingerprint(
        "Notepad++",
        "Notepad++ (64-bit x64)",
        identity(
            &["Notepad++ (64-bit x64)", "Notepad++"],
            &["Notepad++ Team"],
            &["notepad++"],
        ),
        install_root(NPP, RootSource::ArpInstallLocation),
        "notepad++.exe",
    )
}

/// A machine whose drive `C:` is the recorded fixed NTFS volume and whose Program Files directories
/// exist; every install root is gone.
pub fn machine() -> FixtureBuilder {
    Fixture::builder()
        .dir(r"C:\Program Files")
        .dir(r"C:\Program Files (x86)")
        .dir(r"C:\Windows")
        .volume(r"C:\", Some(SERIAL), true, "NTFS")
        .os(EDITION, BUILD, UBR)
}

/// What Firefox's uninstaller leaves in the registry (rig run `firefox`), next to what clean Windows
/// has under `HKLM\SOFTWARE\Mozilla`.
pub fn firefox_leftovers() -> FixtureBuilder {
    let exe = format!(r"{FIREFOX}\firefox.exe");
    let mozilla = r"HKLM\SOFTWARE\Mozilla";
    let wow = r"HKLM\SOFTWARE\WOW6432Node\Mozilla";
    machine()
        // Windows Defender's native-messaging host: part of clean Windows.
        .sz(
            &format!(r"{mozilla}\NativeMessagingHosts\com.microsoft.defender.browser_extension.native_message_host"),
            "",
            r"C:\Program Files\Windows Defender\x.json",
        )
        .sz(&format!(r"{mozilla}\Firefox\TaskBarIDs"), FIREFOX, HASH)
        .key_lwt(&format!(r"{mozilla}\Firefox"), 1_000_100_000_000)
        .sz(&format!(r"{mozilla}\MaintenanceService\{HASH}\0"), "name", "Mozilla Corporation")
        .sz(&format!(r"{mozilla}\MaintenanceService\{HASH}\0"), "issuer", "DigiCert")
        .key_lwt(&format!(r"{mozilla}\MaintenanceService"), 1_000_100_000_000)
        .sz(r"HKLM\SOFTWARE\mozilla.org\Mozilla", "CurrentVersion", "147.0")
        .key_lwt(r"HKLM\SOFTWARE\mozilla.org", 1_000_100_000_000)
        .dword(&format!(r"{wow}\MaintenanceService"), "Attempted", 1)
        .dword(&format!(r"{wow}\MaintenanceService"), "Installed", 1)
        .qword(&launcher_key(), &format!("{exe}|Launcher"), 1)
        .qword(&launcher_key(), &format!("{exe}|Browser"), 2)
        .dword(&format!(r"{}\Mozilla\Firefox\DllPrefetchExperiment", hkcu()), &exe, 1)
}

/// A baseline of the test Windows holding `keys`.
pub fn baseline(keys: &[&str]) -> Baseline {
    let mut text = format!("#purge-baseline 1\tT\tPC\t{EDITION}\t{BUILD}.{UBR}\n");
    for key in keys {
        text.push_str(&format!("K\t{}\t0\t0\t0\n", key.replace('\\', "\\\\")));
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
    /// A world over `fixture` and `fp`, with the baseline of clean Windows as far as these tests need
    /// it: `HKLM\SOFTWARE\Mozilla` and its native-messaging list are on both committed baselines.
    pub fn new(fixture: FixtureBuilder, fp: Fingerprint) -> Self {
        let env = BTreeMap::from([
            ("PROGRAMFILES".to_owned(), r"C:\Program Files".to_owned()),
            ("SYSTEMROOT".to_owned(), r"C:\Windows".to_owned()),
        ]);
        Self {
            fixture: fixture.build(),
            fp,
            baseline: Some(baseline(&[
                r"HKLM\SOFTWARE\Mozilla",
                r"HKLM\SOFTWARE\Mozilla\NativeMessagingHosts",
            ])),
            env,
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

    /// Runs one scanner over the world.
    pub fn scan(&self, scanner: &dyn Scanner) -> Vec<Candidate> {
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
        scanner.scan(&self.ctx(), &app)
    }
}
