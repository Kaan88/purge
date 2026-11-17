//! M1b scanner framework tests (M1B-FRAMEWORK, contracts C-SCANEXT and C-PATHSTORES). Every source is a
//! fixture.

use std::collections::BTreeMap;

use purge_guard::canon::GuardEnv;
use purge_index::baseline::Baseline;
use purge_index::ownership::{MACHINE_SID, OwnershipLimits, USERDATA, pack_guid};
use purge_index::sysobj::{ProgramRef, ServiceFacts, SysObjectIndex};
use purge_model::{
    Action, Anchors, AppRef, Blocker, Candidate, Category, Evidence, EvidenceKind, ExeFile,
    Fingerprint, FingerprintSchema, IdentitySnapshot, InstallScope, InstallerKind, InventoryEntry,
    MsiComponentFact, MsiContext, MsiFacts, MsiInfo, MsiKeyPath, ObjectWhy, OsInfo, ProgramId,
    RawFlags, Root, RootKind, RootSource, ScanMode, Scope, ServiceIdentity, SourceTrust,
    SysService, Target, Tier, TimeWindow, VerifyGone, View, WritableBy,
};
use purge_scan::framework::{
    AppIdentityView, OtherApps, PathStore, ScanCtx, ScanExt, ScanLimits, Scanner,
};
use purge_source::fixture::Fixture;
use purge_source::sysobj::{MsiComponentRow, MsiRegistryRaw, MsiTables};
use purge_source::types::{KnownFolder, MsiProductState, RegData};

const SID: &str = GuardEnv::SAMPLE_SID;
const ROOT: &str = r"C:\Program Files\7-Zip";
const EDITION: &str = "Professional";
const BUILD: u32 = 26340;
const UBR: u32 = 9882;
const SERIAL: u32 = 0x1234_5678;

/// The app's own MSI product.
const OWN: &str = "{70707070-0000-0000-0000-000000000001}";
/// Another installed product.
const OTHER: &str = "{22222222-2222-2222-2222-222222222222}";
/// A product registered as a component client but not installed.
const STALE: &str = "{33333333-3333-3333-3333-333333333333}";
/// A component id.
const C1: &str = "{C1C1C1C1-0000-0000-0000-000000000001}";
const LP_OWN: &str = r"C:\Windows\Installer\own.msi";
const LP_OTHER: &str = r"C:\Windows\Installer\other.msi";

fn packed(guid: &str) -> String {
    pack_guid(guid).expect("test GUID")
}

/// The 7-Zip fingerprint: one admin-only InstallRoot and one exe.
fn fingerprint() -> Fingerprint {
    Fingerprint {
        schema: FingerprintSchema,
        app: AppRef {
            program_id: ProgramId::machine(View::K64, "7-Zip").unwrap(),
            display_name: "7-Zip".into(),
        },
        identity: IdentitySnapshot {
            names: vec!["7-Zip".into()],
            vendors: vec!["Igor Pavlov".into()],
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
            path: format!(r"{ROOT}zFM.exe"),
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

fn baseline() -> Baseline {
    let text = format!("#purge-baseline 1\tT\tPC\t{EDITION}\t{BUILD}.{UBR}\n");
    Baseline::from_bytes(text.as_bytes()).expect("the baseline parses")
}

/// A fixture with the synthetic Windows, drive `C:`, the user's hive and the known folders.
fn machine() -> Fixture {
    let mut fx = Fixture::builder()
        .os(EDITION, BUILD, UBR)
        .user_sid(SID)
        .volume(r"C:\", Some(SERIAL), true, "NTFS")
        .dir(r"C:\Program Files")
        .known_folder(KnownFolder::ProgramFiles, r"C:\Program Files")
        .known_folder(KnownFolder::ProgramFilesX86, r"C:\Program Files (x86)")
        .known_folder(KnownFolder::Windows, r"C:\Windows")
        .key(&format!(r"HKU\{SID}\Software"))
        .build();
    fx.set_current_control_set(1);
    fx.add_key(&format!(r"{USERDATA}\{MACHINE_SID}\Components"));
    fx.set_msi_tables_captured(true);
    fx
}

/// Everything a [`ScanCtx`] borrows.
struct World {
    fixture: Fixture,
    fp: Fingerprint,
    baseline: Option<Baseline>,
    env: BTreeMap<String, String>,
    guard: GuardEnv,
    other_apps: OtherApps,
    ext: ScanExt,
}

impl World {
    fn new(fixture: Fixture) -> Self {
        Self {
            fixture,
            fp: fingerprint(),
            baseline: Some(baseline()),
            env: BTreeMap::new(),
            guard: GuardEnv::sample(),
            other_apps: OtherApps::default(),
            ext: ScanExt::new(Default::default(), Default::default()),
        }
    }

    /// Builds the shared data over the fixture with `inventory`, as the pipeline does.
    fn with_ext(mut self, inventory: &[InventoryEntry]) -> Self {
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
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

    fn ctx(&self) -> ScanCtx<'_> {
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
            ext: &self.ext,
        }
    }

    /// Runs `scanner` through the sealing driver.
    fn run(&self, scanner: &dyn Scanner) -> Vec<Candidate> {
        let app = AppIdentityView::from_fingerprint(&self.fp, &self.env);
        self.ctx().run(scanner, &app)
    }
}

/// A scanner that emits what its function builds.
struct Emit(fn(&ScanCtx<'_>) -> Vec<Candidate>);

impl Scanner for Emit {
    fn id(&self) -> &'static str {
        "TEST-EMIT"
    }
    fn captured_roots(&self) -> &[purge_scan::framework::RootSpec] {
        &[]
    }
    fn scan(&self, ctx: &ScanCtx<'_>, _app: &AppIdentityView) -> Vec<Candidate> {
        (self.0)(ctx)
    }
}

/// An inventory entry for an MSI product.
fn msi_entry(code: &str, local_package: &str) -> InventoryEntry {
    let id = ProgramId::machine(View::K64, code).unwrap();
    InventoryEntry {
        key_path: id.key_path(),
        program_id: id,
        hive_sid: None,
        view: View::K64,
        display_name: format!("Product {code}"),
        version: None,
        publisher: None,
        flags: RawFlags::default(),
        installer_kind: InstallerKind::Msi,
        scope: InstallScope::Machine,
        product_code: Some(code.to_owned()),
        upgrade_code: None,
        inno_app_id: None,
        writable_by: WritableBy::Admin,
        install_location: None,
        uninstall_string: None,
        quiet_uninstall_string: None,
        display_icon: None,
        install_time_evidence: Vec::new(),
        msi: Some(MsiInfo {
            context: MsiContext::Machine,
            local_package: Some(local_package.to_owned()),
            install_date: None,
        }),
    }
}

/// Registers `product` as a client of component `C1` with key path `data`.
fn client(fx: &mut Fixture, product: &str, data: &str) {
    fx.set_value(
        &format!(r"{USERDATA}\{MACHINE_SID}\Components\{}", packed(C1)),
        &packed(product),
        RegData::from_sz(data),
    );
}

/// The app's MSI facts: product `OWN` with component `C1` keyed on `key_path`.
fn own_msi(key_path: &str) -> MsiFacts {
    MsiFacts {
        product_code: OWN.into(),
        packed_code: packed(OWN),
        upgrade_code: None,
        context: MsiContext::Machine,
        user_sid: None,
        local_package: Some(LP_OWN.into()),
        package_readable: true,
        components: vec![MsiComponentFact {
            component_id: C1.into(),
            key_path: MsiKeyPath::File {
                path: key_path.into(),
            },
            other_clients: Vec::new(),
            shared_dll: false,
        }],
        registry_rows: Vec::new(),
        services: Vec::new(),
        source_dirs: Vec::new(),
        custom_actions: 0,
        unresolved_rows: 0,
    }
}

fn path(p: &str) -> Target {
    Target::Path { path: p.into() }
}

fn owned_by(blockers: &[Blocker]) -> Vec<(String, String)> {
    blockers
        .iter()
        .filter_map(|b| match b {
            Blocker::OwnedByInstalledMsi { product, row } => Some((product.clone(), row.clone())),
            _ => None,
        })
        .collect()
}

// -------------------------------------------------------------------------------------------------------
// ScanExt
// -------------------------------------------------------------------------------------------------------

/// `ScanExt::none` adds nothing to M1a: no hits (REF-ANY walks itself), no ownership, no blockers, no
/// objects. The M1a scanner suites run with it unchanged (every ScanCtx literal passes it).
#[test]
fn ext_none_keeps_all_m1a_scanner_tests_green() {
    let none = ScanExt::none();
    assert!(none.ref_hits.is_none());
    assert!(
        none.ref_hits_for(&ProgramId::machine(View::K64, "7-Zip").unwrap())
            .is_none()
    );
    assert!(none.sysobj.services.is_empty() && none.sysobj.tasks.is_empty());
    assert!(none.ownership.unreadable().is_empty());
    let mut world = World::new(machine());
    world.ext = ScanExt::new(Default::default(), Default::default());
    let ctx = ScanCtx {
        ext: ScanExt::none(),
        ..world.ctx()
    };
    for target in [
        path(&format!(r"{ROOT}\7z.dll")),
        Target::RegKey {
            path: r"HKLM\SOFTWARE\Classes\7-Zip.7z".into(),
        },
        Target::RegValue {
            path: r"HKLM\SOFTWARE\7-Zip".into(),
            name: "Path".into(),
        },
    ] {
        assert!(ctx.msi_blockers(&target).is_empty(), "{target:?}");
    }
    assert_eq!(ctx.ref_hits_under("HKLM").count(), 0);
    assert!(ScanExt::none().take_faults().is_empty());
}

#[test]
fn ref_hits_under_separator_aware() {
    let fx = {
        let mut fx = machine();
        let exe = format!(r"{ROOT}\7zFM.exe");
        fx.set_value(r"HKLM\SOFTWARE\A\Sub", "Cmd", RegData::from_sz(&exe));
        fx.set_value(r"HKLM\SOFTWARE\A", "Cmd", RegData::from_sz(&exe));
        fx.set_value(r"HKLM\SOFTWARE\AB", "Cmd", RegData::from_sz(&exe));
        fx
    };
    let world = World::new(fx).with_ext(&[]);
    let ctx = world.ctx();
    let keys = |prefix: &str| -> Vec<String> {
        let mut v: Vec<String> = ctx.ref_hits_under(prefix).map(|h| h.key.clone()).collect();
        v.sort();
        v.dedup();
        v
    };
    assert_eq!(
        keys(r"HKLM\SOFTWARE\A"),
        vec![
            r"HKLM\SOFTWARE\A".to_owned(),
            r"HKLM\SOFTWARE\A\Sub".to_owned()
        ]
    );
    // Case folded, trailing separator ignored.
    assert_eq!(keys(r"hklm\software\a\"), keys(r"HKLM\SOFTWARE\A"));
    assert_eq!(
        keys(r"HKLM\SOFTWARE\AB"),
        vec![r"HKLM\SOFTWARE\AB".to_owned()]
    );
    assert!(keys(r"HKLM\SOFTWARE\A\Su").is_empty());
    // The hits are the app's: a context for another app (a co-removed product) sees none.
    let mut other = World::new(machine());
    other.ext = ScanExt::new(Default::default(), Default::default());
    let hits = world.ext.ref_hits.clone().unwrap();
    other.ext = ScanExt::new(Default::default(), Default::default())
        .with_ref_hits(&ProgramId::machine(View::K64, "Other").unwrap(), hits);
    assert_eq!(other.ctx().ref_hits_under("HKLM").count(), 0);
}

// -------------------------------------------------------------------------------------------------------
// Path-keyed stores
// -------------------------------------------------------------------------------------------------------

const MUICACHE: &str = r"Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
const SHARED_DLLS: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs";

fn user_assist() -> String {
    format!(
        r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}}\Count"
    )
}

#[test]
fn path_store_detected_through_aliases() {
    let world = World::new(machine());
    let ctx = world.ctx();
    let cases: Vec<(String, Option<PathStore>)> = vec![
        (SHARED_DLLS.into(), Some(PathStore::SharedDlls)),
        (
            r"hklm\software\wow6432node\microsoft\windows\currentversion\shareddlls".into(),
            Some(PathStore::SharedDlls),
        ),
        (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders".into(),
            Some(PathStore::InstallerFolders),
        ),
        (
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers".into(),
            Some(PathStore::AppCompatLayers),
        ),
        (
            format!(
                r"HKU\{SID}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
            ),
            Some(PathStore::AppCompatLayers),
        ),
        (
            format!(
                r"HKU\{SID}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store"
            ),
            Some(PathStore::PcaStore),
        ),
        (
            format!(
                r"HKU\{SID}\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted"
            ),
            Some(PathStore::PcaPersisted),
        ),
        (
            format!(r"HKU\{SID}_Classes\{MUICACHE}"),
            Some(PathStore::MuiCache),
        ),
        (
            format!(r"HKU\{SID}\Software\Classes\{MUICACHE}"),
            Some(PathStore::MuiCache),
        ),
        (user_assist(), Some(PathStore::UserAssist)),
        (
            format!(
                r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched"
            ),
            Some(PathStore::FeatureUsage),
        ),
        // Below a store, beside a store, the merged view: not a store.
        (format!(r"{SHARED_DLLS}\Sub"), None),
        (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs2".into(),
            None,
        ),
        (format!(r"HKCR\{MUICACHE}"), None),
        (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".into(),
            None,
        ),
    ];
    for (key, want) in cases {
        assert_eq!(ctx.path_keyed_store(&key), want, "{key}");
    }
}

#[test]
fn path_store_muicache_suffix_stripped() {
    let world = World::new(machine());
    let ctx = world.ctx();
    let exe = format!(r"{ROOT}\7zFM.exe");
    for suffix in [
        ".FriendlyAppName",
        ".ApplicationCompany",
        ".friendlyappname",
    ] {
        assert_eq!(
            ctx.path_from_value_name(PathStore::MuiCache, &format!("{exe}{suffix}")),
            Some(exe.clone()),
            "{suffix}"
        );
    }
    // No suffix: not a MuiCache path entry.
    assert_eq!(ctx.path_from_value_name(PathStore::MuiCache, &exe), None);
    let key = format!(r"HKU\{SID}_Classes\{MUICACHE}");
    assert!(ctx.owns_registration(&key, &format!("{exe}.FriendlyAppName")));
}

#[test]
fn path_store_muicache_resource_name_ignored() {
    let world = World::new(machine());
    let ctx = world.ctx();
    for name in [
        r"@C:\Program Files\7-Zip\7-zip.dll,-1001",
        r"@%SystemRoot%\system32\shell32.dll,-22067",
        r"@C:\Program Files\7-Zip\7zFM.exe.FriendlyAppName",
    ] {
        assert_eq!(
            ctx.path_from_value_name(PathStore::MuiCache, name),
            None,
            "{name}"
        );
        let key = format!(r"HKU\{SID}_Classes\{MUICACHE}");
        assert!(!ctx.owns_registration(&key, name), "{name}");
    }
}

/// ROT13 of the ASCII letters (the GUID's hex letters included).
fn rot13(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            'a'..='z' => char::from((c as u8 - b'a' + 13) % 26 + b'a'),
            'A'..='Z' => char::from((c as u8 - b'A' + 13) % 26 + b'A'),
            _ => c,
        })
        .collect()
}

#[test]
fn path_store_userassist_rot13_and_known_folder_guid() {
    let world = World::new(machine());
    let ctx = world.ctx();
    let want = Some(format!(r"{ROOT}\7zFM.exe"));
    // FOLDERID_ProgramFilesX64 and FOLDERID_ProgramFiles.
    for guid in [
        "{6D809377-6AF0-444B-8957-A3773F02200E}",
        "{905E63B6-C1BF-494E-B29C-65B732D3D21A}",
    ] {
        let name = rot13(&format!(r"{guid}\7-Zip\7zFM.exe"));
        assert_eq!(
            ctx.path_from_value_name(PathStore::UserAssist, &name),
            want,
            "{name}"
        );
    }
    // A plain path, ROT13.
    let name = rot13(&format!(r"{ROOT}\7zFM.exe"));
    assert_eq!(ctx.path_from_value_name(PathStore::UserAssist, &name), want);
    assert!(ctx.owns_registration(&user_assist(), &name));
    // FOLDERID_ProgramFilesX86 names another directory.
    let name = rot13(r"{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\7-Zip\7zFM.exe");
    assert_eq!(
        ctx.path_from_value_name(PathStore::UserAssist, &name),
        Some(r"C:\Program Files (x86)\7-Zip\7zFM.exe".into())
    );
    assert!(!ctx.owns_registration(&user_assist(), &name));
    // An unknown GUID, and a known one the source cannot name: nothing.
    for guid in [
        "{00000000-1111-2222-3333-444444444444}",
        "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}",
    ] {
        let name = rot13(&format!(r"{guid}\7-Zip\7zFM.exe"));
        assert_eq!(
            ctx.path_from_value_name(PathStore::UserAssist, &name),
            None,
            "{guid}"
        );
    }
}

#[test]
fn path_store_userassist_non_path_ignored() {
    let world = World::new(machine());
    let ctx = world.ctx();
    for plain in [
        "UEME_CTLSESSION",
        "UEME_CTLCUACount:ctor",
        "Microsoft.Windows.Explorer",
        "Microsoft.WindowsCalculator_8wekyb3d8bbwe!App",
        "7zFM.exe",
        "{00000000-1111-2222-3333-444444444444}",
    ] {
        let name = rot13(plain);
        assert_eq!(
            ctx.path_from_value_name(PathStore::UserAssist, &name),
            None,
            "{plain}"
        );
        assert!(!ctx.owns_registration(&user_assist(), &name), "{plain}");
    }
}

/// Hostile: a value named after the app's exe file name alone, in every store.
#[test]
fn path_store_bare_file_name_never_matches() {
    let world = World::new(machine());
    let ctx = world.ctx();
    for (store, key, name) in [
        (
            PathStore::SharedDlls,
            SHARED_DLLS.to_owned(),
            "7zFM.exe".to_owned(),
        ),
        (
            PathStore::MuiCache,
            format!(r"HKU\{SID}_Classes\{MUICACHE}"),
            "7zFM.exe.FriendlyAppName".to_owned(),
        ),
        (PathStore::UserAssist, user_assist(), rot13("7zFM.exe")),
        (
            PathStore::FeatureUsage,
            format!(
                r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch"
            ),
            "7zFM.exe".to_owned(),
        ),
        (
            PathStore::AppCompatLayers,
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers".to_owned(),
            "7zFM.exe".to_owned(),
        ),
    ] {
        assert_eq!(ctx.path_keyed_store(&key), Some(store), "{key}");
        assert_eq!(ctx.path_from_value_name(store, &name), None, "{name}");
        assert!(!ctx.owns_registration(&key, &name), "{key} {name}");
    }
}

#[test]
fn path_store_unc_and_relative_rejected() {
    let world = World::new(machine());
    let ctx = world.ctx();
    for name in [
        r"\\server\share\7-Zip\7zFM.exe",
        r"\\?\C:\Program Files\7-Zip\7zFM.exe",
        r"\??\C:\Program Files\7-Zip\7zFM.exe",
        r"Program Files\7-Zip\7zFM.exe",
        r"\Program Files\7-Zip\7zFM.exe",
        r"C:Program Files\7-Zip\7zFM.exe",
        r"C:/Program Files/7-Zip/7zFM.exe",
        r"%UNKNOWN_VAR%\7zFM.exe",
        "",
    ] {
        assert_eq!(
            ctx.path_from_value_name(PathStore::SharedDlls, name),
            None,
            "{name}"
        );
        assert!(!ctx.owns_registration(SHARED_DLLS, name), "{name}");
    }
}

#[test]
fn path_store_prefix_sibling_not_matched() {
    let world = World::new(machine());
    let ctx = world.ctx();
    assert!(!ctx.owns_registration(SHARED_DLLS, r"C:\Program Files\7-Zip2\x.exe"));
    assert!(!ctx.owns_registration(SHARED_DLLS, r"C:\Program Files\7-Zip.exe"));
    assert!(ctx.owns_registration(SHARED_DLLS, r"C:\Program Files\7-Zip\7z.dll"));
    assert!(ctx.owns_registration(SHARED_DLLS, r"c:\program files\7-zip\Lang\de.txt"));
    // Installer\Folders: a directory with a trailing separator; the root itself counts.
    let folders = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders";
    assert!(ctx.owns_registration(folders, r"C:\Program Files\7-Zip\"));
    assert!(!ctx.owns_registration(folders, r"C:\Program Files\7-Zip2\"));
    assert!(!ctx.owns_registration(folders, r"C:\Program Files\"));
}

/// M1a keys are no path stores, and the shared data changes nothing about who owns their values.
#[test]
fn owns_registration_m1a_table_unchanged() {
    let fx = {
        let mut fx = machine();
        client(&mut fx, OTHER, &format!(r"{ROOT}\7z.dll"));
        fx.set_msi_tables(LP_OTHER, MsiTables::default());
        fx
    };
    let bare = World::new(fx.clone());
    let full = World::new(fx).with_ext(&[msi_entry(OTHER, LP_OTHER)]);
    let none_ctx = ScanCtx {
        ext: ScanExt::none(),
        ..bare.ctx()
    };
    let full_ctx = full.ctx();
    for (key, name) in [
        (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "7-Zip",
        ),
        (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\7zFM.exe",
            "",
        ),
        (r"HKLM\SOFTWARE\7-Zip", "Path"),
        (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip",
            "DisplayName",
        ),
        (r"HKLM\SOFTWARE\Classes\7-Zip.7z", ""),
        (r"HKLM\SOFTWARE\RegisteredApplications", "7-Zip"),
    ] {
        assert_eq!(none_ctx.path_keyed_store(key), None, "{key}");
        assert_eq!(
            none_ctx.owns_registration(key, name),
            full_ctx.owns_registration(key, name),
            "{key} {name}"
        );
    }
}

// -------------------------------------------------------------------------------------------------------
// System objects
// -------------------------------------------------------------------------------------------------------

#[test]
fn object_owner_unresolved_is_none() {
    let world = World::new(machine());
    let ctx = world.ctx();
    assert_eq!(
        ctx.object_owner(&ProgramRef::Unresolved {
            raw: r"%ProgramFiles%\7-Zip\7zFM.exe".into()
        }),
        None
    );
    assert_eq!(ctx.object_owner(&ProgramRef::None), None);
    assert_eq!(
        ctx.object_owner(&ProgramRef::File(format!(r"{ROOT}\7zFM.exe"))),
        Some(ObjectWhy::ProgramInRoot)
    );
}

#[test]
fn object_owner_file_outside_root_is_none() {
    let mut world = World::new(machine());
    let ctx = world.ctx();
    for file in [
        r"C:\Program Files\7-Zip2\7zFM.exe",
        r"C:\Windows\System32\svchost.exe",
        r"\\server\share\7-Zip\7zFM.exe",
        "7zFM.exe",
    ] {
        assert_eq!(
            ctx.object_owner(&ProgramRef::File(file.into())),
            None,
            "{file}"
        );
    }
    // An exe of the app outside its roots is the app's.
    let outside = r"C:\Tools\7z-helper.exe";
    let mut exe = world.fp.exes[0].clone();
    exe.path = outside.into();
    world.fp.exes.push(exe);
    assert_eq!(
        world
            .ctx()
            .object_owner(&ProgramRef::File(outside.to_ascii_uppercase())),
        Some(ObjectWhy::ProgramIsAppExe)
    );
}

fn service_identity() -> ServiceIdentity {
    ServiceIdentity {
        name: "7zSvc".into(),
        image_path: Some(format!(r#""{ROOT}\7zsvc.exe""#)),
        service_dll: None,
        service_type: 16,
        start: 2,
        object_name: Some("LocalSystem".into()),
    }
}

fn service() -> Target {
    Target::Service {
        name: "7zSvc".into(),
    }
}

/// The system-object index holding `identity` as a plain own-process service of the app.
fn indexed(identity: ServiceIdentity) -> ScanExt {
    ScanExt::new(
        Default::default(),
        SysObjectIndex {
            services: vec![ServiceFacts {
                identity,
                display_name: None,
                depend_on: Vec::new(),
                delete_flag: false,
                program: ProgramRef::File(format!(r"{ROOT}\7zsvc.exe")),
                is_driver: false,
                per_user_template: false,
                svchost: false,
            }],
            ..SysObjectIndex::default()
        },
    )
}

/// R2a S2: sealing judges a system object against the index it was read from. Not in the index, or
/// with a digest that is not the indexed object's: dropped with a fault. A service the object rules
/// deny (a per-user template) gets the rule's hard blocker.
#[test]
fn seal_applies_the_object_rules_and_the_index_digest() {
    let emit = Emit(|ctx| {
        vec![
            ctx.candidate("TEST-EMIT", service(), Action::DeleteKey, Category::System)
                .object_fp(service_identity().fp())
                .build(),
        ]
    });
    // Not in the index.
    let world = World::new(machine());
    assert!(world.run(&emit).is_empty());
    assert_eq!(world.ext.take_faults().len(), 1);
    // In the index with another digest.
    let mut world = World::new(machine());
    let mut changed = service_identity();
    changed.start = 3;
    world.ext = indexed(changed);
    assert!(world.run(&emit).is_empty());
    assert_eq!(world.ext.take_faults().len(), 1);
    // In the index, the same digest: kept, no object-rule blocker.
    let mut world = World::new(machine());
    world.ext = indexed(service_identity());
    let found = world.run(&emit);
    assert_eq!(found.len(), 1);
    assert!(
        !found[0]
            .blockers
            .iter()
            .any(|b| matches!(b, Blocker::DenyListed { .. })),
        "{:?}",
        found[0].blockers
    );
    // A per-user service template: the object rule blocks it.
    let mut world = World::new(machine());
    let mut ext = indexed(service_identity());
    ext.sysobj.services[0].per_user_template = true;
    world.ext = ext;
    let found = world.run(&emit);
    assert_eq!(found.len(), 1);
    assert!(
        found[0]
            .blockers
            .iter()
            .any(|b| matches!(b, Blocker::DenyListed { .. }) && b.is_hard()),
        "{:?}",
        found[0].blockers
    );
}

fn owned_object(c: &Candidate) -> Vec<&Evidence> {
    c.evidence
        .iter()
        .filter(|e| e.kind == EvidenceKind::OwnedSystemObject)
        .collect()
}

#[test]
fn owned_system_object_without_harvest_record_is_not_tier_a() {
    // Not recorded at harvest: the builder grants no OwnedSystemObject.
    let mut world = World::new(machine());
    world.ext = indexed(service_identity());
    let found = world.run(&Emit(|ctx| {
        vec![
            ctx.candidate("TEST-EMIT", service(), Action::DeleteKey, Category::System)
                .object_fp(service_identity().fp())
                .owned_system_object(ObjectWhy::ProgramInRoot, false)
                .build(),
        ]
    }));
    assert_eq!(found.len(), 1);
    assert!(owned_object(&found[0]).is_empty());
    let weak: Vec<&Evidence> = found[0]
        .evidence
        .iter()
        .filter(|e| e.kind == EvidenceKind::PointsIntoInstallRoot)
        .collect();
    assert_eq!(weak.len(), 1);
    assert_eq!(weak[0].scope, Scope::Value);

    // Claimed as recorded, but the fingerprint holds no such object: lowered to Tier B.
    let found = world.run(&Emit(|ctx| {
        vec![
            ctx.candidate("TEST-EMIT", service(), Action::DeleteKey, Category::System)
                .object_fp(service_identity().fp())
                .owned_system_object(ObjectWhy::ProgramInRoot, true)
                .build(),
        ]
    }));
    assert_eq!(found.len(), 1);
    let owned = owned_object(&found[0]);
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].tier, Tier::B);

    // Recorded with the same digest: Tier A, Object scope.
    let mut world = World::new(machine());
    world.ext = indexed(service_identity());
    world.fp.sys.services.push(SysService {
        identity: service_identity(),
        program: Some(format!(r"{ROOT}\7zsvc.exe")),
        why: ObjectWhy::ProgramInRoot,
    });
    let found = world.run(&Emit(|ctx| {
        vec![
            ctx.candidate("TEST-EMIT", service(), Action::DeleteKey, Category::System)
                .object_fp(service_identity().fp())
                .owned_system_object(ObjectWhy::ProgramInRoot, true)
                .build(),
        ]
    }));
    let owned = owned_object(&found[0]);
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0].tier, Tier::A);
    assert_eq!(owned[0].scope, Scope::Object);

    // Recorded, but the object changed since (the index holds the changed one): the digest differs
    // from the harvest's, Tier B.
    let mut changed = service_identity();
    changed.start = 3;
    world.ext = indexed(changed);
    let found = world.run(&Emit(|ctx| {
        let mut changed = service_identity();
        changed.start = 3;
        vec![
            ctx.candidate("TEST-EMIT", service(), Action::DeleteKey, Category::System)
                .object_fp(changed.fp())
                .owned_system_object(ObjectWhy::ProgramInRoot, true)
                .build(),
        ]
    }));
    assert_eq!(owned_object(&found[0])[0].tier, Tier::B);
}

/// R2a S3: a `ServiceInstall` row of the app's MSI with the service's name backs nothing by itself, and
/// `MsiServiceRow` is no reason to grant `OwnedSystemObject` without the harvest's record.
#[test]
fn msi_service_row_name_alone_backs_no_object() {
    let mut world = World::new(machine());
    let mut msi = own_msi(&format!(r"{ROOT}\7zsvc.exe"));
    msi.services.push(purge_model::MsiServiceRow {
        name: "7zSvc".into(),
        component: "Svc".into(),
    });
    world.fp.msi.push(msi);
    let unrecorded = world.run(&Emit(|ctx| {
        vec![
            ctx.candidate("TEST-EMIT", service(), Action::DeleteKey, Category::System)
                .object_fp(service_identity().fp())
                .owned_system_object(ObjectWhy::MsiServiceRow, false)
                .build(),
        ]
    }));
    // Claimed as recorded, but `fp.sys` holds no such service: the MSI row does not back it.
    let claimed = world.run(&Emit(|ctx| {
        vec![
            ctx.candidate("TEST-EMIT", service(), Action::DeleteKey, Category::System)
                .object_fp(service_identity().fp())
                .owned_system_object(ObjectWhy::MsiServiceRow, true)
                .build(),
        ]
    }));
    for found in [unrecorded, claimed] {
        assert_eq!(found.len(), 1);
        assert!(
            owned_object(&found[0]).iter().all(|e| e.tier != Tier::A),
            "{:?}",
            found[0].evidence
        );
    }
}

#[test]
fn seal_drops_typed_candidate_without_object_fp() {
    let world = World::new(machine());
    let found = world.run(&Emit(|ctx| {
        vec![
            ctx.candidate("TEST-EMIT", service(), Action::DeleteKey, Category::System)
                .build(),
            // A digest of another kind is refused by the builder, so the candidate has none.
            ctx.candidate(
                "TEST-EMIT",
                Target::Task {
                    path: r"\7-Zip Update".into(),
                },
                Action::DeleteKey,
                Category::System,
            )
            .object_fp(service_identity().fp())
            .build(),
        ]
    }));
    assert!(found.is_empty(), "{found:?}");
    let faults = world.ext.take_faults();
    assert_eq!(faults.len(), 2, "{faults:?}");
    assert!(faults.iter().all(|f| f.starts_with("TEST-EMIT")));
}

/// Hostile: a scanner that writes `OwnedSystemObject` on a file by hand.
#[test]
fn seal_drops_owned_system_object_on_non_object_target() {
    let world = World::new(machine());
    let found = world.run(&Emit(|ctx| {
        let mut c = ctx
            .candidate(
                "TEST-EMIT",
                path(&format!(r"{ROOT}\7zFM.exe")),
                Action::Quarantine,
                Category::AppFiles,
            )
            .build();
        c.evidence.push(
            Evidence::new(
                EvidenceKind::OwnedSystemObject,
                Scope::Object,
                SourceTrust::AdminOnly,
                "hostile",
            )
            .expect("Object scope is allowed"),
        );
        vec![c]
    }));
    assert!(found.is_empty(), "{found:?}");
    assert_eq!(world.ext.take_faults().len(), 1);
}

// -------------------------------------------------------------------------------------------------------
// MSI blockers
// -------------------------------------------------------------------------------------------------------

/// The 7-Zip file `7z.dll`, whose component `C1` has `clients` as clients; `OTHER` is installed.
fn msi_world(clients: &[&str], own: bool) -> World {
    let mut fx = machine();
    let dll = format!(r"{ROOT}\7z.dll");
    for c in clients {
        client(&mut fx, c, &dll);
    }
    fx.set_msi_tables(LP_OTHER, MsiTables::default());
    let mut world = World::new(fx);
    if own {
        world.fp.msi.push(own_msi(&dll));
    }
    world.with_ext(&[msi_entry(OTHER, LP_OTHER)])
}

#[test]
fn msi_blockers_foreign_client_blocks_file() {
    let world = msi_world(&[OTHER], false);
    let blockers = world.ctx().msi_blockers(&path(&format!(r"{ROOT}\7z.dll")));
    assert_eq!(
        owned_by(&blockers),
        vec![(OTHER.to_owned(), format!("Component:{C1}"))]
    );
    assert!(blockers.iter().all(Blocker::is_hard));
    // The directory that holds the component is owned too; a sibling is not.
    assert!(!owned_by(&world.ctx().msi_blockers(&path(ROOT))).is_empty());
    assert!(
        world
            .ctx()
            .msi_blockers(&path(&format!(r"{ROOT}\7zFM.exe")))
            .is_empty()
    );
}

#[test]
fn msi_blockers_stale_client_blocks_file() {
    let world = msi_world(&[STALE], false);
    let blockers = world.ctx().msi_blockers(&path(&format!(r"{ROOT}\7z.dll")));
    assert_eq!(
        owned_by(&blockers),
        vec![(STALE.to_owned(), format!("Component:{C1}"))]
    );
}

#[test]
fn msi_blockers_own_component_does_not_block() {
    // The app's own product is uninstalled (a stale registration of its own component).
    let world = msi_world(&[OWN], true);
    assert!(
        world
            .ctx()
            .msi_blockers(&path(&format!(r"{ROOT}\7z.dll")))
            .is_empty()
    );
    // With a foreign client beside it, only the foreign one blocks.
    let world = msi_world(&[OWN, OTHER], true);
    let blockers = world.ctx().msi_blockers(&path(&format!(r"{ROOT}\7z.dll")));
    assert_eq!(owned_by(&blockers).len(), 1);
    assert_eq!(owned_by(&blockers)[0].0, OTHER);
}

#[test]
fn msi_blockers_target_product_still_registered_is_hard() {
    let mut fx = machine();
    let dll = format!(r"{ROOT}\7z.dll");
    client(&mut fx, OWN, &dll);
    fx.set_msi_tables(LP_OWN, MsiTables::default());
    let mut world = World::new(fx);
    world.fp.msi.push(own_msi(&dll));
    let world = world.with_ext(&[msi_entry(OWN, LP_OWN)]);
    let blockers = world.ctx().msi_blockers(&path(&dll));
    assert_eq!(blockers, vec![Blocker::MsiProductStillRegistered]);
    assert!(blockers[0].is_hard());
}

fn registry_tables(rows: Vec<MsiRegistryRaw>) -> MsiTables {
    MsiTables {
        properties: vec![("ProductName".into(), "Other".into())],
        components: vec![MsiComponentRow {
            component: "Main".into(),
            component_id: Some(C1.into()),
            attributes: 256,
            key_path: None,
        }],
        registry: rows,
        ..MsiTables::default()
    }
}

#[test]
fn msi_blockers_whole_key_row_blocks_descendant_value() {
    let mut fx = machine();
    fx.set_msi_tables(
        LP_OTHER,
        registry_tables(vec![MsiRegistryRaw {
            row: "VendorKey".into(),
            root: 2,
            key: r"Software\Vendor".into(),
            name: Some("*".into()),
            value: None,
            component: "Main".into(),
        }]),
    );
    let world = World::new(fx).with_ext(&[msi_entry(OTHER, LP_OTHER)]);
    let ctx = world.ctx();
    let value = Target::RegValue {
        path: r"HKLM\SOFTWARE\Vendor\7-Zip\Options".into(),
        name: "Lang".into(),
    };
    assert_eq!(
        owned_by(&ctx.msi_blockers(&value)),
        vec![(OTHER.to_owned(), "Registry:VendorKey".to_owned())]
    );
    let key = Target::RegKey {
        path: r"HKLM\SOFTWARE\Vendor\7-Zip".into(),
    };
    assert_eq!(owned_by(&ctx.msi_blockers(&key)).len(), 1);
    let beside = Target::RegValue {
        path: r"HKLM\SOFTWARE\Vendor2".into(),
        name: "Lang".into(),
    };
    assert!(ctx.msi_blockers(&beside).is_empty());
}

#[test]
fn msi_blockers_unreadable_is_soft() {
    // `OTHER`'s package is not in the fixture: unreadable.
    let world = World::new(machine()).with_ext(&[msi_entry(OTHER, LP_OTHER)]);
    assert!(!world.ext.ownership.unreadable().is_empty());
    let ctx = world.ctx();
    // R2a S11: an unreadable package hides its registry rows only; under Classes that is said.
    for target in [
        Target::RegKey {
            path: r"HKLM\SOFTWARE\Classes\7-Zip.7z".into(),
        },
        Target::RegValue {
            path: format!(r"HKU\{SID}_Classes\.7z"),
            name: String::new(),
        },
    ] {
        let blockers = ctx.msi_blockers(&target);
        assert_eq!(blockers, vec![Blocker::MsiPackageUnreadable], "{target:?}");
        assert!(!blockers[0].is_hard());
    }
    assert_eq!(world.ext.unknown_ownership_items(), 2);
    // Its files are known from the registry's component clients, which were read: no demotion.
    for target in [
        path(&format!(r"{ROOT}\7z.dll")),
        path(r"C:\Program Files (x86)\7-Zip\x.dll"),
        path(r"C:\Users\me\AppData\Roaming\7-Zip"),
        Target::RegKey {
            path: r"HKLM\SOFTWARE\7-Zip".into(),
        },
    ] {
        assert!(ctx.msi_blockers(&target).is_empty(), "{target:?}");
    }
}

/// R2a S1: a SharedDLLs count is explained only by the app's own components whose live clients still
/// name the app; anything above that is another installer's reference. A directory with a counted
/// file inside is SharedRefcount too.
#[test]
fn shared_refcount_is_explained_by_the_apps_live_components() {
    let dll = format!(r"{ROOT}\7z.dll");
    let shared = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs";
    let world_with = |count: u32, own_client: bool| {
        let mut fx = machine();
        fx.set_value(shared, &dll, RegData::from_dword(count));
        if own_client {
            client(&mut fx, OWN, &dll);
        }
        let mut world = World::new(fx);
        world.fp.msi = vec![own_msi(&dll)];
        world.with_ext(&[])
    };
    let refcount = |world: &World, target: &Target| {
        world
            .ctx()
            .msi_blockers(target)
            .contains(&Blocker::SharedRefcount)
    };
    // Count 1, the app's live component explains it.
    let world = world_with(1, true);
    assert!(!refcount(&world, &path(&dll)));
    assert!(!refcount(&world, &path(ROOT)));
    // Count 2: one reference is someone else's; the file and its folder are blocked.
    let world = world_with(2, true);
    assert!(refcount(&world, &path(&dll)));
    assert!(refcount(&world, &path(ROOT)));
    // Count 1 but the component's clients no longer name the app: unexplained.
    let world = world_with(1, false);
    assert!(refcount(&world, &path(&dll)));
}

/// The scan-warning channel: each line once, prefixed with the scanner, drained by the pipeline.
#[test]
fn warnings_are_recorded_once_and_drained() {
    let world = World::new(machine());
    world.ext.warn("TEST", "a list could not be read");
    world.ext.warn("TEST", "a list could not be read");
    world.ext.warn("OTHER", "x");
    assert_eq!(
        world.ext.take_warnings(),
        vec![
            "TEST: a list could not be read".to_owned(),
            "OTHER: x".to_owned()
        ]
    );
    assert!(world.ext.take_warnings().is_empty());
}

/// Every candidate of every scanner gets the MSI blockers, M1a scanners included.
#[test]
fn seal_adds_msi_blockers_to_m1a_scanner_candidate() {
    let world = msi_world(&[OTHER], false);
    let found = world.run(&Emit(|ctx| {
        let mut b = ctx.candidate(
            "TEST-EMIT",
            path(r"C:\Program Files\7-Zip\7z.dll"),
            Action::Quarantine,
            Category::AppFiles,
        );
        b.inside_install_root();
        b.common_blockers();
        vec![b.build()]
    }));
    assert_eq!(found.len(), 1);
    assert_eq!(
        owned_by(&found[0].blockers),
        vec![(OTHER.to_owned(), format!("Component:{C1}"))]
    );
}

// -------------------------------------------------------------------------------------------------------
// Products
// -------------------------------------------------------------------------------------------------------

#[test]
fn product_gone_source_error_is_not_gone() {
    // The source cannot answer: not gone.
    let mut fx = machine();
    fx.set_msi_products(None);
    let world = World::new(fx);
    assert!(!world.ctx().product_gone(OWN));
    // Unknown in every context: gone.
    let world = World::new(machine());
    assert!(world.ctx().product_gone(OWN));
    assert!(world.ctx().product_gone(&packed(OWN)));
    // Known in one context: not gone.
    let mut fx = machine();
    fx.set_msi_state(OWN, MsiContext::UserManaged, MsiProductState::Default);
    let world = World::new(fx);
    assert!(!world.ctx().product_gone(OWN));
    // No GUID: not gone.
    assert!(!World::new(machine()).ctx().product_gone("7-Zip"));
}
