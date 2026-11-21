//! The machine the MSI registry scanners are tested on, built in code: the app "App" (one admin-only
//! InstallRoot) with its MSI product `OWN`, another installed product `OTHER`, and every Windows
//! Installer shape of `OWN` present.

use std::collections::BTreeMap;

use purge_guard::canon::GuardEnv;
use purge_guard::deny::{self, Exemptions};
use purge_index::baseline::Baseline;
use purge_index::baseline_view::BaselineView;
use purge_index::ownership::{MACHINE_SID, OwnershipIndex, OwnershipInput, USERDATA, pack_guid};
use purge_model::{
    AppRef, Band, Blocker, Candidate, EvidenceKind, ExeFile, Fingerprint, FingerprintSchema,
    IdentitySnapshot, InstallScope, InstallerKind, InventoryEntry, ManifestKind, MsiComponentFact,
    MsiContext, MsiFacts, MsiInfo, MsiKeyPath, OsInfo, ProgramId, RawFlags, Root, RootKind,
    RootSource, ScanMode, SourceTrust, Target, Tier, TimeWindow, VerifyGone, View, WritableBy,
};
use purge_policy::band::{PolicyCtx, TargetScope, decide};
use purge_scan::framework::{AppIdentityView, OtherApps, ScanCtx, ScanExt, ScanLimits, Scanner};
use purge_source::fixture::Fixture;
use purge_source::sysobj::MsiTables;
use purge_source::types::{KnownFolder, MsiProduct, RegData};

pub const SID: &str = GuardEnv::SAMPLE_SID;
pub const ROOT: &str = r"C:\Program Files\App";
pub const SERIAL: u32 = 0x1234_5678;
const EDITION: &str = "Professional";
const BUILD: u32 = 26340;
const UBR: u32 = 9882;

/// The app's own MSI product.
pub const OWN: &str = "{70707070-0000-0000-0000-000000000001}";
/// Its UpgradeCode.
pub const UPGRADE: &str = "{80808080-0000-0000-0000-000000000002}";
/// Another installed product.
pub const OTHER: &str = "{22222222-2222-2222-2222-222222222222}";
/// A product code that is in no fingerprint.
pub const FAKE: &str = "{99999999-0000-0000-0000-000000000009}";
/// A component only the app's product is a client of, keyed on the app's exe.
pub const C1: &str = "{C1C1C1C1-0000-0000-0000-000000000001}";
/// A component the app's product shares with `OTHER`, keyed on a file outside the root.
pub const C2: &str = "{C2C2C2C2-0000-0000-0000-000000000002}";
pub const LP_OTHER: &str = r"C:\Windows\Installer\other.msi";

pub const CLASSES: &str = r"HKLM\SOFTWARE\Classes\Installer";
pub const UPGRADE_CODES: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes";
pub const FOLDERS: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders";
pub const SHARED: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs";
pub const SHARED32: &str = r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs";

pub fn packed(guid: &str) -> String {
    pack_guid(guid).expect("test GUID")
}

pub fn file(name: &str) -> String {
    format!(r"{ROOT}\{name}")
}

/// The app's fingerprint, without MSI facts (see [`own_msi`]).
fn fingerprint() -> Fingerprint {
    Fingerprint {
        baseline_view: None,
        schema: FingerprintSchema,
        app: AppRef {
            program_id: ProgramId::machine(View::K64, "App").unwrap(),
            display_name: "App".into(),
        },
        identity: IdentitySnapshot {
            names: vec!["App".into()],
            vendors: vec!["App Vendor".into()],
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
            path: file("app.exe"),
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

/// The harvest's record of `OWN` (per-machine, with its UpgradeCode and both components).
pub fn own_msi() -> MsiFacts {
    MsiFacts {
        product_code: OWN.into(),
        packed_code: packed(OWN),
        upgrade_code: Some(UPGRADE.into()),
        context: MsiContext::Machine,
        user_sid: None,
        local_package: Some(r"C:\Windows\Installer\own.msi".into()),
        package_readable: true,
        components: vec![
            MsiComponentFact {
                component_id: C1.into(),
                key_path: MsiKeyPath::File {
                    path: file("app.exe"),
                },
                other_clients: Vec::new(),
                shared_dll: false,
            },
            MsiComponentFact {
                component_id: C2.into(),
                key_path: MsiKeyPath::File {
                    path: r"C:\Program Files\Common\shared.dll".into(),
                },
                other_clients: vec![packed(OTHER)],
                shared_dll: false,
            },
        ],
        registry_rows: Vec::new(),
        services: Vec::new(),
        source_dirs: Vec::new(),
        custom_actions: 0,
        unresolved_rows: 0,
    }
}

/// An inventory entry for the installed product `code`.
pub fn msi_entry(code: &str, local_package: &str) -> InventoryEntry {
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

/// `UserData\<sid>\Components\<C>`.
pub fn component_key(sid: &str, component: &str) -> String {
    format!(r"{USERDATA}\{sid}\Components\{}", packed(component))
}

/// The machine after the app's uninstaller ran and left all of `OWN`'s registration behind. The app's
/// root still exists (with its exe); `OTHER` is installed.
pub fn machine() -> Fixture {
    let mut fx = Fixture::builder()
        .os(EDITION, BUILD, UBR)
        .user_sid(SID)
        .volume(r"C:\", Some(SERIAL), true, "NTFS")
        .dir(r"C:\Program Files")
        .dir(ROOT)
        .file(&file("app.exe"), 10)
        .file(r"C:\Program Files\Common\shared.dll", 10)
        .known_folder(KnownFolder::ProgramFiles, r"C:\Program Files")
        .known_folder(KnownFolder::ProgramFilesX86, r"C:\Program Files (x86)")
        .known_folder(KnownFolder::Windows, r"C:\Windows")
        .key(&format!(r"HKU\{SID}\Software"))
        .build();
    fx.set_current_control_set(1);
    // Windows Installer knows OTHER only.
    fx.set_msi_products(Some(vec![MsiProduct {
        code: OTHER.into(),
        context: MsiContext::Machine,
        user_sid: None,
        name: Some("Other".into()),
        version: None,
        publisher: None,
        install_location: None,
        install_date: None,
        local_package: Some(LP_OTHER.into()),
    }]));
    fx.set_msi_tables_captured(true);
    fx.set_msi_tables(LP_OTHER, MsiTables::default());

    let p = packed(OWN);
    let o = packed(OTHER);
    let u = packed(UPGRADE);
    // OWN's keys.
    for key in [
        format!(r"{USERDATA}\{MACHINE_SID}\Products\{p}\InstallProperties"),
        format!(r"{CLASSES}\Products\{p}\SourceList"),
        format!(r"{CLASSES}\Features\{p}"),
    ] {
        fx.add_key(&key);
    }
    fx.set_value(
        &format!(r"{USERDATA}\{MACHINE_SID}\Products\{p}\InstallProperties"),
        "DisplayName",
        RegData::from_sz("App"),
    );
    fx.set_value(
        &format!(r"{CLASSES}\Features\{p}"),
        "Main",
        RegData::from_sz(""),
    );
    // OTHER's keys, side by side.
    fx.add_key(&format!(
        r"{USERDATA}\{MACHINE_SID}\Products\{o}\InstallProperties"
    ));
    fx.add_key(&format!(r"{CLASSES}\Products\{o}"));
    // The UpgradeCodes: OWN alone under its code.
    for base in [UPGRADE_CODES, &format!(r"{CLASSES}\UpgradeCodes")] {
        fx.set_value(&format!(r"{base}\{u}"), &p, RegData::from_sz(""));
    }
    // Components.
    fx.set_value(
        &component_key(MACHINE_SID, C1),
        &p,
        RegData::from_sz(&file("app.exe")),
    );
    for client in [&p, &o] {
        fx.set_value(
            &component_key(MACHINE_SID, C2),
            client,
            RegData::from_sz(r"C:\Program Files\Common\shared.dll"),
        );
    }
    fx
}

/// Everything a [`ScanCtx`] borrows.
pub struct World {
    pub fixture: Fixture,
    pub fp: Fingerprint,
    pub inventory: Vec<InventoryEntry>,
    pub baseline: BaselineView,
    env: BTreeMap<String, String>,
    pub guard: GuardEnv,
    pub other_apps: OtherApps,
    pub ext: ScanExt,
}

impl World {
    /// [`machine`] with the app's MSI record and the ownership index built.
    pub fn new() -> Self {
        Self::with(machine())
    }

    pub fn with(fixture: Fixture) -> Self {
        let mut fp = fingerprint();
        fp.msi.push(own_msi());
        let header = format!("#purge-baseline 1\tT\tPC\t{EDITION}\t{BUILD}.{UBR}\n");
        let mut world = Self {
            fixture,
            fp,
            inventory: vec![msi_entry(OTHER, LP_OTHER)],
            baseline: BaselineView::exact(
                Baseline::from_bytes(header.as_bytes()).expect("baseline parses"),
            ),
            env: BTreeMap::new(),
            guard: GuardEnv::sample(),
            other_apps: OtherApps::default(),
            ext: ScanExt::new(Default::default(), Default::default()),
        };
        world.reindex();
        world
    }

    /// Builds the ownership index again over the fixture and the inventory, as the pipeline does.
    pub fn reindex(&mut self) {
        let ownership = OwnershipIndex::build(&OwnershipInput {
            reg: &self.fixture,
            fs: &self.fixture,
            sys: &self.fixture,
            products: &self.inventory,
            msi_only: &[],
            cache: None,
            threads: 1,
        });
        self.ext = ScanExt::new(ownership, Default::default());
    }

    pub fn ctx(&self) -> ScanCtx<'_> {
        ScanCtx {
            reg: &self.fixture,
            fs: &self.fixture,
            sys: &self.fixture,
            fp: &self.fp,
            baseline: &self.baseline,
            mode: ScanMode::Post,
            verify_gone: Some(VerifyGone::new(true, true, true)),
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
        out
    }

    /// The candidate on `target`, if any (at most one).
    pub fn find(&self, scanner: &dyn Scanner, target: &Target) -> Option<Candidate> {
        let mut found: Vec<Candidate> = self
            .run(scanner)
            .into_iter()
            .filter(|c| self.ctx().same_target(&c.target, target))
            .collect();
        assert!(found.len() <= 1, "one candidate per target: {found:?}");
        found.pop()
    }

    pub fn get(&self, scanner: &dyn Scanner, target: &Target) -> Candidate {
        self.find(scanner, target)
            .unwrap_or_else(|| panic!("a candidate for {target:?}"))
    }

    /// Removes the app's root (and the exe in it).
    pub fn remove_root(&mut self) {
        assert!(
            self.fixture.remove_path(ROOT),
            "the root was in the fixture"
        );
    }
}

pub fn key(path: &str) -> Target {
    Target::RegKey { path: path.into() }
}

pub fn value(path: &str, name: &str) -> Target {
    Target::RegValue {
        path: path.into(),
        name: name.into(),
    }
}

/// The band and preselection the policy gives.
pub fn band(c: &Candidate) -> (Band, bool) {
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

/// Whether the candidate carries Tier A `InstallerManifest(Msi)`.
pub fn has_msi_manifest(c: &Candidate) -> bool {
    c.evidence
        .iter()
        .any(|e| e.kind == EvidenceKind::InstallerManifest(ManifestKind::Msi) && e.tier == Tier::A)
}

/// The guard's verdict with `gone` as the gone MSI products (packed).
pub fn guard_check(w: &World, target: &Target, gone: &[String]) -> Option<Blocker> {
    deny::check(
        target,
        &w.guard,
        &Exemptions {
            gone_msi_products: gone,
            ..Default::default()
        },
    )
}
