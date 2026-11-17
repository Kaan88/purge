//! FS-PKGCACHE.

use std::sync::Mutex;

use purge_model::{
    Action, Band, Candidate, Category, EvidenceKind, ManifestKind, MsiContext, MsiFacts, Scope,
    Target, Tier,
};
use purge_scan::framework::{AppIdentityView, ScanCtx};
use purge_scan::fs_pkgcache::FsPkgCache as Scanner;
use purge_source::filesystem::FileSystemSource;
use purge_source::types::{
    DirEntry, ExistsState, FileMeta, MsiProductState, ShortcutInfo, SourceResult, VersionInfo,
    VolumeInfo,
};

use crate::world::*;

fn run(w: &World) -> Vec<Candidate> {
    w.run(&Scanner)
}

fn bundle_dir() -> Target {
    dir(format!(r"{CACHE}\{BUNDLE}"))
}

fn core_dir() -> Target {
    dir(format!(r"{CACHE}\{CORE}v1.0.0.0"))
}

fn has_manifest(c: &Candidate, kind: ManifestKind) -> bool {
    c.evidence.iter().any(|e| {
        e.kind == EvidenceKind::InstallerManifest(kind)
            && e.tier == Tier::A
            && e.scope == Scope::Path
    })
}

#[test]
fn pkgcache_bundle_dir_safe_when_gone() {
    let w = World::new();
    let found = run(&w);
    let c = find(&found, &bundle_dir()).expect("the bundle's cache directory");
    assert_eq!(c.action, Action::Quarantine);
    assert_eq!(c.category, Category::Package);
    assert_eq!(c.scanner, "FS-PKGCACHE");
    assert!(has_manifest(c, ManifestKind::Burn), "{:?}", c.evidence);
    assert_eq!(c.size_bytes, Some(1024));
    assert_eq!(c.child_count, Some(2));
    assert!(c.blockers.is_empty(), "{:?}", c.blockers);
    assert_eq!(band(c), (Band::Safe, true));

    // A package whose product is gone and that nothing else keeps goes too, in the bundle's own cache.
    let core = find(&found, &core_dir()).expect("the Core package's directory");
    assert_eq!(band(core), (Band::Safe, true));
    // R3a S4: a machine bundle's own cache is the machine's; a user's Package Cache holds that user's
    // install, never this bundle's leftover.
    assert!(find(&found, &dir(format!(r"{USER_CACHE}\{USER_PART}v1.0.0.0"))).is_none());

    // A recorded directory that no longer exists is not offered.
    let mut w = World::new();
    assert!(w.fixture.remove_path(&format!(r"{CACHE}\{BUNDLE}")));
    assert!(find(&run(&w), &bundle_dir()).is_none());
}

/// R3a S4: a per-user bundle's own cache is its user's `%LOCALAPPDATA%\Package Cache`; the machine's
/// Package Cache holds another (machine) install of the same packages, never this bundle's leftover.
#[test]
fn pkgcache_per_user_bundle_only_its_own_cache() {
    let w = World::new().per_user();
    let found = run(&w);
    let user = find(&found, &dir(format!(r"{USER_CACHE}\{USER_PART}v1.0.0.0")))
        .expect("the per-user package's directory");
    assert_eq!(user.action, Action::Quarantine);
    assert!(find(&found, &core_dir()).is_none(), "{found:?}");
    assert!(find(&found, &bundle_dir()).is_none(), "{found:?}");
}

#[test]
fn pkgcache_package_dir_kept_when_product_installed() {
    let w = World::new();
    let found = run(&w);
    for kept in [
        format!(r"{CACHE}\{LAUNCHER}v3.12.7150.0"),
        format!(r"{CACHE}\{VC}v14.44.35211"),
    ] {
        assert!(find(&found, &dir(kept.clone())).is_none(), "{kept}");
    }

    // The Core product comes back (reinstalled by itself): its directory stays.
    let mut w = World::new();
    w.fixture
        .set_msi_state(CORE, MsiContext::Machine, MsiProductState::Default);
    assert!(find(&run(&w), &core_dir()).is_none());

    // The harvest saw another dependent of Core: its directory stays.
    let mut w = World::new();
    w.burn_mut().packages[0].other_dependents = vec![OTHER_BUNDLE.into()];
    assert!(find(&run(&w), &core_dir()).is_none());

    // The ownership index could not read its Burn area: the dependents are unknown, nothing goes.
    let mut w = World::new();
    w.fixture.add_denied(DEPS);
    w.reindex();
    let found = run(&w);
    assert!(find(&found, &core_dir()).is_none());
    // The bundle's own directory does not depend on the packages' dependents.
    assert!(find(&found, &bundle_dir()).is_some());

    // The same directory recorded as an MSI source directory of a kept product is not offered either.
    let mut w = World::new();
    w.fp.msi.push(msi_facts(
        LAUNCHER,
        vec![format!(r"{CACHE}\{LAUNCHER}v3.12.7150.0")],
    ));
    assert!(find(&run(&w), &dir(format!(r"{CACHE}\{LAUNCHER}v3.12.7150.0"))).is_none());
}

/// Hostile: the recorded cache path climbs out of the Package Cache. Only direct children of a cache
/// root count, in their canonical form.
#[test]
fn pkgcache_dir_not_direct_child_ignored() {
    let mut w = World::new();
    w.burn_mut().cache_path = Some(format!(r"{CACHE}\..\x"));
    w.burn_mut().packages[0].cache_dir = Some(format!(r"{CACHE}\{CORE}v1.0.0.0\core.msi"));
    let found = run(&w);
    assert!(
        found
            .iter()
            .all(|c| !matches!(&c.target, Target::Path { path }
            if path.to_lowercase().contains(r"programdata\x"))),
        "{found:?}"
    );
    assert!(find(&found, &bundle_dir()).is_none());
    assert!(find(&found, &core_dir()).is_none());
    assert!(find(&found, &dir(format!(r"{CACHE}\{CORE}v1.0.0.0\core.msi"))).is_none());
    // The other recorded directories are not affected.
    let mut w = World::new();
    w.burn_mut().cache_path = Some(format!(r"{CACHE}\..\x"));
    assert!(find(&run(&w), &core_dir()).is_some());

    // Not under a cache root at all.
    let mut w = World::new();
    w.burn_mut().cache_path = Some(r"C:\ProgramData\x".into());
    assert!(find(&run(&w), &dir(r"C:\ProgramData\x")).is_none());

    // A short-name spelling the guard cannot vouch for.
    let mut w = World::new();
    w.burn_mut().cache_path = Some(format!(r"C:\ProgramData\PACKAG~1\{BUNDLE}"));
    assert!(find(&run(&w), &bundle_dir()).is_none());
}

/// A file system that remembers every directory listed.
struct Recording<'a> {
    inner: &'a dyn FileSystemSource,
    listed: Mutex<Vec<String>>,
}

impl FileSystemSource for Recording<'_> {
    fn metadata(&self, path: &str) -> SourceResult<FileMeta> {
        self.inner.metadata(path)
    }
    fn list_dir(&self, path: &str) -> SourceResult<Vec<DirEntry>> {
        self.listed.lock().unwrap().push(path.to_owned());
        self.inner.list_dir(path)
    }
    fn exists(&self, path: &str) -> ExistsState {
        self.inner.exists(path)
    }
    fn read_bytes(&self, path: &str, max: usize) -> SourceResult<Vec<u8>> {
        self.inner.read_bytes(path, max)
    }
    fn long_path(&self, path: &str) -> SourceResult<String> {
        self.inner.long_path(path)
    }
    fn volume_info(&self, path: &str) -> SourceResult<VolumeInfo> {
        self.inner.volume_info(path)
    }
    fn version_info(&self, path: &str) -> SourceResult<Option<VersionInfo>> {
        self.inner.version_info(path)
    }
    fn signer_cn(&self, path: &str) -> SourceResult<Option<String>> {
        self.inner.signer_cn(path)
    }
    fn read_shortcut(&self, path: &str) -> SourceResult<ShortcutInfo> {
        self.inner.read_shortcut(path)
    }
    fn is_admin_only_writable(&self, path: &str) -> SourceResult<bool> {
        self.inner.is_admin_only_writable(path)
    }
}

/// R2a S7 (hostile): a recorded path naming another bundle's or product's folder of the cache (a
/// fingerprint written before the harvest tied the folders, or a user-writable record) gives nothing:
/// the folder's name must be the bundle id or the product's code.
#[test]
fn pkgcache_recorded_foreign_folder_not_offered() {
    let foreign = format!(r"{CACHE}\{FOREIGN}v2.0");
    let mut w = World::new();
    w.burn_mut().cache_path = Some(foreign.clone());
    w.burn_mut().packages[0].cache_dir = Some(foreign.clone());
    w.fp.msi.push(msi_facts(CORE, vec![foreign.clone()]));
    let found = run(&w);
    assert!(find(&found, &dir(foreign.clone())).is_none(), "{found:?}");
    // The foreign folder exists: it is the name that keeps it out.
    assert!(w.fixture.metadata(&foreign).is_ok());
}

/// Trap `pkgcache-foreign`: a Package Cache directory named by another product's code, as Burn names
/// it. Nothing records it for the app, and the Package Cache is never listed, so it is never seen.
#[test]
fn pkgcache_foreign_dir_never_listed() {
    let w = World::new();
    let fs = Recording {
        inner: &w.fixture,
        listed: Mutex::new(Vec::new()),
    };
    let ctx = ScanCtx { fs: &fs, ..w.ctx() };
    let app = AppIdentityView::from_fingerprint(&w.fp, &w.env);
    let found = ctx.run(&Scanner, &app);
    assert!(!found.is_empty());
    assert!(
        found
            .iter()
            .all(|c| !format!("{:?}", c.target).contains(FOREIGN)),
        "{found:?}"
    );
    let listed = fs.listed.lock().unwrap();
    for root in [CACHE, USER_CACHE] {
        assert!(
            listed
                .iter()
                .all(|l| !l.trim_end_matches('\\').eq_ignore_ascii_case(root)),
            "{root} was listed: {listed:?}"
        );
    }
    // What is listed is only the inside of offered directories (their size and file count).
    for l in listed.iter() {
        assert!(
            found
                .iter()
                .any(|c| matches!(&c.target, Target::Path { path }
                if l.to_lowercase().starts_with(&path.to_lowercase()))),
            "{l} listed outside an offered directory"
        );
    }
}

#[test]
fn pkgcache_root_never() {
    let mut w = World::new();
    w.burn_mut().cache_path = Some(CACHE.into());
    w.burn_mut().packages[0].cache_dir = Some(format!(r"{USER_CACHE}\"));
    w.fp.msi.push(msi_facts(CORE, vec![format!(r"{CACHE}\")]));
    let found = run(&w);
    for root in [CACHE, USER_CACHE] {
        assert!(find(&found, &dir(root)).is_none(), "{root}: {found:?}");
    }
    assert!(
        found.iter().all(|c| match &c.target {
            Target::Path { path } =>
                path.to_lowercase().matches("package cache").count() == 1
                    && !path.to_lowercase().ends_with("package cache"),
            _ => false,
        }),
        "{found:?}"
    );
}

#[test]
fn msi_source_dir_of_gone_product_offered() {
    let mut w = World::new();
    w.fp.msi
        .push(msi_facts(CORE, vec![format!(r"{CACHE}\{CORE}v1.0.0.0\")]));
    let found = run(&w);
    let c = find(&found, &core_dir()).expect("the Core directory, once");
    assert!(has_manifest(c, ManifestKind::Burn));
    assert!(has_manifest(c, ManifestKind::Msi));

    // An MSI-only app (no bundle): the product is gone, its source directory goes.
    let mut w = World::new();
    w.fp.burn = None;
    w.fp.msi
        .push(msi_facts(CORE, vec![format!(r"{CACHE}\{CORE}v1.0.0.0")]));
    let found = run(&w);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(has_manifest(&found[0], ManifestKind::Msi));
}

fn msi_facts(code: &str, source_dirs: Vec<String>) -> MsiFacts {
    MsiFacts {
        product_code: code.into(),
        packed_code: purge_index::ownership::pack_guid(code).unwrap(),
        upgrade_code: None,
        context: MsiContext::Machine,
        user_sid: None,
        local_package: None,
        package_readable: true,
        components: Vec::new(),
        registry_rows: Vec::new(),
        services: Vec::new(),
        source_dirs,
        custom_actions: 0,
        unresolved_rows: 0,
    }
}
