//! Fixtures shared by the round-trip and crash tests. Everything runs unelevated: files live in a
//! fresh directory below the temp directory, registry items below a fresh
//! `HKU\<current SID>\Software\PurgeTest-<random>` key, and both are removed on drop. Packages, the
//! Restart Manager, the restore point and the boot-time move list are stand-ins: no package is
//! installed or removed, no restore point is requested, and `HKLM` is never written.

#![allow(dead_code)]

use std::cell::RefCell;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use purge_exec::act_fs::{RETRY_DELAYS, Retry};
use purge_exec::act_typed::{ListError, PackageBackend, PackageInfo};
use purge_exec::execute::{ExecEnv, ExecOutput, execute};
use purge_exec::journal::{self, JournalRead};
use purge_exec::locked::MemoryPendingRenames;
use purge_exec::plan_in::{ExecRequest, ExecSettings, Selection, confirm_hash, selection_hash};
use purge_exec::prepare::{LockerQuery, RestorePointBackend, RestorePointSetting};
use purge_exec::recover::{RecoverEnv, RecoverOutput};
use purge_exec::storage::{SessionDir, StorageRoots};
use purge_exec::undo::{UndoEnv, UndoOutput, UndoRequest, UndoSelection, undo};
use purge_guard::canon::{GuardEnv, ProfileEnv};
use purge_guard::deny::DenyList;
use purge_model::exec::op::{Inverse, ItemOutcome, OpId};
use purge_model::exec::session::{SessionId, SessionSummary};
use purge_model::{
    Action, AppRef, Band, Candidate, CandidateId, Category, Decision, Harm, Origin, Reversibility,
    ScanMode, Target, Tool,
};
use purge_plan::emit::{ScanDoc, ScanSchema};
use purge_win::appx::{AppxPackage, SignatureKind};
use purge_win::appx_write::{RemovalScope, RemoveOutcome};
use purge_win::fs::FileHandle;
use purge_win::os::Win32Error;
use purge_win::reg::{RegRoot, RegView};
use purge_win::reg_write::{KeyAccess, WKey};
use purge_win::rm::{LockerList, RebootReasons};
use purge_win::sid::current_user_sid;
use purge_win::sr::SrOutcome;

// ---------------------------------------------------------------------------------------------------
// Scratch directories
// ---------------------------------------------------------------------------------------------------

static COUNTER: AtomicU32 = AtomicU32::new(0);

pub fn unique(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "{tag}-{:x}-{nanos:x}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// The `\\?\` form of an absolute path.
pub fn ext(path: &str) -> PathBuf {
    purge_win::secure::extended_path(Path::new(path)).unwrap()
}

pub fn exists(path: &str) -> bool {
    std::fs::symlink_metadata(ext(path)).is_ok()
}

/// A fresh directory below the temp directory (its final, long-form path), removed on drop.
pub struct Scratch {
    pub root: String,
    owned: bool,
}

impl Scratch {
    pub fn new(tag: &str) -> Scratch {
        let dir = std::env::temp_dir().join(unique(&format!("purge-xundo-{tag}")));
        std::fs::create_dir(&dir).unwrap();
        let mut scratch = Scratch::at(&dir);
        scratch.owned = true;
        scratch
    }

    /// The scratch directory `dir`, which exists and belongs to someone else (a child process works in
    /// its parent's directory and must not remove it).
    pub fn at(dir: &Path) -> Scratch {
        let final_path = FileHandle::open(dir).unwrap().final_path().unwrap();
        let root = final_path
            .strip_prefix(r"\\?\")
            .unwrap_or(&final_path)
            .to_owned();
        Scratch { root, owned: false }
    }

    pub fn path(&self, rel: &str) -> String {
        format!(r"{}\{rel}", self.root)
    }

    pub fn dir(&self, rel: &str) -> String {
        let p = self.path(rel);
        std::fs::create_dir_all(ext(&p)).unwrap();
        p
    }

    pub fn file(&self, rel: &str, data: &[u8]) -> String {
        let p = self.path(rel);
        std::fs::create_dir_all(ext(&p).parent().unwrap()).unwrap();
        std::fs::write(ext(&p), data).unwrap();
        p
    }
}

/// Clears the read-only attribute of everything below `dir`, so that it can be removed.
fn make_writable(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            let mut permissions = meta.permissions();
            if permissions.readonly() {
                #[allow(clippy::permissions_set_readonly_false)]
                permissions.set_readonly(false);
                let _ = std::fs::set_permissions(&path, permissions);
            }
            if meta.is_dir() {
                make_writable(&path);
            }
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if self.owned {
            make_writable(&ext(&self.root));
            let _ = std::fs::remove_dir_all(ext(&self.root));
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Snapshots of files
// ---------------------------------------------------------------------------------------------------

/// Everything a round trip must bring back about one file or directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSnap {
    /// The path below the snapshot root (`""` for the root).
    pub rel: String,
    pub is_dir: bool,
    pub attributes: u32,
    /// The bytes of the unnamed stream; `None` for a directory.
    pub data: Option<Vec<u8>>,
    /// The NTFS file id.
    pub id: [u8; 16],
    pub n_links: u32,
    pub created: u64,
    /// Last write time; 0 for a directory (moving its children changes it).
    pub written: u64,
    /// Every alternate data stream with its bytes.
    pub streams: Vec<(String, Vec<u8>)>,
    /// The security descriptor.
    pub sddl: String,
}

fn sddl_of(path: &Path) -> String {
    const READ_CONTROL: u32 = 0x0002_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let file = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .unwrap();
    purge_win::secure::handle_sddl(&file).unwrap()
}

fn snap_one(root: &str, rel: &str) -> FileSnap {
    let full = if rel.is_empty() {
        root.to_owned()
    } else {
        format!(r"{root}\{rel}")
    };
    let path = ext(&full);
    let meta = FileHandle::open(&path).unwrap().metadata().unwrap();
    let streams = purge_win::fs_write::list_streams(&path)
        .unwrap()
        .into_iter()
        .filter(|stream| stream.name != "::$DATA")
        .map(|stream| {
            let name = stream.name.trim_end_matches(":$DATA").to_owned();
            let data = std::fs::read(format!("{}{name}", path.display())).unwrap();
            (name, data)
        })
        .collect();
    FileSnap {
        rel: rel.to_owned(),
        is_dir: meta.is_dir,
        attributes: meta.attributes,
        data: (!meta.is_dir).then(|| std::fs::read(&path).unwrap()),
        id: meta.file_id.id,
        n_links: meta.n_links,
        created: meta.creation_time,
        written: if meta.is_dir { 0 } else { meta.last_write_time },
        streams,
        sddl: sddl_of(&path),
    }
}

fn snap_into(root: &str, rel: &str, out: &mut Vec<FileSnap>) {
    let snap = snap_one(root, rel);
    let is_dir = snap.is_dir;
    out.push(snap);
    if !is_dir {
        return;
    }
    let full = if rel.is_empty() {
        root.to_owned()
    } else {
        format!(r"{root}\{rel}")
    };
    let mut names: Vec<String> = std::fs::read_dir(ext(&full))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    for name in names {
        let child = if rel.is_empty() {
            name
        } else {
            format!(r"{rel}\{name}")
        };
        snap_into(root, &child, out);
    }
}

/// The tree below `root` (which exists), in a fixed order; empty when `root` does not exist.
pub fn snap_tree(root: &str) -> Vec<FileSnap> {
    let mut out = Vec::new();
    if exists(root) {
        snap_into(root, "", &mut out);
    }
    out
}

/// The snapshot without what a recreated directory cannot keep: its file id.
pub fn without_dir_ids(mut tree: Vec<FileSnap>) -> Vec<FileSnap> {
    for snap in &mut tree {
        if snap.is_dir {
            snap.id = [0; 16];
        }
    }
    tree
}

// ---------------------------------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------------------------------

/// A fresh `HKU\<SID>\Software\PurgeTest-<random>` key, removed with everything below it on drop.
pub struct TestKey {
    pub sid: String,
    pub name: String,
    owned: bool,
}

/// One key of a registry snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySnap {
    /// The path below the test key (`""` for the test key itself).
    pub rel: String,
    pub class: String,
    pub volatile: bool,
    pub sddl: String,
    /// Name, type and raw bytes of every value, by name.
    pub values: Vec<(String, u32, Vec<u8>)>,
}

impl TestKey {
    pub fn new() -> TestKey {
        let sid = current_user_sid().unwrap();
        let name = unique("PurgeTest");
        WKey::open(
            RegRoot::Hku,
            &format!(r"{sid}\Software"),
            RegView::K64,
            KeyAccess::CREATE_SUB_KEY,
        )
        .unwrap()
        .create_subkey(&name, "", None, false)
        .unwrap();
        TestKey {
            sid,
            name,
            owned: true,
        }
    }

    /// The test key named `name`, which exists and belongs to someone else.
    pub fn at(name: &str) -> TestKey {
        TestKey {
            sid: current_user_sid().unwrap(),
            name: name.to_owned(),
            owned: false,
        }
    }

    /// The path below `HKU`.
    pub fn rel(&self, sub: &str) -> String {
        let base = format!(r"{}\Software\{}", self.sid, self.name);
        if sub.is_empty() {
            base
        } else {
            format!(r"{base}\{sub}")
        }
    }

    /// The canonical wire spelling.
    pub fn wire(&self, sub: &str) -> String {
        format!(r"HKU\{}", self.rel(sub))
    }

    pub fn open(&self, sub: &str, access: KeyAccess) -> WKey {
        WKey::open(RegRoot::Hku, &self.rel(sub), RegView::K64, access).unwrap()
    }

    pub fn exists(&self, sub: &str) -> bool {
        match WKey::open(RegRoot::Hku, &self.rel(sub), RegView::K64, KeyAccess::READ) {
            Ok(_) => true,
            Err(e) if e.is_not_found() => false,
            Err(e) => panic!("open {sub}: {e:?}"),
        }
    }

    /// Creates `sub` (and the keys above it) below the root.
    pub fn create(&self, sub: &str) {
        let mut at = String::new();
        for part in sub.split('\\') {
            let parent = self.open(&at, KeyAccess::CREATE_SUB_KEY);
            match parent.create_subkey(part, "", None, false) {
                Ok(_) => {}
                Err(e) if e == purge_win::reg_write::ALREADY_EXISTS => {}
                Err(e) => panic!("create {part}: {e:?}"),
            }
            at = if at.is_empty() {
                part.to_owned()
            } else {
                format!(r"{at}\{part}")
            };
        }
    }

    /// Creates the key `leaf` below the existing key `parent` with a class, a security descriptor and
    /// a volatility of its own.
    pub fn create_with(
        &self,
        parent: &str,
        leaf: &str,
        class: &str,
        sddl: Option<&str>,
        volatile: bool,
    ) {
        self.open(parent, KeyAccess::CREATE_SUB_KEY)
            .create_subkey(leaf, class, sddl, volatile)
            .unwrap();
    }

    pub fn set(&self, sub: &str, name: &str, ty: u32, data: &[u8]) {
        self.open(sub, KeyAccess::SET_VALUE)
            .set_value_raw(name, ty, data)
            .unwrap();
    }

    /// Type and raw bytes of a value, `None` when it is absent.
    pub fn get(&self, sub: &str, name: &str) -> Option<(u32, Vec<u8>)> {
        self.open(sub, KeyAccess::READ)
            .value(name)
            .unwrap()
            .map(|v| (v.ty, v.data))
    }

    fn snap_into(&self, rel: &str, out: &mut Vec<KeySnap>) {
        let key = self.open(rel, KeyAccess::READ);
        let mut values: Vec<(String, u32, Vec<u8>)> = key
            .values()
            .unwrap()
            .into_iter()
            .map(|v| (v.name, v.ty, v.data))
            .collect();
        values.sort();
        out.push(KeySnap {
            rel: rel.to_owned(),
            class: key.info().unwrap().class,
            volatile: key.flags().unwrap().volatile,
            sddl: key.security_sddl().unwrap(),
            values,
        });
        let mut names = key.subkey_names().unwrap();
        names.sort();
        for name in names {
            let child = if rel.is_empty() {
                name
            } else {
                format!(r"{rel}\{name}")
            };
            self.snap_into(&child, out);
        }
    }

    /// Every key below (and including) the test key: class, volatility, security and values.
    pub fn snap(&self) -> Vec<KeySnap> {
        let mut out = Vec::new();
        self.snap_into("", &mut out);
        out
    }

    /// Puts the test key back to `snap` (a [`TestKey::snap`] of it): every key below it is removed and
    /// its values deleted, then the keys of the snapshot are created again, parent-first, with their
    /// class and volatility and inherited security (as [`TestKey::create`] leaves it), and every key's
    /// values set.
    pub fn restore_snap(&self, snap: &[KeySnap]) {
        let root = self.open("", KeyAccess::DELETE | KeyAccess::SET_VALUE);
        for sub in root.subkey_names().unwrap() {
            Self::nuke(&root.open_subkey(&sub, KeyAccess::DELETE).unwrap());
        }
        for value in root.values().unwrap() {
            root.delete_value(&value.name).unwrap();
        }
        for key in snap {
            if !key.rel.is_empty() {
                let (parent, leaf) = key.rel.rsplit_once('\\').unwrap_or(("", &key.rel));
                self.create_with(parent, leaf, &key.class, None, key.volatile);
            }
            for (name, ty, data) in &key.values {
                self.set(&key.rel, name, *ty, data);
            }
        }
    }

    fn nuke(key: &WKey) {
        for sub in key.subkey_names().unwrap_or_default() {
            if let Ok(child) = key.open_subkey(&sub, KeyAccess::DELETE) {
                Self::nuke(&child);
            }
        }
        let _ = key.delete();
    }
}

impl Drop for TestKey {
    fn drop(&mut self) {
        if !self.owned {
            return;
        }
        if let Ok(root) = WKey::open(RegRoot::Hku, &self.rel(""), RegView::K64, KeyAccess::DELETE) {
            Self::nuke(&root);
        }
    }
}

/// A registry snapshot as JSON, for a child process to hand to its parent.
pub fn snap_json(snap: &[KeySnap]) -> String {
    let keys: Vec<serde_json::Value> = snap
        .iter()
        .map(|key| {
            serde_json::json!({
                "rel": key.rel,
                "class": key.class,
                "volatile": key.volatile,
                "sddl": key.sddl,
                "values": key.values,
            })
        })
        .collect();
    serde_json::Value::Array(keys).to_string()
}

/// The snapshot [`snap_json`] wrote.
pub fn snap_from_json(text: &str) -> Vec<KeySnap> {
    let keys: Vec<serde_json::Value> = serde_json::from_str(text).unwrap();
    keys.into_iter()
        .map(|key| KeySnap {
            rel: key["rel"].as_str().unwrap().to_owned(),
            class: key["class"].as_str().unwrap().to_owned(),
            volatile: key["volatile"].as_bool().unwrap(),
            sddl: key["sddl"].as_str().unwrap().to_owned(),
            values: serde_json::from_value(key["values"].clone()).unwrap(),
        })
        .collect()
}

/// The bytes of a NUL-terminated UTF-16 string.
pub fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// The bytes of a `REG_MULTI_SZ` holding `segments`.
pub fn multi_sz(segments: &[&str]) -> Vec<u8> {
    let mut data: Vec<u8> = segments.iter().flat_map(|s| utf16z(s)).collect();
    data.extend([0, 0]);
    data
}

// ---------------------------------------------------------------------------------------------------
// Stand-ins
// ---------------------------------------------------------------------------------------------------

pub const PACKAGE: &str = "Vendor.App_1.0.0.0_x64__abcdefghjkmnp";

pub fn package_info(full_name: &str) -> PackageInfo {
    PackageInfo {
        package: AppxPackage {
            full_name: full_name.to_owned(),
            family_name: "Vendor.App_abcdefghjkmnp".to_owned(),
            installed_location: Some(r"C:\Program Files\Vendor\App".to_owned()),
            effective_external_path: Some(r"C:\Program Files\Vendor\App".to_owned()),
            signature_kind: Some(SignatureKind::Developer),
            is_framework: false,
            is_resource_package: false,
            users: Vec::new(),
            dependencies: None,
        },
        dependencies: Some(Vec::new()),
    }
}

/// A package backend that lists [`PACKAGE`] while a marker file exists and "removes" it by deleting
/// the marker, so that what one process removed is gone for the next one too. Nothing real is listed
/// or removed.
pub struct FakePackages {
    marker: PathBuf,
    pub removed: RefCell<Vec<String>>,
}

impl FakePackages {
    pub fn new(marker: &str) -> FakePackages {
        FakePackages {
            marker: ext(marker),
            removed: RefCell::new(Vec::new()),
        }
    }

    pub fn install(&self) {
        std::fs::write(&self.marker, b"installed").unwrap();
    }

    pub fn installed(&self) -> bool {
        self.marker.exists()
    }
}

impl PackageBackend for FakePackages {
    fn list(&self, _: RemovalScope) -> Result<Vec<PackageInfo>, ListError> {
        Ok(if self.installed() {
            vec![package_info(PACKAGE)]
        } else {
            Vec::new()
        })
    }

    fn remove(&self, full_name: &str, _: RemovalScope) -> RemoveOutcome {
        self.removed.borrow_mut().push(full_name.to_owned());
        if full_name.eq_ignore_ascii_case(PACKAGE) && self.installed() {
            std::fs::remove_file(&self.marker).unwrap();
            RemoveOutcome::Removed
        } else {
            RemoveOutcome::NotFound
        }
    }
}

/// A Restart Manager stand-in: nothing holds anything.
#[derive(Default)]
pub struct FakeRm;

impl LockerQuery for FakeRm {
    fn query(&self, _: &[PathBuf]) -> Result<LockerList, Win32Error> {
        Ok(LockerList {
            lockers: Vec::new(),
            reboot_reasons: RebootReasons(0),
        })
    }
}

/// A restore-point backend that is never asked (the tests switch the restore point off).
pub struct FakeRestore;

impl RestorePointBackend for FakeRestore {
    fn create(&self, _: &str) -> SrOutcome {
        SrOutcome::Created { seq: 7 }
    }
}

fn env_var(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

/// A `GuardEnv` for this machine and user, with the test store's data root as one of Purge's directories.
pub fn live_env(data_root: &str) -> GuardEnv {
    let sid = current_user_sid().unwrap();
    let profile = env_var("USERPROFILE");
    let set = purge_win::reg::current_control_set().unwrap();
    GuardEnv {
        system_drive: env_var("SystemDrive"),
        windir: env_var("WINDIR"),
        program_files: env_var("ProgramW6432"),
        program_files_x86: Some(env_var("ProgramFiles(x86)")),
        program_data: env_var("ProgramData"),
        profiles_dir: Path::new(&profile)
            .parent()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
        profiles: vec![ProfileEnv {
            sid: sid.clone(),
            root: profile,
            appdata: env_var("APPDATA"),
            local_appdata: env_var("LOCALAPPDATA"),
            ..ProfileEnv::default()
        }],
        current_control_set: set.trim_start_matches("ControlSet").parse().unwrap(),
        loaded_sids: vec![sid],
        purge_dirs: vec![
            format!(r"{}\Purge", env_var("ProgramData")),
            data_root.to_owned(),
        ],
        ..GuardEnv::default()
    }
}

// ---------------------------------------------------------------------------------------------------
// The rig
// ---------------------------------------------------------------------------------------------------

/// Everything a run, an undo and a recovery need besides the request. The scratch directory drops
/// last.
pub struct Rig {
    pub roots: StorageRoots,
    pub deny: DenyList,
    pub packages: FakePackages,
    pub rm: FakeRm,
    pub pending: MemoryPendingRenames,
    pub s: Scratch,
}

fn fast_retry() -> Retry {
    Retry::with(RETRY_DELAYS.to_vec(), |_| {})
}

impl Rig {
    pub fn new(tag: &str) -> Rig {
        let s = Scratch::new(tag);
        let roots = StorageRoots::install_relaxed(Path::new(&s.path("data"))).unwrap();
        Rig::with(s, roots)
    }

    pub fn with(s: Scratch, roots: StorageRoots) -> Rig {
        let deny = DenyList::compile(&live_env(roots.data_root().to_str().unwrap()));
        Rig {
            roots,
            deny,
            packages: FakePackages::new(&s.path("package.installed")),
            rm: FakeRm,
            pending: MemoryPendingRenames::with_pairs(&[]),
            s,
        }
    }

    /// The environment of a run: no sleeping between retries, no waiting for the restore point.
    pub fn exec_env(&mut self) -> ExecEnv<'_> {
        ExecEnv {
            retry: fast_retry(),
            restore_point_wait: Duration::from_secs(5),
            restore_point_finish_wait: Duration::ZERO,
            ..ExecEnv::new(
                &self.roots,
                &self.deny,
                &self.packages,
                &self.rm,
                &mut self.pending,
            )
        }
    }

    pub fn run(&mut self, request: ExecRequest) -> ExecOutput {
        execute(request, self.exec_env(), FakeRestore).unwrap()
    }

    pub fn undo_env(&mut self) -> UndoEnv<'_> {
        UndoEnv {
            retry: fast_retry(),
            ..UndoEnv::new(&self.roots, &self.deny, &mut self.pending)
        }
    }

    pub fn undo(&mut self, session: &SessionId, selection: UndoSelection) -> UndoOutput {
        let request = UndoRequest {
            session: session.clone(),
            selection,
            plan_hash: None,
        };
        undo(&request, self.undo_env()).unwrap()
    }

    pub fn undo_all(&mut self, session: &SessionId) -> UndoOutput {
        self.undo(session, UndoSelection::All)
    }

    pub fn recover_env(&mut self) -> RecoverEnv<'_> {
        RecoverEnv {
            retry: fast_retry(),
            ..RecoverEnv::new(
                &self.roots,
                &self.deny,
                &self.packages,
                &self.rm,
                &mut self.pending,
            )
        }
    }

    pub fn resume(&mut self, session: &SessionId) -> RecoverOutput {
        purge_exec::recover::resume(session, self.recover_env()).unwrap()
    }

    pub fn rollback(&mut self, session: &SessionId) -> RecoverOutput {
        purge_exec::recover::rollback(session, self.recover_env()).unwrap()
    }

    pub fn sessions(&self) -> Vec<SessionId> {
        self.roots.list_sessions().unwrap().sessions
    }

    pub fn session(&self, id: &SessionId) -> SessionDir {
        self.roots.open_session(id).unwrap()
    }

    pub fn journal(&self, id: &SessionId) -> JournalRead {
        journal::read(&self.session(id)).unwrap()
    }

    /// The session's index entry.
    pub fn entry(&self, id: &SessionId) -> Option<SessionSummary> {
        self.roots.read_index().unwrap().get(id).cloned()
    }

    /// The bytes of every file of the store's `sessions` directory (the index, each journal, each
    /// backup, each report), by path: what "nothing changed" is checked on.
    pub fn store_files(&self) -> Vec<(String, Vec<u8>)> {
        fn walk(dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect();
            entries.sort();
            for path in entries {
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.push((path.display().to_string(), std::fs::read(&path).unwrap()));
                }
            }
        }
        let mut out = Vec::new();
        walk(
            &ext(&self.roots.sessions_path().display().to_string()),
            &mut out,
        );
        out
    }
}

// ---------------------------------------------------------------------------------------------------
// Plans
// ---------------------------------------------------------------------------------------------------

pub fn cid(id: &str) -> CandidateId {
    CandidateId(id.to_owned())
}

pub fn path(p: &str) -> Target {
    Target::Path { path: p.to_owned() }
}

pub fn key(p: &str) -> Target {
    Target::RegKey { path: p.to_owned() }
}

pub fn value(p: &str, name: &str) -> Target {
    Target::RegValue {
        path: p.to_owned(),
        name: name.to_owned(),
    }
}

pub fn segment(p: &str, name: &str, segment: &str) -> Target {
    Target::RegMultiSzSegment {
        path: p.to_owned(),
        name: name.to_owned(),
        segment: segment.to_owned(),
        index: None,
    }
}

/// A Safe, preselected candidate with no evidence and no blockers.
pub fn safe(id: &str, target: Target, action: Action) -> Candidate {
    Candidate {
        id: cid(id),
        target,
        action,
        owner: AppRef {
            program_id: "HKLM|64|VendorApp".parse().unwrap(),
            display_name: "Vendor App".into(),
        },
        origin: Origin::Scanner,
        scanner: "TEST".into(),
        category: Category::AppFiles,
        evidence: Vec::new(),
        blockers: Vec::new(),
        harm: Harm::Low,
        reversibility: Reversibility::Full,
        children: Vec::new(),
        size_bytes: None,
        child_count: None,
        item_fp: None,
        decision: Some(Decision {
            band: Band::Safe,
            preselected: true,
            score: 9,
            explanation: "test".into(),
        }),
    }
}

pub fn quarantine(id: &str, p: &str) -> Candidate {
    safe(id, path(p), Action::Quarantine)
}

pub fn package(id: &str) -> Candidate {
    safe(
        id,
        Target::AppxPackage {
            full_name: PACKAGE.into(),
        },
        Action::RemovePackage,
    )
}

/// A request for every item of a plan over `items`, with the right confirm hash and no restore point.
pub fn request(items: Vec<Candidate>, absorbed: Vec<Candidate>) -> ExecRequest {
    let mut scan = ScanDoc {
        schema: ScanSchema,
        app: "vendor-app".into(),
        tool: Tool::Purge,
        mode: ScanMode::Post,
        policy_version: "m1a.6".into(),
        plan_hash: String::new(),
        items,
        absorbed,
    };
    scan.plan_hash = purge_plan::hash::plan_hash(&scan.items, &scan.policy_version, scan.mode);
    let ids: Vec<CandidateId> = scan.items.iter().map(|c| c.id.clone()).collect();
    ExecRequest {
        confirm: confirm_hash(scan.plan_hash.parse().unwrap(), selection_hash(&ids)).to_string(),
        scan,
        selection: Selection::Preselected,
        allow_irreversible: false,
        settings: ExecSettings {
            restore_point: RestorePointSetting::Off,
            ..ExecSettings::default()
        },
    }
}

// ---------------------------------------------------------------------------------------------------
// Reading the journal
// ---------------------------------------------------------------------------------------------------

/// The outcome of every op, in op order, as the journal records it.
pub fn outcomes(read: &JournalRead) -> Vec<Option<ItemOutcome>> {
    read.state.ops().map(|op| op.outcome.clone()).collect()
}

/// Where the journal says op `n`'s item went.
pub fn quarantine_path(read: &JournalRead, n: u32) -> String {
    match &read
        .state
        .op(OpId(n))
        .unwrap()
        .intent
        .as_ref()
        .unwrap()
        .inverse
    {
        Inverse::MoveBack {
            quarantine_path, ..
        } => quarantine_path.clone(),
        other => panic!("{other:?}"),
    }
}

/// The op of the plan item `id`.
pub fn op_of(read: &JournalRead, id: &str) -> OpId {
    read.state
        .ops()
        .find(|op| op.item.0 == id)
        .unwrap_or_else(|| panic!("no op for {id}"))
        .op
}
