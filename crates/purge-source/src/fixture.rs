//! `Fixture`: an in-memory machine that implements all three source traits, so every scanner can be
//! tested without touching the host (ENGINE_PLAN.md §3.2, §10.1).
//!
//! A fixture is built three ways:
//! - from a **`purge.fixture/1` JSON** document ([`Fixture::from_json_str`], [`Fixture::from_json_file`]),
//! - from a **rig snapshot** plus its structured lists ([`Fixture::from_snap`], in `snapfixture.rs`),
//! - with the **builder** ([`Fixture::builder`]) or the `&mut` mutators, mostly in tests.
//!
//! # The `purge.fixture/1` format
//!
//! ```json
//! {
//!   "schema": "purge.fixture/1",
//!   "system": { "os": {"edition": "Professional", "build": 26100, "ubr": 1742},
//!               "user_sid": "S-1-5-21-1-2-3-1001", "elevated": true,
//!               "profiles": [{"sid": "…", "path": "C:\\Users\\tester"}],
//!               "known_folders": {"ProgramFiles": "C:\\Program Files"},
//!               "env": {"APPDATA": "C:\\Users\\tester\\AppData\\Roaming"},
//!               "processes": [], "now": 134388866613378836 },
//!   "registry": {
//!     "current_control_set": 1,
//!     "coverage": {"roots": [{"path": "HKLM\\SOFTWARE"}], "exclude": []},
//!     "denied": ["HKLM\\SOFTWARE\\Secret"],
//!     "keys": {
//!       "HKLM\\SOFTWARE\\Vendor\\App": {
//!         "lwt": 133000000000000000,
//!         "values": { "": "default string", "Count": {"dword": 3},
//!                     "Blob": {"type": 3, "b64": "AAEC"} },
//!         "keys": { "Sub\\Deeper": {} } } } },
//!   "filesystem": {
//!     "volumes": {"C:\\": {"serial": 305419896, "fixed": true, "fs": "NTFS"}},
//!     "admin_only_roots": ["C:\\Program Files"],
//!     "entries": {
//!       "C:\\Program Files\\App": { "dir": true, "children": {
//!         "app.exe": {"size": 1024, "version_info": {"product_name": "App"}, "signer": "Vendor Ltd"},
//!         "readme.txt": {"content_text": "hello"},
//!         "unins000.dat": {"content_file": "side/unins000.dat"} } } } },
//!   "msi": {"products": [], "states": {}},
//!   "packages": [],
//!   "msi_tables": { "C:\\Windows\\Installer\\1a2b3c.msi": {
//!       "properties": [["ProductName", "App"]],
//!       "components": [{"component": "Main", "component_id": "{…}", "attributes": 256,
//!                       "key_path": "app.exe"}] } },
//!   "tasks": [{"identity": {"path": "\\Vendor\\Update",
//!                           "actions": [{"kind": "exec", "path": "C:\\Program Files\\App\\u.exe"}]},
//!              "enabled": true}]
//! }
//! ```
//!
//! - Registry key and file entry names are path fragments: `"A\\B"` creates `A` and `A\B`. Keys and entries
//!   nest through `keys` / `children`. Ancestors are created implicitly (keys with LastWriteTime 0,
//!   directories).
//! - A value is either a plain string (`REG_SZ`) or an object with exactly one data form: `sz`,
//!   `expand_sz`, `link`, `multi_sz`, `dword`, `qword`, or `type` + `b64`; or `type` + `"unknown": true`
//!   (+ `len`). Optional `len`, `hash` (16 hex chars) and `truncated` describe incomplete data.
//! - A file's content is `content_b64`, `content_text` or `content_file` (a side file, relative to the JSON
//!   file's directory, read lazily). A file without content answers `read_bytes` with `NotCaptured`.
//! - Lists (`system.profiles`, `system.processes`, `msi.products`, `packages`) default to empty when
//!   missing; an explicit `null` means "not captured" and the matching trait method returns
//!   [`SourceError::NotCaptured`].
//! - `coverage` limits what the fixture claims to know: outside it a missing key/path is
//!   [`SourceError::NotCaptured`] (and [`ExistsState::Unknown`]), never `NotFound`/`Absent`. Empty coverage
//!   means "everything". A root's `depth` (e.g. 1) limits how deep below it the fixture is complete.
//! - `filesystem.volumes` maps volume roots to [`VolumeInfo`]; a missing path on a volume that is not fixed
//!   NTFS/ReFS, or on no declared volume when some are declared, is `Unknown`.
//! - `admin_only_roots` and per-entry `admin_only_writable` drive `is_admin_only_writable`: the nearest
//!   explicit flag on the path or an ancestor wins, otherwise a path under an admin-only root is admin-only.
//! - `unknown_file_facts: true` makes missing version info, signer and shortcut data `NotCaptured` instead
//!   of "none" (set by snapshot fixtures, which do not record them).
//! - `msi_tables` maps `LocalPackage` paths (compared like file paths: case-insensitive, `/` = `\`) to
//!   [`MsiTables`]; `tasks` lists [`TaskInfo`]s. Unlike the other lists, an **absent** section (or
//!   `null`) means "not captured": `msi_tables` and `tasks` then return [`SourceError::NotCaptured`]; a
//!   package missing from a present section is [`SourceError::NotFound`]. Both are returned within the
//!   C-SOURCE limits ([`crate::sysobj`]).
//! - Unknown fields are rejected at the top level and anywhere in `msi_tables` and `tasks`, so a typo
//!   fails the load instead of reading as "not captured" or "none".
//!
//! Serialisation ([`Fixture::to_json`]) writes the same format with every key and entry flat at the top
//! level, in case-folded order, so the output is deterministic and loads back to an equal fixture.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::filesystem::{FileSystemSource, join_file_path, split_file_path};
use crate::local_baseline::{
    self, HiveEntry, HiveWalk, InboxPackages, LocalSources, ManifestIter, SYSTEM_DEFAULT_KEY,
};
use crate::registry::{RegistrySource, is_registry_path, map_current_control_set, split_key};
use crate::snapfixture::SnapStats;
use crate::sysobj::{MsiTables, TaskInfo, limited_tasks};
use crate::system::SystemSource;
use crate::types::{
    DirEntry, ExistsState, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FileMeta, FileTime,
    FileTimes, KeyInfo, KnownFolder, MsiContext, MsiContextState, MsiProduct, MsiProductState,
    OsInfo, PackageInfo, ProcessInfo, ProfileInfo, REG_DWORD, REG_EXPAND_SZ, REG_LINK,
    REG_MULTI_SZ, REG_QWORD, REG_SZ, RegData, RegValue, ShortcutInfo, SourceError, SourceResult,
    VersionInfo, VolumeInfo,
};

/// The schema id of the JSON fixture format.
pub const FIXTURE_SCHEMA: &str = "purge.fixture/1";

/// Why a fixture could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    /// Reading a file failed.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        source: std::io::Error,
    },
    /// The JSON is malformed or does not match the format.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// The document's `schema` is not [`FIXTURE_SCHEMA`].
    #[error("unsupported schema {0:?} (want {FIXTURE_SCHEMA})")]
    Schema(String),
    /// A value or entry is inconsistent (e.g. two data forms on one value, bad base64).
    #[error("{0}")]
    Invalid(String),
    /// A snapshot line could not be parsed.
    #[error("snapshot line {line}: {msg}")]
    Snap {
        /// 1-based line number.
        line: usize,
        /// What was wrong.
        msg: String,
    },
}

// ---------------------------------------------------------------------------------------------------------
// Case folding and the path tree
// ---------------------------------------------------------------------------------------------------------

/// Case-folds one name for case-insensitive lookup.
pub(crate) fn fold(s: &str) -> String {
    if s.is_ascii() {
        s.to_ascii_lowercase()
    } else {
        s.to_lowercase()
    }
}

#[derive(Debug, Clone)]
struct Node<T> {
    name: String,
    parent: usize,
    children: BTreeMap<String, usize>,
    /// Declared by the source (a snap record, a JSON entry, a builder call) rather than created as an
    /// implicit ancestor.
    declared: bool,
    data: T,
}

/// An arena tree of case-insensitive path segments. Node 0 is the unnamed root.
#[derive(Debug, Clone)]
struct Tree<T> {
    nodes: Vec<Node<T>>,
}

impl<T: Default> Tree<T> {
    fn new() -> Self {
        Self {
            nodes: vec![Node {
                name: String::new(),
                parent: 0,
                children: BTreeMap::new(),
                declared: false,
                data: T::default(),
            }],
        }
    }

    /// Follows folded segments as far as they exist; returns the matched node chain (without the root).
    fn walk(&self, folded: &[String]) -> Vec<usize> {
        let mut chain = Vec::with_capacity(folded.len());
        let mut cur = 0;
        for seg in folded {
            match self.nodes[cur].children.get(seg) {
                Some(&next) => {
                    chain.push(next);
                    cur = next;
                }
                None => break,
            }
        }
        chain
    }

    fn find(&self, folded: &[String]) -> Option<usize> {
        let chain = self.walk(folded);
        (chain.len() == folded.len() && !folded.is_empty()).then(|| chain[chain.len() - 1])
    }

    /// Creates every missing node of `segs` (original case) and returns the last one.
    fn ensure<S: AsRef<str>>(&mut self, segs: &[S]) -> usize {
        let mut cur = 0;
        for seg in segs {
            let seg = seg.as_ref();
            let key = fold(seg);
            cur = match self.nodes[cur].children.get(&key) {
                Some(&next) => next,
                None => {
                    let idx = self.nodes.len();
                    self.nodes.push(Node {
                        name: seg.to_string(),
                        parent: cur,
                        children: BTreeMap::new(),
                        declared: false,
                        data: T::default(),
                    });
                    self.nodes[cur].children.insert(key, idx);
                    idx
                }
            };
        }
        cur
    }

    /// Detaches a node (and so its subtree) from its parent. The arena keeps the orphans.
    fn detach(&mut self, idx: usize) {
        if idx == 0 {
            return;
        }
        let parent = self.nodes[idx].parent;
        let key = fold(&self.nodes[idx].name);
        self.nodes[parent].children.remove(&key);
    }

    fn names_to(&self, idx: usize) -> Vec<String> {
        let mut names = Vec::new();
        let mut cur = idx;
        while cur != 0 {
            names.push(self.nodes[cur].name.clone());
            cur = self.nodes[cur].parent;
        }
        names.reverse();
        names
    }

    /// Every reachable node except the root, depth first in folded order.
    fn dfs(&self) -> Vec<usize> {
        let mut out = Vec::new();
        let mut stack: Vec<usize> = self.nodes[0].children.values().rev().copied().collect();
        while let Some(idx) = stack.pop() {
            out.push(idx);
            stack.extend(self.nodes[idx].children.values().rev().copied());
        }
        out
    }
}

/// Folded path prefix test.
fn starts_with(path: &[String], prefix: &[String]) -> bool {
    path.len() >= prefix.len() && path[..prefix.len()] == *prefix
}

// ---------------------------------------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------------------------------------

/// One captured root of a fixture.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CoverageRoot {
    /// The root key or directory.
    pub path: String,
    /// How many levels below the root the capture is complete (`1` = the root's direct entries only);
    /// `None` = the whole subtree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
}

/// What part of the registry or filesystem a fixture captured. Empty `roots` means everything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Coverage {
    /// Captured roots.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<CoverageRoot>,
    /// Subtrees left out of the capture.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
}

impl Coverage {
    /// Whether nothing limits the coverage.
    pub fn is_everything(&self) -> bool {
        self.roots.is_empty() && self.exclude.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
struct CompiledCoverage {
    roots: Vec<(Vec<String>, Option<u32>)>,
    exclude: Vec<Vec<String>>,
}

impl CompiledCoverage {
    fn new(cov: &Coverage, registry: bool, ccs: u32) -> Self {
        let comp = |p: &str| folded_segments(p, registry, ccs).unwrap_or_default();
        Self {
            roots: cov.roots.iter().map(|r| (comp(&r.path), r.depth)).collect(),
            exclude: cov.exclude.iter().map(|p| comp(p)).collect(),
        }
    }

    fn excluded(&self, path: &[String]) -> bool {
        self.exclude.iter().any(|e| starts_with(path, e))
    }

    /// Whether the fixture knows the existence of `path` itself.
    fn covers(&self, path: &[String]) -> bool {
        if self.excluded(path) {
            return false;
        }
        self.roots.is_empty()
            || self.roots.iter().any(|(r, depth)| {
                starts_with(path, r) && depth.is_none_or(|d| path.len() - r.len() <= d as usize)
            })
    }

    /// Whether the fixture knows every direct child of `path`.
    fn covers_listing(&self, path: &[String]) -> bool {
        if self.excluded(path) {
            return false;
        }
        self.roots.is_empty()
            || self.roots.iter().any(|(r, depth)| {
                starts_with(path, r) && depth.is_none_or(|d| path.len() + 1 - r.len() <= d as usize)
            })
    }
}

/// Splits and folds a registry or file path; registry paths get the `CurrentControlSet` mapping.
fn folded_segments(path: &str, registry: bool, ccs: u32) -> Option<Vec<String>> {
    original_segments(path, registry, ccs).map(|s| s.iter().map(|x| fold(x)).collect())
}

fn original_segments(path: &str, registry: bool, ccs: u32) -> Option<Vec<String>> {
    if registry {
        let mut segs: Vec<String> = split_key(path).into_iter().map(String::from).collect();
        if segs.is_empty() {
            return None;
        }
        map_current_control_set(&mut segs, ccs);
        Some(segs)
    } else {
        split_file_path(path)
    }
}

// ---------------------------------------------------------------------------------------------------------
// Node data
// ---------------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct KeyData {
    lwt: u64,
    n_values: Option<u32>,
    n_subkeys: Option<u32>,
    link_target: Option<String>,
    ti_owned: Option<bool>,
    values: Vec<RegValue>,
}

impl KeyData {
    fn is_default(&self) -> bool {
        *self == KeyData::default()
    }

    fn symbolic_link_value(&self) -> Option<String> {
        self.values
            .iter()
            .find(|v| v.data.ty == REG_LINK && v.name.eq_ignore_ascii_case("SymbolicLinkValue"))
            .and_then(|v| v.data.link_target())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Content {
    Inline(Vec<u8>),
    File { given: String, resolved: PathBuf },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FsData {
    attrs: u32,
    size: u64,
    times: FileTimes,
    reparse_tag: u32,
    file_id: Option<u128>,
    volume_serial: Option<u64>,
    short_name: Option<String>,
    content: Option<Content>,
    version_info: Option<VersionInfo>,
    signer: Option<String>,
    shortcut: Option<ShortcutInfo>,
    admin_only_writable: Option<bool>,
}

impl Default for FsData {
    /// An implicit directory.
    fn default() -> Self {
        Self {
            attrs: FILE_ATTRIBUTE_DIRECTORY,
            size: 0,
            times: FileTimes::default(),
            reparse_tag: 0,
            file_id: None,
            volume_serial: None,
            short_name: None,
            content: None,
            version_info: None,
            signer: None,
            shortcut: None,
            admin_only_writable: None,
        }
    }
}

impl FsData {
    fn is_dir(&self) -> bool {
        self.attrs & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    fn meta(&self) -> FileMeta {
        FileMeta {
            size: self.size,
            attrs: self.attrs,
            times: self.times,
            reparse_tag: self.reparse_tag,
            file_id: self.file_id,
            volume_serial: self.volume_serial,
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// System facts
// ---------------------------------------------------------------------------------------------------------

/// Machine and session facts of a fixture (the `system` object of the JSON format).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemFacts {
    /// Windows edition and build; `None` = not captured.
    #[serde(default)]
    pub os: Option<OsInfo>,
    /// The interactive user's SID; `None` = not captured.
    #[serde(default)]
    pub user_sid: Option<String>,
    /// Whether the engine is elevated.
    #[serde(default)]
    pub elevated: bool,
    /// The computer name, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computer: Option<String>,
    /// `ProfileList`; `None` = not captured.
    #[serde(default = "some_empty")]
    pub profiles: Option<Vec<ProfileInfo>>,
    /// Known folders.
    #[serde(default)]
    pub known_folders: BTreeMap<KnownFolder, String>,
    /// The interactive user's environment, names upper-cased.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Running processes; `None` = not captured.
    #[serde(default = "some_empty")]
    pub processes: Option<Vec<ProcessInfo>>,
    /// The fixture's "now"; `FileTime(0)` when absent.
    #[serde(default)]
    pub now: Option<FileTime>,
}

impl Default for SystemFacts {
    fn default() -> Self {
        Self {
            os: None,
            user_sid: None,
            elevated: false,
            computer: None,
            profiles: Some(Vec::new()),
            known_folders: BTreeMap::new(),
            env: BTreeMap::new(),
            processes: Some(Vec::new()),
            now: None,
        }
    }
}

fn some_empty<T>() -> Option<Vec<T>> {
    Some(Vec::new())
}

// ---------------------------------------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------------------------------------

/// An offline machine: registry, filesystem and system facts in memory. Implements
/// [`RegistrySource`], [`FileSystemSource`] and [`SystemSource`].
#[derive(Debug, Clone)]
pub struct Fixture {
    reg: Tree<KeyData>,
    fs: Tree<FsData>,
    current_control_set: u32,
    values_captured: bool,
    reg_coverage: Coverage,
    reg_cov: CompiledCoverage,
    fs_coverage: Coverage,
    fs_cov: CompiledCoverage,
    reg_denied: Vec<String>,
    reg_denied_f: Vec<Vec<String>>,
    fs_denied: Vec<String>,
    fs_denied_f: Vec<Vec<String>>,
    volumes: BTreeMap<String, VolumeInfo>,
    volumes_f: Vec<(Vec<String>, VolumeInfo)>,
    admin_only_roots: Vec<String>,
    admin_only_roots_f: Vec<Vec<String>>,
    unknown_file_facts: bool,
    system: SystemFacts,
    msi_products: Option<Vec<MsiProduct>>,
    msi_states: BTreeMap<String, Vec<MsiContextState>>,
    packages: Option<Vec<PackageInfo>>,
    /// MSI tables by [`package_key`], with the path as given; `None` = not captured.
    msi_tables: Option<BTreeMap<String, (String, MsiTables)>>,
    /// Scheduled tasks; `None` = not captured.
    tasks: Option<Vec<TaskInfo>>,
    base_dir: Option<PathBuf>,
    overlay_dir: Option<PathBuf>,
    pub(crate) snap_stats: Option<SnapStats>,
    /// Offline hive files by [`package_key`] of their path (the S2 local source).
    offline_hives: BTreeMap<String, HiveFixture>,
}

impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}

impl Fixture {
    /// An empty fixture: no keys, no files, `ControlSet001`, every location covered, empty lists.
    pub fn new() -> Self {
        Self {
            reg: Tree::new(),
            fs: Tree::new(),
            current_control_set: 1,
            values_captured: true,
            reg_coverage: Coverage::default(),
            reg_cov: CompiledCoverage::default(),
            fs_coverage: Coverage::default(),
            fs_cov: CompiledCoverage::default(),
            reg_denied: Vec::new(),
            reg_denied_f: Vec::new(),
            fs_denied: Vec::new(),
            fs_denied_f: Vec::new(),
            volumes: BTreeMap::new(),
            volumes_f: Vec::new(),
            admin_only_roots: Vec::new(),
            admin_only_roots_f: Vec::new(),
            unknown_file_facts: false,
            system: SystemFacts::default(),
            msi_products: Some(Vec::new()),
            msi_states: BTreeMap::new(),
            packages: Some(Vec::new()),
            msi_tables: None,
            tasks: None,
            base_dir: None,
            overlay_dir: None,
            snap_stats: None,
            offline_hives: BTreeMap::new(),
        }
    }

    /// Places an offline hive file at `path` (not in the filesystem tree: only
    /// [`LocalSources::default_hive`] reads it). Replaces an earlier one at the same path.
    pub fn set_offline_hive(&mut self, path: &str, hive: HiveFixture) {
        if let Some(k) = package_key(path) {
            self.offline_hives.insert(k, hive);
        }
    }

    /// A builder over an empty fixture.
    pub fn builder() -> FixtureBuilder {
        FixtureBuilder(Fixture::new())
    }

    // ---- registry mutators --------------------------------------------------------------------------

    fn reg_segs(&self, key: &str) -> SourceResult<Vec<String>> {
        original_segments(key, true, self.current_control_set)
            .ok_or_else(|| SourceError::InvalidPath(key.to_string()))
    }

    fn ensure_key(&mut self, key: &str) -> usize {
        let segs = self.reg_segs(key).unwrap_or_default();
        let idx = self.reg.ensure(&segs);
        if idx != 0 {
            self.reg.nodes[idx].declared = true;
        }
        idx
    }

    /// Creates a key (and its missing ancestors). Keeps an existing key unchanged.
    pub fn add_key(&mut self, key: &str) {
        self.ensure_key(key);
    }

    /// Sets a key's LastWriteTime, creating the key when missing.
    pub fn set_key_lwt(&mut self, key: &str, lwt: FileTime) {
        let idx = self.ensure_key(key);
        self.reg.nodes[idx].data.lwt = lwt.0;
    }

    /// Records value and subkey counts that override the counts of the stored contents (a capture that
    /// left part of the key out). `None` = count the stored contents.
    pub fn set_key_counts(&mut self, key: &str, n_values: Option<u32>, n_subkeys: Option<u32>) {
        let idx = self.ensure_key(key);
        let data = &mut self.reg.nodes[idx].data;
        data.n_values = n_values;
        data.n_subkeys = n_subkeys;
    }

    /// Makes a key a registry link to `target` (also stored as its `SymbolicLinkValue`).
    pub fn set_link(&mut self, key: &str, target: &str) {
        let idx = self.ensure_key(key);
        self.reg.nodes[idx].data.link_target = Some(target.to_string());
        self.set_value(key, "SymbolicLinkValue", RegData::from_link(target));
    }

    /// Sets whether TrustedInstaller owns the key.
    pub fn set_ti_owned(&mut self, key: &str, ti_owned: bool) {
        let idx = self.ensure_key(key);
        self.reg.nodes[idx].data.ti_owned = Some(ti_owned);
    }

    /// Sets a value (replacing one with the same name, case-insensitively), creating the key when missing.
    pub fn set_value(&mut self, key: &str, name: &str, data: RegData) {
        let idx = self.ensure_key(key);
        let kd = &mut self.reg.nodes[idx].data;
        kd.n_values = None;
        match kd
            .values
            .iter_mut()
            .find(|v| v.name.eq_ignore_ascii_case(name))
        {
            Some(v) => v.data = data,
            None => kd.values.push(RegValue {
                name: name.to_string(),
                data,
            }),
        }
    }

    /// Snapshot loading: declares a key with its recorded facts; returns its node.
    pub(crate) fn snap_key(
        &mut self,
        key: &str,
        lwt: u64,
        n_values: Option<u32>,
        n_subkeys: Option<u32>,
    ) -> usize {
        let idx = self.ensure_key(key);
        let data = &mut self.reg.nodes[idx].data;
        data.lwt = lwt;
        data.n_values = n_values;
        data.n_subkeys = n_subkeys;
        idx
    }

    /// Snapshot loading: appends a value to a key node (`idx`, or the key found or created by path)
    /// without the duplicate check and without touching recorded counts; returns the key's node.
    pub(crate) fn snap_value(
        &mut self,
        idx: Option<usize>,
        key: &str,
        name: String,
        data: RegData,
    ) -> usize {
        let idx = idx.unwrap_or_else(|| {
            let segs = self.reg_segs(key).unwrap_or_default();
            self.reg.ensure(&segs)
        });
        self.reg.nodes[idx]
            .data
            .values
            .push(RegValue { name, data });
        idx
    }

    /// Removes a key and its subtree. Returns whether it existed.
    pub fn remove_key(&mut self, key: &str) -> bool {
        let Ok(segs) = self.reg_segs(key) else {
            return false;
        };
        let folded: Vec<String> = segs.iter().map(|s| fold(s)).collect();
        match self.reg.find(&folded) {
            Some(idx) => {
                let parent = self.reg.nodes[idx].parent;
                self.reg.detach(idx);
                self.reg.nodes[parent].data.n_subkeys = None;
                true
            }
            None => false,
        }
    }

    /// Removes one value. Returns whether it existed.
    pub fn remove_value(&mut self, key: &str, name: &str) -> bool {
        let Ok(idx) = self.reg_find(key) else {
            return false;
        };
        let kd = &mut self.reg.nodes[idx].data;
        let before = kd.values.len();
        kd.values.retain(|v| !v.name.eq_ignore_ascii_case(name));
        let removed = kd.values.len() != before;
        if removed {
            kd.n_values = None;
        }
        removed
    }

    /// Sets the `ControlSet00N` that `CurrentControlSet` maps to. Set it before adding keys: keys already
    /// stored under another `ControlSet00N` are not moved.
    pub fn set_current_control_set(&mut self, n: u32) {
        self.current_control_set = n;
        self.reg_cov = CompiledCoverage::new(&self.reg_coverage, true, n);
        self.recompile_denied();
    }

    /// Declares whether registry values were captured at all (`false` for a `--no-values` snapshot, which
    /// makes every value query `NotCaptured`).
    pub fn set_values_captured(&mut self, captured: bool) {
        self.values_captured = captured;
    }

    /// Sets what part of the registry the fixture captured.
    pub fn set_registry_coverage(&mut self, coverage: Coverage) {
        self.reg_cov = CompiledCoverage::new(&coverage, true, self.current_control_set);
        self.reg_coverage = coverage;
    }

    // ---- filesystem mutators ------------------------------------------------------------------------

    fn ensure_path(&mut self, path: &str) -> Option<usize> {
        let segs = split_file_path(path)?;
        let idx = self.fs.ensure(&segs);
        self.fs.nodes[idx].declared = true;
        Some(idx)
    }

    fn with_entry(&mut self, path: &str, f: impl FnOnce(&mut FsData)) {
        if let Some(idx) = self.ensure_path(path) {
            f(&mut self.fs.nodes[idx].data);
        }
    }

    /// Creates a directory (and its missing ancestors). Relative paths are ignored.
    pub fn add_dir(&mut self, path: &str) {
        self.with_entry(path, |d| {
            d.attrs |= FILE_ATTRIBUTE_DIRECTORY;
            d.size = 0;
        });
    }

    /// Creates a file of `size` bytes without content.
    pub fn add_file(&mut self, path: &str, size: u64) {
        self.with_entry(path, |d| {
            if d.is_dir() {
                d.attrs = FILE_ATTRIBUTE_ARCHIVE;
            }
            d.size = size;
        });
    }

    /// Creates a file with inline content (its size is the content length).
    pub fn add_file_with_content(&mut self, path: &str, content: Vec<u8>) {
        self.with_entry(path, |d| {
            if d.is_dir() {
                d.attrs = FILE_ATTRIBUTE_ARCHIVE;
            }
            d.size = content.len() as u64;
            d.content = Some(Content::Inline(content));
        });
    }

    /// Overwrites an entry's metadata (attributes decide whether it is a directory), creating it when
    /// missing.
    pub fn set_meta(&mut self, path: &str, meta: FileMeta) {
        self.with_entry(path, |d| {
            d.attrs = meta.attrs;
            d.size = meta.size;
            d.times = meta.times;
            d.reparse_tag = meta.reparse_tag;
            d.file_id = meta.file_id;
            d.volume_serial = meta.volume_serial;
        });
    }

    /// Makes an entry a reparse point with `tag` (a directory junction when it is a directory).
    pub fn set_reparse_tag(&mut self, path: &str, tag: u32) {
        self.with_entry(path, |d| {
            d.reparse_tag = tag;
            if tag != 0 {
                d.attrs |= crate::types::FILE_ATTRIBUTE_REPARSE_POINT;
            } else {
                d.attrs &= !crate::types::FILE_ATTRIBUTE_REPARSE_POINT;
            }
        });
    }

    /// Sets an entry's times.
    pub fn set_times(&mut self, path: &str, times: FileTimes) {
        self.with_entry(path, |d| d.times = times);
    }

    /// Sets an entry's 8.3 short name (used by `long_path`).
    pub fn set_short_name(&mut self, path: &str, short: &str) {
        self.with_entry(path, |d| d.short_name = Some(short.to_string()));
    }

    /// Sets a file's version resource.
    pub fn set_version_info(&mut self, path: &str, info: VersionInfo) {
        self.with_entry(path, |d| d.version_info = Some(info));
    }

    /// Sets a file's signer CN.
    pub fn set_signer(&mut self, path: &str, cn: &str) {
        self.with_entry(path, |d| d.signer = Some(cn.to_string()));
    }

    /// Makes a file a shortcut with the given contents.
    pub fn set_shortcut(&mut self, path: &str, info: ShortcutInfo) {
        self.with_entry(path, |d| d.shortcut = Some(info));
    }

    /// Sets the explicit admin-only-writable flag of an entry (inherited by its descendants).
    pub fn set_admin_only_writable(&mut self, path: &str, admin_only: bool) {
        self.with_entry(path, |d| d.admin_only_writable = Some(admin_only));
    }

    /// Removes a file or directory and its subtree. Returns whether it existed.
    pub fn remove_path(&mut self, path: &str) -> bool {
        let Some(folded) = folded_segments(path, false, 0) else {
            return false;
        };
        match self.fs.find(&folded) {
            Some(idx) => {
                self.fs.detach(idx);
                true
            }
            None => false,
        }
    }

    /// Declares a volume by its root (`C:\`, or a mount-point directory).
    pub fn add_volume(&mut self, root: &str, info: VolumeInfo) {
        self.volumes.insert(root.to_string(), info);
        self.recompile_volumes();
    }

    /// Declares a path whose contents could not be read (registry key or file path).
    pub fn add_denied(&mut self, path: &str) {
        if is_registry_path(path) {
            self.reg_denied.push(path.to_string());
        } else {
            self.fs_denied.push(path.to_string());
        }
        self.recompile_denied();
    }

    /// Sets what part of the filesystem the fixture captured.
    pub fn set_fs_coverage(&mut self, coverage: Coverage) {
        self.fs_cov = CompiledCoverage::new(&coverage, false, 0);
        self.fs_coverage = coverage;
    }

    /// Sets the directories under which paths are admin-only writable by default.
    pub fn set_admin_only_roots(&mut self, roots: Vec<String>) {
        self.admin_only_roots_f = roots
            .iter()
            .filter_map(|r| folded_segments(r, false, 0))
            .collect();
        self.admin_only_roots = roots;
    }

    /// Declares that missing version info, signer and shortcut data mean "not captured" rather than
    /// "none".
    pub fn set_unknown_file_facts(&mut self, unknown: bool) {
        self.unknown_file_facts = unknown;
    }

    /// Sets the overlay directory that supplies file contents by path: `C:\a\b.dat` is read from
    /// `<overlay>\C\a\b.dat`. Only files present in the fixture are read through it.
    pub fn set_overlay_dir(&mut self, dir: Option<PathBuf>) {
        self.overlay_dir = dir;
    }

    fn recompile_denied(&mut self) {
        let ccs = self.current_control_set;
        self.reg_denied_f = self
            .reg_denied
            .iter()
            .filter_map(|p| folded_segments(p, true, ccs))
            .collect();
        self.fs_denied_f = self
            .fs_denied
            .iter()
            .filter_map(|p| folded_segments(p, false, 0))
            .collect();
    }

    fn recompile_volumes(&mut self) {
        self.volumes_f = self
            .volumes
            .iter()
            .filter_map(|(root, info)| folded_segments(root, false, 0).map(|f| (f, info.clone())))
            .collect();
    }

    // ---- system mutators ----------------------------------------------------------------------------

    /// The system facts, for reading.
    pub fn system(&self) -> &SystemFacts {
        &self.system
    }

    /// The system facts, for editing.
    pub fn system_mut(&mut self) -> &mut SystemFacts {
        &mut self.system
    }

    /// Replaces the MSI product list (`None` = not captured).
    pub fn set_msi_products(&mut self, products: Option<Vec<MsiProduct>>) {
        self.msi_products = products;
    }

    /// Adds an MSI product (turning a "not captured" list into a captured one).
    pub fn add_msi_product(&mut self, product: MsiProduct) {
        self.msi_products.get_or_insert_with(Vec::new).push(product);
    }

    /// Sets the state of a ProductCode in one context explicitly. Once any state is set for a code, its
    /// other contexts are reported only as set here.
    pub fn set_msi_state(&mut self, code: &str, context: MsiContext, state: MsiProductState) {
        let list = self
            .msi_states
            .entry(code.to_ascii_uppercase())
            .or_default();
        match list.iter_mut().find(|s| s.context == context) {
            Some(s) => s.state = state,
            None => list.push(MsiContextState { context, state }),
        }
    }

    /// Replaces the package list (`None` = not captured).
    pub fn set_packages(&mut self, packages: Option<Vec<PackageInfo>>) {
        self.packages = packages;
    }

    /// Adds a package.
    pub fn add_package(&mut self, package: PackageInfo) {
        self.packages.get_or_insert_with(Vec::new).push(package);
    }

    /// Sets the tables of one cached MSI package (turning "not captured" into captured); replaces the
    /// tables of the same path in any case or slash form. Returns `false`, changing nothing, when
    /// `local_package` is not an absolute file path.
    pub fn set_msi_tables(&mut self, local_package: &str, tables: MsiTables) -> bool {
        let Some(key) = package_key(local_package) else {
            return false;
        };
        self.msi_tables
            .get_or_insert_with(BTreeMap::new)
            .insert(key, (local_package.to_string(), tables));
        true
    }

    /// Whether the fixture captured MSI tables: `false` drops them all (`msi_tables` answers
    /// `NotCaptured`), `true` keeps those set and makes every other package `NotFound`.
    pub fn set_msi_tables_captured(&mut self, captured: bool) {
        if captured {
            self.msi_tables.get_or_insert_with(BTreeMap::new);
        } else {
            self.msi_tables = None;
        }
    }

    /// Replaces the task list (`None` = not captured).
    pub fn set_tasks(&mut self, tasks: Option<Vec<TaskInfo>>) {
        self.tasks = tasks;
    }

    /// Adds a task (turning a "not captured" list into a captured one).
    pub fn add_task(&mut self, task: TaskInfo) {
        self.tasks.get_or_insert_with(Vec::new).push(task);
    }

    // ---- counts ---------------------------------------------------------------------------------------

    /// Number of declared keys (implicit ancestors not counted).
    pub fn key_count(&self) -> usize {
        self.reg
            .dfs()
            .into_iter()
            .filter(|&i| self.reg.nodes[i].declared)
            .count()
    }

    /// Number of values over all keys.
    pub fn value_count(&self) -> usize {
        self.reg
            .dfs()
            .into_iter()
            .map(|i| self.reg.nodes[i].data.values.len())
            .sum()
    }

    /// Number of declared directories.
    pub fn dir_count(&self) -> usize {
        self.fs
            .dfs()
            .into_iter()
            .filter(|&i| self.fs.nodes[i].declared && self.fs.nodes[i].data.is_dir())
            .count()
    }

    /// Number of declared files.
    pub fn file_count(&self) -> usize {
        self.fs
            .dfs()
            .into_iter()
            .filter(|&i| self.fs.nodes[i].declared && !self.fs.nodes[i].data.is_dir())
            .count()
    }

    /// Load statistics when the fixture came from a rig snapshot.
    pub fn snap_stats(&self) -> Option<&SnapStats> {
        self.snap_stats.as_ref()
    }

    // ---- lookups --------------------------------------------------------------------------------------

    fn reg_folded(&self, key: &str) -> SourceResult<Vec<String>> {
        Ok(self.reg_segs(key)?.iter().map(|s| fold(s)).collect())
    }

    fn under_denied(denied: &[Vec<String>], path: &[String], strict: bool) -> bool {
        denied
            .iter()
            .any(|d| starts_with(path, d) && (!strict || path.len() > d.len()))
    }

    /// Finds a key node, or explains why it is missing.
    fn reg_find(&self, key: &str) -> SourceResult<usize> {
        let folded = self.reg_folded(key)?;
        let chain = self.reg.walk(&folded);
        if chain.len() == folded.len() {
            return Ok(chain[chain.len() - 1]);
        }
        if Self::under_denied(&self.reg_denied_f, &folded, false) {
            return Err(SourceError::AccessDenied);
        }
        // Below a link the real tree continues elsewhere; the fixture does not follow links.
        if let Some(&last) = chain.last() {
            let d = &self.reg.nodes[last].data;
            if d.link_target.is_some() || d.symbolic_link_value().is_some() {
                return Err(SourceError::NotCaptured);
            }
        }
        if !self.reg_cov.covers(&folded) {
            return Err(SourceError::NotCaptured);
        }
        Err(SourceError::NotFound)
    }

    fn fs_folded(path: &str) -> SourceResult<Vec<String>> {
        folded_segments(path, false, 0).ok_or_else(|| SourceError::InvalidPath(path.to_string()))
    }

    /// Finds a filesystem node, or explains why it is missing.
    fn fs_find(&self, path: &str) -> SourceResult<usize> {
        let folded = Self::fs_folded(path)?;
        let chain = self.fs.walk(&folded);
        if chain.len() == folded.len() {
            return Ok(chain[chain.len() - 1]);
        }
        if chain
            .iter()
            .any(|&i| self.fs.nodes[i].data.reparse_tag != 0)
        {
            return Err(SourceError::ReparsePoint);
        }
        if Self::under_denied(&self.fs_denied_f, &folded, false) {
            return Err(SourceError::AccessDenied);
        }
        if !self.fs_cov.covers(&folded) {
            return Err(SourceError::NotCaptured);
        }
        Err(SourceError::NotFound)
    }

    fn volume_for(&self, folded: &[String]) -> Option<&VolumeInfo> {
        self.volumes_f
            .iter()
            .filter(|(root, _)| starts_with(folded, root))
            .max_by_key(|(root, _)| root.len())
            .map(|(_, v)| v)
    }

    fn file_node(&self, path: &str) -> SourceResult<&FsData> {
        let idx = self.fs_find(path)?;
        let data = &self.fs.nodes[idx].data;
        if data.is_dir() {
            return Err(SourceError::WrongKind);
        }
        Ok(data)
    }

    fn missing_fact<T>(&self) -> SourceResult<Option<T>> {
        if self.unknown_file_facts {
            Err(SourceError::NotCaptured)
        } else {
            Ok(None)
        }
    }

    fn overlay_path(&self, path: &str) -> Option<PathBuf> {
        let dir = self.overlay_dir.as_ref()?;
        let segs = split_file_path(path)?;
        let drive = segs.first()?.strip_suffix(':')?;
        let mut p = dir.join(drive);
        for s in &segs[1..] {
            p.push(s);
        }
        Some(p)
    }
}

fn read_prefix(path: &Path, max: usize) -> SourceResult<Vec<u8>> {
    let file = std::fs::File::open(path).map_err(|e| io_to_source(&e))?;
    let mut buf = Vec::new();
    file.take(max as u64)
        .read_to_end(&mut buf)
        .map_err(|e| io_to_source(&e))?;
    Ok(buf)
}

fn io_to_source(e: &std::io::Error) -> SourceError {
    SourceError::Other(
        e.raw_os_error()
            .and_then(|c| u32::try_from(c).ok())
            .unwrap_or(0),
    )
}

// ---------------------------------------------------------------------------------------------------------
// Trait implementations
// ---------------------------------------------------------------------------------------------------------

impl RegistrySource for Fixture {
    fn key_info(&self, key: &str) -> SourceResult<KeyInfo> {
        let idx = self.reg_find(key)?;
        let node = &self.reg.nodes[idx];
        let d = &node.data;
        let link_target = d.link_target.clone().or_else(|| d.symbolic_link_value());
        Ok(KeyInfo {
            lwt: FileTime(d.lwt),
            n_values: d
                .n_values
                .unwrap_or_else(|| u32::try_from(d.values.len()).unwrap_or(u32::MAX)),
            n_subkeys: d
                .n_subkeys
                .unwrap_or_else(|| u32::try_from(node.children.len()).unwrap_or(u32::MAX)),
            is_link: link_target.is_some(),
            link_target,
            ti_owned: d.ti_owned,
        })
    }

    fn subkeys(&self, key: &str) -> SourceResult<Vec<String>> {
        let idx = self.reg_find(key)?;
        let folded = self.reg_folded(key)?;
        if Self::under_denied(&self.reg_denied_f, &folded, false) {
            return Err(SourceError::AccessDenied);
        }
        if !self.reg_cov.covers_listing(&folded) {
            return Err(SourceError::NotCaptured);
        }
        Ok(self.reg.nodes[idx]
            .children
            .values()
            .map(|&c| self.reg.nodes[c].name.clone())
            .collect())
    }

    fn values(&self, key: &str) -> SourceResult<Vec<RegValue>> {
        let idx = self.reg_find(key)?;
        let folded = self.reg_folded(key)?;
        if Self::under_denied(&self.reg_denied_f, &folded, false) {
            return Err(SourceError::AccessDenied);
        }
        if !self.values_captured || !self.reg_cov.covers(&folded) {
            return Err(SourceError::NotCaptured);
        }
        Ok(self.reg.nodes[idx].data.values.clone())
    }

    fn value(&self, key: &str, name: &str) -> SourceResult<RegData> {
        let idx = self.reg_find(key)?;
        if let Some(v) = self.reg.nodes[idx]
            .data
            .values
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case(name) || fold(&v.name) == fold(name))
        {
            return Ok(v.data.clone());
        }
        let folded = self.reg_folded(key)?;
        if Self::under_denied(&self.reg_denied_f, &folded, false) {
            return Err(SourceError::AccessDenied);
        }
        if !self.values_captured || !self.reg_cov.covers(&folded) {
            return Err(SourceError::NotCaptured);
        }
        Err(SourceError::NotFound)
    }

    fn loaded_user_sids(&self) -> SourceResult<Vec<String>> {
        let Some(hku) = self.reg.find(&["hku".to_string()]) else {
            return Ok(Vec::new());
        };
        Ok(self.reg.nodes[hku]
            .children
            .values()
            .map(|&c| self.reg.nodes[c].name.clone())
            .filter(|n| !n.eq_ignore_ascii_case(".DEFAULT") && !fold(n).ends_with("_classes"))
            .collect())
    }

    fn current_control_set(&self) -> SourceResult<u32> {
        Ok(self.current_control_set)
    }
}

impl FileSystemSource for Fixture {
    fn metadata(&self, path: &str) -> SourceResult<FileMeta> {
        let idx = self.fs_find(path)?;
        Ok(self.fs.nodes[idx].data.meta())
    }

    fn list_dir(&self, path: &str) -> SourceResult<Vec<DirEntry>> {
        let idx = self.fs_find(path)?;
        let node = &self.fs.nodes[idx];
        if !node.data.is_dir() {
            return Err(SourceError::WrongKind);
        }
        if node.data.reparse_tag != 0 {
            return Err(SourceError::ReparsePoint);
        }
        let folded = Self::fs_folded(path)?;
        if Self::under_denied(&self.fs_denied_f, &folded, false) {
            return Err(SourceError::AccessDenied);
        }
        if !self.fs_cov.covers_listing(&folded) {
            return Err(SourceError::NotCaptured);
        }
        Ok(node
            .children
            .values()
            .map(|&c| DirEntry {
                name: self.fs.nodes[c].name.clone(),
                meta: self.fs.nodes[c].data.meta(),
            })
            .collect())
    }

    fn exists(&self, path: &str) -> ExistsState {
        let Ok(folded) = Self::fs_folded(path) else {
            return ExistsState::Unknown;
        };
        let chain = self.fs.walk(&folded);
        if chain.len() == folded.len() {
            return ExistsState::Present;
        }
        if chain
            .iter()
            .any(|&i| self.fs.nodes[i].data.reparse_tag != 0)
            || Self::under_denied(&self.fs_denied_f, &folded, false)
        {
            return ExistsState::Unknown;
        }
        match self.volume_for(&folded) {
            Some(v) if !v.proves_absence() => return ExistsState::Unknown,
            None if !self.volumes_f.is_empty() => return ExistsState::Unknown,
            _ => {}
        }
        if !self.fs_cov.covers(&folded) {
            return ExistsState::Unknown;
        }
        ExistsState::Absent
    }

    fn read_bytes(&self, path: &str, max: usize) -> SourceResult<Vec<u8>> {
        let data = self.file_node(path)?;
        match &data.content {
            Some(Content::Inline(bytes)) => Ok(bytes[..bytes.len().min(max)].to_vec()),
            Some(Content::File { resolved, .. }) => read_prefix(resolved, max),
            None => match self.overlay_path(path) {
                Some(p) if p.is_file() => read_prefix(&p, max),
                _ => Err(SourceError::NotCaptured),
            },
        }
    }

    fn long_path(&self, path: &str) -> SourceResult<String> {
        let segs =
            split_file_path(path).ok_or_else(|| SourceError::InvalidPath(path.to_string()))?;
        let mut cur = 0;
        let mut names = Vec::with_capacity(segs.len());
        for seg in &segs {
            let f = fold(seg);
            let node = &self.fs.nodes[cur];
            let next = node.children.get(&f).copied().or_else(|| {
                node.children.values().copied().find(|&c| {
                    self.fs.nodes[c]
                        .data
                        .short_name
                        .as_deref()
                        .is_some_and(|s| fold(s) == f)
                })
            });
            match next {
                Some(n) => {
                    names.push(self.fs.nodes[n].name.clone());
                    cur = n;
                }
                None => {
                    // Report why, using the lexical path.
                    self.fs_find(path)?;
                    return Err(SourceError::NotFound);
                }
            }
        }
        Ok(join_file_path(&names))
    }

    fn volume_info(&self, path: &str) -> SourceResult<VolumeInfo> {
        let folded = Self::fs_folded(path)?;
        self.volume_for(&folded)
            .cloned()
            .ok_or(SourceError::NotCaptured)
    }

    fn version_info(&self, path: &str) -> SourceResult<Option<VersionInfo>> {
        match &self.file_node(path)?.version_info {
            Some(v) => Ok(Some(v.clone())),
            None => self.missing_fact(),
        }
    }

    fn signer_cn(&self, path: &str) -> SourceResult<Option<String>> {
        match &self.file_node(path)?.signer {
            Some(s) => Ok(Some(s.clone())),
            None => self.missing_fact(),
        }
    }

    fn read_shortcut(&self, path: &str) -> SourceResult<ShortcutInfo> {
        match &self.file_node(path)?.shortcut {
            Some(s) => Ok(s.clone()),
            None if self.unknown_file_facts => Err(SourceError::NotCaptured),
            None => Err(SourceError::WrongKind),
        }
    }

    fn is_admin_only_writable(&self, path: &str) -> SourceResult<bool> {
        let mut cur = self.fs_find(path)?;
        while cur != 0 {
            if let Some(flag) = self.fs.nodes[cur].data.admin_only_writable {
                return Ok(flag);
            }
            cur = self.fs.nodes[cur].parent;
        }
        let folded = Self::fs_folded(path)?;
        Ok(self
            .admin_only_roots_f
            .iter()
            .any(|r| starts_with(&folded, r)))
    }
}

impl SystemSource for Fixture {
    fn os_info(&self) -> SourceResult<OsInfo> {
        self.system.os.clone().ok_or(SourceError::NotCaptured)
    }

    fn user_sid(&self) -> SourceResult<String> {
        self.system.user_sid.clone().ok_or(SourceError::NotCaptured)
    }

    fn elevated(&self) -> bool {
        self.system.elevated
    }

    fn profiles(&self) -> SourceResult<Vec<ProfileInfo>> {
        self.system.profiles.clone().ok_or(SourceError::NotCaptured)
    }

    fn known_folders(&self) -> SourceResult<BTreeMap<KnownFolder, String>> {
        Ok(self.system.known_folders.clone())
    }

    fn env(&self) -> SourceResult<BTreeMap<String, String>> {
        Ok(self.system.env.clone())
    }

    fn processes(&self) -> SourceResult<Vec<ProcessInfo>> {
        self.system
            .processes
            .clone()
            .ok_or(SourceError::NotCaptured)
    }

    fn msi_products(&self) -> SourceResult<Vec<MsiProduct>> {
        self.msi_products.clone().ok_or(SourceError::NotCaptured)
    }

    fn msi_product_state_all(&self, code: &str) -> SourceResult<Vec<MsiContextState>> {
        if let Some(states) = self.msi_states.get(&code.to_ascii_uppercase()) {
            return Ok(states.clone());
        }
        let products = self.msi_products.as_ref().ok_or(SourceError::NotCaptured)?;
        Ok([
            MsiContext::Machine,
            MsiContext::UserManaged,
            MsiContext::UserUnmanaged,
        ]
        .into_iter()
        .map(|context| MsiContextState {
            context,
            state: if products
                .iter()
                .any(|p| p.context == context && p.code.eq_ignore_ascii_case(code))
            {
                MsiProductState::Default
            } else {
                MsiProductState::Unknown
            },
        })
        .collect())
    }

    fn packages(&self) -> SourceResult<Vec<PackageInfo>> {
        self.packages.clone().ok_or(SourceError::NotCaptured)
    }

    fn msi_tables(&self, local_package: &str) -> SourceResult<MsiTables> {
        let tables = self.msi_tables.as_ref().ok_or(SourceError::NotCaptured)?;
        let key = package_key(local_package)
            .ok_or_else(|| SourceError::InvalidPath(local_package.to_string()))?;
        let (_, t) = tables.get(&key).ok_or(SourceError::NotFound)?;
        Ok(t.limited())
    }

    fn tasks(&self) -> SourceResult<Vec<TaskInfo>> {
        limited_tasks(self.tasks.as_deref().ok_or(SourceError::NotCaptured)?)
    }

    fn now(&self) -> FileTime {
        self.system.now.unwrap_or(FileTime(0))
    }
}

/// The look-up key of a `LocalPackage` path: the file-path segments, case-folded, `/` read as `\`.
fn package_key(path: &str) -> Option<String> {
    folded_segments(path, false, 0).map(|segs| join_file_path(&segs))
}

// ---------------------------------------------------------------------------------------------------------
// Local baseline sources
// ---------------------------------------------------------------------------------------------------------

/// Value names and types of one key of a [`HiveFixture`], in insertion order.
type HiveValues = Vec<(String, u32)>;

/// An offline registry hive file in memory, for [`LocalSources::default_hive`] of a fixture: key paths
/// relative to the hive root with their value names and types. Walked depth-first in case-folded name
/// order, a key before its values (in insertion order) and subkeys, the root (empty path) first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HiveFixture {
    /// Folded segments -> (path as given, values).
    keys: BTreeMap<Vec<String>, (String, HiveValues)>,
}

impl HiveFixture {
    /// An empty hive (the root key only).
    pub fn new() -> Self {
        let mut h = Self::default();
        h.keys.insert(Vec::new(), (String::new(), Vec::new()));
        h
    }

    /// Adds `path` and its ancestors.
    pub fn key(mut self, path: &str) -> Self {
        self.add_key(path);
        self
    }

    /// Adds value `name` of type `kind` to `path` (created with its ancestors).
    pub fn value(mut self, path: &str, name: &str, kind: u32) -> Self {
        let segs = self.add_key(path);
        let values = &mut self.keys.get_mut(&segs).expect("just added").1;
        values.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        values.push((name.to_owned(), kind));
        self
    }

    /// Number of keys, the root included.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    fn add_key(&mut self, path: &str) -> Vec<String> {
        let parts = split_key(path);
        for n in 0..=parts.len() {
            self.keys
                .entry(parts[..n].iter().map(|s| fold(s)).collect())
                .or_insert_with(|| (parts[..n].join("\\"), Vec::new()));
        }
        parts.iter().map(|s| fold(s)).collect()
    }

    fn walk(&self, origin: &str, visit: &mut dyn FnMut(HiveEntry<'_>)) -> HiveWalk {
        let mut walk = HiveWalk {
            origin: origin.to_owned(),
            ..HiveWalk::default()
        };
        // Lexicographic order of the folded segment lists is a pre-order walk.
        for (path, values) in self.keys.values() {
            visit(HiveEntry::Key { path });
            walk.keys += 1;
            for (name, kind) in values {
                visit(HiveEntry::Value {
                    key: path,
                    name,
                    kind: *kind,
                });
                walk.values += 1;
            }
        }
        walk
    }
}

/// The local sources of the fixture machine, read with the same code as the Live ones: S1 lists
/// `%SystemRoot%\WinSxS\Manifests` in the fixture filesystem, S2 walks the [`HiveFixture`] placed at the
/// path `ProfileList` names ([`Fixture::set_offline_hive`]; none there is [`SourceError::NotFound`]), S3
/// walks the fixture registry's `HKU\.DEFAULT`, S4 reads the fixture's packages, files and registry.
impl LocalSources for Fixture {
    fn manifests(&self) -> SourceResult<ManifestIter<'_>> {
        local_baseline::list_manifests(self, self)
    }

    fn default_hive(&self, visit: &mut dyn FnMut(HiveEntry<'_>)) -> SourceResult<HiveWalk> {
        let path = local_baseline::default_hive_path(self, self)?;
        let hive = package_key(&path)
            .and_then(|k| self.offline_hives.get(&k))
            .ok_or(SourceError::NotFound)?;
        Ok(hive.walk(&path, visit))
    }

    fn system_default(&self, visit: &mut dyn FnMut(HiveEntry<'_>)) -> SourceResult<HiveWalk> {
        local_baseline::walk_registry(self, SYSTEM_DEFAULT_KEY, visit)
    }

    fn inbox_packages(&self) -> SourceResult<InboxPackages> {
        local_baseline::collect_inbox_packages(self, self, self)
    }
}

#[cfg(test)]
mod local_tests {
    use super::*;
    use crate::local_baseline::{InboxReason, PROFILE_LIST, PROVISIONED_KEY, RepositoryProgId};
    use crate::types::PackageSignatureKind;

    const REPO: &str = local_baseline::REPOSITORY_EXTENSIONS_KEY;

    fn hive() -> HiveFixture {
        HiveFixture::new()
            .value(r"Software\Microsoft\Windows\CurrentVersion\Run", "x", 1)
            .key(r"Control Panel\Desktop")
            .value(r"Control Panel\Desktop", "Wallpaper", REG_SZ)
            .value(r"control panel\desktop", "", REG_SZ)
    }

    fn entries(f: &Fixture, s3: bool) -> (Vec<String>, HiveWalk) {
        let mut out = Vec::new();
        let mut visit = |e: HiveEntry<'_>| match e {
            HiveEntry::Key { path } => out.push(format!("K {path}")),
            HiveEntry::Value { key, name, kind } => out.push(format!("V {key}|{name}|{kind}")),
        };
        let walk = if s3 {
            f.system_default(&mut visit)
        } else {
            f.default_hive(&mut visit)
        }
        .unwrap();
        (out, walk)
    }

    #[test]
    fn default_hive_at_the_profile_list_path() {
        let mut f = Fixture::builder()
            .expand_sz(PROFILE_LIST, "Default", r"%SystemDrive%\Users\Default")
            .env("SystemDrive", "D:")
            .build();
        // Nothing at the named path yet.
        assert_eq!(
            f.default_hive(&mut |_| {}).unwrap_err(),
            SourceError::NotFound
        );
        f.set_offline_hive(r"d:\users\default\ntuser.dat", hive());
        let (got, walk) = entries(&f, false);
        assert_eq!(
            got,
            [
                "K ",
                "K Control Panel",
                r"K Control Panel\Desktop",
                r"V Control Panel\Desktop|Wallpaper|1",
                r"V Control Panel\Desktop||1",
                "K Software",
                r"K Software\Microsoft",
                r"K Software\Microsoft\Windows",
                r"K Software\Microsoft\Windows\CurrentVersion",
                r"K Software\Microsoft\Windows\CurrentVersion\Run",
                r"V Software\Microsoft\Windows\CurrentVersion\Run|x|1",
            ]
        );
        assert_eq!((walk.keys, walk.values), (8, 3));
        assert!(walk.is_complete());
        assert_eq!(walk.origin, r"D:\Users\Default\NTUSER.DAT");
    }

    #[test]
    fn default_hive_path_fallback_and_errors() {
        // No `Default` value: `ProfilesDirectory\Default`.
        let f = Fixture::builder()
            .expand_sz(
                PROFILE_LIST,
                "ProfilesDirectory",
                r"%SystemDrive%\Profiles\",
            )
            .env("SYSTEMDRIVE", "C:")
            .build();
        assert_eq!(
            local_baseline::default_hive_path(&f, &f).unwrap(),
            r"C:\Profiles\Default\NTUSER.DAT"
        );
        // A reference that cannot be expanded is an error, not a guess.
        let f = Fixture::builder()
            .expand_sz(PROFILE_LIST, "Default", r"%NoSuchVar%\Default")
            .build();
        assert!(matches!(
            local_baseline::default_hive_path(&f, &f),
            Err(SourceError::InvalidPath(_))
        ));
        // Neither value: not found; no hard-coded C:\Users\Default.
        let f = Fixture::builder().key(PROFILE_LIST).build();
        assert_eq!(
            local_baseline::default_hive_path(&f, &f),
            Err(SourceError::NotFound)
        );
    }

    #[test]
    fn system_default_walk() {
        let f = Fixture::builder()
            .sz(r"HKU\.DEFAULT\Control Panel\Desktop", "Wallpaper", "")
            .key(r"HKU\.DEFAULT\Software\Secret\Deeper")
            .denied(r"HKU\.DEFAULT\Software\Secret")
            .link(
                r"HKU\.DEFAULT\Software\Linked",
                r"\REGISTRY\MACHINE\SOFTWARE",
            )
            .key(r"HKU\S-1-5-21-1-2-3-1001\Software\Other")
            .build();
        let (got, walk) = entries(&f, true);
        assert_eq!(
            got,
            [
                "K ",
                "K Control Panel",
                r"K Control Panel\Desktop",
                r"V Control Panel\Desktop|Wallpaper|1",
                "K Software",
                r"K Software\Linked",
                r"V Software\Linked|SymbolicLinkValue|6",
                r"K Software\Secret",
            ]
        );
        assert_eq!((walk.keys, walk.links, walk.unreadable), (6, 1, 1));
        assert_eq!(walk.unreadable_keys, [r"HKU\.DEFAULT\Software\Secret"]);
        assert!(walk.vanished_keys.is_empty());
        assert!(!walk.is_complete());
        // Not there at all: an error.
        let empty = Fixture::new();
        assert_eq!(
            empty.system_default(&mut |_| {}).unwrap_err(),
            SourceError::NotFound
        );
    }

    #[test]
    fn manifests_listing() {
        let dir = r"C:\Windows\WinSxS\Manifests";
        let f = Fixture::builder()
            .env("SystemRoot", r"C:\Windows")
            .file_content(&format!(r"{dir}\b.manifest"), b"<assembly/>".to_vec())
            .file_content(&format!(r"{dir}\A.MANIFEST"), b"DCM\x01PA30".to_vec())
            .file_content(&format!(r"{dir}\x.cat"), b"cat".to_vec())
            .file(&format!(r"{dir}\c.manifest"), 3)
            .dir(&format!(r"{dir}\sub.manifest"))
            .build();
        let got: Vec<(String, SourceResult<Vec<u8>>)> = f
            .manifests()
            .unwrap()
            .map(|(name, read)| (name, read()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("A.MANIFEST".to_string(), Ok(b"DCM\x01PA30".to_vec())),
                ("b.manifest".to_string(), Ok(b"<assembly/>".to_vec())),
                ("c.manifest".to_string(), Err(SourceError::NotCaptured)),
            ]
        );
        assert!(Fixture::new().manifests().is_err());
    }

    fn package(full: &str, kind: PackageSignatureKind, dir: Option<&str>) -> PackageInfo {
        PackageInfo {
            full_name: full.into(),
            family: local_baseline::family_of_full_name(full).unwrap(),
            install_location: dir.map(String::from),
            external_location: None,
            sparse: false,
            users: Vec::new(),
            is_framework: false,
            is_resource: false,
            signature_kind: kind,
        }
    }

    #[test]
    fn inbox_packages_selection_manifests_and_repository() {
        let photos = "Microsoft.Windows.Photos_1.0.0.0_x64__8wekyb3d8bbwe";
        let shell = "Microsoft.Windows.ShellExperienceHost_10.0.1.0_neutral_neutral_cw5n1h2txyewy";
        let vendor = "Vendor.App_1.0.0.0_x64__abcdefghijklm";
        let none = RegData::new(0, Vec::new());
        let f = Fixture::builder()
            .elevated(true)
            .key(&format!(
                r"{PROVISIONED_KEY}\Microsoft.Windows.Photos_1.0.0.0_neutral_~_8wekyb3d8bbwe"
            ))
            .key(&format!(
                r"{PROVISIONED_KEY}\Vendor.App_1.0.0.0_neutral_~_abcdefghijklm"
            ))
            .value(
                &format!(r"{REPO}\ProgIDs\AppXphotos1"),
                photos,
                none.clone(),
            )
            .value(
                &format!(r"{REPO}\ProgIDs\AppXphotos2"),
                photos,
                none.clone(),
            )
            .value(&format!(r"{REPO}\ProgIDs\AppXvendor"), vendor, none.clone())
            .value(
                &format!(r"{REPO}\windows.fileTypeAssociation\.jpg\AppXphotos1"),
                photos,
                none.clone(),
            )
            .value(
                &format!(r"{REPO}\windows.fileTypeAssociation\.png\AppXphotos1"),
                photos,
                none.clone(),
            )
            .value(
                &format!(r"{REPO}\windows.protocol\ms-photos\AppXphotos2"),
                photos,
                none.clone(),
            )
            .package(package(
                photos,
                PackageSignatureKind::Store,
                Some(r"C:\Program Files\WindowsApps\Photos"),
            ))
            .package(package(
                shell,
                PackageSignatureKind::System,
                Some(r"C:\Windows\SystemApps\Shell\"),
            ))
            .package(package(
                vendor,
                PackageSignatureKind::Store,
                Some(r"C:\Program Files\WindowsApps\Vendor"),
            ))
            .file_content(
                r"C:\Program Files\WindowsApps\Photos\AppxManifest.xml",
                b"\xEF\xBB\xBF<Package/>".to_vec(),
            )
            .file_content(
                r"C:\Program Files\WindowsApps\Vendor\AppxManifest.xml",
                b"<Package/>".to_vec(),
            )
            .build();
        let s4 = f.inbox_packages().unwrap();
        assert!(s4.machine_wide);
        assert_eq!(s4.not_inbox, 1);
        assert_eq!(s4.provisioned, Ok(2));
        assert_eq!(s4.repository, Ok(()));
        let names: Vec<(&str, InboxReason)> = s4
            .packages
            .iter()
            .map(|p| (p.full_name.as_str(), p.reason))
            .collect();
        assert_eq!(
            names,
            [
                (photos, InboxReason::MicrosoftProvisioned),
                (shell, InboxReason::System)
            ]
        );
        assert_eq!(s4.packages[0].manifest.as_deref(), Ok("<Package/>"));
        // The System package's manifest is not in the fixture: counted by the caller, not fatal.
        assert!(s4.packages[1].manifest.is_err());
        assert_eq!(
            s4.packages[0].repository_prog_ids,
            [
                RepositoryProgId {
                    prog_id: "AppXphotos1".into(),
                    file_types: vec![".jpg".into(), ".png".into()],
                    protocols: vec![],
                },
                RepositoryProgId {
                    prog_id: "AppXphotos2".into(),
                    file_types: vec![],
                    protocols: vec!["ms-photos".into()],
                },
            ]
        );
        assert!(s4.packages[1].repository_prog_ids.is_empty());

        // No repository and no provisioned list: still a result, with the gaps reported.
        let f = Fixture::builder()
            .package(package(photos, PackageSignatureKind::Store, None))
            .package(package(shell, PackageSignatureKind::System, None))
            .build();
        let s4 = f.inbox_packages().unwrap();
        assert_eq!(s4.packages.len(), 1);
        assert_eq!(s4.not_inbox, 1);
        assert!(s4.provisioned.is_err() && s4.repository.is_err() && !s4.machine_wide);
        assert_eq!(s4.packages[0].manifest, Err(SourceError::NotFound));
    }
}

// ---------------------------------------------------------------------------------------------------------
// Deriving system facts from the registry (snapshot fixtures)
// ---------------------------------------------------------------------------------------------------------

/// Expands `%NAME%` against `env` (names upper-cased); unknown variables stay as written.
pub(crate) fn expand_env(s: &str, env: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let name = &after[..end];
                match env.get(&name.to_uppercase()) {
                    Some(v) if !name.is_empty() => {
                        out.push_str(v);
                        rest = &after[end + 1..];
                    }
                    _ => {
                        // Keep the first `%` and continue at the second, which may open a real variable.
                        out.push('%');
                        out.push_str(name);
                        rest = &after[end..];
                    }
                }
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

impl Fixture {
    fn reg_string(&self, key: &str, name: &str) -> Option<String> {
        let d = self.value(key, name).ok()?;
        d.string().filter(|s| !s.is_empty())
    }

    /// Fills the system facts a snapshot does not record from the registry it does record: `user_sid`
    /// (the single `S-1-5-21-*` hive with a profile, when not set), `ProfileList` profiles, the
    /// interactive user's environment (system + user + volatile, expanded), the known folders (from
    /// `User Shell Folders`, with Windows defaults) and the admin-only roots (`Program Files*`,
    /// `Windows`). Only empty facts are filled.
    pub fn derive_system_facts(&mut self) {
        const NT_CV: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
        const CV: &str = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion";
        let profile_list = format!("{NT_CV}\\ProfileList");

        let mut env: BTreeMap<String, String> = BTreeMap::new();
        let system_root = self
            .reg_string(NT_CV, "SystemRoot")
            .unwrap_or_else(|| "C:\\Windows".to_string());
        let system_drive: String = system_root.chars().take(2).collect();
        fn put(env: &mut BTreeMap<String, String>, k: &str, v: String) {
            env.insert(k.to_string(), v);
        }
        put(&mut env, "SYSTEMDRIVE", system_drive.clone());
        put(&mut env, "SYSTEMROOT", system_root.clone());
        put(&mut env, "WINDIR", system_root.clone());
        let pf = self
            .reg_string(CV, "ProgramFilesDir")
            .unwrap_or_else(|| format!("{system_drive}\\Program Files"));
        let pf86 = self
            .reg_string(CV, "ProgramFilesDir (x86)")
            .unwrap_or_else(|| format!("{system_drive}\\Program Files (x86)"));
        let cf = self
            .reg_string(CV, "CommonFilesDir")
            .unwrap_or_else(|| format!("{pf}\\Common Files"));
        let cf86 = self
            .reg_string(CV, "CommonFilesDir (x86)")
            .unwrap_or_else(|| format!("{pf86}\\Common Files"));
        put(&mut env, "PROGRAMFILES", pf.clone());
        put(&mut env, "PROGRAMW6432", pf.clone());
        put(&mut env, "PROGRAMFILES(X86)", pf86.clone());
        put(&mut env, "COMMONPROGRAMFILES", cf.clone());
        put(&mut env, "COMMONPROGRAMW6432", cf.clone());
        put(&mut env, "COMMONPROGRAMFILES(X86)", cf86.clone());
        let program_data = self
            .reg_string(&profile_list, "ProgramData")
            .map(|s| expand_env(&s, &env))
            .unwrap_or_else(|| format!("{system_drive}\\ProgramData"));
        let public = self
            .reg_string(&profile_list, "Public")
            .map(|s| expand_env(&s, &env))
            .unwrap_or_else(|| format!("{system_drive}\\Users\\Public"));
        put(&mut env, "PROGRAMDATA", program_data.clone());
        put(&mut env, "ALLUSERSPROFILE", program_data.clone());
        put(&mut env, "PUBLIC", public.clone());
        if let Some(c) = &self.system.computer {
            put(&mut env, "COMPUTERNAME", c.clone());
        }

        // Profiles.
        let mut profiles = Vec::new();
        for sid in self.subkeys(&profile_list).unwrap_or_default() {
            if let Some(p) = self.reg_string(&format!("{profile_list}\\{sid}"), "ProfileImagePath")
            {
                profiles.push(ProfileInfo {
                    sid,
                    path: expand_env(&p, &env),
                });
            }
        }
        if self.system.profiles.as_ref().is_none_or(Vec::is_empty) && !profiles.is_empty() {
            self.system.profiles = Some(profiles.clone());
        }

        // The interactive user.
        if self.system.user_sid.is_none() {
            let users: Vec<String> = self
                .loaded_user_sids()
                .unwrap_or_default()
                .into_iter()
                .filter(|s| s.starts_with("S-1-5-21-"))
                .collect();
            let with_profile: Vec<&String> = users
                .iter()
                .filter(|s| profiles.iter().any(|p| p.sid.eq_ignore_ascii_case(s)))
                .collect();
            self.system.user_sid = match (with_profile.as_slice(), users.as_slice()) {
                ([one], _) => Some((*one).clone()),
                ([], [one]) => Some(one.clone()),
                _ => None,
            };
        }
        let user_sid = self.system.user_sid.clone();
        let profile = user_sid.as_ref().and_then(|sid| {
            profiles
                .iter()
                .find(|p| p.sid.eq_ignore_ascii_case(sid))
                .map(|p| p.path.clone())
        });

        if let Some(profile) = &profile {
            put(&mut env, "USERPROFILE", profile.clone());
            put(&mut env, "HOMEDRIVE", profile.chars().take(2).collect());
            put(&mut env, "HOMEPATH", profile.chars().skip(2).collect());
            if let Some(user) = profile.rsplit('\\').next() {
                put(&mut env, "USERNAME", user.to_string());
            }
            put(&mut env, "APPDATA", format!("{profile}\\AppData\\Roaming"));
            put(
                &mut env,
                "LOCALAPPDATA",
                format!("{profile}\\AppData\\Local"),
            );
            put(&mut env, "TEMP", format!("{profile}\\AppData\\Local\\Temp"));
            put(&mut env, "TMP", format!("{profile}\\AppData\\Local\\Temp"));
        }

        // System, user and volatile environment blocks.
        let session_env = format!(
            "HKLM\\SYSTEM\\{}\\Control\\Session Manager\\Environment",
            crate::registry::control_set_name(self.current_control_set)
        );
        let mut blocks = vec![(session_env, false)];
        if let Some(sid) = &user_sid {
            blocks.push((format!("HKU\\{sid}\\Environment"), true));
            blocks.push((format!("HKU\\{sid}\\Volatile Environment"), false));
        }
        for (key, is_user) in blocks {
            for v in self.values(&key).unwrap_or_default() {
                let Some(raw) = v.data.string() else { continue };
                let name = v.name.to_uppercase();
                let val = expand_env(&raw, &env);
                if is_user && name == "PATH" {
                    let sys = env.get("PATH").cloned().unwrap_or_default();
                    let joined = if sys.is_empty() {
                        val
                    } else {
                        format!("{sys};{val}")
                    };
                    env.insert(name, joined);
                } else {
                    env.insert(name, val);
                }
            }
        }

        // Known folders.
        let mut kf: BTreeMap<KnownFolder, String> = BTreeMap::new();
        kf.insert(KnownFolder::Windows, system_root.clone());
        kf.insert(KnownFolder::System, format!("{system_root}\\System32"));
        kf.insert(KnownFolder::SystemX86, format!("{system_root}\\SysWOW64"));
        kf.insert(KnownFolder::Fonts, format!("{system_root}\\Fonts"));
        kf.insert(KnownFolder::ProgramFiles, pf.clone());
        kf.insert(KnownFolder::ProgramFilesX86, pf86.clone());
        kf.insert(KnownFolder::ProgramFilesCommon, cf);
        kf.insert(KnownFolder::ProgramFilesCommonX86, cf86);
        kf.insert(KnownFolder::ProgramData, program_data.clone());
        kf.insert(KnownFolder::Public, public.clone());
        kf.insert(KnownFolder::PublicDesktop, format!("{public}\\Desktop"));
        let common_sm = format!("{program_data}\\Microsoft\\Windows\\Start Menu");
        kf.insert(KnownFolder::CommonStartMenu, common_sm.clone());
        kf.insert(
            KnownFolder::CommonPrograms,
            format!("{common_sm}\\Programs"),
        );
        kf.insert(
            KnownFolder::CommonStartup,
            format!("{common_sm}\\Programs\\Startup"),
        );
        let machine_usf = format!("{CV}\\Explorer\\User Shell Folders");
        for (name, folder) in [
            ("Common Start Menu", KnownFolder::CommonStartMenu),
            ("Common Programs", KnownFolder::CommonPrograms),
            ("Common Startup", KnownFolder::CommonStartup),
            ("Common Desktop", KnownFolder::PublicDesktop),
        ] {
            if let Some(v) = self.reg_string(&machine_usf, name) {
                kf.insert(folder, expand_env(&v, &env));
            }
        }
        if let (Some(profile), Some(sid)) = (&profile, &user_sid) {
            let local = format!("{profile}\\AppData\\Local");
            let roaming = format!("{profile}\\AppData\\Roaming");
            let sm = format!("{roaming}\\Microsoft\\Windows\\Start Menu");
            kf.insert(KnownFolder::Profile, profile.clone());
            kf.insert(KnownFolder::RoamingAppData, roaming.clone());
            kf.insert(KnownFolder::LocalAppData, local.clone());
            kf.insert(
                KnownFolder::LocalAppDataLow,
                format!("{profile}\\AppData\\LocalLow"),
            );
            kf.insert(KnownFolder::Desktop, format!("{profile}\\Desktop"));
            kf.insert(KnownFolder::Documents, format!("{profile}\\Documents"));
            kf.insert(KnownFolder::Downloads, format!("{profile}\\Downloads"));
            kf.insert(KnownFolder::StartMenu, sm.clone());
            kf.insert(KnownFolder::Programs, format!("{sm}\\Programs"));
            kf.insert(KnownFolder::Startup, format!("{sm}\\Programs\\Startup"));
            kf.insert(
                KnownFolder::Templates,
                format!("{roaming}\\Microsoft\\Windows\\Templates"),
            );
            kf.insert(
                KnownFolder::SendTo,
                format!("{roaming}\\Microsoft\\Windows\\SendTo"),
            );
            let usf = format!(
                "HKU\\{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
            );
            for (name, folder) in [
                ("AppData", KnownFolder::RoamingAppData),
                ("Local AppData", KnownFolder::LocalAppData),
                ("Desktop", KnownFolder::Desktop),
                ("Personal", KnownFolder::Documents),
                (
                    "{374DE290-123F-4565-9164-39C4925E467B}",
                    KnownFolder::Downloads,
                ),
                ("Start Menu", KnownFolder::StartMenu),
                ("Programs", KnownFolder::Programs),
                ("Startup", KnownFolder::Startup),
                ("Templates", KnownFolder::Templates),
                ("SendTo", KnownFolder::SendTo),
            ] {
                if let Some(v) = self.reg_string(&usf, name) {
                    kf.insert(folder, expand_env(&v, &env));
                }
            }
            if let Some(appdata) = kf.get(&KnownFolder::RoamingAppData) {
                env.insert("APPDATA".into(), appdata.clone());
            }
            if let Some(local) = kf.get(&KnownFolder::LocalAppData).cloned() {
                kf.insert(KnownFolder::UserProgramFiles, format!("{local}\\Programs"));
                env.insert("LOCALAPPDATA".into(), local);
            }
        }

        if self.system.env.is_empty() {
            self.system.env = env;
        }
        if self.system.known_folders.is_empty() {
            self.system.known_folders = kf;
        }
        if self.admin_only_roots.is_empty() {
            self.set_admin_only_roots(vec![pf, pf86, system_root]);
        }
    }
}

// ---------------------------------------------------------------------------------------------------------
// JSON format
// ---------------------------------------------------------------------------------------------------------

mod b64 {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub(super) fn encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    pub(super) fn decode(s: &str) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(s.len() / 4 * 3);
        let mut acc = 0u32;
        let mut bits = 0;
        for c in s.bytes().filter(|c| !c.is_ascii_whitespace()) {
            if c == b'=' {
                break;
            }
            let v = ALPHABET
                .iter()
                .position(|&a| a == c)
                .ok_or_else(|| format!("invalid base64 character {:?}", c as char))?;
            acc = (acc << 6) | v as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((acc >> bits) as u8);
                acc &= (1 << bits) - 1;
            }
        }
        Ok(out)
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn default_ccs() -> u32 {
    1
}

fn yes() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureDoc {
    schema: String,
    #[serde(default)]
    system: SystemFacts,
    #[serde(default)]
    registry: RegistryDoc,
    #[serde(default)]
    filesystem: FsDoc,
    #[serde(default)]
    msi: MsiDoc,
    #[serde(default = "some_empty")]
    packages: Option<Vec<PackageInfo>>,
    /// Absent (or `null`) = not captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    msi_tables: Option<BTreeMap<String, MsiTables>>,
    /// Absent (or `null`) = not captured.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "strict_tasks"
    )]
    tasks: Option<Vec<TaskInfo>>,
}

/// The `tasks` section, with unknown fields rejected at every depth: [`TaskInfo`] denies them itself, but
/// the task identity and its actions (purge-model types) would ignore them. Each task is read, written
/// back, and every key of the input must be in what was written (serde writes every field of these types).
fn strict_tasks<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Vec<TaskInfo>>, D::Error> {
    use serde::de::Error as _;
    let Some(items) = Option::<Vec<serde_json::Value>>::deserialize(d)? else {
        return Ok(None);
    };
    let mut tasks = Vec::with_capacity(items.len());
    for (i, item) in items.into_iter().enumerate() {
        let task: TaskInfo = serde_json::from_value(item.clone())
            .map_err(|e| D::Error::custom(format!("tasks[{i}]: {e}")))?;
        let written = serde_json::to_value(&task)
            .map_err(|e| D::Error::custom(format!("tasks[{i}]: {e}")))?;
        if let Some(field) = unknown_field(&item, &written) {
            return Err(D::Error::custom(format!(
                "tasks[{i}]: unknown field `{field}`"
            )));
        }
        tasks.push(task);
    }
    Ok(Some(tasks))
}

/// The first key path of `input` that `known` lacks (objects by key, arrays by position).
fn unknown_field(input: &serde_json::Value, known: &serde_json::Value) -> Option<String> {
    use serde_json::Value;
    match (input, known) {
        (Value::Object(a), Value::Object(b)) => a.iter().find_map(|(k, va)| match b.get(k) {
            None => Some(k.clone()),
            Some(vb) => unknown_field(va, vb).map(|rest| format!("{k}.{rest}")),
        }),
        (Value::Array(a), Value::Array(b)) => a
            .iter()
            .zip(b)
            .enumerate()
            .find_map(|(i, (va, vb))| unknown_field(va, vb).map(|rest| format!("{i}.{rest}"))),
        _ => None,
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RegistryDoc {
    #[serde(default = "default_ccs")]
    current_control_set: u32,
    #[serde(default = "yes")]
    values_captured: bool,
    #[serde(default, skip_serializing_if = "Coverage::is_everything")]
    coverage: Coverage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    denied: Vec<String>,
    #[serde(default)]
    keys: BTreeMap<String, KeyDoc>,
}

impl Default for RegistryDoc {
    fn default() -> Self {
        Self {
            current_control_set: 1,
            values_captured: true,
            coverage: Coverage::default(),
            denied: Vec::new(),
            keys: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct KeyDoc {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    lwt: Option<FileTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    n_values: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    n_subkeys: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ti_owned: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    values: BTreeMap<String, ValueRepr>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    keys: BTreeMap<String, KeyDoc>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum ValueRepr {
    Sz(String),
    Full(ValueDoc),
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ValueDoc {
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    ty: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sz: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expand_sz: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    multi_sz: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dword: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    qword: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    len: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    truncated: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    unknown: bool,
}

impl ValueRepr {
    fn into_data(self, where_: &str) -> Result<RegData, FixtureError> {
        let doc = match self {
            ValueRepr::Sz(s) => return Ok(RegData::from_sz(&s)),
            ValueRepr::Full(d) => d,
        };
        let bad = |m: &str| FixtureError::Invalid(format!("{where_}: {m}"));
        let forms = [
            doc.sz.is_some(),
            doc.expand_sz.is_some(),
            doc.link.is_some(),
            doc.multi_sz.is_some(),
            doc.dword.is_some(),
            doc.qword.is_some(),
            doc.b64.is_some(),
            doc.unknown,
        ]
        .iter()
        .filter(|&&b| b)
        .count();
        if forms != 1 {
            return Err(bad("a value needs exactly one data form"));
        }
        let (mut data, implied) = if let Some(s) = &doc.sz {
            (RegData::from_sz(s), Some(REG_SZ))
        } else if let Some(s) = &doc.expand_sz {
            (RegData::from_expand_sz(s), Some(REG_EXPAND_SZ))
        } else if let Some(s) = &doc.link {
            (RegData::from_link(s), Some(REG_LINK))
        } else if let Some(m) = &doc.multi_sz {
            (RegData::from_multi_sz(m), Some(REG_MULTI_SZ))
        } else if let Some(n) = doc.dword {
            (RegData::from_dword(n), Some(REG_DWORD))
        } else if let Some(n) = doc.qword {
            (RegData::from_qword(n), Some(REG_QWORD))
        } else if let Some(b) = &doc.b64 {
            let ty = doc.ty.ok_or_else(|| bad("b64 needs a type"))?;
            (RegData::new(ty, b64::decode(b).map_err(|e| bad(&e))?), None)
        } else {
            let ty = doc.ty.ok_or_else(|| bad("unknown data needs a type"))?;
            (RegData::unknown(ty, doc.len.unwrap_or(0)), None)
        };
        if matches!((implied, doc.ty), (Some(implied), Some(ty)) if implied != ty) {
            return Err(bad("type does not match the data form"));
        }
        if let Some(len) = doc.len {
            data.len = len;
        }
        if let Some(h) = &doc.hash {
            data.hash = Some(u64::from_str_radix(h, 16).map_err(|e| bad(&format!("hash: {e}")))?);
        }
        data.truncated = doc.truncated;
        Ok(data)
    }

    fn from_data(d: &RegData) -> ValueRepr {
        let mut doc = ValueDoc::default();
        let plain =
            !d.truncated && !d.data_unknown && d.hash.is_none() && d.len as usize == d.bytes.len();
        if d.data_unknown {
            doc.ty = Some(d.ty);
            doc.unknown = true;
            doc.len = Some(d.len);
        } else {
            let exact = |candidate: RegData| candidate.bytes == d.bytes;
            match d.ty {
                REG_SZ if d.sz().is_some_and(|s| exact(RegData::from_sz(&s))) => {
                    let s = d.sz().unwrap_or_default();
                    if plain {
                        return ValueRepr::Sz(s);
                    }
                    doc.sz = Some(s);
                }
                REG_EXPAND_SZ
                    if d.expand_sz()
                        .is_some_and(|s| exact(RegData::from_expand_sz(&s))) =>
                {
                    doc.expand_sz = d.expand_sz();
                }
                REG_LINK
                    if d.link_target()
                        .is_some_and(|s| exact(RegData::from_link(&s))) =>
                {
                    doc.link = d.link_target();
                }
                REG_MULTI_SZ
                    if d.multi_sz()
                        .is_some_and(|m| exact(RegData::from_multi_sz(&m))) =>
                {
                    doc.multi_sz = d.multi_sz();
                }
                REG_DWORD if d.dword().is_some() && !d.truncated => doc.dword = d.dword(),
                REG_QWORD if d.qword().is_some() && !d.truncated => doc.qword = d.qword(),
                _ => {
                    doc.ty = Some(d.ty);
                    doc.b64 = Some(b64::encode(&d.bytes));
                }
            }
            if d.len as usize != d.bytes.len() {
                doc.len = Some(d.len);
            }
        }
        doc.hash = d.hash.map(|h| format!("{h:016x}"));
        doc.truncated = d.truncated;
        ValueRepr::Full(doc)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct FsDoc {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    volumes: BTreeMap<String, VolumeInfo>,
    #[serde(default, skip_serializing_if = "Coverage::is_everything")]
    coverage: Coverage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    denied: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    admin_only_roots: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    unknown_file_facts: bool,
    #[serde(default)]
    entries: BTreeMap<String, EntryDoc>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EntryDoc {
    #[serde(default, skip_serializing_if = "is_false")]
    dir: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attrs: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    created: Option<FileTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    modified: Option<FileTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    accessed: Option<FileTime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reparse_tag: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file_id: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    volume_serial: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    short_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content_text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version_info: Option<VersionInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    shortcut: Option<ShortcutInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admin_only_writable: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    children: BTreeMap<String, EntryDoc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct MsiDoc {
    #[serde(default = "some_empty")]
    products: Option<Vec<MsiProduct>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    states: BTreeMap<String, Vec<MsiContextState>>,
}

impl Default for MsiDoc {
    fn default() -> Self {
        Self {
            products: Some(Vec::new()),
            states: BTreeMap::new(),
        }
    }
}

impl Fixture {
    /// Loads a `purge.fixture/1` document. Side files (`content_file`) resolve against `base_dir`, or the
    /// current directory when `None`.
    pub fn from_json_str(json: &str, base_dir: Option<&Path>) -> Result<Fixture, FixtureError> {
        let doc: FixtureDoc = serde_json::from_str(json.trim_start_matches('\u{feff}'))?;
        if doc.schema != FIXTURE_SCHEMA {
            return Err(FixtureError::Schema(doc.schema));
        }
        let mut f = Fixture::new();
        f.base_dir = base_dir.map(Path::to_path_buf);
        f.system = doc.system;
        f.msi_products = doc.msi.products;
        f.msi_states = doc
            .msi
            .states
            .into_iter()
            .map(|(k, v)| (k.to_ascii_uppercase(), v))
            .collect();
        f.packages = doc.packages;
        if let Some(tables) = doc.msi_tables {
            let mut map = BTreeMap::new();
            for (path, t) in tables {
                let key = package_key(&path).ok_or_else(|| {
                    FixtureError::Invalid(format!("msi_tables: bad package path {path:?}"))
                })?;
                if map.insert(key, (path.clone(), t)).is_some() {
                    return Err(FixtureError::Invalid(format!(
                        "msi_tables: package {path:?} listed twice"
                    )));
                }
            }
            f.msi_tables = Some(map);
        }
        f.tasks = doc.tasks;

        let reg = doc.registry;
        f.current_control_set = reg.current_control_set;
        f.values_captured = reg.values_captured;
        f.set_registry_coverage(reg.coverage);
        f.reg_denied = reg.denied;
        for (name, key) in reg.keys {
            f.load_key("", &name, key)?;
        }

        let fs = doc.filesystem;
        f.fs_denied = fs.denied;
        f.recompile_denied();
        f.volumes = fs.volumes;
        f.recompile_volumes();
        f.set_fs_coverage(fs.coverage);
        f.set_admin_only_roots(fs.admin_only_roots);
        f.unknown_file_facts = fs.unknown_file_facts;
        for (name, entry) in fs.entries {
            f.load_entry(None, &name, entry)?;
        }
        Ok(f)
    }

    /// Loads a `purge.fixture/1` file; side files resolve against its directory.
    pub fn from_json_file(path: &Path) -> Result<Fixture, FixtureError> {
        let text = std::fs::read_to_string(path).map_err(|source| FixtureError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_json_str(&text, path.parent())
    }

    fn load_key(&mut self, prefix: &str, name: &str, doc: KeyDoc) -> Result<(), FixtureError> {
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}\\{name}")
        };
        let segs = self
            .reg_segs(&path)
            .map_err(|_| FixtureError::Invalid(format!("bad key path {path:?}")))?;
        let idx = self.reg.ensure(&segs);
        self.reg.nodes[idx].declared = true;
        let mut values = Vec::with_capacity(doc.values.len());
        for (vname, repr) in doc.values {
            let data = repr.into_data(&format!("{path} [{vname}]"))?;
            values.push(RegValue { name: vname, data });
        }
        let data = &mut self.reg.nodes[idx].data;
        data.lwt = doc.lwt.map_or(0, |t| t.0);
        data.n_values = doc.n_values;
        data.n_subkeys = doc.n_subkeys;
        data.link_target = doc.link_target;
        data.ti_owned = doc.ti_owned;
        data.values = values;
        let full = segs.join("\\");
        for (child, cdoc) in doc.keys {
            self.load_key(&full, &child, cdoc)?;
        }
        Ok(())
    }

    fn load_entry(
        &mut self,
        parent: Option<&[String]>,
        name: &str,
        doc: EntryDoc,
    ) -> Result<(), FixtureError> {
        let segs: Vec<String> = match parent {
            None => split_file_path(name)
                .ok_or_else(|| FixtureError::Invalid(format!("bad file path {name:?}")))?,
            Some(p) => {
                let mut s = p.to_vec();
                s.extend(
                    name.split(['\\', '/'])
                        .filter(|x| !x.is_empty())
                        .map(String::from),
                );
                s
            }
        };
        let idx = self.fs.ensure(&segs);
        self.fs.nodes[idx].declared = true;
        let is_dir = doc.dir || !doc.children.is_empty();
        let content = match (doc.content_b64, doc.content_text, doc.content_file) {
            (None, None, None) => None,
            (Some(b), None, None) => {
                Some(Content::Inline(b64::decode(&b).map_err(|e| {
                    FixtureError::Invalid(format!("{name}: {e}"))
                })?))
            }
            (None, Some(t), None) => Some(Content::Inline(t.into_bytes())),
            (None, None, Some(given)) => {
                let resolved = match &self.base_dir {
                    Some(b) => b.join(&given),
                    None => PathBuf::from(&given),
                };
                Some(Content::File { given, resolved })
            }
            _ => {
                return Err(FixtureError::Invalid(format!(
                    "{name}: at most one of content_b64, content_text, content_file"
                )));
            }
        };
        if is_dir && content.is_some() {
            return Err(FixtureError::Invalid(format!(
                "{name}: a directory has no content"
            )));
        }
        let size = doc.size.unwrap_or(match &content {
            Some(Content::Inline(b)) => b.len() as u64,
            Some(Content::File { resolved, .. }) => {
                std::fs::metadata(resolved).map(|m| m.len()).unwrap_or(0)
            }
            None => 0,
        });
        let default_attrs = if is_dir {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_ARCHIVE
        };
        let mut attrs = doc.attrs.unwrap_or(default_attrs);
        if is_dir {
            attrs |= FILE_ATTRIBUTE_DIRECTORY;
        } else {
            attrs &= !FILE_ATTRIBUTE_DIRECTORY;
        }
        self.fs.nodes[idx].data = FsData {
            attrs,
            size: if is_dir { 0 } else { size },
            times: FileTimes {
                created: doc.created,
                modified: doc.modified,
                accessed: doc.accessed,
            },
            reparse_tag: doc.reparse_tag.unwrap_or(0),
            file_id: doc.file_id,
            volume_serial: doc.volume_serial,
            short_name: doc.short_name,
            content,
            version_info: doc.version_info,
            signer: doc.signer,
            shortcut: doc.shortcut,
            admin_only_writable: doc.admin_only_writable,
        };
        for (child, cdoc) in doc.children {
            self.load_entry(Some(&segs), &child, cdoc)?;
        }
        Ok(())
    }

    /// The fixture as a `purge.fixture/1` document (keys and entries flat, deterministic order).
    fn to_doc(&self) -> FixtureDoc {
        let mut keys = BTreeMap::new();
        for idx in self.reg.dfs() {
            let node = &self.reg.nodes[idx];
            if !node.declared && !node.children.is_empty() && node.data.is_default() {
                continue;
            }
            let d = &node.data;
            let doc = KeyDoc {
                lwt: (d.lwt != 0).then_some(FileTime(d.lwt)),
                n_values: d.n_values,
                n_subkeys: d.n_subkeys,
                link_target: d.link_target.clone(),
                ti_owned: d.ti_owned,
                values: d
                    .values
                    .iter()
                    .map(|v| (v.name.clone(), ValueRepr::from_data(&v.data)))
                    .collect(),
                keys: BTreeMap::new(),
            };
            keys.insert(self.reg.names_to(idx).join("\\"), doc);
        }
        let mut entries = BTreeMap::new();
        for idx in self.fs.dfs() {
            let node = &self.fs.nodes[idx];
            let d = &node.data;
            if !node.declared && !node.children.is_empty() && *d == FsData::default() {
                continue;
            }
            let is_dir = d.is_dir();
            let default_attrs = if is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_ARCHIVE
            };
            let (content_b64, content_text, content_file) = match &d.content {
                None => (None, None, None),
                Some(Content::Inline(b)) => match std::str::from_utf8(b) {
                    Ok(t) => (None, Some(t.to_string()), None),
                    Err(_) => (Some(b64::encode(b)), None, None),
                },
                Some(Content::File { given, .. }) => (None, None, Some(given.clone())),
            };
            let size_implied = match &d.content {
                Some(Content::Inline(b)) => b.len() as u64 == d.size,
                _ => d.size == 0,
            };
            let doc = EntryDoc {
                dir: is_dir,
                size: (!is_dir && !size_implied).then_some(d.size),
                attrs: (d.attrs != default_attrs).then_some(d.attrs),
                created: d.times.created,
                modified: d.times.modified,
                accessed: d.times.accessed,
                reparse_tag: (d.reparse_tag != 0).then_some(d.reparse_tag),
                file_id: d.file_id,
                volume_serial: d.volume_serial,
                short_name: d.short_name.clone(),
                content_b64,
                content_text,
                content_file,
                version_info: d.version_info.clone(),
                signer: d.signer.clone(),
                shortcut: d.shortcut.clone(),
                admin_only_writable: d.admin_only_writable,
                children: BTreeMap::new(),
            };
            entries.insert(join_file_path(&self.fs.names_to(idx)), doc);
        }
        FixtureDoc {
            schema: FIXTURE_SCHEMA.to_string(),
            system: self.system.clone(),
            registry: RegistryDoc {
                current_control_set: self.current_control_set,
                values_captured: self.values_captured,
                coverage: self.reg_coverage.clone(),
                denied: self.reg_denied.clone(),
                keys,
            },
            filesystem: FsDoc {
                volumes: self.volumes.clone(),
                coverage: self.fs_coverage.clone(),
                denied: self.fs_denied.clone(),
                admin_only_roots: self.admin_only_roots.clone(),
                unknown_file_facts: self.unknown_file_facts,
                entries,
            },
            msi: MsiDoc {
                products: self.msi_products.clone(),
                states: self.msi_states.clone(),
            },
            packages: self.packages.clone(),
            msi_tables: self.msi_tables.as_ref().map(|m| {
                m.values()
                    .map(|(path, t)| (path.clone(), t.clone()))
                    .collect()
            }),
            tasks: self.tasks.clone(),
        }
    }

    /// The fixture as pretty-printed `purge.fixture/1` JSON: keys and entries flat at the top level, in
    /// case-folded order, so equal fixtures give equal text. (Written straight to text rather than through
    /// `serde_json::Value`, which cannot hold a 128-bit file id.)
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.to_doc()).expect("a fixture document always serialises")
    }
}

// ---------------------------------------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------------------------------------

/// Chainable construction of a [`Fixture`] for tests. Every method mirrors a `Fixture` mutator.
#[derive(Debug, Clone, Default)]
pub struct FixtureBuilder(Fixture);

impl FixtureBuilder {
    /// Adds a key.
    pub fn key(mut self, key: &str) -> Self {
        self.0.add_key(key);
        self
    }

    /// Sets a key's LastWriteTime.
    pub fn key_lwt(mut self, key: &str, lwt: u64) -> Self {
        self.0.set_key_lwt(key, FileTime(lwt));
        self
    }

    /// Sets a value of any data.
    pub fn value(mut self, key: &str, name: &str, data: RegData) -> Self {
        self.0.set_value(key, name, data);
        self
    }

    /// Sets a `REG_SZ` value.
    pub fn sz(self, key: &str, name: &str, s: &str) -> Self {
        self.value(key, name, RegData::from_sz(s))
    }

    /// Sets a `REG_EXPAND_SZ` value.
    pub fn expand_sz(self, key: &str, name: &str, s: &str) -> Self {
        self.value(key, name, RegData::from_expand_sz(s))
    }

    /// Sets a `REG_MULTI_SZ` value.
    pub fn multi_sz(self, key: &str, name: &str, segments: &[&str]) -> Self {
        self.value(key, name, RegData::from_multi_sz(segments))
    }

    /// Sets a `REG_DWORD` value.
    pub fn dword(self, key: &str, name: &str, v: u32) -> Self {
        self.value(key, name, RegData::from_dword(v))
    }

    /// Sets a `REG_QWORD` value.
    pub fn qword(self, key: &str, name: &str, v: u64) -> Self {
        self.value(key, name, RegData::from_qword(v))
    }

    /// Sets a `REG_BINARY` value.
    pub fn binary(self, key: &str, name: &str, bytes: Vec<u8>) -> Self {
        self.value(key, name, RegData::from_binary(bytes))
    }

    /// Makes a key a registry link.
    pub fn link(mut self, key: &str, target: &str) -> Self {
        self.0.set_link(key, target);
        self
    }

    /// Sets TrustedInstaller ownership of a key.
    pub fn ti_owned(mut self, key: &str, ti: bool) -> Self {
        self.0.set_ti_owned(key, ti);
        self
    }

    /// Adds a directory.
    pub fn dir(mut self, path: &str) -> Self {
        self.0.add_dir(path);
        self
    }

    /// Adds a file without content.
    pub fn file(mut self, path: &str, size: u64) -> Self {
        self.0.add_file(path, size);
        self
    }

    /// Adds a file with content.
    pub fn file_content(mut self, path: &str, content: impl Into<Vec<u8>>) -> Self {
        self.0.add_file_with_content(path, content.into());
        self
    }

    /// Adds a directory that is a reparse point with `tag`.
    pub fn reparse_dir(mut self, path: &str, tag: u32) -> Self {
        self.0.add_dir(path);
        self.0.set_reparse_tag(path, tag);
        self
    }

    /// Sets an entry's times.
    pub fn times(mut self, path: &str, times: FileTimes) -> Self {
        self.0.set_times(path, times);
        self
    }

    /// Sets an entry's 8.3 name.
    pub fn short_name(mut self, path: &str, short: &str) -> Self {
        self.0.set_short_name(path, short);
        self
    }

    /// Sets a file's version resource.
    pub fn version_info(mut self, path: &str, info: VersionInfo) -> Self {
        self.0.set_version_info(path, info);
        self
    }

    /// Sets a file's signer CN.
    pub fn signer(mut self, path: &str, cn: &str) -> Self {
        self.0.set_signer(path, cn);
        self
    }

    /// Adds a shortcut file.
    pub fn shortcut(mut self, path: &str, info: ShortcutInfo) -> Self {
        self.0.add_file(path, 0);
        self.0.set_shortcut(path, info);
        self
    }

    /// Sets an entry's admin-only-writable flag.
    pub fn admin_only_writable(mut self, path: &str, admin_only: bool) -> Self {
        self.0.set_admin_only_writable(path, admin_only);
        self
    }

    /// Sets the admin-only roots.
    pub fn admin_only_roots(mut self, roots: &[&str]) -> Self {
        self.0
            .set_admin_only_roots(roots.iter().map(|s| s.to_string()).collect());
        self
    }

    /// Declares a volume.
    pub fn volume(mut self, root: &str, serial: Option<u32>, fixed: bool, fs: &str) -> Self {
        self.0.add_volume(
            root,
            VolumeInfo {
                serial,
                fixed,
                fs: fs.to_string(),
            },
        );
        self
    }

    /// Declares an unreadable path.
    pub fn denied(mut self, path: &str) -> Self {
        self.0.add_denied(path);
        self
    }

    /// Sets the registry coverage.
    pub fn registry_coverage(mut self, coverage: Coverage) -> Self {
        self.0.set_registry_coverage(coverage);
        self
    }

    /// Sets the filesystem coverage.
    pub fn fs_coverage(mut self, coverage: Coverage) -> Self {
        self.0.set_fs_coverage(coverage);
        self
    }

    /// Sets the OS facts.
    pub fn os(mut self, edition: &str, build: u32, ubr: u32) -> Self {
        self.0.system.os = Some(OsInfo {
            edition: edition.to_string(),
            build,
            ubr,
        });
        self
    }

    /// Sets the interactive user's SID.
    pub fn user_sid(mut self, sid: &str) -> Self {
        self.0.system.user_sid = Some(sid.to_string());
        self
    }

    /// Sets the elevation flag.
    pub fn elevated(mut self, elevated: bool) -> Self {
        self.0.system.elevated = elevated;
        self
    }

    /// Adds a profile.
    pub fn profile(mut self, sid: &str, path: &str) -> Self {
        self.0
            .system
            .profiles
            .get_or_insert_with(Vec::new)
            .push(ProfileInfo {
                sid: sid.to_string(),
                path: path.to_string(),
            });
        self
    }

    /// Sets a known folder.
    pub fn known_folder(mut self, folder: KnownFolder, path: &str) -> Self {
        self.0.system.known_folders.insert(folder, path.to_string());
        self
    }

    /// Sets an environment variable (the name is upper-cased).
    pub fn env(mut self, name: &str, value: &str) -> Self {
        self.0
            .system
            .env
            .insert(name.to_uppercase(), value.to_string());
        self
    }

    /// Adds a process.
    pub fn process(mut self, process: ProcessInfo) -> Self {
        self.0
            .system
            .processes
            .get_or_insert_with(Vec::new)
            .push(process);
        self
    }

    /// Adds an MSI product.
    pub fn msi_product(mut self, product: MsiProduct) -> Self {
        self.0.add_msi_product(product);
        self
    }

    /// Sets an explicit MSI state.
    pub fn msi_state(mut self, code: &str, context: MsiContext, state: MsiProductState) -> Self {
        self.0.set_msi_state(code, context, state);
        self
    }

    /// Adds a package.
    pub fn package(mut self, package: PackageInfo) -> Self {
        self.0.add_package(package);
        self
    }

    /// Sets the tables of one cached MSI package.
    pub fn msi_tables(mut self, local_package: &str, tables: MsiTables) -> Self {
        self.0.set_msi_tables(local_package, tables);
        self
    }

    /// Adds a scheduled task.
    pub fn task(mut self, task: TaskInfo) -> Self {
        self.0.add_task(task);
        self
    }

    /// Sets the fixture's "now".
    pub fn now(mut self, now: u64) -> Self {
        self.0.system.now = Some(FileTime(now));
        self
    }

    /// Runs any mutator on the fixture being built.
    pub fn with(mut self, f: impl FnOnce(&mut Fixture)) -> Self {
        f(&mut self.0);
        self
    }

    /// The finished fixture.
    pub fn build(self) -> Fixture {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{REG_BINARY, SourceResultExt};

    const SID: &str = "S-1-5-21-1-2-3-1001";

    fn sample() -> Fixture {
        Fixture::builder()
            .os("Professional", 26100, 1742)
            .user_sid(SID)
            .elevated(true)
            .profile(SID, "C:\\Users\\tester")
            .known_folder(KnownFolder::ProgramFiles, "C:\\Program Files")
            .env("appdata", "C:\\Users\\tester\\AppData\\Roaming")
            .now(134_000_000_000_000_000)
            .key_lwt("HKLM\\SOFTWARE\\Vendor\\App", 133_000_000_000_000_000)
            .sz("HKLM\\SOFTWARE\\Vendor\\App", "", "default")
            .sz(
                "HKLM\\SOFTWARE\\Vendor\\App",
                "InstallLocation",
                "C:\\Program Files\\App",
            )
            .expand_sz(
                "HKLM\\SOFTWARE\\Vendor\\App",
                "Icon",
                "%ProgramFiles%\\App\\app.exe",
            )
            .multi_sz("HKLM\\SOFTWARE\\Vendor\\App", "List", &["a", "b"])
            .dword("HKLM\\SOFTWARE\\Vendor\\App", "Count", 3)
            .qword("HKLM\\SOFTWARE\\Vendor\\App", "Big", 1 << 40)
            .binary("HKLM\\SOFTWARE\\Vendor\\App", "Blob", vec![0, 1, 2, 255])
            .value("HKLM\\SOFTWARE\\Vendor\\App", "Odd", {
                let mut d = RegData::from_sz("cut");
                d.truncated = true;
                d.len = 4000;
                d.hash = Some(0xdead_beef);
                d
            })
            .value(
                "HKLM\\SOFTWARE\\Vendor\\App",
                "Unk",
                RegData::unknown(REG_BINARY, 12),
            )
            .value(
                "HKLM\\SOFTWARE\\Vendor\\App",
                "Pad",
                RegData::new(REG_SZ, vec![b'a', 0, 0, 0, 0, 0]),
            )
            .key("HKLM\\SOFTWARE\\Vendor\\App\\Sub\\Deeper")
            .link(
                "HKU\\S-1-5-21-1-2-3-1001\\Software\\Classes",
                "\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001_Classes",
            )
            .ti_owned("HKLM\\SOFTWARE\\Vendor", true)
            .key("HKU\\S-1-5-21-1-2-3-1001_Classes\\.txt")
            .key("HKU\\.DEFAULT\\Software")
            .sz(
                "HKLM\\SYSTEM\\CurrentControlSet\\Services\\AppSvc",
                "ImagePath",
                "x",
            )
            .volume("C:\\", Some(0x1234_5678), true, "NTFS")
            .volume("E:\\", Some(7), false, "FAT32")
            .admin_only_roots(&["C:\\Program Files"])
            .dir("C:\\Program Files\\App")
            .file_content("C:\\Program Files\\App\\readme.txt", "hello world")
            .file("C:\\Program Files\\App\\app.exe", 4096)
            .version_info(
                "C:\\Program Files\\App\\app.exe",
                VersionInfo {
                    product_name: Some("App".into()),
                    company_name: Some("Vendor".into()),
                    ..Default::default()
                },
            )
            .signer("C:\\Program Files\\App\\app.exe", "Vendor Ltd")
            .file_content("C:\\Program Files\\App\\bin.dat", vec![0xff, 0x00, 0x80])
            .short_name("C:\\Program Files", "PROGRA~1")
            .shortcut(
                "C:\\Users\\tester\\Desktop\\App.lnk",
                ShortcutInfo {
                    raw_path: Some("C:\\Program Files\\App\\app.exe".into()),
                    args: Some("--x".into()),
                    ..Default::default()
                },
            )
            .admin_only_writable("C:\\Program Files\\App\\plugins", false)
            .reparse_dir("C:\\Users\\tester\\Junction", 0xA000_0003)
            .times(
                "C:\\Program Files\\App\\app.exe",
                FileTimes {
                    created: Some(FileTime(1)),
                    modified: Some(FileTime(2)),
                    accessed: None,
                },
            )
            .with(|f| {
                f.set_meta(
                    "C:\\Program Files\\App\\id.bin",
                    FileMeta {
                        size: 5,
                        attrs: FILE_ATTRIBUTE_ARCHIVE | 0x1,
                        times: FileTimes::default(),
                        reparse_tag: 0,
                        file_id: Some(u128::MAX - 3),
                        volume_serial: Some(0x1122_3344_5566_7788),
                    },
                )
            })
            .msi_product(MsiProduct {
                code: "{11111111-2222-3333-4444-555555555555}".into(),
                context: MsiContext::Machine,
                user_sid: None,
                name: Some("App".into()),
                version: None,
                publisher: None,
                install_location: None,
                local_package: None,
                install_date: None,
            })
            .msi_state(
                "{AAAAAAAA-2222-3333-4444-555555555555}",
                MsiContext::UserUnmanaged,
                MsiProductState::Advertised,
            )
            .package(PackageInfo {
                full_name: "Vendor.App_1.0.0.0_neutral__abc".into(),
                family: "Vendor.App_abc".into(),
                install_location: None,
                external_location: Some("C:\\Program Files\\App".into()),
                sparse: true,
                users: vec![SID.into()],
                is_framework: false,
                is_resource: false,
                signature_kind: Default::default(),
            })
            .process(ProcessInfo {
                pid: 42,
                ppid: Some(4),
                name: "app.exe".into(),
                path: Some("C:\\Program Files\\App\\app.exe".into()),
                start: Some(FileTime(5)),
                session: Some(1),
                cmd: None,
            })
            .build()
    }

    #[test]
    fn json_round_trip() {
        let f = sample();
        let json = f.to_json();
        let g = Fixture::from_json_str(&json, None).unwrap();
        assert_eq!(g.to_json(), json, "second serialisation differs");
        // Spot checks through the traits.
        for fx in [&f, &g] {
            let app = "HKLM\\SOFTWARE\\Vendor\\App";
            assert_eq!(fx.value(app, "").unwrap().sz().as_deref(), Some("default"));
            assert_eq!(fx.value(app, "Count").unwrap().dword(), Some(3));
            assert_eq!(fx.value(app, "Big").unwrap().qword(), Some(1 << 40));
            assert_eq!(
                fx.value(app, "List").unwrap().multi_sz().unwrap(),
                vec!["a", "b"]
            );
            assert_eq!(fx.value(app, "Blob").unwrap().bytes, vec![0, 1, 2, 255]);
            let odd = fx.value(app, "Odd").unwrap();
            assert!(odd.truncated && odd.len == 4000 && odd.hash == Some(0xdead_beef));
            assert!(fx.value(app, "Unk").unwrap().data_unknown);
            assert_eq!(fx.value(app, "Pad").unwrap().bytes.len(), 6);
            assert_eq!(
                fx.key_info(app).unwrap().lwt,
                FileTime(133_000_000_000_000_000)
            );
            assert_eq!(
                fx.key_info("HKLM\\SOFTWARE\\Vendor").unwrap().ti_owned,
                Some(true)
            );
            assert!(
                fx.key_info(&format!("HKU\\{SID}\\Software\\Classes"))
                    .unwrap()
                    .is_link
            );
            assert_eq!(
                fx.read_bytes("C:\\Program Files\\App\\bin.dat", 10)
                    .unwrap(),
                vec![0xff, 0x00, 0x80]
            );
            assert_eq!(
                fx.metadata("C:\\Program Files\\App\\id.bin")
                    .unwrap()
                    .file_id,
                Some(u128::MAX - 3)
            );
            assert_eq!(
                fx.metadata("C:\\Program Files\\App\\id.bin")
                    .unwrap()
                    .volume_serial,
                Some(0x1122_3344_5566_7788)
            );
            assert_eq!(
                fx.metadata("C:\\Program Files\\App\\app.exe")
                    .unwrap()
                    .times
                    .modified,
                Some(FileTime(2))
            );
            assert_eq!(fx.os_info().unwrap().build, 26100);
            assert_eq!(
                fx.env().unwrap()["APPDATA"],
                "C:\\Users\\tester\\AppData\\Roaming"
            );
            assert_eq!(fx.packages().unwrap().len(), 1);
            assert_eq!(fx.processes().unwrap()[0].pid, 42);
            assert_eq!(fx.now(), FileTime(134_000_000_000_000_000));
        }
        assert_eq!(f.key_count(), g.key_count());
        assert_eq!(f.value_count(), g.value_count());
        assert_eq!(f.file_count(), g.file_count());
        assert_eq!(f.dir_count(), g.dir_count());
    }

    #[test]
    fn case_insensitive_lookup() {
        let f = sample();
        assert!(f.key_info("hklm\\software\\VENDOR\\app").is_ok());
        assert_eq!(
            f.value("HKLM\\SOFTWARE\\Vendor\\App", "installlocation")
                .unwrap()
                .sz()
                .as_deref(),
            Some("C:\\Program Files\\App")
        );
        assert!(f.metadata("c:\\PROGRAM FILES\\app\\APP.EXE").is_ok());
        assert_eq!(
            f.exists("c:\\program files\\APP\\readme.TXT"),
            ExistsState::Present
        );
        // Original case is reported.
        assert_eq!(f.subkeys("HKLM\\SOFTWARE\\vendor").unwrap(), vec!["App"]);
        assert_eq!(
            f.long_path("c:\\progra~1\\app\\APP.exe").unwrap(),
            "C:\\Program Files\\App\\app.exe"
        );
    }

    #[test]
    fn default_value_name_is_empty() {
        let f = sample();
        let values = f.values("HKLM\\SOFTWARE\\Vendor\\App").unwrap();
        assert!(values.iter().any(|v| v.name.is_empty()));
        assert_eq!(
            f.value("HKLM\\SOFTWARE\\Vendor\\App", "")
                .unwrap()
                .sz()
                .as_deref(),
            Some("default")
        );
        // A key without a default value.
        assert_eq!(
            f.value("HKLM\\SOFTWARE\\Vendor", ""),
            Err(SourceError::NotFound)
        );
        assert_eq!(f.value("HKLM\\SOFTWARE\\Vendor", "").found(), Ok(None));
    }

    #[test]
    fn registry_queries() {
        let f = sample();
        assert_eq!(
            f.key_info("HKLM\\SOFTWARE\\Nope"),
            Err(SourceError::NotFound)
        );
        assert_eq!(f.key_exists("HKLM\\SOFTWARE\\Nope"), ExistsState::Absent);
        assert_eq!(f.key_exists("HKLM\\SOFTWARE\\Vendor"), ExistsState::Present);
        let info = f.key_info("HKLM\\SOFTWARE\\Vendor\\App").unwrap();
        assert_eq!(info.n_subkeys, 1);
        assert_eq!(info.n_values, 10);
        assert!(!info.is_link);
        // CurrentControlSet maps to ControlSet001 both ways.
        assert!(
            f.key_info("HKLM\\SYSTEM\\ControlSet001\\Services\\AppSvc")
                .is_ok()
        );
        assert!(
            f.key_info("HKLM\\SYSTEM\\CurrentControlSet\\Services\\AppSvc")
                .is_ok()
        );
        assert_eq!(f.current_control_set(), Ok(1));
        assert_eq!(f.loaded_user_sids().unwrap(), vec![SID.to_string()]);
        // Below a link: not followed, so unknown.
        assert_eq!(
            f.key_info(&format!("HKU\\{SID}\\Software\\Classes\\.txt")),
            Err(SourceError::NotCaptured)
        );
    }

    #[test]
    fn coverage_and_denied() {
        let f = Fixture::builder()
            .key("HKLM\\SOFTWARE\\A")
            .key("HKLM\\SOFTWARE\\Locked")
            .denied("HKLM\\SOFTWARE\\Locked")
            .registry_coverage(Coverage {
                roots: vec![CoverageRoot {
                    path: "HKLM\\SOFTWARE".into(),
                    depth: None,
                }],
                exclude: vec!["HKLM\\SOFTWARE\\Excluded".into()],
            })
            .dir("C:\\Windows\\System32")
            .file("C:\\Windows\\System32\\notepad.exe", 1)
            .fs_coverage(Coverage {
                roots: vec![CoverageRoot {
                    path: "C:\\Windows\\System32".into(),
                    depth: Some(1),
                }],
                exclude: vec![],
            })
            .build();
        assert_eq!(f.key_info("HKLM\\SOFTWARE\\B"), Err(SourceError::NotFound));
        assert_eq!(
            f.key_info("HKLM\\SOFTWARE\\Excluded\\X"),
            Err(SourceError::NotCaptured)
        );
        assert_eq!(f.key_info("HKLM\\SYSTEM\\X"), Err(SourceError::NotCaptured));
        assert_eq!(f.subkeys("HKLM"), Err(SourceError::NotCaptured));
        assert_eq!(
            f.subkeys("HKLM\\SOFTWARE\\Locked"),
            Err(SourceError::AccessDenied)
        );
        assert_eq!(
            f.key_info("HKLM\\SOFTWARE\\Locked\\Inner"),
            Err(SourceError::AccessDenied)
        );
        assert_eq!(
            f.exists("C:\\Windows\\System32\\calc.exe"),
            ExistsState::Absent
        );
        // Depth 1: deeper paths are not captured.
        assert_eq!(
            f.exists("C:\\Windows\\System32\\drivers\\x.sys"),
            ExistsState::Unknown
        );
        assert_eq!(f.list_dir("C:\\Windows\\System32").unwrap().len(), 1);
        assert_eq!(f.exists("C:\\Program Files\\X"), ExistsState::Unknown);
    }

    #[test]
    fn tri_state_exists() {
        let f = sample();
        assert_eq!(
            f.exists("C:\\Program Files\\App\\app.exe"),
            ExistsState::Present
        );
        assert_eq!(
            f.exists("C:\\Program Files\\App\\gone.exe"),
            ExistsState::Absent
        );
        // Removable volume: missing is unknown.
        assert_eq!(f.exists("E:\\Portable\\app.exe"), ExistsState::Unknown);
        // No declared volume while others are declared: unmounted.
        assert_eq!(f.exists("F:\\x"), ExistsState::Unknown);
        // Through a reparse point.
        assert_eq!(
            f.exists("C:\\Users\\tester\\Junction\\x"),
            ExistsState::Unknown
        );
        assert_eq!(f.exists("relative\\path"), ExistsState::Unknown);
    }

    #[test]
    fn filesystem_queries() {
        let f = sample();
        let list = f.list_dir("C:\\Program Files\\App").unwrap();
        let names: Vec<&str> = list.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["app.exe", "bin.dat", "id.bin", "plugins", "readme.txt"]
        );
        assert!(
            list.iter()
                .find(|e| e.name == "plugins")
                .unwrap()
                .meta
                .is_dir()
        );
        assert_eq!(
            f.list_dir("C:\\Users\\tester\\Junction"),
            Err(SourceError::ReparsePoint)
        );
        assert!(
            f.metadata("C:\\Users\\tester\\Junction")
                .unwrap()
                .is_reparse_point()
        );
        assert_eq!(
            f.list_dir("C:\\Program Files\\App\\app.exe"),
            Err(SourceError::WrongKind)
        );
        assert_eq!(
            f.read_bytes("C:\\Program Files\\App\\readme.txt", 5)
                .unwrap(),
            b"hello"
        );
        assert_eq!(
            f.read_bytes("C:\\Program Files\\App\\app.exe", 5),
            Err(SourceError::NotCaptured)
        );
        assert_eq!(
            f.read_bytes("C:\\Program Files\\App", 5),
            Err(SourceError::WrongKind)
        );
        assert_eq!(
            f.metadata("C:\\Program Files\\App\\app.exe").unwrap().size,
            4096
        );
        assert_eq!(
            f.version_info("C:\\Program Files\\App\\app.exe")
                .unwrap()
                .unwrap()
                .product_name
                .as_deref(),
            Some("App")
        );
        assert_eq!(
            f.version_info("C:\\Program Files\\App\\readme.txt"),
            Ok(None)
        );
        assert_eq!(
            f.signer_cn("C:\\Program Files\\App\\app.exe")
                .unwrap()
                .as_deref(),
            Some("Vendor Ltd")
        );
        assert_eq!(
            f.read_shortcut("C:\\Users\\tester\\Desktop\\App.lnk")
                .unwrap()
                .args
                .as_deref(),
            Some("--x")
        );
        assert_eq!(
            f.read_shortcut("C:\\Program Files\\App\\app.exe"),
            Err(SourceError::WrongKind)
        );
        assert_eq!(
            f.volume_info("C:\\Program Files").unwrap().serial,
            Some(0x1234_5678)
        );
        assert!(
            f.is_admin_only_writable("C:\\Program Files\\App\\app.exe")
                .unwrap()
        );
        assert!(
            !f.is_admin_only_writable("C:\\Program Files\\App\\plugins")
                .unwrap()
        );
        assert!(
            !f.is_admin_only_writable("C:\\Users\\tester\\Desktop")
                .unwrap()
        );
        assert_eq!(
            f.is_admin_only_writable("C:\\Program Files\\Nope"),
            Err(SourceError::NotFound)
        );
    }

    #[test]
    fn unknown_file_facts_are_not_captured() {
        let mut f = sample();
        f.set_unknown_file_facts(true);
        assert_eq!(
            f.version_info("C:\\Program Files\\App\\readme.txt"),
            Err(SourceError::NotCaptured)
        );
        assert_eq!(
            f.signer_cn("C:\\Program Files\\App\\readme.txt"),
            Err(SourceError::NotCaptured)
        );
        assert_eq!(
            f.read_shortcut("C:\\Program Files\\App\\readme.txt"),
            Err(SourceError::NotCaptured)
        );
    }

    #[test]
    fn system_queries() {
        let f = sample();
        assert_eq!(f.user_sid().unwrap(), SID);
        assert!(f.elevated());
        assert_eq!(f.profiles().unwrap()[0].path, "C:\\Users\\tester");
        assert_eq!(
            f.known_folders().unwrap()[&KnownFolder::ProgramFiles],
            "C:\\Program Files"
        );
        let states = f
            .msi_product_state_all("{11111111-2222-3333-4444-555555555555}")
            .unwrap();
        assert_eq!(states.len(), 3);
        assert_eq!(
            states[0],
            MsiContextState {
                context: MsiContext::Machine,
                state: MsiProductState::Default
            }
        );
        assert!(states[1].state.is_unknown() && states[2].state.is_unknown());
        let states = f
            .msi_product_state_all("{aaaaaaaa-2222-3333-4444-555555555555}")
            .unwrap();
        assert_eq!(
            states,
            vec![MsiContextState {
                context: MsiContext::UserUnmanaged,
                state: MsiProductState::Advertised
            }]
        );
        let mut g = sample();
        g.set_msi_products(None);
        assert_eq!(g.msi_products(), Err(SourceError::NotCaptured));
        assert_eq!(
            g.msi_product_state_all("{0}"),
            Err(SourceError::NotCaptured)
        );
    }

    #[test]
    fn json_lists_null_means_not_captured() {
        let f = Fixture::from_json_str(
            r#"{"schema":"purge.fixture/1","system":{"processes":null},"msi":{"products":null},"packages":null}"#,
            None,
        )
        .unwrap();
        assert_eq!(f.processes(), Err(SourceError::NotCaptured));
        assert_eq!(f.msi_products(), Err(SourceError::NotCaptured));
        assert_eq!(f.packages(), Err(SourceError::NotCaptured));
        assert_eq!(f.profiles(), Ok(vec![]));
        assert_eq!(f.os_info(), Err(SourceError::NotCaptured));
        let g = Fixture::from_json_str(r#"{"schema":"purge.fixture/1"}"#, None).unwrap();
        assert_eq!(g.processes(), Ok(vec![]));
        assert!(Fixture::from_json_str(r#"{"schema":"purge.fixture/0"}"#, None).is_err());
    }

    #[test]
    fn json_value_forms_are_validated() {
        let bad = r#"{"schema":"purge.fixture/1","registry":{"keys":{"HKLM\\X":{"values":{"v":{"sz":"a","dword":1}}}}}}"#;
        assert!(matches!(
            Fixture::from_json_str(bad, None),
            Err(FixtureError::Invalid(_))
        ));
        let bad = r#"{"schema":"purge.fixture/1","registry":{"keys":{"HKLM\\X":{"values":{"v":{"type":4,"sz":"a"}}}}}}"#;
        assert!(matches!(
            Fixture::from_json_str(bad, None),
            Err(FixtureError::Invalid(_))
        ));
    }

    #[test]
    fn hand_written_json_fixture() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mini.fixture.json");
        let f = Fixture::from_json_file(&path).unwrap();
        let key = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Demo_is1";
        assert_eq!(
            f.value(key, "DisplayName").unwrap().sz().as_deref(),
            Some("Demo App")
        );
        assert_eq!(f.value(key, "EstimatedSize").unwrap().dword(), Some(1234));
        assert_eq!(f.value(key, "Blob").unwrap().bytes, vec![0, 1, 2]);
        assert!(f.key_info("HKLM\\SOFTWARE\\Demo\\Settings\\Deep").is_ok());
        // Starts-with: a checkout may turn the side file's LF into CRLF.
        assert!(
            f.read_bytes("C:\\Program Files\\Demo\\unins000.dat", 64)
                .unwrap()
                .starts_with(b"side file content")
        );
        assert_eq!(
            f.read_bytes("C:\\Program Files\\Demo\\notes.txt", 64)
                .unwrap(),
            b"inline"
        );
        assert_eq!(
            f.exists("C:\\Program Files\\Demo\\demo.exe"),
            ExistsState::Present
        );
        assert_eq!(f.exists("D:\\Removable\\demo.exe"), ExistsState::Unknown);
        assert_eq!(
            f.exists("C:\\Program Files\\Demo\\missing.exe"),
            ExistsState::Absent
        );
        assert!(
            f.is_admin_only_writable("C:\\Program Files\\Demo\\demo.exe")
                .unwrap()
        );
        assert_eq!(f.user_sid().unwrap(), "S-1-5-21-100-200-300-1001");
        // Round trip keeps the side-file reference.
        let again = Fixture::from_json_str(&f.to_json(), path.parent()).unwrap();
        assert_eq!(again.to_json(), f.to_json());
        assert_eq!(
            again
                .read_bytes("C:\\Program Files\\Demo\\unins000.dat", 4)
                .unwrap(),
            b"side"
        );
    }

    #[test]
    fn mutators_remove() {
        let mut f = sample();
        assert!(f.remove_value("HKLM\\SOFTWARE\\Vendor\\App", "count"));
        assert_eq!(
            f.value("HKLM\\SOFTWARE\\Vendor\\App", "Count"),
            Err(SourceError::NotFound)
        );
        assert!(f.remove_key("HKLM\\SOFTWARE\\Vendor\\App"));
        assert_eq!(
            f.key_info("HKLM\\SOFTWARE\\Vendor\\App\\Sub"),
            Err(SourceError::NotFound)
        );
        assert_eq!(f.key_info("HKLM\\SOFTWARE\\Vendor").unwrap().n_subkeys, 0);
        assert!(f.remove_path("C:\\Program Files\\App"));
        assert_eq!(
            f.exists("C:\\Program Files\\App\\app.exe"),
            ExistsState::Absent
        );
        assert!(!f.remove_path("C:\\Program Files\\App"));
    }

    #[test]
    fn env_expansion() {
        let mut env = BTreeMap::new();
        env.insert("PROGRAMFILES".to_string(), "C:\\PF".to_string());
        assert_eq!(expand_env("%ProgramFiles%\\x", &env), "C:\\PF\\x");
        assert_eq!(expand_env("%NOPE%\\%programfiles%", &env), "%NOPE%\\C:\\PF");
        assert_eq!(expand_env("50% off", &env), "50% off");
        assert_eq!(expand_env("%%", &env), "%%");
    }

    #[test]
    fn base64_round_trip() {
        for data in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            &[0, 255, 128, 7],
        ] {
            let e = b64::encode(data);
            assert_eq!(b64::decode(&e).unwrap(), data);
        }
        assert_eq!(b64::encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64::encode(b"fo"), "Zm8=");
        assert!(b64::decode("@@").is_err());
    }

    #[test]
    fn sources_are_object_safe_and_shareable() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Fixture>();
        let f = sample();
        let r: &dyn RegistrySource = &f;
        let fs: &dyn FileSystemSource = &f;
        let s: &dyn SystemSource = &f;
        assert!(r.key_info("HKLM\\SOFTWARE").is_ok());
        assert!(fs.metadata("C:\\Program Files").is_ok());
        assert!(s.os_info().is_ok());
    }

    // ---- M1b: MSI tables and tasks ----------------------------------------------------------------------

    mod m1b {
        use super::*;
        use crate::sysobj::{
            MAX_CELL_BYTES, MAX_TABLE_ROWS, MAX_TASKS, MsiClassRow, MsiComponentRow,
            MsiExtensionRow, MsiRegistryRaw, MsiServiceRaw, TOO_MANY_TASKS,
        };
        use purge_model::object::{TaskAction, TaskIdentity};

        const PKG: &str = r"C:\Windows\Installer\1A2b3C.msi";

        fn load(json: &str) -> Result<Fixture, FixtureError> {
            Fixture::from_json_str(json, None)
        }

        fn tables() -> MsiTables {
            MsiTables {
                properties: vec![
                    ("ProductName".into(), "App".into()),
                    ("Manufacturer".into(), "Vendor".into()),
                ],
                components: vec![MsiComponentRow {
                    component: "Main".into(),
                    component_id: Some("{11111111-2222-3333-4444-555555555555}".into()),
                    attributes: 256,
                    key_path: Some("app.exe".into()),
                }],
                registry: vec![MsiRegistryRaw {
                    row: "reg1".into(),
                    root: -1,
                    key: "Software\\[Manufacturer]\\[ProductName]".into(),
                    name: Some("Path".into()),
                    value: Some("[INSTALLDIR]".into()),
                    component: "Main".into(),
                }],
                remove_registry: vec![MsiRegistryRaw {
                    row: "rm1".into(),
                    root: 1,
                    key: "Software\\Old".into(),
                    name: None,
                    value: None,
                    component: "Main".into(),
                }],
                classes: vec![MsiClassRow {
                    clsid: "{AAAAAAAA-0000-0000-0000-000000000001}".into(),
                    context: "LocalServer32".into(),
                    component: "Main".into(),
                    progid: Some("App.Doc.1".into()),
                    appid: None,
                }],
                progids: vec!["App.Doc.1".into()],
                extensions: vec![MsiExtensionRow {
                    extension: "appdoc".into(),
                    component: "Main".into(),
                    progid: Some("App.Doc.1".into()),
                }],
                typelibs: vec!["{BBBBBBBB-0000-0000-0000-000000000002}".into()],
                appids: vec!["{CCCCCCCC-0000-0000-0000-000000000003}".into()],
                service_install: vec![MsiServiceRaw {
                    name: "AppSvc".into(),
                    component: "Main".into(),
                    service_type: 16,
                    start_type: 2,
                }],
                custom_action_count: 4,
                truncated: false,
            }
        }

        fn tasks() -> Vec<TaskInfo> {
            vec![
                TaskInfo {
                    identity: TaskIdentity {
                        path: r"\Vendor\App Update".into(),
                        actions: vec![
                            TaskAction::Exec {
                                path: r"C:\Program Files\App\update.exe".into(),
                                arguments: Some("/silent".into()),
                                working_dir: None,
                            },
                            TaskAction::ComHandler {
                                clsid: "{AAAAAAAA-0000-0000-0000-000000000001}".into(),
                                data: Some("x".into()),
                            },
                            TaskAction::Other {
                                kind: "email".into(),
                            },
                        ],
                    },
                    enabled: true,
                    hidden: true,
                    author: Some("Vendor".into()),
                    stored_password: true,
                    run_as: Some("S-1-5-18".into()),
                },
                // Unreadable to the scanning user: no actions.
                TaskInfo {
                    identity: TaskIdentity {
                        path: r"\Locked".into(),
                        actions: Vec::new(),
                    },
                    ..TaskInfo::default()
                },
            ]
        }

        #[test]
        fn fixture_msi_tables_absent_section_is_not_captured() {
            let f = load(r#"{"schema":"purge.fixture/1"}"#).unwrap();
            assert_eq!(f.msi_tables(PKG), Err(SourceError::NotCaptured));
            assert_eq!(f.tasks(), Err(SourceError::NotCaptured));
            let f = load(r#"{"schema":"purge.fixture/1","msi_tables":null,"tasks":null}"#).unwrap();
            assert_eq!(f.msi_tables(PKG), Err(SourceError::NotCaptured));
            assert_eq!(f.tasks(), Err(SourceError::NotCaptured));
            // Built in code: not captured until something is set.
            let mut f = Fixture::new();
            assert_eq!(f.msi_tables(PKG), Err(SourceError::NotCaptured));
            assert_eq!(f.tasks(), Err(SourceError::NotCaptured));
            f.set_msi_tables_captured(true);
            assert_eq!(f.msi_tables(PKG), Err(SourceError::NotFound));
            f.set_msi_tables_captured(false);
            assert_eq!(f.msi_tables(PKG), Err(SourceError::NotCaptured));
            // An empty list is a captured "no tasks", not "unknown".
            let f = load(r#"{"schema":"purge.fixture/1","tasks":[]}"#).unwrap();
            assert_eq!(f.tasks(), Ok(Vec::new()));
            // Not captured survives a round trip (the sections are left out, not written empty).
            let text = Fixture::new().to_json();
            assert!(
                !text.contains("msi_tables") && !text.contains("tasks"),
                "{text}"
            );
            let back = load(&text).unwrap();
            assert_eq!(back.msi_tables(PKG), Err(SourceError::NotCaptured));
            assert_eq!(back.tasks(), Err(SourceError::NotCaptured));
        }

        #[test]
        fn fixture_msi_tables_unknown_package_is_not_found() {
            let f = load(
                r#"{"schema":"purge.fixture/1","msi_tables":{"C:\\Windows\\Installer\\1a2b3c.msi":{}}}"#,
            )
            .unwrap();
            assert_eq!(f.msi_tables(PKG), Ok(MsiTables::default()));
            for other in [
                r"C:\Windows\Installer\ffff.msi",
                r"C:\Windows\Installer\1a2b3c.msi.bak",
                r"C:\Windows\Installer",
                r"D:\Windows\Installer\1a2b3c.msi",
            ] {
                assert_eq!(f.msi_tables(other), Err(SourceError::NotFound), "{other}");
            }
            let f = load(r#"{"schema":"purge.fixture/1","msi_tables":{}}"#).unwrap();
            assert_eq!(f.msi_tables(PKG), Err(SourceError::NotFound));
            // Not a path at all: an error of its own, never an empty table set.
            assert!(matches!(
                f.msi_tables("1a2b3c.msi"),
                Err(SourceError::InvalidPath(_))
            ));
        }

        #[test]
        fn fixture_msi_tables_path_case_and_slash_insensitive() {
            let f = Fixture::builder().msi_tables(PKG, tables()).build();
            for spelling in [
                PKG,
                r"c:\windows\installer\1a2b3c.MSI",
                "C:/Windows/Installer/1a2b3c.msi",
                r"c:\WINDOWS/installer\\1A2B3C.msi",
                r"\\?\C:\Windows\Installer\1a2b3c.msi",
            ] {
                assert_eq!(f.msi_tables(spelling), Ok(tables()), "{spelling}");
            }
            // The same through JSON, keyed with forward slashes.
            let f = load(
                r#"{"schema":"purge.fixture/1","msi_tables":{"c:/windows/INSTALLER/1a2b3c.msi":{"progids":["App.Doc.1"]}}}"#,
            )
            .unwrap();
            assert_eq!(f.msi_tables(PKG).unwrap().progids, vec!["App.Doc.1"]);
            // Setting the same package in another spelling replaces it.
            let mut f = Fixture::new();
            assert!(f.set_msi_tables(PKG, MsiTables::default()));
            assert!(f.set_msi_tables("c:/windows/installer/1a2b3c.msi", tables()));
            assert_eq!(f.msi_tables(PKG), Ok(tables()));
            assert!(!f.set_msi_tables("relative.msi", tables()));
            // Hostile: two spellings of one package in a document is ambiguous, not "last wins".
            let dup = r#"{"schema":"purge.fixture/1","msi_tables":{
                "C:\\Windows\\Installer\\a.msi":{"progids":["One"]},
                "c:/windows/installer/A.MSI":{"progids":["Two"]}}}"#;
            assert!(matches!(load(dup), Err(FixtureError::Invalid(m)) if m.contains("twice")));
            let bad = r#"{"schema":"purge.fixture/1","msi_tables":{"a.msi":{}}}"#;
            assert!(matches!(load(bad), Err(FixtureError::Invalid(_))));
        }

        #[test]
        fn fixture_tasks_round_trip() {
            let f = Fixture::builder()
                .msi_tables(PKG, tables())
                .task(tasks()[0].clone())
                .task(tasks()[1].clone())
                .build();
            assert_eq!(f.tasks(), Ok(tasks()));
            let text = f.to_json();
            let back = load(&text).unwrap();
            assert_eq!(back.tasks(), Ok(tasks()));
            assert_eq!(back.msi_tables(PKG), Ok(tables()));
            assert_eq!(back.to_json(), text);
            // The path keeps the spelling it was given.
            assert!(
                text.contains(r#""C:\\Windows\\Installer\\1A2b3C.msi""#),
                "{text}"
            );

            // Written by hand: optional fields may be left out.
            let f = load(
                r#"{"schema":"purge.fixture/1","tasks":[
                    {"identity":{"path":"\\Vendor\\App Update","actions":[
                        {"kind":"exec","path":"C:\\Program Files\\App\\update.exe"},
                        {"kind":"com_handler","clsid":"{AAAAAAAA-0000-0000-0000-000000000001}"},
                        {"kind":"other","other_kind":"email"}]},
                     "enabled":true}]}"#,
            )
            .unwrap();
            let got = f.tasks().unwrap();
            assert_eq!(got.len(), 1);
            assert!(got[0].enabled && !got[0].hidden && got[0].author.is_none());
            assert_eq!(
                got[0].identity.actions[0],
                TaskAction::Exec {
                    path: r"C:\Program Files\App\update.exe".into(),
                    arguments: None,
                    working_dir: None,
                }
            );
            assert_eq!(
                got[0].identity.actions[2],
                TaskAction::Other {
                    kind: "email".into()
                }
            );
        }

        #[test]
        fn fixture_rejects_unknown_field() {
            // Hostile: every misspelt or invented field fails the load, at every depth.
            let cases = [
                // A section name.
                r#"{"schema":"purge.fixture/1","task":[]}"#,
                r#"{"schema":"purge.fixture/1","msi_table":{}}"#,
                // MsiTables itself and each kind of row.
                r#"{"schema":"purge.fixture/1","msi_tables":{"C:\\a.msi":{"propertys":[]}}}"#,
                r#"{"schema":"purge.fixture/1","msi_tables":{"C:\\a.msi":{"components":[
                    {"component":"Main","attributes":0,"keypath":"app.exe"}]}}}"#,
                r#"{"schema":"purge.fixture/1","msi_tables":{"C:\\a.msi":{"registry":[
                    {"row":"r","root":2,"key":"Software\\X","component":"c","Value":"v"}]}}}"#,
                r#"{"schema":"purge.fixture/1","msi_tables":{"C:\\a.msi":{"classes":[
                    {"clsid":"{A}","context":"InprocServer32","component":"c","prog_id":"P"}]}}}"#,
                r#"{"schema":"purge.fixture/1","msi_tables":{"C:\\a.msi":{"extensions":[
                    {"extension":"x","component":"c","verb":"open"}]}}}"#,
                r#"{"schema":"purge.fixture/1","msi_tables":{"C:\\a.msi":{"service_install":[
                    {"name":"S","component":"c","service_type":16,"start_type":2,"account":"x"}]}}}"#,
                // TaskInfo itself.
                r#"{"schema":"purge.fixture/1","tasks":[{"identity":{"path":"\\T","actions":[]},"enabld":true}]}"#,
                // The identity and the actions (purge-model types, which do not deny unknown fields).
                r#"{"schema":"purge.fixture/1","tasks":[{"identity":{"path":"\\T","actions":[],"author":"x"}}]}"#,
                r#"{"schema":"purge.fixture/1","tasks":[{"identity":{"path":"\\T","actions":[
                    {"kind":"exec","path":"C:\\a.exe","argument":"/x"}]}}]}"#,
                r#"{"schema":"purge.fixture/1","tasks":[{"identity":{"path":"\\T","actions":[
                    {"kind":"exec","path":"C:\\a.exe"},
                    {"kind":"com_handler","clsid":"{A}","Data":"d"}]}}]}"#,
            ];
            for json in cases {
                let err = load(json).map(|_| ()).unwrap_err();
                assert!(
                    err.to_string().contains("unknown field"),
                    "{json}\n=> {err}"
                );
            }
        }

        #[test]
        fn fixture_table_over_limit_sets_truncated() {
            let row = |i: usize| MsiComponentRow {
                component: format!("C{i}"),
                component_id: None,
                attributes: 0,
                key_path: None,
            };
            // Exactly at the limit: whole and not truncated.
            let at = MsiTables {
                components: (0..MAX_TABLE_ROWS).map(row).collect(),
                ..MsiTables::default()
            };
            let f = Fixture::builder().msi_tables(PKG, at).build();
            let got = f.msi_tables(PKG).unwrap();
            assert_eq!(got.components.len(), MAX_TABLE_ROWS);
            assert!(!got.truncated);

            // Hostile: one row over the limit is cut and flagged, never returned whole.
            let over = MsiTables {
                components: (0..=MAX_TABLE_ROWS).map(row).collect(),
                progids: vec!["App.Doc".into()],
                ..MsiTables::default()
            };
            let f = Fixture::builder().msi_tables(PKG, over).build();
            let got = f.msi_tables(PKG).unwrap();
            assert_eq!(got.components.len(), MAX_TABLE_ROWS);
            assert_eq!(got.components.last(), Some(&row(MAX_TABLE_ROWS - 1)));
            assert_eq!(got.progids, vec!["App.Doc"]);
            assert!(got.truncated);

            // Hostile: a cell over 64 KiB drops its row and flags the set.
            let long = MsiTables {
                registry: vec![
                    MsiRegistryRaw {
                        row: "big".into(),
                        root: 2,
                        key: "Software\\X".into(),
                        name: None,
                        value: Some("v".repeat(MAX_CELL_BYTES + 1)),
                        component: "c".into(),
                    },
                    MsiRegistryRaw {
                        row: "small".into(),
                        root: 2,
                        key: "Software\\X".into(),
                        name: None,
                        value: Some("v".into()),
                        component: "c".into(),
                    },
                ],
                ..MsiTables::default()
            };
            let f = Fixture::builder().msi_tables(PKG, long).build();
            let got = f.msi_tables(PKG).unwrap();
            assert!(got.truncated);
            assert_eq!(got.registry.len(), 1);
            assert_eq!(got.registry[0].row, "small");

            // A package flagged truncated by its capture stays flagged.
            let flagged = MsiTables {
                truncated: true,
                ..MsiTables::default()
            };
            let f = Fixture::builder().msi_tables(PKG, flagged).build();
            assert!(f.msi_tables(PKG).unwrap().truncated);

            // Hostile: more tasks than the limit is an error, never a cut list.
            let mut f = Fixture::new();
            f.set_tasks(Some(vec![TaskInfo::default(); MAX_TASKS]));
            assert_eq!(f.tasks().map(|t| t.len()), Ok(MAX_TASKS));
            f.add_task(TaskInfo::default());
            assert_eq!(f.tasks(), Err(SourceError::Other(TOO_MANY_TASKS)));
        }
    }
}
