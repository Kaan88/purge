//! Ownership index: which installed product owns which file, key or component (M1b, contract C-OWNERSHIP).
//!
//! Built once per harvest and once per scan ([`OwnershipIndex::build`]) and shared by everything that
//! needs to know whether another installed product owns a target. It holds:
//!
//! - **Component clients**: for every component registered under
//!   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\<sid>\Components`, in every user and
//!   context, the products registered as its clients (packed product codes, as found) and its key path.
//!   A client that is not an installed product (a stale registration) is still a client, and the
//!   permanent marker [`PERMANENT_CLIENT`] is kept as one.
//! - **MSI rows**: the `Registry`, `Class`, `ProgId`, `Extension`, `TypeLib`, `AppId` and `ServiceInstall`
//!   rows of every installed product's cached package, resolved by [`msi_rows`]. A package that cannot be
//!   read puts its product in [`OwnershipIndex::unreadable`]: its rows are unknown, never "none".
//! - **SharedDLLs** reference counts, **Installer\Folders** directories and **Burn** dependents.
//!
//! # Inputs and lookups
//!
//! Every path and key argument of a lookup must be in the canonical form `purge_guard::canon` produces;
//! lookups fold case with the guard's fold. The index canonicalises what it reads with the guard as
//! well, and never with code of its own. A file path that is not canonical (a short `PROGRA~1` segment,
//! another case of the drive letter, a trailing separator) is refused by an assertion in debug builds.
//!
//! # Failure
//!
//! [`OwnershipIndex::build`] never fails. A source error leaves the part it was reading unknown: the
//! product goes to [`OwnershipIndex::unreadable`] (tables) or the area is named in
//! [`OwnershipStats::incomplete`] (components, SharedDLLs, Installer\Folders, Burn), and the error is
//! listed in [`OwnershipStats::errors`].
//!
//! # Timing
//!
//! When a source meter is installed (`PURGE_TIMING`), `build` writes one line per phase to stderr:
//! `timing:   phase ownership.components <seconds>s; <source calls>` and the same for
//! `ownership.tables`.

pub mod cache;
pub mod msi_rows;

pub use cache::{
    CACHE_SCHEMA, CacheKey, DiskTableCache, MAX_CACHE_FILE, MemTableCache, TableCache,
};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use purge_guard::canon::{GuardEnv, canon_path};
use purge_guard::prefix::{ancestors, fold};
use purge_model::{InventoryEntry, MsiContext, MsiKeyPath, MsiOnlyRow};
use purge_source::filesystem::FileSystemSource;
use purge_source::registry::RegistrySource;
use purge_source::sysobj::MsiTables;
use purge_source::system::SystemSource;
use purge_source::types::{REG_DWORD, RegValue, SourceError};

use msi_rows::{ANY_USER, ResolvedRow, RowContext, RowValue};

/// `...\Installer\UserData`: one subkey per SID, each with a `Components` key.
pub const USERDATA: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData";

/// The two SharedDLLs keys (64-bit and 32-bit view).
///
/// They are two keys, not one: `SharedDLLs` is redirected by WOW64, not shared. Checked on Windows 11
/// 26300 (x64): `reg query ...\SharedDLLs /reg:64` lists 5,839 values and `/reg:32` (the same as
/// `WOW6432Node\...\SharedDLLs`) 150 different ones. A 64-bit install counts a file in the first, a
/// 32-bit install in the second, so the number of installs that use a file is the sum over both.
pub const SHARED_DLLS: [&str; 2] = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDLLs",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\SharedDLLs",
];

/// `Installer\Folders`: one value per directory Windows Installer created.
pub const INSTALLER_FOLDERS: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders";

/// The machine's Burn/MSI dependency providers.
pub const MACHINE_DEPENDENCIES: &str = r"HKLM\SOFTWARE\Classes\Installer\Dependencies";

/// The value name that marks a permanent component, kept in the client list as found.
pub const PERMANENT_CLIENT: &str = "00000000000000000000000000000000";

/// The SID under `UserData` that holds per-machine registrations.
pub const MACHINE_SID: &str = "S-1-5-18";

/// Reader threads when [`OwnershipInput::threads`] is zero.
pub const DEFAULT_THREADS: usize = 8;

/// The longest key path data read from a component value, in UTF-16 units (the longest Win32 path).
const MAX_KEY_PATH_CHARS: usize = 32_767;

/// The `SharedDLLs` count of a value whose data is not a `REG_DWORD`: unknown, which blocks.
pub const SHARED_DLL_UNKNOWN: u32 = u32::MAX;

/// An installed MSI product the index knows.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProductRef {
    /// ProductCode, `{GUID}` in upper case.
    pub product_code: String,
    /// The packed product code (32 hex digits, upper case).
    pub packed_code: String,
    /// The entry's display name.
    pub name: String,
    /// The installation context.
    pub context: MsiContext,
    /// The user of a per-user product.
    pub user_sid: Option<String>,
}

/// A component that owns a file or a directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentOwner<'a> {
    /// ComponentId, `{GUID}` in upper case.
    pub component_id: &'a str,
    /// Its clients over every user and context: packed product codes, as found (stale ones and
    /// [`PERMANENT_CLIENT`] included).
    pub clients: &'a [String],
    /// The key path that matched is reference-counted in SharedDLLs (`C?\...`).
    pub shared_dll: bool,
}

/// An MSI row that owns a registry key or value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowOwner<'a> {
    /// The product whose package holds the row.
    pub product: &'a ProductRef,
    /// `Registry`, `Class`, `ProgId`, `Extension`, `TypeLib`, `AppId` or `ServiceInstall`.
    pub table: &'static str,
    /// The row's primary key in its table.
    pub row: &'a str,
    /// The row claims the key and everything under it.
    pub whole_key: bool,
}

/// What [`OwnershipIndex::build`] reads from.
#[derive(Clone, Copy)]
pub struct OwnershipInput<'a> {
    /// The registry.
    pub reg: &'a dyn RegistrySource,
    /// The file system (package metadata for the cache key, long names of key paths).
    pub fs: &'a dyn FileSystemSource,
    /// The MSI tables.
    pub sys: &'a dyn SystemSource,
    /// The inventory; every entry with MSI information is a product of the index.
    pub products: &'a [InventoryEntry],
    /// The MSI products Windows Installer lists without an Uninstall key (`InventoryDoc::msi_only`):
    /// products of the index too, read like the others. Leaving them out would make what they own
    /// "nothing" instead of "unknown" (R2a S8).
    pub msi_only: &'a [MsiOnlyRow],
    /// A table cache.
    pub cache: Option<&'a dyn TableCache>,
    /// Reader threads; zero means [`DEFAULT_THREADS`].
    pub threads: usize,
}

/// How much the index holds before it stops reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnershipLimits {
    /// Component-client pairs.
    pub max_component_clients: usize,
    /// MSI table rows over all packages.
    pub max_rows: usize,
}

impl Default for OwnershipLimits {
    /// 2,000,000 of each.
    fn default() -> Self {
        Self {
            max_component_clients: 2_000_000,
            max_rows: 2_000_000,
        }
    }
}

/// An area of the index that could not be read completely.
pub mod area {
    /// The component clients.
    pub const COMPONENTS: &str = "components";
    /// The SharedDLLs counts.
    pub const SHARED_DLLS: &str = "shared_dlls";
    /// The Installer\Folders directories.
    pub const INSTALLER_FOLDERS: &str = "installer_folders";
    /// The Burn dependents.
    pub const BURN: &str = "burn";
    /// The MSI rows (some product's package was not read because of the memory limit).
    pub const ROWS: &str = "rows";
}

/// What the build read and how long it took.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnershipStats {
    /// Installed MSI products.
    pub products: u32,
    /// Packages read from the source.
    pub packages_read: u32,
    /// Packages taken from the cache.
    pub packages_cached: u32,
    /// Products whose package could not be read (see [`OwnershipIndex::unreadable`]).
    pub packages_unreadable: u32,
    /// Distinct components.
    pub components: u32,
    /// Registry keys opened by the component read.
    pub component_keys_opened: u32,
    /// Resolved rows.
    pub rows: u32,
    /// Milliseconds spent on the component read (with SharedDLLs, Folders and Burn).
    pub ms_components: u32,
    /// Milliseconds spent on the tables.
    pub ms_tables: u32,
    /// Rows dropped because they could not be resolved.
    pub unresolved_rows: u32,
    /// A memory limit was reached and reading stopped.
    pub capped: bool,
    /// Areas that could not be read completely (names from [`area`]). Unknown is never "none".
    pub incomplete: Vec<&'static str>,
    /// Every source error, as `<what>: <error>`.
    pub errors: Vec<String>,
}

impl OwnershipStats {
    fn mark(&mut self, what: &'static str, error: String) {
        if !self.incomplete.contains(&what) {
            self.incomplete.push(what);
        }
        self.errors.push(error);
    }

    /// The area was read completely.
    pub fn complete(&self, area: &str) -> bool {
        !self.incomplete.contains(&area)
    }
}

/// One key path a component is registered with.
#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyPathEntry {
    key_path: MsiKeyPath,
    shared_dll: bool,
}

#[derive(Debug, Clone)]
struct Component {
    id: String,
    clients: Vec<String>,
    key_paths: Vec<KeyPathEntry>,
}

#[derive(Debug, Clone)]
struct Row {
    product: u32,
    table: &'static str,
    row: String,
    value: RowValue,
}

/// The ownership index. See the module documentation.
#[derive(Debug, Default)]
pub struct OwnershipIndex {
    stats: OwnershipStats,
    products: Vec<ProductRef>,
    product_by_packed: HashMap<String, u32>,
    unreadable: Vec<ProductRef>,
    components: Vec<Component>,
    component_by_id: HashMap<String, u32>,
    /// Folded file key path -> (component, key path entry).
    files: BTreeMap<String, Vec<(u32, u32)>>,
    /// Folded directory key path -> components.
    dirs: BTreeMap<String, Vec<u32>>,
    /// Packed client -> (component, key path entry).
    by_client: HashMap<String, Vec<(u32, u32)>>,
    rows: Vec<Row>,
    /// Folded key -> rows (every spelling the row is looked up under).
    rows_by_key: BTreeMap<String, Vec<u32>>,
    /// Folded file path -> count summed over both views.
    shared_dlls: BTreeMap<String, u32>,
    folders: HashSet<String>,
    /// Folded provider key -> its dependents, merged and by hive.
    burn: BTreeMap<String, BurnProvider>,
}

/// One Burn/MSI dependency provider key as found under the machine's and the loaded users' Classes.
#[derive(Debug, Clone, Default)]
struct BurnProvider {
    /// The provider key as first found.
    name: String,
    /// Every dependent over all hives, first spelling kept.
    dependents: Vec<String>,
    /// Each dependent with the hive it was read from: `None` for the machine
    /// (`HKLM\SOFTWARE\Classes`), else the user's SID.
    records: Vec<(String, Option<String>)>,
}

/// A provider key that lists a dependent, and where the record was read (R2a S6: a user can write the
/// records of their own Classes hive, and nothing else).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BurnProviderRef<'a> {
    /// The provider key as found.
    pub provider: &'a str,
    /// The machine's records (`HKLM\SOFTWARE\Classes\Installer\Dependencies`) list the dependent.
    pub machine: bool,
}

// ---------------------------------------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------------------------------------

/// The fold of a canonical path or key, without trailing separators (a drive root `C:\` is `c:`).
fn key_of(path: &str) -> String {
    fold(path.trim_end_matches('\\'))
}

/// The folded keys strictly below `prefix` (already folded, no trailing separator) in `map`.
fn below<'m, V>(map: &'m BTreeMap<String, V>, prefix: &str) -> impl Iterator<Item = &'m V> {
    let lo = format!("{prefix}\\");
    let hi = format!("{prefix}]"); // `]` follows `\` in every ordering of these strings
    map.range(lo..hi).map(|(_, v)| v)
}

/// The packing permutation of a GUID's 32 hex digits (its own inverse).
fn permute(hex: &[u8]) -> String {
    let mut out = Vec::with_capacity(32);
    out.extend(hex[0..8].iter().rev());
    out.extend(hex[8..12].iter().rev());
    out.extend(hex[12..16].iter().rev());
    for i in (16..32).step_by(2) {
        out.push(hex[i + 1]);
        out.push(hex[i]);
    }
    String::from_utf8(out).unwrap_or_default()
}

/// 32 hex digits, upper-cased.
fn packed_form(s: &str) -> Option<String> {
    (s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())).then(|| s.to_ascii_uppercase())
}

/// `{GUID}` (braces required, any case) to its packed form.
pub fn pack_guid(guid: &str) -> Option<String> {
    let inner = guid.strip_prefix('{')?.strip_suffix('}')?;
    let ok = inner.len() == 36
        && inner.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        });
    if !ok {
        return None;
    }
    let hex: Vec<u8> = inner
        .bytes()
        .filter(|&b| b != b'-')
        .map(|b| b.to_ascii_uppercase())
        .collect();
    Some(permute(&hex))
}

/// A packed GUID (32 hex digits) to `{GUID}` in upper case.
pub fn unpack_guid(packed: &str) -> Option<String> {
    let hex = packed_form(packed)?;
    let g = permute(hex.as_bytes());
    Some(format!(
        "{{{}-{}-{}-{}-{}}}",
        &g[0..8],
        &g[8..12],
        &g[12..16],
        &g[16..20],
        &g[20..32]
    ))
}

/// A component id in either form, as the `{GUID}` upper-case form the index keys by.
fn component_key(id: &str) -> Option<String> {
    if id.starts_with('{') {
        pack_guid(id).and_then(|p| unpack_guid(&p))
    } else {
        unpack_guid(id)
    }
}

/// The spellings a canonical user key is looked up under: itself and, below `HKU\<sid>` or
/// `HKU\<sid>_Classes`, the same key with the user segment [`ANY_USER`].
fn key_variants(key: &str) -> Vec<String> {
    let folded = key_of(key);
    let mut out = vec![folded.clone()];
    if let Some(rest) = folded.strip_prefix("hku\\") {
        let (user, tail) = rest.split_once('\\').unwrap_or((rest, ""));
        if user != ANY_USER {
            let classes = user.ends_with("_classes");
            let mut any = format!("hku\\{ANY_USER}");
            if classes {
                any.push_str("_classes");
            }
            if !tail.is_empty() {
                any.push('\\');
                any.push_str(tail);
            }
            out.push(any);
        }
    }
    out
}

/// In debug builds, refuses a file path that is not in canonical form.
fn debug_assert_canonical_path(path: &str) {
    if cfg!(debug_assertions) {
        let canon = canon_path(path, &GuardEnv::default(), None);
        let ok = canon
            .as_ref()
            .is_ok_and(|c| c.path == path && !c.needs_long_name);
        assert!(
            ok,
            "ownership index: {path:?} is not a canonical path ({canon:?})"
        );
    }
}

/// Writes a `PURGE_TIMING` phase line when a meter is installed.
struct Phase {
    name: &'static str,
    started: Instant,
    before: Option<purge_source::metered::MeterSnapshot>,
}

impl Phase {
    fn start(name: &'static str) -> Self {
        Self {
            name,
            started: Instant::now(),
            before: purge_source::metered::installed().map(|m| m.snapshot()),
        }
    }

    /// Ends the phase and returns its milliseconds.
    fn end(self) -> u32 {
        let elapsed = self.started.elapsed();
        if let (Some(meter), Some(before)) = (purge_source::metered::installed(), self.before) {
            let calls = meter.snapshot().since(&before).summary();
            eprintln!(
                "timing:   phase {} {:.3}s; {}",
                self.name,
                elapsed.as_secs_f64(),
                calls
            );
        }
        u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX)
    }
}

/// Runs `job(i)` for `i` in `0..n` on at most `threads` threads and returns the results in order of `i`.
/// A job that sees `stop` set may return its "not done" value early.
fn parallel<T: Send>(n: usize, threads: usize, job: impl Fn(usize) -> T + Sync) -> Vec<T> {
    let threads = threads.clamp(1, n.max(1));
    if threads == 1 {
        return (0..n).map(job).collect();
    }
    let next = AtomicUsize::new(0);
    let mut parts: Vec<Vec<(usize, T)>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= n {
                            break;
                        }
                        done.push((i, job(i)));
                    }
                    done
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    });
    let mut all: Vec<(usize, T)> = parts.drain(..).flatten().collect();
    all.sort_by_key(|(i, _)| *i);
    all.into_iter().map(|(_, t)| t).collect()
}

// ---------------------------------------------------------------------------------------------------------
// Component key paths
// ---------------------------------------------------------------------------------------------------------

/// A key path as read: what it is, whether it is shared, and the directory of a directory key path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedKeyPath {
    key_path: MsiKeyPath,
    shared_dll: bool,
    dir: Option<String>,
}

impl ParsedKeyPath {
    fn none() -> Self {
        Self {
            key_path: MsiKeyPath::None,
            shared_dll: false,
            dir: None,
        }
    }
}

/// A canonical file path for a key path or SharedDLLs name; a short-name segment is expanded through
/// `fs` when the file exists, and kept as read otherwise.
fn canonical_file(path: &str, fs: &dyn FileSystemSource) -> Option<String> {
    let env = GuardEnv::default();
    let canon = canon_path(path, &env, None).ok()?;
    if !canon.needs_long_name {
        return Some(canon.path);
    }
    match fs
        .long_path(&canon.path)
        .ok()
        .and_then(|long| canon_path(&long, &env, None).ok())
    {
        Some(long) if !long.needs_long_name => Some(long.path),
        _ => Some(canon.path),
    }
}

/// Parses the data of a component value (contract C-OWNERSHIP). `sid` is the `UserData` SID: `None` for
/// the machine ([`MACHINE_SID`]). Anything malformed is [`MsiKeyPath::None`].
fn parse_key_path(
    data: &str,
    sid: Option<&str>,
    env: &GuardEnv,
    fs: &dyn FileSystemSource,
) -> ParsedKeyPath {
    if data.is_empty() || data.encode_utf16().count() > MAX_KEY_PATH_CHARS {
        return ParsedKeyPath::none();
    }
    let b = data.as_bytes();
    // Registry: `NN:\Key\Name`.
    if b.len() >= 3 && b[0].is_ascii_digit() && b[1].is_ascii_digit() && b[2] == b':' {
        let nn = (b[0] - b'0') * 10 + (b[1] - b'0');
        if !matches!(nn, 0..=3 | 20..=23) {
            return ParsedKeyPath::none();
        }
        let rest = data[3..].trim_start_matches('\\');
        let (key, name) = if let Some(key) = rest.strip_suffix('\\') {
            (key.trim_end_matches('\\'), None)
        } else {
            match rest.rsplit_once('\\') {
                Some((key, name)) => (key.trim_end_matches('\\'), Some(name.to_owned())),
                None => return ParsedKeyPath::none(),
            }
        };
        if key.is_empty() {
            return ParsedKeyPath::none();
        }
        return match msi_rows::component_registry_key(nn, key, sid, env) {
            Some(key) => ParsedKeyPath {
                key_path: MsiKeyPath::Registry { key, name },
                shared_dll: false,
                dir: None,
            },
            None => ParsedKeyPath::none(),
        };
    }
    // File: `C:\dir\file`, `C?\dir\file`, or a directory ending in `\`.
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && matches!(b[1], b':' | b'?') && b[2] == b'\\' {
        let shared_dll = b[1] == b'?';
        let path = format!("{}:{}", &data[..1], &data[2..]);
        let Some(canon) = canonical_file(&path, fs) else {
            return ParsedKeyPath::none();
        };
        if data.ends_with('\\') {
            return ParsedKeyPath {
                key_path: MsiKeyPath::None,
                shared_dll,
                dir: Some(canon),
            };
        }
        return ParsedKeyPath {
            key_path: MsiKeyPath::File { path: canon },
            shared_dll,
            dir: None,
        };
    }
    ParsedKeyPath::none()
}

// ---------------------------------------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------------------------------------

/// One component value set as read.
struct ComponentRead {
    sid: usize,
    packed: String,
    values: Result<Vec<RegValue>, SourceError>,
}

/// One product's tables as read.
enum TablesRead {
    Read(Box<MsiTables>),
    Cached(Box<MsiTables>),
    Unreadable(String),
    /// Not read: the row limit was reached first.
    Skipped,
}

impl OwnershipIndex {
    /// An index that knows nothing, with nothing marked unknown either. For callers that build no
    /// index (M1a behaviour); never a stand-in for an index that failed.
    pub fn empty() -> &'static OwnershipIndex {
        static EMPTY: OnceLock<OwnershipIndex> = OnceLock::new();
        EMPTY.get_or_init(OwnershipIndex::default)
    }

    /// Builds the index with the default [`OwnershipLimits`]. Never fails; see the module documentation.
    pub fn build(inp: &OwnershipInput) -> OwnershipIndex {
        Self::build_with_limits(inp, OwnershipLimits::default())
    }

    /// Builds the index with explicit limits.
    pub fn build_with_limits(inp: &OwnershipInput, limits: OwnershipLimits) -> OwnershipIndex {
        let mut ix = OwnershipIndex::default();
        let threads = if inp.threads == 0 {
            DEFAULT_THREADS
        } else {
            inp.threads
        };
        let env = match inp.reg.current_control_set() {
            Ok(n) => GuardEnv {
                current_control_set: n,
                ..GuardEnv::default()
            },
            Err(e) => {
                ix.stats.errors.push(format!("current control set: {e}"));
                GuardEnv::default()
            }
        };
        ix.collect_products(inp);

        let phase = Phase::start("ownership.components");
        ix.read_components(inp, threads, &env, limits);
        ix.read_shared_dlls(inp);
        ix.read_installer_folders(inp);
        ix.read_burn(inp, &env);
        ix.stats.ms_components = phase.end();

        let phase = Phase::start("ownership.tables");
        ix.read_tables(inp, threads, &env, limits);
        ix.stats.ms_tables = phase.end();

        ix.stats.products = u32::try_from(ix.products.len()).unwrap_or(u32::MAX);
        ix.stats.components = u32::try_from(ix.components.len()).unwrap_or(u32::MAX);
        ix.stats.rows = u32::try_from(ix.rows.len()).unwrap_or(u32::MAX);
        ix.stats.packages_unreadable = u32::try_from(ix.unreadable.len()).unwrap_or(u32::MAX);
        ix
    }

    fn collect_products(&mut self, inp: &OwnershipInput) {
        for input in product_inputs(inp) {
            let code = input.code;
            let Some(packed) = pack_guid(code.trim()) else {
                self.stats
                    .errors
                    .push(format!("product {code:?}: not a GUID"));
                continue;
            };
            let product = ProductRef {
                product_code: unpack_guid(&packed).unwrap_or_default(),
                packed_code: packed.clone(),
                name: input.name,
                context: input.context,
                user_sid: input.user_sid,
            };
            if self.products.contains(&product) {
                continue;
            }
            let idx = u32::try_from(self.products.len()).unwrap_or(u32::MAX);
            self.product_by_packed.entry(packed).or_insert(idx);
            self.products.push(product);
        }
    }

    fn read_components(
        &mut self,
        inp: &OwnershipInput,
        threads: usize,
        env: &GuardEnv,
        limits: OwnershipLimits,
    ) {
        let mut opened: u32 = 0;
        let mut walker = inp.reg.walker();
        opened += 1;
        let sids = match walker.enter(USERDATA).and_then(|_| walker.subkeys()) {
            Ok(sids) => sids,
            Err(SourceError::NotFound) => Vec::new(),
            Err(e) => {
                self.stats
                    .mark(area::COMPONENTS, format!("{USERDATA}: {e}"));
                Vec::new()
            }
        };
        let mut jobs: Vec<(usize, String)> = Vec::new();
        for (i, sid) in sids.iter().enumerate() {
            let key = format!("{USERDATA}\\{sid}\\Components");
            opened += 1;
            match walker.enter(&key).and_then(|_| walker.subkeys()) {
                Ok(names) => jobs.extend(names.into_iter().map(|n| (i, n))),
                Err(SourceError::NotFound) => {}
                Err(e) => self.stats.mark(area::COMPONENTS, format!("{key}: {e}")),
            }
        }
        drop(walker);

        // Component keys, split into contiguous chunks, one walker per chunk.
        let pairs = AtomicUsize::new(0);
        let stop = AtomicBool::new(false);
        let chunks = threads.clamp(1, jobs.len().max(1));
        let size = jobs.len().div_ceil(chunks).max(1);
        let job_chunks: Vec<&[(usize, String)]> = jobs.chunks(size).collect();
        let reads: Vec<(Vec<ComponentRead>, u32)> = parallel(job_chunks.len(), threads, |c| {
            let mut walker = inp.reg.walker();
            let mut out = Vec::with_capacity(job_chunks[c].len());
            let mut opened = 0u32;
            for (sid, packed) in job_chunks[c] {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let key = format!("{USERDATA}\\{}\\Components\\{packed}", sids[*sid]);
                opened += 1;
                let values = walker.enter(&key).and_then(|_| walker.values());
                if let Ok(v) = &values {
                    let total = pairs.fetch_add(v.len(), Ordering::Relaxed) + v.len();
                    if total > limits.max_component_clients {
                        stop.store(true, Ordering::Relaxed);
                    }
                }
                out.push(ComponentRead {
                    sid: *sid,
                    packed: packed.clone(),
                    values,
                });
            }
            (out, opened)
        });

        let mut held = 0usize;
        let mut capped = stop.load(Ordering::Relaxed);
        'all: for (chunk, n) in reads {
            opened = opened.saturating_add(n);
            for read in chunk {
                let values = match read.values {
                    Ok(v) => v,
                    Err(SourceError::NotFound) => continue, // gone between listing and reading
                    Err(e) => {
                        self.stats.mark(
                            area::COMPONENTS,
                            format!(
                                "{USERDATA}\\{}\\Components\\{}: {e}",
                                sids[read.sid], read.packed
                            ),
                        );
                        continue;
                    }
                };
                if held + values.len() > limits.max_component_clients {
                    capped = true;
                    break 'all;
                }
                held += values.len();
                self.add_component(&sids[read.sid], &read.packed, &values, env, inp.fs);
            }
        }
        if capped {
            self.stats.capped = true;
            self.stats.mark(
                area::COMPONENTS,
                format!(
                    "components: more than {} component-client pairs; the rest is not read",
                    limits.max_component_clients
                ),
            );
        }
        self.stats.component_keys_opened = opened;
    }

    fn add_component(
        &mut self,
        sid: &str,
        packed_component: &str,
        values: &[RegValue],
        env: &GuardEnv,
        fs: &dyn FileSystemSource,
    ) {
        let Some(id) = unpack_guid(packed_component) else {
            self.stats.errors.push(format!(
                "{USERDATA}\\{sid}\\Components\\{packed_component}: not a packed GUID"
            ));
            return;
        };
        let user = (!sid.eq_ignore_ascii_case(MACHINE_SID)).then_some(sid);
        let comp = match self.component_by_id.get(&id) {
            Some(&c) => c,
            None => {
                let c = u32::try_from(self.components.len()).unwrap_or(u32::MAX);
                self.components.push(Component {
                    id: id.clone(),
                    clients: Vec::new(),
                    key_paths: Vec::new(),
                });
                self.component_by_id.insert(id, c);
                c
            }
        };
        for value in values {
            let Some(client) = packed_form(&value.name) else {
                continue; // not a client registration
            };
            let parsed = match value.data.string() {
                Some(data) if value.data.is_complete() => parse_key_path(&data, user, env, fs),
                _ => ParsedKeyPath::none(),
            };
            let component = &mut self.components[comp as usize];
            if !component.clients.contains(&client) {
                component.clients.push(client.clone());
            }
            let entry = KeyPathEntry {
                key_path: parsed.key_path.clone(),
                shared_dll: parsed.shared_dll,
            };
            let kp = match component.key_paths.iter().position(|k| *k == entry) {
                Some(i) => i,
                None => {
                    component.key_paths.push(entry);
                    component.key_paths.len() - 1
                }
            };
            let kp = u32::try_from(kp).unwrap_or(u32::MAX);
            let slot = self.by_client.entry(client).or_default();
            if !slot.contains(&(comp, kp)) {
                slot.push((comp, kp));
            }
            if let MsiKeyPath::File { path } = &parsed.key_path {
                let slot = self.files.entry(key_of(path)).or_default();
                if !slot.contains(&(comp, kp)) {
                    slot.push((comp, kp));
                }
            }
            if let Some(dir) = &parsed.dir {
                let slot = self.dirs.entry(key_of(dir)).or_default();
                if !slot.contains(&comp) {
                    slot.push(comp);
                }
            }
        }
    }

    /// Both views of SharedDLLs, summed per file: they are two keys ([`SHARED_DLLS`]).
    fn read_shared_dlls(&mut self, inp: &OwnershipInput) {
        for key in SHARED_DLLS {
            let values = match inp.reg.values(key) {
                Ok(v) => v,
                Err(SourceError::NotFound) => continue,
                Err(e) => {
                    self.stats.mark(area::SHARED_DLLS, format!("{key}: {e}"));
                    continue;
                }
            };
            for v in values {
                let Some(path) = canonical_file(&v.name, inp.fs) else {
                    continue;
                };
                let count = if v.data.ty == REG_DWORD {
                    v.data.dword().unwrap_or(SHARED_DLL_UNKNOWN)
                } else {
                    SHARED_DLL_UNKNOWN
                };
                let slot = self.shared_dlls.entry(key_of(&path)).or_insert(0);
                *slot = slot.saturating_add(count);
            }
        }
    }

    fn read_installer_folders(&mut self, inp: &OwnershipInput) {
        match inp.reg.values(INSTALLER_FOLDERS) {
            Ok(values) => {
                for v in values {
                    if let Ok(c) = canon_path(&v.name, &GuardEnv::default(), None) {
                        self.folders.insert(key_of(&c.path));
                    }
                }
            }
            Err(SourceError::NotFound) => {}
            Err(e) => self
                .stats
                .mark(area::INSTALLER_FOLDERS, format!("{INSTALLER_FOLDERS}: {e}")),
        }
    }

    fn read_burn(&mut self, inp: &OwnershipInput, env: &GuardEnv) {
        // Each root with its hive: `None` for the machine's, else the user's SID.
        let mut roots: Vec<(String, Option<String>)> =
            vec![(MACHINE_DEPENDENCIES.to_owned(), None)];
        match inp.reg.loaded_user_sids() {
            Ok(sids) => {
                for sid in sids {
                    let input = format!("HKU\\{sid}\\Software\\Classes\\Installer\\Dependencies");
                    match purge_guard::canon::canon_key(&input, None, env, None) {
                        Ok(k) => roots.push((k.key_path(), Some(sid))),
                        Err(e) => self.stats.mark(area::BURN, format!("{input}: {e}")),
                    }
                }
            }
            Err(e) => self
                .stats
                .mark(area::BURN, format!("loaded user hives: {e}")),
        }
        for (root, hive) in roots {
            let providers = match inp.reg.subkeys(&root) {
                Ok(p) => p,
                Err(SourceError::NotFound) => continue,
                Err(e) => {
                    self.stats.mark(area::BURN, format!("{root}: {e}"));
                    continue;
                }
            };
            for provider in providers {
                let key = format!("{root}\\{provider}\\Dependents");
                let dependents = match inp.reg.subkeys(&key) {
                    Ok(d) => d,
                    Err(SourceError::NotFound) => Vec::new(),
                    Err(e) => {
                        self.stats.mark(area::BURN, format!("{key}: {e}"));
                        Vec::new()
                    }
                };
                let slot = self
                    .burn
                    .entry(fold(&provider))
                    .or_insert_with(|| BurnProvider {
                        name: provider.clone(),
                        ..BurnProvider::default()
                    });
                for d in dependents {
                    if !slot
                        .dependents
                        .iter()
                        .any(|x| purge_guard::prefix::eq_ci(x, &d))
                    {
                        slot.dependents.push(d.clone());
                    }
                    slot.records.push((d, hive.clone()));
                }
            }
        }
    }

    fn read_tables(
        &mut self,
        inp: &OwnershipInput,
        threads: usize,
        env: &GuardEnv,
        limits: OwnershipLimits,
    ) {
        // The products with a package, each read once (the same product in two entries is one product).
        let mut todo: Vec<(u32, String)> = Vec::new();
        let mut unknown: Vec<u32> = Vec::new();
        for input in product_inputs(inp) {
            let Some(packed) = pack_guid(input.code.trim()) else {
                continue;
            };
            let Some(p) = self.products.iter().position(|p| {
                p.packed_code == packed
                    && p.context == input.context
                    && p.user_sid == input.user_sid
            }) else {
                continue;
            };
            let p = u32::try_from(p).unwrap_or(u32::MAX);
            if todo.iter().any(|(q, _)| *q == p) || unknown.contains(&p) {
                continue;
            }
            // A per-user product whose user is not known (an entry in another hive than the product's
            // user, as a code-only match gives): its per-user rows could not be placed in any hive and
            // would be dropped one by one. Its rows are unknown, said once here (R2a S8).
            if input.context != MsiContext::Machine && input.user_sid.is_none() {
                self.stats.errors.push(format!(
                    "{}: a per-user product whose user is not known; its rows are unknown",
                    self.products[p as usize].product_code
                ));
                self.unreadable.push(self.products[p as usize].clone());
                unknown.push(p);
                continue;
            }
            match input.local_package.map(str::trim) {
                Some(lp) if !lp.is_empty() => todo.push((p, lp.to_owned())),
                _ => {
                    self.stats.errors.push(format!(
                        "{}: no LocalPackage; its rows are unknown",
                        self.products[p as usize].product_code
                    ));
                    self.unreadable.push(self.products[p as usize].clone());
                    unknown.push(p);
                }
            }
        }

        let rows_read = AtomicUsize::new(0);
        let stop = AtomicBool::new(false);
        let reads: Vec<TablesRead> = parallel(todo.len(), threads, |i| {
            if stop.load(Ordering::Relaxed) {
                return TablesRead::Skipped;
            }
            let read = read_package(inp, &todo[i].1);
            if let TablesRead::Read(t) | TablesRead::Cached(t) = &read {
                let n = t.row_count();
                if rows_read.fetch_add(n, Ordering::Relaxed) + n > limits.max_rows {
                    stop.store(true, Ordering::Relaxed);
                }
            }
            read
        });

        let mut held = 0usize;
        let mut capped = false;
        for ((p, lp), read) in todo.iter().zip(reads) {
            let product = self.products[*p as usize].clone();
            let tables = match read {
                _ if capped => None,
                TablesRead::Skipped => {
                    capped = true;
                    None
                }
                TablesRead::Read(t) => {
                    self.stats.packages_read += 1;
                    Some(t)
                }
                TablesRead::Cached(t) => {
                    self.stats.packages_cached += 1;
                    Some(t)
                }
                TablesRead::Unreadable(why) => {
                    self.stats
                        .errors
                        .push(format!("{} ({lp}): {why}", product.product_code));
                    self.unreadable.push(product);
                    continue;
                }
            };
            let Some(tables) = tables else {
                self.unreadable.push(product);
                continue;
            };
            if tables.truncated {
                self.stats.errors.push(format!(
                    "{} ({lp}): tables truncated; its rows are unknown",
                    product.product_code
                ));
                self.unreadable.push(product);
                continue;
            }
            let n = tables.row_count();
            if held + n > limits.max_rows {
                capped = true;
                self.unreadable.push(product);
                continue;
            }
            held += n;
            let ctx = RowContext {
                product_code: &product.product_code,
                context: product.context,
                user_sid: product.user_sid.as_deref(),
                current_control_set: env.current_control_set,
            };
            let resolved = msi_rows::resolve(&tables, &ctx);
            self.stats.unresolved_rows = self
                .stats
                .unresolved_rows
                .saturating_add(resolved.unresolved);
            for row in resolved.rows {
                self.add_row(*p, row);
            }
        }
        if capped {
            self.stats.capped = true;
            self.stats.mark(
                area::ROWS,
                format!(
                    "rows: more than {} table rows; the remaining products are unreadable",
                    limits.max_rows
                ),
            );
        }
    }

    fn add_row(&mut self, product: u32, row: ResolvedRow) {
        let idx = u32::try_from(self.rows.len()).unwrap_or(u32::MAX);
        let mut seen: Vec<String> = Vec::with_capacity(row.keys.len());
        for key in &row.keys {
            let k = key_of(key);
            if seen.contains(&k) {
                continue;
            }
            self.rows_by_key.entry(k.clone()).or_default().push(idx);
            seen.push(k);
        }
        self.rows.push(Row {
            product,
            table: row.table,
            row: row.row,
            value: row.value,
        });
    }

    // -----------------------------------------------------------------------------------------------------
    // Lookups
    // -----------------------------------------------------------------------------------------------------

    /// What the build read.
    pub fn stats(&self) -> &OwnershipStats {
        &self.stats
    }

    fn owner(&self, comp: u32, shared_dll: bool) -> ComponentOwner<'_> {
        let c = &self.components[comp as usize];
        ComponentOwner {
            component_id: &c.id,
            clients: &c.clients,
            shared_dll,
        }
    }

    /// The components whose key path is the file `path` (canonical).
    /// Adds the owner `comp` to `out`, or ORs `shared` into the one already there.
    fn push_owner<'s>(&'s self, out: &mut Vec<ComponentOwner<'s>>, comp: u32, shared: bool) {
        let id = &self.components[comp as usize].id;
        match out.iter_mut().find(|o| o.component_id == id) {
            Some(o) => o.shared_dll |= shared,
            None => out.push(self.owner(comp, shared)),
        }
    }

    /// The components whose key path is the file `path` (canonical).
    pub fn file_owners(&self, path: &str) -> Vec<ComponentOwner<'_>> {
        debug_assert_canonical_path(path);
        let mut out = Vec::new();
        for &(comp, kp) in self.files.get(&key_of(path)).into_iter().flatten() {
            let shared = self.components[comp as usize].key_paths[kp as usize].shared_dll;
            self.push_owner(&mut out, comp, shared);
        }
        out
    }

    /// Every file key path (folded) whose file name is `name` (compared ignoring case), each with the
    /// components it is the key path of, in path order. Empty for a name that is empty or holds a
    /// separator. One pass over the index's files.
    pub fn files_named(&self, name: &str) -> Vec<(&str, Vec<ComponentOwner<'_>>)> {
        let want = fold(name.trim());
        if want.is_empty() || want.contains(['\\', '/']) {
            return Vec::new();
        }
        let suffix = format!("\\{want}");
        self.files
            .iter()
            .filter(|(path, _)| path.ends_with(&suffix))
            .map(|(path, list)| {
                let mut out = Vec::new();
                for &(comp, kp) in list {
                    let shared = self.components[comp as usize].key_paths[kp as usize].shared_dll;
                    self.push_owner(&mut out, comp, shared);
                }
                (path.as_str(), out)
            })
            .collect()
    }

    /// The components whose file key path is directly in `dir` (canonical) or below it, and the
    /// components whose key path is a directory at or below `dir`. A sibling with a longer name
    /// (`C:\AppData` beside `C:\App`) is not below.
    pub fn dir_components(&self, dir: &str) -> Vec<ComponentOwner<'_>> {
        debug_assert_canonical_path(dir);
        let k = key_of(dir);
        let mut out = Vec::new();
        for list in below(&self.files, &k) {
            for &(comp, kp) in list {
                let shared = self.components[comp as usize].key_paths[kp as usize].shared_dll;
                self.push_owner(&mut out, comp, shared);
            }
        }
        for list in self.dirs.get(&k).into_iter().chain(below(&self.dirs, &k)) {
            for &comp in list {
                self.push_owner(&mut out, comp, false);
            }
        }
        out
    }

    fn row_owner(&self, idx: u32) -> RowOwner<'_> {
        let row = &self.rows[idx as usize];
        RowOwner {
            product: &self.products[row.product as usize],
            table: row.table,
            row: &row.row,
            whole_key: row.value == RowValue::WholeKey,
        }
    }

    /// Whole-key rows at `key` itself (`at`) or at a strict ancestor of it.
    fn whole_key_rows(&self, key: &str, at: bool, out: &mut Vec<u32>) {
        let mut keys: Vec<&str> = Vec::new();
        if at {
            keys.push(key);
        }
        keys.extend(ancestors(key));
        for k in keys {
            for variant in key_variants(k) {
                for &idx in self.rows_by_key.get(&variant).into_iter().flatten() {
                    if self.rows[idx as usize].value == RowValue::WholeKey && !out.contains(&idx) {
                        out.push(idx);
                    }
                }
            }
        }
    }

    /// The rows that own the value `name` of `key` (canonical; `None` and `""` are the default value),
    /// and the whole-key rows at `key` or an ancestor. A key-only row (`Registry.Name` `+`, a row of the
    /// other tables) owns no value.
    pub fn reg_owners(&self, key: &str, name: Option<&str>) -> Vec<RowOwner<'_>> {
        let want = name.filter(|n| !n.is_empty());
        let mut idxs: Vec<u32> = Vec::new();
        for variant in key_variants(key) {
            for &idx in self.rows_by_key.get(&variant).into_iter().flatten() {
                let RowValue::Value(have) = &self.rows[idx as usize].value else {
                    continue;
                };
                let same = match (have.as_deref(), want) {
                    (None, None) => true,
                    (Some(a), Some(b)) => purge_guard::prefix::eq_ci(a, b),
                    _ => false,
                };
                if same && !idxs.contains(&idx) {
                    idxs.push(idx);
                }
            }
        }
        self.whole_key_rows(key, true, &mut idxs);
        idxs.into_iter().map(|i| self.row_owner(i)).collect()
    }

    /// Every row at `key` (canonical) or below it, and the whole-key rows at an ancestor.
    pub fn key_owners(&self, key: &str) -> Vec<RowOwner<'_>> {
        let mut idxs: Vec<u32> = Vec::new();
        for variant in key_variants(key) {
            let at = self.rows_by_key.get(&variant).into_iter();
            for list in at.chain(below(&self.rows_by_key, &variant)) {
                for &idx in list {
                    if !idxs.contains(&idx) {
                        idxs.push(idx);
                    }
                }
            }
        }
        self.whole_key_rows(key, false, &mut idxs);
        idxs.into_iter().map(|i| self.row_owner(i)).collect()
    }

    /// The clients of a component (`{GUID}` or packed), over every user and context; empty when the
    /// index does not know the component.
    pub fn clients_of(&self, component_id: &str) -> &[String] {
        component_key(component_id)
            .and_then(|id| self.component_by_id.get(&id))
            .map_or(&[], |&c| &self.components[c as usize].clients)
    }

    /// The components a product (packed code) is a client of, each with every key path it is
    /// registered with for the product.
    pub fn components_of(&self, packed_code: &str) -> Vec<(&str, &MsiKeyPath)> {
        let Some(packed) = packed_form(packed_code) else {
            return Vec::new();
        };
        self.by_client
            .get(&packed)
            .into_iter()
            .flatten()
            .map(|&(comp, kp)| {
                let c = &self.components[comp as usize];
                (c.id.as_str(), &c.key_paths[kp as usize].key_path)
            })
            .collect()
    }

    /// The installed product with this packed code.
    pub fn installed(&self, packed_code: &str) -> Option<&ProductRef> {
        let packed = packed_form(packed_code)?;
        self.product_by_packed
            .get(&packed)
            .map(|&i| &self.products[i as usize])
    }

    /// The products whose rows are unknown: package missing, unreadable, truncated, or not read because
    /// of the memory limit.
    pub fn unreadable(&self) -> &[ProductRef] {
        &self.unreadable
    }

    /// The SharedDLLs count of a file (canonical), summed over both views; `None` when it is not listed;
    /// [`SHARED_DLL_UNKNOWN`] when a count is not a `REG_DWORD`.
    pub fn shared_dll_count(&self, path: &str) -> Option<u32> {
        debug_assert_canonical_path(path);
        self.shared_dlls.get(&key_of(path)).copied()
    }

    /// The files strictly below the directory `dir` (canonical) that SharedDLLs counts, each with its
    /// count summed over both views ([`SHARED_DLL_UNKNOWN`] when a count is not a `REG_DWORD`), as
    /// folded paths in path order. A sibling with a longer name (`C:\AppData` beside `C:\App`) is not
    /// below.
    pub fn shared_dlls_under(&self, dir: &str) -> Vec<(&str, u32)> {
        debug_assert_canonical_path(dir);
        let k = key_of(dir);
        let lo = format!("{k}\\");
        let hi = format!("{k}]");
        self.shared_dlls
            .range(lo..hi)
            .map(|(file, count)| (file.as_str(), *count))
            .collect()
    }

    /// The directory (canonical) is listed in `Installer\Folders`.
    pub fn installer_folder(&self, dir: &str) -> bool {
        debug_assert_canonical_path(dir);
        self.folders.contains(&key_of(dir))
    }

    /// The dependents of a Burn/MSI dependency provider key (compared without regard to case), merged
    /// over the machine and every loaded user. More dependents only ever keep more: this is the list
    /// for "does anybody else still depend on it", never for "whose is it".
    pub fn burn_dependents(&self, provider_key: &str) -> &[String] {
        self.burn
            .get(&fold(provider_key))
            .map_or(&[], |p| p.dependents.as_slice())
    }

    /// The provider keys (as found) that list `dependent` (compared without regard to case) in any
    /// hive. Not an ownership answer: a user can write a record naming any dependent in their own
    /// hive; use [`OwnershipIndex::burn_providers_in`] for that.
    pub fn burn_providers_of(&self, dependent: &str) -> Vec<&str> {
        self.burn
            .values()
            .filter(|p| {
                p.dependents
                    .iter()
                    .any(|x| purge_guard::prefix::eq_ci(x, dependent))
            })
            .map(|p| p.name.as_str())
            .collect()
    }

    /// The provider keys that list `dependent` in the machine's records, or, with `user_sid`, in that
    /// user's records (compared without regard to case), in key order. A machine bundle passes `None`
    /// and sees the machine's records only; a per-user bundle passes its own SID (R2a S6).
    pub fn burn_providers_in(
        &self,
        dependent: &str,
        user_sid: Option<&str>,
    ) -> Vec<BurnProviderRef<'_>> {
        let mut out = Vec::new();
        for p in self.burn.values() {
            let mut machine = false;
            let mut user = false;
            for (d, hive) in &p.records {
                if !purge_guard::prefix::eq_ci(d, dependent) {
                    continue;
                }
                match (hive.as_deref(), user_sid) {
                    (None, _) => machine = true,
                    (Some(h), Some(sid)) if h.eq_ignore_ascii_case(sid.trim()) => user = true,
                    _ => {}
                }
            }
            if machine || user {
                out.push(BurnProviderRef {
                    provider: p.name.as_str(),
                    machine,
                });
            }
        }
        out
    }
}

/// One installed MSI product as the index takes it: from an inventory entry with MSI information or from
/// a product without an Uninstall key.
struct ProductInput<'a> {
    code: &'a str,
    context: MsiContext,
    /// The product's user; `None` for the machine context, and for a per-user product whose user is
    /// not known (see `read_tables`).
    user_sid: Option<String>,
    name: String,
    local_package: Option<&'a str>,
}

/// The products of the index, entries first, then the products without an Uninstall key. A per-user
/// product takes its user from the entry's hive (`None` when the entry is in `HKLM`) or from Windows
/// Installer's row.
fn product_inputs<'a>(inp: &OwnershipInput<'a>) -> Vec<ProductInput<'a>> {
    let entries = inp.products.iter().filter_map(|e| {
        let (Some(msi), Some(code)) = (&e.msi, &e.product_code) else {
            return None;
        };
        Some(ProductInput {
            code,
            context: msi.context,
            user_sid: match msi.context {
                MsiContext::Machine => None,
                _ => e.hive_sid.clone(),
            },
            name: e.display_name.clone(),
            local_package: msi.local_package.as_deref(),
        })
    });
    let msi_only = inp.msi_only.iter().map(|row| ProductInput {
        code: &row.product_code,
        context: row.context,
        user_sid: match row.context {
            MsiContext::Machine => None,
            _ => row.user_sid.clone(),
        },
        name: row
            .product_name
            .clone()
            .unwrap_or_else(|| row.product_code.clone()),
        local_package: row.local_package.as_deref(),
    });
    entries.chain(msi_only).collect()
}

/// Reads one package's tables, from the cache when it has them. Never fails.
fn read_package(inp: &OwnershipInput, local_package: &str) -> TablesRead {
    let canonical = canon_path(local_package, &GuardEnv::default(), None)
        .map(|c| c.path)
        .unwrap_or_else(|_| local_package.to_owned());
    let key = inp.fs.metadata(&canonical).ok().and_then(|m| {
        m.times.modified.map(|t| CacheKey {
            local_package: canonical.clone(),
            size: m.size,
            mtime: t.0,
        })
    });
    if let (Some(cache), Some(key)) = (inp.cache, &key) {
        if let Some(tables) = cache.get(key) {
            return TablesRead::Cached(Box::new(tables));
        }
    }
    match inp.sys.msi_tables(local_package) {
        Ok(tables) => {
            if let (Some(cache), Some(key), false) = (inp.cache, &key, tables.truncated) {
                cache.put(key, &tables);
            }
            TablesRead::Read(Box::new(tables))
        }
        Err(e) => TablesRead::Unreadable(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_and_unpack_are_inverse() {
        let g = "{12345678-90AB-CDEF-1234-567890ABCDEF}";
        assert_eq!(
            pack_guid(g).as_deref(),
            Some("87654321BA09FEDC2143658709BADCFE")
        );
        assert_eq!(
            unpack_guid("87654321ba09fedc2143658709badcfe").as_deref(),
            Some(g)
        );
        assert_eq!(pack_guid("{1234}"), None);
        assert_eq!(pack_guid("12345678-90AB-CDEF-1234-567890ABCDEF"), None);
        assert_eq!(unpack_guid("XYZ"), None);
        assert_eq!(component_key(g).as_deref(), Some(g));
        assert_eq!(
            component_key("87654321BA09FEDC2143658709BADCFE").as_deref(),
            Some(g)
        );
    }

    #[test]
    fn below_is_separator_aware() {
        let mut m: BTreeMap<String, u32> = BTreeMap::new();
        for (i, k) in [
            "c:\\app",
            "c:\\app\\x",
            "c:\\app (x86)\\y",
            "c:\\appdata\\z",
            "c:\\app\\a\\b",
        ]
        .iter()
        .enumerate()
        {
            m.insert((*k).to_owned(), i as u32);
        }
        let got: Vec<u32> = below(&m, "c:\\app").copied().collect();
        assert_eq!(got, vec![4, 1]);
    }

    #[test]
    fn user_keys_have_an_any_user_variant() {
        assert_eq!(
            key_variants(r"HKU\S-1-5-21-1-2-3-1001\Software\X"),
            vec![
                r"hku\s-1-5-21-1-2-3-1001\software\x".to_owned(),
                r"hku\*\software\x".to_owned()
            ]
        );
        assert_eq!(
            key_variants(r"HKU\S-1-5-21-1-2-3-1001_Classes\CLSID"),
            vec![
                r"hku\s-1-5-21-1-2-3-1001_classes\clsid".to_owned(),
                r"hku\*_classes\clsid".to_owned()
            ]
        );
        assert_eq!(
            key_variants(r"HKLM\SOFTWARE"),
            vec![r"hklm\software".to_owned()]
        );
    }
}
