//! The engine pipeline behind the CLI verbs (ENGINE_PLAN.md §3.4, §3.6 steps 1-7, §5.1).
//!
//! Every step reads the machine only through the three source traits ([`Sources`]), so the live machine,
//! a JSON fixture and a rig snapshot go through exactly the same code:
//!
//! | Step | Function | §3.6 |
//! |---|---|---|
//! | inventory | [`inventory`] | (S1 list) |
//! | harvest | [`harvest`] | 1 HARVEST |
//! | uninstall | [`uninstall`] | 2 OBSERVE, 3 VERIFY-GONE |
//! | scan | [`scan`], [`scan_path`] | 4 QUERY, 5 SCAN, 6 DECIDE, 7 PLAN |
//!
//! # Scan modes (§5.1, §5.8.3)
//!
//! - `post`: the fingerprint must hold a completed uninstall window (`t_start` and `t_end`, written by
//!   [`uninstall`]); otherwise the scan refuses to run ([`PipelineError::Precondition`]). The verify-gone
//!   result of that run gates the Safe band: when it failed, the policy applies the forced-mode rules
//!   (nothing is Safe or preselected) and the scan reports a warning.
//! - `external` and `forced`: verify-gone is checked afresh against the current machine (without a
//!   ProductCode, which the fingerprint does not keep). `forced` never yields Safe.
//! - `scan --path` ([`scan_path`]) is a **minimal M1a implementation** of the portable-app path: the
//!   directory becomes the `InstallLocation` of a synthetic inventory entry whose name and publisher come
//!   from the version resources and signers of the executables directly inside it; that entry is
//!   harvested like any other and scanned in `forced` mode, so nothing is ever Safe.
//!
//! # What the scan context is built from
//!
//! - the guard facts of the machine (`purge_harvest::roots::guard_env`), plus the roots of every other
//!   installed app and Purge's own directories;
//! - the other apps from a fresh inventory, without the app being cleaned and without its co-removed
//!   products: their `InstallLocation`, the files their `UninstallString` and `DisplayIcon` name, their
//!   own Uninstall key and the exe name of their icon. Directories the guard refuses as roots (Program
//!   Files itself, a profile, …) are left out, so one bad `InstallLocation` cannot block a whole drive;
//! - the baseline view ([`baseline`]): the clean-Windows baseline of exactly this (edition, build.ubr)
//!   when the baseline directory holds one; otherwise the cached local baseline and the neighbouring
//!   shipped baselines, which only ever say "this is Windows' own" (BASELINE_LOCAL_DESIGN.md). A view
//!   the caller built replaces it only through `harvest_with_view` and `scan_with_view`, which exist
//!   with the `inject-view` feature alone (the offline replay `cargo xtask replay --baseline-view` and
//!   tests); the CLI and the server never call them.
//!
//! Nothing here fails because a fact could not be read: what is missing becomes a warning line and the
//! pipeline goes on with less. Only a broken precondition (an unknown program id, a fingerprint of another
//! app, a post scan without an uninstall) is an error.
//!
//! # Scan output for the UI (M3-ENGINE-OUT)
//!
//! A scan's warnings are [`ScanWarning`]s: the same lines as before, each with a typed
//! [`WarningKind`](purge_model::WarningKind). Service, task and firewall-rule candidates also carry
//! [`Candidate::display_name`] and [`Candidate::owner_program`]. Both fields are display only and are
//! outside the plan hash (`purge.planhash/0`): the frozen M1b plans keep their hashes.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use purge_guard::canon::{GuardEnv, OtherAppRoot, canon_path};
use purge_guard::deny::DenyList;
use purge_guard::prefix;
use purge_harvest::coproducts;
use purge_harvest::harvest::{
    HarvestOpts, HarvestReport, SharedIndexes, harvest_report_ahead, harvest_report_with, walk_sids,
};
use purge_harvest::refsnap::EarlyWalk;
use purge_harvest::refsnap::HarvestCtx;
use purge_harvest::roots::guard_env;
use purge_identity::kbdata::Kb;
use purge_index::baseline::{Baseline, RecordCounts};
use purge_index::baseline_view::BaselineView;
use purge_index::matcher::AnchorSet;
use purge_index::ownership::{
    CacheKey, DiskTableCache, MemTableCache, OwnershipLimits, TableCache,
};
use purge_index::sysobj::{ProgramRef, SysObjectIndex};
use purge_inventory::arp::Inventory;
use purge_inventory::quiet::{QuietCommand, quiet_command};
use purge_inventory::runner::{ProcessHost, RunError, RunOptions, RunReport, RunRequest};
use purge_inventory::verify_gone::{self, VerifyTarget};
use purge_model::{
    AnchorKind, AnchorRef, BaselineTrust, Candidate, Fingerprint, InstallScope, InstallerKind,
    InventoryDoc, InventoryEntry, OsInfo, ProgramId, RawFlags, ResidueDoc, ScanMode, ScanWarning,
    Target, VerifyGone, View, WritableBy,
};
use purge_plan::decide::{DecideCtx, Limits, M1bDecide, bundle_known, colliding_ids};
use purge_plan::emit::{Built, build};
use purge_scan::catalog::all_scanners;
use purge_scan::framework::{
    AppIdentityView, OtherApp, OtherApps, ScanCtx, ScanExt, ScanLimits, inventory_lists_product,
    product_known_in,
};
use purge_source::filesystem::FileSystemSource;
use purge_source::registry::RegistrySource;
use purge_source::sysobj::MsiTables;
use purge_source::types::SourceError;
use purge_win::env::{EnvMap, expand_with};

pub use purge_harvest::harvest::Sources;

pub mod baseline;

pub use baseline::{
    LocalBuild, LocalCacheSource, PipelineBaseline, SharedLocalCacheSource, local_cache,
    start_local_build,
};

/// Receives one progress line at a time (the CLI writes them to stderr).
pub type Progress<'a> = &'a mut dyn FnMut(&str);

/// Where the time-zone bias of the machine is read from: `ActiveTimeBias` is UTC minus local time, in
/// minutes.
const TIME_ZONE_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation";

/// Prefix of the key name of the synthetic inventory entry [`scan_path`] builds.
pub const PATH_KEY_PREFIX: &str = "purge-path:";

// ---------------------------------------------------------------------------------------------------------
// Errors and settings
// ---------------------------------------------------------------------------------------------------------

/// Why a pipeline step did not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PipelineError {
    /// A precondition does not hold: an unknown program id, a fingerprint of another app, a post scan
    /// without a completed uninstall, a `--path` that is not a usable directory. CLI exit code 2.
    Precondition(String),
    /// Something failed while running. CLI exit code 3.
    Runtime(String),
}

impl fmt::Display for PipelineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PipelineError::Precondition(m) | PipelineError::Runtime(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for PipelineError {}

/// Facts about the engine's own installation that the pipeline needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Settings {
    /// The directory holding the `<Edition>-<build>.<ubr>.tsv.gz` baselines. `None`: no baseline is
    /// looked for.
    pub baseline_dir: Option<PathBuf>,
    /// Purge's own directories (the engine's directory, its data store). The guard never lets anything
    /// remove them. Paths that do not canonicalise are dropped with a warning, because one bad entry
    /// would make the guard deny everything.
    pub purge_dirs: Vec<String>,
    /// The directory of the on-disk MSI table cache, `<ProgramData>\Purge\fp\msitables` (D17). `None`:
    /// the cache is in memory for the run. See [`table_cache`] for when the directory is used.
    pub msi_table_dir: Option<PathBuf>,
    /// The MSI table cache's source when it is not reached by path: the broker's checked
    /// `fp\msitables` (DECISIONS 2026-11-22, "fp checked"). When set, [`table_cache`] takes the cache
    /// from it and never opens [`Settings::msi_table_dir`] by path (which then only names the cache in
    /// the timing line). `None` in the engine.
    pub msi_table_source: Option<SharedTableCacheSource>,
    /// The directory of the local baseline cache, `<ProgramData>\Purge\baseline`
    /// (BASELINE_LOCAL_DESIGN.md §5). `None`: no local baseline is read or built. See
    /// [`baseline::local_cache`] for when the directory is used.
    pub local_baseline_dir: Option<PathBuf>,
    /// The local baseline cache's source when it is not reached by path: the broker's checked
    /// `baseline` directory (DECISIONS 2026-11-22, "baseline checked"). When set, [`local_cache`]
    /// takes the cache from it and never opens [`Settings::local_baseline_dir`] by path (which then
    /// only names the cache in warnings, and still says that a cache is configured). `None` in the
    /// engine.
    pub local_baseline_source: Option<SharedLocalCacheSource>,
    /// Purge's machine data root, `<ProgramData>\Purge` (session index, quarantine). `None`: the
    /// executor's store is not located. Read-only users of the index (the medium engine's
    /// `history.index`) need it; nothing in the pipeline writes here.
    pub data_root: Option<PathBuf>,
    /// The sources describe the machine the baseline directory is on (the live engine): when the
    /// engine is elevated, [`Settings::baseline_dir`] is used only if administrators and the system
    /// alone can write it (design §5 "The shipped directory"). Off for fixtures and replays, whose
    /// file system knows nothing about the directory the engine reads its baselines from.
    pub check_shipped_dir: bool,
    /// The volume every directory a trust decision of an elevated engine rests on must be on: the
    /// shipped baseline directory, the local baseline cache, the MSI table cache (BL-R1 S4, M3
    /// design 3.4). [`VolumeRule::Any`] for fixtures and replays.
    pub volume_rule: VolumeRule,
    /// The background build of the local baseline that this engine process started
    /// ([`baseline::start_local_build`]); `None` when it started none.
    pub local_build: Option<LocalBuild>,
}

/// Where the directories an elevated engine trusts must lie ([`Settings::volume_rule`]).
///
/// The directory rule (`is_admin_only_writable`) compares well-known SIDs, which are the same on
/// every machine: a volume prepared on another machine (a removable or external disk) can carry
/// administrator-only descriptors over content a standard user chose (BL-R1 S4). The volume of the
/// running Windows directory cannot be such a volume.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum VolumeRule {
    /// No volume rule. For fixtures and replays, whose sources are not the machine the directories
    /// are on.
    #[default]
    Any,
    /// The directory must be on the volume of this volume GUID path (`\\?\volume{…}\`), as
    /// `purge_win::secure::volume_of` reads it from the directory itself. The live engine names the
    /// system volume ([`VolumeRule::live`]).
    On(String),
    /// The live engine could not read the system volume: an elevated engine trusts no directory.
    Unreadable,
}

impl VolumeRule {
    /// The rule of the live engine: the system volume (`purge_win::secure::system_volume`), or
    /// [`VolumeRule::Unreadable`] when it cannot be read.
    pub fn live() -> VolumeRule {
        purge_win::secure::system_volume().map_or(VolumeRule::Unreadable, VolumeRule::On)
    }

    /// Whether `dir`, which exists, passes the rule. A directory whose volume cannot be read does
    /// not pass [`VolumeRule::On`].
    pub fn admits(&self, dir: &Path) -> bool {
        match self {
            VolumeRule::Any => true,
            VolumeRule::On(volume) => {
                purge_win::secure::volume_of(dir).is_ok_and(|v| v.eq_ignore_ascii_case(volume))
            }
            VolumeRule::Unreadable => false,
        }
    }
}

/// Whether `dir` passes [`Settings::volume_rule`] for this engine: always when it is not elevated
/// (an unelevated engine's trust decisions do not rest on the directory), otherwise as the rule
/// says.
pub(crate) fn volume_admits(sources: Sources<'_>, settings: &Settings, dir: &Path) -> bool {
    !sources.sys.elevated() || settings.volume_rule.admits(dir)
}

/// Where an engine call gets its MSI table cache when the cache is not a directory opened by path
/// ([`Settings::msi_table_source`]): the broker's, which reads and writes the files relative to the
/// checked handle of its store's `fp\msitables`.
pub trait TableCacheSource: Send + Sync {
    /// The cache of one engine call, or `None` when the source cannot give one now (its directory
    /// failed its check, say): the call then caches in memory.
    fn open(&self) -> Option<Box<dyn TableCache>>;
}

/// A shared [`TableCacheSource`], as [`Settings`] holds it. Two are equal when they are the same
/// source.
#[derive(Clone)]
pub struct SharedTableCacheSource(pub std::sync::Arc<dyn TableCacheSource>);

impl fmt::Debug for SharedTableCacheSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedTableCacheSource")
    }
}

impl PartialEq for SharedTableCacheSource {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::addr_eq(
            std::sync::Arc::as_ptr(&self.0),
            std::sync::Arc::as_ptr(&other.0),
        )
    }
}

impl Eq for SharedTableCacheSource {}

/// Which MSI table cache an engine call uses ([`table_cache`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableCacheKind {
    /// The admin-only directory of [`Settings::msi_table_dir`].
    Disk,
    /// Memory, for this call only.
    Memory,
}

/// The MSI table cache of one engine call (D17, C-OWNERSHIP): the directory of
/// [`Settings::msi_table_dir`] when `DiskTableCache::open` accepts it (only administrators and the
/// system can write it and every ancestor), else an in-memory cache.
///
/// The directory is created only when the process is elevated, and only inside a Purge data root
/// (its grandparent, `<ProgramData>\Purge`) that already exists and is itself admin-only writable: a
/// directory created under a weaker parent would inherit the parent's write grants and could never be
/// trusted. An unelevated run never creates it; it still reads an existing admin-only cache (its writes
/// then fail silently, and the next elevated run fills it).
///
/// Elevated, the data root and the directory must also pass [`Settings::volume_rule`] (BL-R1 S4): a
/// cache on another volume is never created, read or written.
///
/// With [`Settings::msi_table_source`] (the broker), the cache is the source's, or memory when it
/// gives none; nothing here touches the directory by path.
pub fn table_cache(
    sources: Sources<'_>,
    settings: &Settings,
) -> (Box<dyn TableCache>, TableCacheKind) {
    let memory = || -> (Box<dyn TableCache>, TableCacheKind) {
        (Box::new(MemTableCache::new()), TableCacheKind::Memory)
    };
    if let Some(source) = &settings.msi_table_source {
        return match source.0.open() {
            Some(cache) => (cache, TableCacheKind::Disk),
            None => memory(),
        };
    }
    let Some(dir) = settings.msi_table_dir.as_deref() else {
        return memory();
    };
    let admin_only = |p: &Path| {
        p.to_str()
            .is_some_and(|s| sources.fs.is_admin_only_writable(s) == Ok(true))
    };
    let on_volume = |p: &Path| volume_admits(sources, settings, p);
    if sources.sys.elevated()
        && !dir.is_dir()
        && dir
            .parent()
            .and_then(Path::parent)
            .is_some_and(|root| on_volume(root) && admin_only(root))
    {
        // Failing to create it leaves the memory cache; the next run tries again.
        let _ = std::fs::create_dir_all(dir);
    }
    if !on_volume(dir) {
        return memory();
    }
    match DiskTableCache::open(dir, sources.fs) {
        Some(disk) => (Box::new(disk), TableCacheKind::Disk),
        None => memory(),
    }
}

/// A [`TableCache`] that counts its lookups, for the `PURGE_TIMING` line that says which MSI table
/// cache an engine call used and how warm it was ([`CountingCache::timing_line`]). It changes nothing
/// of what the cache holds or answers.
struct CountingCache<'c> {
    inner: &'c dyn TableCache,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl<'c> CountingCache<'c> {
    fn new(inner: &'c dyn TableCache) -> Self {
        Self {
            inner,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// `msi_table_cache disk <dir> hits=N misses=M`, or `msi_table_cache memory hits=N misses=M`.
    fn timing_line(&self, kind: TableCacheKind, settings: &Settings) -> String {
        let place = match (kind, settings.msi_table_dir.as_deref()) {
            (TableCacheKind::Disk, Some(dir)) => format!("disk {}", dir.display()),
            (TableCacheKind::Disk, None) => "disk".to_owned(),
            (TableCacheKind::Memory, _) => "memory".to_owned(),
        };
        format!(
            "msi_table_cache {place} hits={} misses={}",
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed)
        )
    }

    /// Writes [`CountingCache::timing_line`] to stderr when a source meter is installed
    /// (`PURGE_TIMING`), like the other `timing:` lines of the engine.
    fn report(&self, kind: TableCacheKind, settings: &Settings) {
        if purge_source::metered::installed().is_some() {
            eprintln!("timing: {}", self.timing_line(kind, settings));
        }
    }
}

impl TableCache for CountingCache<'_> {
    fn get(&self, key: &CacheKey) -> Option<MsiTables> {
        let found = self.inner.get(key);
        let counter = if found.is_some() {
            &self.hits
        } else {
            &self.misses
        };
        counter.fetch_add(1, Ordering::Relaxed);
        found
    }

    fn put(&self, key: &CacheKey, tables: &MsiTables) {
        self.inner.put(key, tables);
    }
}

/// Measures and reports the duration of one step.
struct Step<'p, 'a> {
    progress: &'p mut Progress<'a>,
    started: Instant,
}

impl<'p, 'a> Step<'p, 'a> {
    fn new(progress: &'p mut Progress<'a>) -> Self {
        Self {
            progress,
            started: Instant::now(),
        }
    }

    fn say(&mut self, line: &str) {
        (self.progress)(line);
    }

    fn done(&mut self, what: &str) {
        let ms = self.started.elapsed().as_millis();
        (self.progress)(&format!("{what} ({ms} ms)"));
        self.started = Instant::now();
    }
}

// ---------------------------------------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------------------------------------

/// The local time zone's offset from UTC in seconds (local minus UTC), from the registry; 0 when it
/// cannot be read. Day-precision `InstallDate` values are local midnights.
pub fn utc_offset_secs(reg: &dyn RegistrySource) -> i64 {
    reg.value(TIME_ZONE_KEY, "ActiveTimeBias")
        .ok()
        .and_then(|d| d.dword())
        // The value is a signed 32-bit number of minutes stored as a DWORD.
        .map(|bias| -i64::from(bias as i32) * 60)
        .unwrap_or(0)
}

/// The full inventory (`purge.inventory/0`) of the machine the sources describe.
pub fn inventory(sources: Sources<'_>) -> Inventory {
    purge_inventory::arp::inventory(
        sources.reg,
        sources.fs,
        sources.sys,
        utc_offset_secs(sources.reg),
    )
}

/// The inventory entry a command-line program id names: a full id (`HKLM|64|Git_is1`), or the bare key
/// name of exactly one entry (compared case-insensitively).
///
/// # Errors
///
/// [`PipelineError::Precondition`] when no entry, or more than one, matches.
pub fn find_entry<'d>(
    inventory: &'d InventoryDoc,
    wanted: &str,
) -> Result<&'d InventoryEntry, PipelineError> {
    let wanted = wanted.trim();
    if let Ok(id) = wanted.parse::<ProgramId>() {
        return inventory.entry(&id).ok_or_else(|| {
            PipelineError::Precondition(format!("no inventory entry has the program id {id}"))
        });
    }
    let hits: Vec<&InventoryEntry> = inventory
        .entries
        .iter()
        .filter(|e| e.program_id.key_name().eq_ignore_ascii_case(wanted))
        .collect();
    match hits.as_slice() {
        [one] => Ok(one),
        [] => Err(PipelineError::Precondition(format!(
            "no inventory entry has the program id or key name {wanted:?}"
        ))),
        many => Err(PipelineError::Precondition(format!(
            "{} inventory entries have the key name {wanted:?}; pass one of their program ids: {}",
            many.len(),
            many.iter()
                .map(|e| e.program_id.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

// ---------------------------------------------------------------------------------------------------------
// Baseline
// ---------------------------------------------------------------------------------------------------------

/// The baseline of exactly this Windows from `dir`, or `None` (with the reason in `warnings`). Never a
/// baseline of another (edition, build, ubr).
pub fn load_baseline(
    dir: Option<&Path>,
    os: &OsInfo,
    warnings: &mut Vec<String>,
) -> Option<Baseline> {
    let dir = dir?;
    if os.edition.is_empty() {
        warnings.push("baseline: the Windows edition is unknown; no baseline is used".into());
        return None;
    }
    match Baseline::try_select(dir, &os.edition, os.build, os.ubr) {
        Ok(Some(b)) => Some(b),
        Ok(None) => {
            warnings.push(format!(
                "baseline: no {} in {}; the scan works values-only",
                Baseline::file_name(&os.edition, os.build, os.ubr),
                dir.display()
            ));
            None
        }
        Err(e) => {
            warnings.push(format!(
                "baseline: {} in {} is unusable ({e}); the scan works values-only",
                Baseline::file_name(&os.edition, os.build, os.ubr),
                dir.display()
            ));
            None
        }
    }
}

fn not_elevated_warning(step: &str) -> String {
    format!(
        "{step}: the engine is not elevated; keys and folders that need administrator rights may be \
         unreadable, so the result may be incomplete"
    )
}

// ---------------------------------------------------------------------------------------------------------
// Harvest
// ---------------------------------------------------------------------------------------------------------

/// A harvest and what the pipeline noticed around it.
#[derive(Debug, Clone)]
pub struct Harvested {
    /// The harvest's own report; its fingerprint is what `harvest -o` writes.
    pub report: HarvestReport,
    /// Warnings of the pipeline itself (inventory, baseline, elevation). The fingerprint's own warnings
    /// are in `report.fingerprint.warnings`.
    pub warnings: Vec<String>,
}

/// Harvests the entry `program_id` names (step 1 of §3.6): inventory, baseline, then
/// `purge_harvest::harvest::harvest_report`. Not being elevated is a warning, also recorded in the
/// fingerprint.
///
/// # Errors
///
/// [`PipelineError::Precondition`] when the program id names no single entry.
pub fn harvest(
    sources: Sources<'_>,
    program_id: &str,
    kb: &Kb,
    settings: &Settings,
    progress: Progress<'_>,
) -> Result<Harvested, PipelineError> {
    harvest_in(sources, program_id, kb, settings, None, progress)
}

/// [`harvest`] with the baseline view `baseline` ([`PipelineBaseline::injected`]) in place of the one
/// the engine would load: the settings' baseline directory and cache are not read. For the offline
/// replay (`cargo xtask replay --baseline-view`) and tests; only with the `inject-view` feature, which
/// neither the CLI nor the RPC server uses.
///
/// # Errors
///
/// As [`harvest`].
#[cfg(any(test, feature = "inject-view"))]
pub fn harvest_with_view(
    sources: Sources<'_>,
    program_id: &str,
    kb: &Kb,
    settings: &Settings,
    baseline: &PipelineBaseline,
    progress: Progress<'_>,
) -> Result<Harvested, PipelineError> {
    harvest_in(sources, program_id, kb, settings, Some(baseline), progress)
}

/// [`harvest`]; `injected`: the view to work with instead of the loaded one.
fn harvest_in(
    sources: Sources<'_>,
    program_id: &str,
    kb: &Kb,
    settings: &Settings,
    injected: Option<&PipelineBaseline>,
    mut progress: Progress<'_>,
) -> Result<Harvested, PipelineError> {
    let mut step = Step::new(&mut progress);
    let mut warnings = Vec::new();
    step.say("harvest: reading the inventory");
    let inv = inventory(sources);
    warnings.extend(inv.warnings.iter().map(|w| format!("inventory: {w}")));
    let entry = find_entry(&inv.doc, program_id)?;
    step.done(&format!(
        "harvest: {} entries; target {} ({})",
        inv.doc.entries.len(),
        entry.program_id,
        entry.display_name
    ));

    let (cache, cache_kind) = table_cache(sources, settings);
    let cache = CountingCache::new(cache.as_ref());
    let opts = HarvestOpts {
        table_cache: Some(&cache),
        shared: None,
    };
    // The walk of the reference snapshot reads the same keys whatever the baseline and the anchors
    // turn out to be: it starts here, beside the baseline load, and the harvest gives it its
    // matcher when it has the anchors (`purge_harvest::refsnap::EarlyWalk`).
    let mut report = std::thread::scope(|threads| {
        let early = EarlyWalk::start(threads, sources.reg, &walk_sids(sources.sys, entry));
        let loaded;
        let baseline = match injected {
            Some(injected) => step_injected(injected, &mut warnings, &mut step),
            None => {
                loaded = baseline_for(sources, settings, &mut warnings, &mut step);
                &loaded
            }
        };
        step.say("harvest: reading roots, Inno log, anchors and the reference snapshot");
        harvest_report_ahead(entry, &inv.doc, sources, &baseline.view, kb, &opts, early)
    });
    cache.report(cache_kind, settings);
    if !sources.sys.elevated() {
        let w = not_elevated_warning("harvest");
        report.fingerprint.warnings.push(w.clone());
        warnings.push(w);
    }
    step.done(&format!(
        "harvest: {} roots, {} exes, {} Inno records, {} reference-snapshot entries",
        report.fingerprint.roots.len(),
        report.fingerprint.exes.len(),
        report.fingerprint.inno.len(),
        report.fingerprint.ref_snapshot.len()
    ));
    Ok(Harvested { report, warnings })
}

/// The result of `engine.hello` for the machine the sources describe (ENGINE_PLAN.md §3.3): the
/// engine's version and policy, the account and its elevation, this Windows, and the baseline view a
/// harvest or a scan started now would work with ([`baseline::load`]: the same directory check, the
/// same cache). Read-only: nothing is built. What lowered the view's trust is in `warnings`.
///
/// Before the stdio server and the broker exist (M3) the CLI verb `hello` is its one transport; the VM
/// rig reads `baseline_trust` from it and refuses a run whose engine does not have the trust the run
/// is for (review BL-R1 M1).
pub fn hello(
    sources: Sources<'_>,
    settings: &Settings,
    warnings: &mut Vec<String>,
) -> purge_rpc::EngineHello {
    let mut silent = |_: &str| {};
    let mut progress: Progress<'_> = &mut silent;
    let mut step = Step::new(&mut progress);
    let baseline = baseline_for(sources, settings, warnings, &mut step);
    let os = sources.sys.os_info().unwrap_or(OsInfo {
        edition: String::new(),
        build: 0,
        ubr: 0,
    });
    purge_rpc::EngineHello {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        elevated: sources.sys.elevated(),
        user_sid: sources.sys.user_sid().unwrap_or_default(),
        shell_sid: None,
        edition: os.edition,
        build: os.build,
        ubr: os.ubr,
        policy_version: purge_policy::band::POLICY_VERSION.to_owned(),
        baseline: baseline.status(settings.local_build.as_ref()),
    }
}

/// The injected view of a step, said in the progress and in the warnings, so a plan made with one
/// never reads as a plan of the engine's own baseline.
fn step_injected<'b>(
    injected: &'b PipelineBaseline,
    warnings: &mut Vec<String>,
    step: &mut Step<'_, '_>,
) -> &'b PipelineBaseline {
    let line = format!(
        "baseline view {} injected by the caller: trust {}",
        injected.view.name(),
        injected.view.trust()
    );
    warnings.push(format!("baseline: {line}"));
    step.done(&line);
    injected
}

/// Loads the baseline view for the Windows the sources describe ([`baseline::load`]), with progress.
/// With an exact shipped baseline the lines are the ones the engine printed before the view.
fn baseline_for(
    sources: Sources<'_>,
    settings: &Settings,
    warnings: &mut Vec<String>,
    step: &mut Step<'_, '_>,
) -> PipelineBaseline {
    if settings.baseline_dir.is_none() {
        return PipelineBaseline::unconfigured();
    }
    let os = match sources.sys.os_info() {
        Ok(os) => os,
        Err(e) => {
            warnings.push(format!(
                "baseline: the Windows edition and build could not be read ({e}); no baseline is used"
            ));
            return PipelineBaseline::unconfigured();
        }
    };
    step.say(&format!("loading the baseline {}", os.baseline_name()));
    let loaded = baseline::load(sources, settings, &os, warnings);
    match loaded.exact_counts() {
        Some(counts) => {
            let timing = purge_source::metered::installed().is_some();
            step.done(&baseline_loaded(&os.baseline_name(), counts, timing));
        }
        None => step.done(&format!(
            "baseline view {} loaded: trust {}",
            loaded.view.name(),
            loaded.view.trust()
        )),
    }
    loaded
}

/// The progress line of a loaded baseline: its record counts only when `PURGE_TIMING` is on, so the
/// line stays what it was without it.
fn baseline_loaded(name: &str, n: RecordCounts, timing: bool) -> String {
    if timing {
        format!(
            "baseline {name} loaded: {} keys, {} values, {} dirs, {} files",
            n.keys, n.values, n.dirs, n.files
        )
    } else {
        format!("baseline {name} loaded")
    }
}

// ---------------------------------------------------------------------------------------------------------
// Route
// ---------------------------------------------------------------------------------------------------------

/// The commands an entry's Uninstall key names, expanded with `env`.
///
/// `command` is the interactive `UninstallString`; `quiet` is the quiet form [`quiet_command`] resolves
/// (`QuietUninstallString`, or the generated form). Either is `None` when the entry does not give a
/// usable command. The engine shows these strings and runs the chosen one verbatim: `uninstall.route`
/// answers with them and `uninstall.run_user` passes the matching [`QuietCommand`] to
/// [`uninstall_with_command`], so the command shown is the command run. A machine-scope command is
/// expanded with the machine environment (never the user's `HKCU\Environment`) before it is shown to
/// the broker's client (review M3-R2 B1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UninstallCommands {
    /// The interactive command, expanded.
    pub command: Option<QuietCommand>,
    /// The quiet command, expanded.
    pub quiet: Option<QuietCommand>,
}

impl UninstallCommands {
    /// The interactive command line, as it would be started.
    pub fn command_line(&self) -> Option<String> {
        self.command.as_ref().map(QuietCommand::to_command_line)
    }

    /// The quiet command line, as it would be started.
    pub fn quiet_command_line(&self) -> Option<String> {
        self.quiet.as_ref().map(QuietCommand::to_command_line)
    }
}

/// Resolves both commands of `entry` and expands `%NAME%` references with `env` (the interactive
/// user's environment, [`purge_win::env::expand_with`]).
pub fn uninstall_commands(
    entry: &InventoryEntry,
    env: &BTreeMap<String, String>,
) -> UninstallCommands {
    let map: EnvMap = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let expanded = |command: QuietCommand| QuietCommand {
        exe: expand_with(&command.exe, &map),
        args: expand_with(&command.args, &map),
        ..command
    };
    let command = entry
        .uninstall_string
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| purge_win::cmdline::split(s).ok())
        .map(|split| QuietCommand {
            exe: split.exe,
            args: split.args,
            generated: false,
            kind: entry.installer_kind,
        })
        .map(expanded);
    let quiet = quiet_command(entry).ok().map(expanded);
    UninstallCommands { command, quiet }
}

/// The directories a running process must be under to count as the program's own (the "close these
/// first" list of `uninstall.prepare`, medium engine and broker alike): its `InstallLocation`, and
/// the directory of each command the entry names, except a Windows host (`msiexec`, `rundll32`,
/// `regsvr32`, `cmd`) and anything in the Windows directory `windows_dir` or below it. An MSI's
/// command is `C:\Windows\System32\msiexec.exe`, and its folder made every System32 process (sihost,
/// svchost, ctfmon...) "still running from the program's folder", a warning "Check again" could
/// never clear (M3 e2e chain, 7-Zip). An empty `windows_dir` leaves only the host rule.
pub fn running_roots(
    entry: &InventoryEntry,
    commands: &UninstallCommands,
    windows_dir: &str,
) -> Vec<String> {
    let windows_dir = windows_dir
        .trim_end_matches(['\\', '/'])
        .to_ascii_lowercase();
    let in_windows = |dir: &str| {
        let dir = dir.trim_end_matches(['\\', '/']).to_ascii_lowercase();
        !windows_dir.is_empty()
            && (dir == windows_dir
                || dir
                    .strip_prefix(windows_dir.as_str())
                    .is_some_and(|rest| rest.starts_with(['\\', '/'])))
    };
    let mut roots: Vec<String> = Vec::new();
    let mut push = |root: String| {
        let root = root.trim_end_matches(['\\', '/']).to_owned();
        if !root.is_empty() && !roots.iter().any(|r| r.eq_ignore_ascii_case(&root)) {
            roots.push(root);
        }
    };
    if let Some(location) = entry.install_location.as_deref() {
        if !in_windows(location) {
            push(location.to_owned());
        }
    }
    for command in [commands.command.as_ref(), commands.quiet.as_ref()]
        .into_iter()
        .flatten()
    {
        if HOST_EXECUTABLES.contains(&file_name_lower(&command.exe).as_str()) {
            continue;
        }
        if let Some(parent) = Path::new(&command.exe).parent() {
            let parent = parent.to_string_lossy().into_owned();
            if !in_windows(&parent) {
                push(parent);
            }
        }
    }
    roots
}

/// The Windows directory of this PC (`%SystemRoot%`, else `%windir%`), for [`running_roots`].
pub fn windows_dir() -> String {
    std::env::var("SystemRoot")
        .or_else(|_| std::env::var("windir"))
        .unwrap_or_default()
}

/// Where the uninstaller of `entry` runs (M3 design 3.2, ENGINE_PLAN §4.4): the broker for a
/// machine-scope entry whose uninstaller path has admin-only ancestors, medium otherwise.
///
/// The medium engine and the broker both call this with their own inventory: the route is never taken
/// from the other side. A per-user entry (an `HKU` key or a user-writable Uninstall key) is always
/// medium, whatever its path; that is the rule that keeps Purge from being an elevation vehicle for a
/// command a standard user can replace. A machine-scope entry is broker only when **every** command the
/// entry names (the interactive and the quiet one) is writable by administrators alone; a path that
/// cannot be read or does not exist is not provably admin-only and therefore stays medium. "Writable by
/// administrators alone" is the run rule (`is_admin_only_executable`): the file and its ancestors, and
/// also no non-administrator may add a file to its directory, where the loader looks first for the DLLs
/// the program imports. A vendor folder under `C:\ProgramData` inherits that right for BUILTIN\Users,
/// so an uninstaller there is medium-route (review M3-R2 H3).
///
/// `env` is the interactive user's environment and `machine_env` the machine's. The command is expanded
/// with both; any difference between the two strings would let a value in `HKCU\Environment` change the
/// command after it was shown, so it makes the route medium. A `%NAME%` neither map defines is medium
/// for the same reason (review M3-R2 B1). A known host executable (`cmd`, `rundll32`, `regsvr32`,
/// `msiexec`) is judged on the script, DLL or package it is told to load as well; a load path that is
/// user-writable, cannot be found or cannot be worked out makes the route medium (review M3-R2 M2).
/// Narrower still:
/// - an interpreter or script host ([`INTERPRETERS`]: `powershell`, `python`, `node`, `java`,
///   `wscript`, `mshta`, `wsl`, ...) is always medium, whatever it is told to run: it also loads code
///   from per-user places the command line does not name (the PowerShell profile and `PSModulePath`,
///   Python's user site-packages, ...), which no argument or environment cleaning shuts off.
/// - `cmd` is medium unless `/d` comes before `/c` (`/k`, `/r`), since without it cmd runs the
///   `AutoRun` value in `HKCU\Software\Microsoft\Command Processor`; it is also medium when the program
///   it runs is itself a host or has no extension, the command text can run a second program (`&`,
///   `|`, ...), or cmd's quote handling could cut the program somewhere else (`/s`, more than two
///   quotes, a quoted program with `(`, `)`, `@` and the like in it).
/// - `msiexec` with a ProductCode and no package path stays admin-only (it runs the cached package).
///
/// Every absolute path in the arguments that exists and fails the run rule makes the route medium too;
/// the value of a `NAME=value` token and each `;`-separated part are judged as well
/// (`TRANSFORMS=a.mst;b.mst`).
pub fn route(
    entry: &InventoryEntry,
    fs: &dyn FileSystemSource,
    env: &BTreeMap<String, String>,
    machine_env: &BTreeMap<String, String>,
) -> purge_rpc::methods::Route {
    let per_user = entry.hive_sid.is_some() || entry.writable_by == WritableBy::User;
    if per_user {
        return purge_rpc::methods::Route::Medium;
    }
    let machine_commands = uninstall_commands(entry, machine_env);
    let user_commands = uninstall_commands(entry, env);
    if machine_commands != user_commands {
        return purge_rpc::methods::Route::Medium;
    }
    let commands = &machine_commands;
    let mut exes: Vec<&str> = Vec::new();
    for command in [commands.command.as_ref(), commands.quiet.as_ref()]
        .into_iter()
        .flatten()
    {
        if has_undefined_reference(&command.exe, &[machine_env, env])
            || has_undefined_reference(&command.args, &[machine_env, env])
        {
            return purge_rpc::methods::Route::Medium;
        }
        if !exes.iter().any(|e| e.eq_ignore_ascii_case(&command.exe)) {
            exes.push(&command.exe);
        }
    }
    if exes.is_empty() {
        // Nothing to run, and nothing that proves the path admin-only.
        return purge_rpc::methods::Route::Medium;
    }
    let exes_admin_only = exes
        .iter()
        .all(|exe| fs.is_admin_only_executable(exe) == Ok(true));
    let loads_admin_only = [commands.command.as_ref(), commands.quiet.as_ref()]
        .into_iter()
        .flatten()
        .all(|command| command_loads_admin_only(command, fs));
    if exes_admin_only && loads_admin_only {
        purge_rpc::methods::Route::Broker
    } else {
        purge_rpc::methods::Route::Medium
    }
}

/// Whether `s` holds a `%NAME%` reference that no map in `maps` defines.
fn has_undefined_reference(s: &str, maps: &[&BTreeMap<String, String>]) -> bool {
    let mut rest = s;
    while let Some(open) = rest.find('%') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('%') else {
            break;
        };
        let name = &after[..close];
        if !name.is_empty()
            && !maps
                .iter()
                .any(|map| map.contains_key(&name.to_ascii_uppercase()))
        {
            return true;
        }
        rest = &after[close + 1..];
    }
    false
}

/// The argument string split into tokens; a quoted part stays one token, quotes removed.
fn arg_tokens(args: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    for c in args.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !token.is_empty() {
                    out.push(std::mem::take(&mut token));
                }
            }
            c => token.push(c),
        }
    }
    if !token.is_empty() {
        out.push(token);
    }
    out
}

/// Whether `path` starts at a drive or a UNC share.
fn is_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    (bytes.len() >= 2 && bytes[1] == b':') || path.starts_with(r"\\") || path.starts_with("//")
}

/// The hosts whose load file is worked out from the arguments and judged (`host_load_path`): the
/// route may still be broker for them. Every other program that runs code it is told to load is in
/// [`INTERPRETERS`] and always medium.
const HOST_EXECUTABLES: &[&str] = &["cmd.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe"];

/// Interpreters and script hosts (file name stems; `python` and `pythonw` with or without a version,
/// `python3.12.exe`, are matched in [`is_interpreter`]). A command they run, or whose arguments name
/// one (a launcher such as `conhost --headless powershell ...`, `cmd /c`), is always medium: each
/// loads code from places the command line does not name and a standard user can write, so judging
/// the script is not enough (review M3-R2 M2; coordinator ruling after the fourth Fable review; M7):
/// - `powershell`/`pwsh`/`powershell_ise`: the user's profile (`Documents\WindowsPowerShell\profile.ps1`, found through
///   the known folder in HKCU) unless `-NoProfile`, and even then modules auto-loaded from
///   `Documents\WindowsPowerShell\Modules` and from `PSModulePath` in `HKCU\Environment`, which
///   PowerShell reads from the registry itself; adding `-NoProfile` in the broker would run a command
///   other than the one shown (B1; H1, H2).
/// - `python`/`py`: user site-packages (`%APPDATA%\Python`) and `.pth` files; `node`, `perl`, `ruby`,
///   `php`: per-user module and config paths; `java`/`javaw`: a jar manifest's `Class-Path` and the
///   per-user JVM configuration load further code; `dotnet`: per-user NuGet and runtime config;
///   `wsl`, `bash`, `sh`: a per-user Linux environment.
/// - `wscript`, `cscript`, `mshta`, `hh`, `msxsl`: script engines; `forfiles`: runs any command;
///   `msbuild`, `installutil`, `regasm`, `regsvcs`, `cmstp`: run code from a project, assembly or
///   profile; `sdbinst`: installs a compatibility database that changes how later programs start.
///
/// Not modelled interpreters are plain executables to the route; this list is the place to add one.
const INTERPRETERS: &[&str] = &[
    "powershell",
    "powershell_ise",
    "pwsh",
    "dotnet",
    "py",
    "pyw",
    "node",
    "java",
    "javaw",
    "perl",
    "ruby",
    "php",
    "wsl",
    "bash",
    "sh",
    "forfiles",
    "hh",
    "mshta",
    "wscript",
    "cscript",
    "msbuild",
    "installutil",
    "regasm",
    "regsvcs",
    "cmstp",
    "msxsl",
    "sdbinst",
];

/// Whether `program` (with or without a directory, with or without `.exe`) is in [`INTERPRETERS`] or
/// a versioned `python` name.
fn is_interpreter(program: &str) -> bool {
    let name = file_name_lower(program);
    let stem = name.strip_suffix(".exe").unwrap_or(&name);
    // `python`, `pythonw`, `python3`, `python3.12`, ...; not Python's own installer
    // (`python-3.12.0-amd64.exe`), which Package Cache keeps admin-only.
    let python = ["pythonw", "python"].iter().any(|prefix| {
        stem.strip_prefix(prefix)
            .is_some_and(|version| version.chars().all(|c| c.is_ascii_digit() || c == '.'))
    });
    python || INTERPRETERS.contains(&stem)
}

/// The lowercase file name of `exe`.
fn file_name_lower(exe: &str) -> String {
    // Windows drops trailing dots and spaces from a file name: `powershell.exe.` is `powershell.exe`.
    exe.rsplit(['\\', '/'])
        .next()
        .unwrap_or(exe)
        .trim_end_matches(['.', ' '])
        .to_ascii_lowercase()
}

/// Whether `exe` is a known host executable (its file name, with the `.exe`).
fn is_host_executable(exe: &str) -> bool {
    HOST_EXECUTABLES.contains(&file_name_lower(exe).as_str())
}

/// Whether `program`, as `cmd.exe` would be told to run it, names a known host or an interpreter: with
/// or without the `.exe`, with or without a directory.
fn names_a_host(program: &str) -> bool {
    let name = file_name_lower(program);
    is_interpreter(program)
        || HOST_EXECUTABLES
            .iter()
            .any(|host| name == *host || host.strip_suffix(".exe") == Some(name.as_str()))
}

/// The path a known host is told to load. `None` means it cannot be worked out from the arguments, or
/// the host is one whose load cannot be judged from a path at all.
fn host_load_path(exe: &str, args: &str, tokens: &[&str]) -> Option<String> {
    let first_operand = || {
        tokens
            .iter()
            .find(|t| !t.starts_with('/') && !t.starts_with('-'))
            .map(|t| (*t).to_owned())
    };
    match file_name_lower(exe).as_str() {
        "cmd.exe" => cmd_program(args),
        "rundll32.exe" => rundll32_dll(args),
        "regsvr32.exe" => first_operand(),
        "msiexec.exe" => tokens
            .iter()
            .find(|t| t.to_ascii_lowercase().ends_with(".msi"))
            .map(|t| (*t).to_owned())
            .or_else(|| first_operand_filtered(tokens)),
        _ => None,
    }
}

/// The program `cmd.exe` is told to run with `/c` (`/k`, `/r`), or `None` when the line is not provably
/// limited to that program (review M3-R2 M2, M1 M2):
///
/// - Without `/d` before `/c`, cmd first runs the `AutoRun` value of
///   `HKCU\Software\Microsoft\Command Processor`, which a standard user writes. Only the documented
///   switches may come before `/c`; anything after it (a `/d` included) is command text.
/// - A program that is itself a host (`cmd /c powershell ...`, `cmd /c msiexec ...`) is not followed:
///   its own load is not judged here.
/// - Command operators (`&` `|` `<` `>` `^`) or `!` (delayed expansion) anywhere in the command text can
///   run a second program.
/// - cmd's own quote handling (`cmd /?`) keeps the quotes of the command text only when there is no
///   `/s`, exactly two quotes, no `&<>()@^|` between them and the quoted string names an executable;
///   otherwise it strips the first quote and the *last* one, so `"C:\ProgramData\My Vendor\u.cmd" "/x"`
///   runs `C:\ProgramData\My`. The line is followed only when that cannot change the program: no `/s`,
///   and either no quote at all or exactly two that enclose the program at the start of the text, with
///   none of those characters in it (review M3-R2 M3, read from the raw line as [`rundll32_dll`] does).
/// - The program must carry an extension: without one cmd tries each `PATHEXT` extension in turn, and
///   the file it finds is not the one judged (M4).
/// - A program holding a cmd delimiter (`,` `;` `=`) or a `/` is not split here the way cmd splits it.
fn cmd_program(args: &str) -> Option<String> {
    let mut autorun_off = false;
    let mut rest = args;
    loop {
        rest = rest.trim_start();
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let (token, after) = rest.split_at(end);
        if token.contains('"') {
            return None;
        }
        match token.to_ascii_lowercase().as_str() {
            "/c" | "/k" | "/r" => return autorun_off.then(|| cmd_text_program(after)).flatten(),
            "/d" => autorun_off = true,
            "/a" | "/u" | "/q" | "/x" | "/y" => {}
            s if ["/e:", "/f:", "/v:", "/t:"]
                .iter()
                .any(|prefix| s.starts_with(prefix)) => {}
            // `/s` (cmd then always strips the first and the last quote, M3), and anything cmd does
            // not document.
            _ => return None,
        }
        rest = after;
    }
}

/// The program the command text after `/c` (`/k`, `/r`) runs, under the rules of [`cmd_program`].
fn cmd_text_program(text: &str) -> Option<String> {
    const OPERATORS: [char; 6] = ['&', '|', '<', '>', '^', '!'];
    // The characters `cmd /?` names for its quote rule, besides the operators.
    const QUOTE_SPECIALS: [char; 8] = ['&', '<', '>', '(', ')', '@', '^', '|'];
    let text = text.trim_start();
    if text.contains(OPERATORS) {
        return None;
    }
    let (program, after) = match text.matches('"').count() {
        0 => text.split_at(text.find(char::is_whitespace).unwrap_or(text.len())),
        2 => {
            let inner = text.strip_prefix('"')?;
            let close = inner.find('"')?;
            (&inner[..close], &inner[close + 1..])
        }
        _ => return None,
    };
    let name = program.rsplit('\\').next().unwrap_or(program);
    let has_extension = name
        .rsplit_once('.')
        .is_some_and(|(stem, ext)| !stem.is_empty() && !ext.is_empty());
    if program.is_empty()
        || (!after.is_empty() && !after.starts_with(char::is_whitespace))
        || program.contains([',', ';', '=', '/'])
        || program.contains(QUOTE_SPECIALS)
        || !has_extension
        || names_a_host(program)
    {
        return None;
    }
    Some(program.to_owned())
}

/// The DLL `rundll32` is told to load, read from the raw argument string so a comma inside a quoted
/// path stays part of the path: a quoted first argument is the path up to its closing quote, an
/// unquoted one ends at the first comma or space. A path whose file name has no extension is not
/// worked out (the loader would add `.dll` to it).
fn rundll32_dll(args: &str) -> Option<String> {
    let args = args.trim_start();
    let dll = if let Some(quoted) = args.strip_prefix('"') {
        &quoted[..quoted.find('"')?]
    } else {
        args.split([',', ' ', '\t']).next()?
    };
    let name = dll.rsplit(['\\', '/']).next().unwrap_or(dll);
    (name.contains('.') && !dll.is_empty()).then(|| dll.to_owned())
}

/// The first operand of `msiexec` that looks like a path, so `/x C:\pkg.msi` is judged even without
/// the extension. `msiexec /x {GUID}` has no such operand and is accepted.
fn first_operand_filtered(tokens: &[&str]) -> Option<String> {
    tokens
        .iter()
        .find(|t| is_absolute_path(t))
        .map(|t| (*t).to_owned())
}

/// Whether the file `command` is told to load, if any, is writable by administrators alone. A known
/// host whose load path cannot be found or worked out is not provably safe.
fn command_loads_admin_only(command: &QuietCommand, fs: &dyn FileSystemSource) -> bool {
    let tokens = arg_tokens(&command.args);
    let tokens: Vec<&str> = tokens.iter().map(String::as_str).collect();
    // Every path in the arguments must be one a standard user cannot supply (`argument_path_admin_only`).
    // Each token is checked whole and in parts (`path_parts`), so a split can only add a check, never
    // replace one.
    for token in &tokens {
        for path in path_parts(token) {
            if !argument_path_admin_only(path, fs) {
                return false;
            }
        }
    }
    // A launcher can start a host or an interpreter named in its arguments (`conhost --headless
    // powershell ...`, `rundll32 shell32.dll,ShellExec_RunDLL powershell ...`, `cmd /c ...`), so any
    // argument that names one makes the command medium, whatever the program is (review M3-R2 M7).
    // An 8.3 short name (`POWERS~1.EXE`) hides what the file is from the name checks, so one in the
    // program's or any argument part's file name makes the command medium too.
    if is_interpreter(&command.exe)
        || is_short_name(&command.exe)
        || tokens
            .iter()
            .any(|token| token_names_a_host(token) || token_has_a_short_name(token))
    {
        return false;
    }
    if !is_host_executable(&command.exe) {
        return true;
    }
    let Some(load) = host_load_path(&command.exe, &command.args, &tokens) else {
        // A host that names no script, DLL or package: only `msiexec` with a ProductCode loads no
        // client-chosen file (it runs the cached package). Everything else is undetermined: `cmd`
        // without `/d` or running another host, an interpreter or more than one
        // program, and a load path that is missing from the arguments (review M3-R2 M2).
        return file_name_lower(&command.exe) == "msiexec.exe";
    };
    is_absolute_path(&load) && fs.is_admin_only_executable(&load) == Ok(true)
}

/// The parts of an argument token that may name a program: each part [`path_parts`] gives (the
/// token, the value after `=`, the `;` parts), each `,`-separated part of those (`dll,Entry`), and the
/// text after each `:` of those that is not a drive letter's (`/RUN:powershell`; `C:\x` stays whole).
fn program_parts(token: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = Vec::new();
    let mut add = |part| {
        if !parts.contains(&part) {
            parts.push(part);
        }
    };
    for part in path_parts(token)
        .into_iter()
        .flat_map(|part| part.split(','))
    {
        add(part);
        let bytes = part.as_bytes();
        for (at, _) in part.match_indices(':') {
            // `X:` at the start of the part or right after another `:` (`/RUN:C:\x`) is a drive.
            let drive_colon = at >= 1
                && bytes[at - 1].is_ascii_alphabetic()
                && (at == 1 || bytes[at - 2] == b':');
            if !drive_colon {
                add(&part[at + 1..]);
            }
        }
    }
    parts
}

/// Whether an argument token names a host or an interpreter ([`names_a_host`]) in one of its
/// [`program_parts`]. A part counts only when its whole file name is a host's (`powershell`,
/// `C:\x\node.exe`), not when it merely contains one (`--uninstall-node-modules`); a switch (`-x`, or a
/// `/x` with no further separator) is not a file name. Review M3-R2 M7.
fn token_names_a_host(token: &str) -> bool {
    program_parts(token).into_iter().any(|part| {
        let switch =
            part.starts_with('-') || (part.starts_with('/') && !part[1..].contains(['/', '\\']));
        !part.is_empty() && !switch && names_a_host(part)
    })
}

/// Whether the file name of `path` looks like an 8.3 short name: a `~` followed by a digit.
fn is_short_name(path: &str) -> bool {
    file_name_lower(path)
        .as_bytes()
        .windows(2)
        .any(|w| w[0] == b'~' && w[1].is_ascii_digit())
}

/// Whether one of the [`program_parts`] of an argument token has an 8.3 short file name.
fn token_has_a_short_name(token: &str) -> bool {
    program_parts(token).into_iter().any(is_short_name)
}

/// Whether one argument part, if it is a path, is one a standard user cannot supply (review M3-R2 M5).
///
/// - A fully qualified path (`X:\...`, `X:/...`, `\\server\...`, `//server/...`; a remote one never
///   passes, M6) that exists must pass the run rule (`is_admin_only_executable`). One that does not exist is judged by its nearest existing ancestor,
///   which must be an admin-only directory (`is_admin_only_writable`, whose leaf mask also refuses
///   "add file"): otherwise a user could create the file while the consent dialog is open (a
///   `/LOADINF=` the uninstaller then reads), or plant a link where an elevated log is written. Any
///   other error is not provably safe.
/// - A drive-relative part (`C:foo`, `x:1`) keeps the earlier rule: only one that exists and
///   fails the run rule counts, so switches and values with a colon in second place are not judged.
/// - Anything else (`/S`, `-key:value`, `http://...`, a GUID, a relative name) is not a path here.
fn argument_path_admin_only(part: &str, fs: &dyn FileSystemSource) -> bool {
    let bytes = part.as_bytes();
    let fully_qualified = (bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/'))
        || part.starts_with(r"\\")
        || part.starts_with("//");
    if !fully_qualified {
        return !(is_absolute_path(part) && fs.is_admin_only_executable(part) == Ok(false));
    }
    match fs.is_admin_only_executable(part) {
        Ok(admin_only) => admin_only,
        Err(SourceError::NotFound) => nearest_existing_dir_admin_only(part, fs),
        Err(_) => false,
    }
}

/// Whether the nearest existing ancestor of the missing `path` is an admin-only directory.
fn nearest_existing_dir_admin_only(path: &str, fs: &dyn FileSystemSource) -> bool {
    let mut dir = path;
    loop {
        let trimmed = dir.trim_end_matches(['\\', '/']);
        let Some(cut) = trimmed.rfind(['\\', '/']) else {
            return false;
        };
        // Keep the separator of a drive root (`C:\`); each step is strictly shorter.
        let parent = if cut == 2 && trimmed.as_bytes()[1] == b':' {
            &trimmed[..=cut]
        } else {
            &trimmed[..cut]
        };
        if parent.is_empty() {
            return false;
        }
        match fs.is_admin_only_writable(parent) {
            Ok(admin_only) => return admin_only,
            Err(SourceError::NotFound) => dir = parent,
            Err(_) => return false,
        }
    }
}

/// The parts of an argument token that may name a file: the token, the value of a `NAME=value` token
/// (`TRANSFORMS=...`, `/LOG=...`), each `;`-separated part of either (`a.mst;b.mst`), and each of those
/// cut at its first comma (`dll,Entry`). Review M3-R2 L1, L3.
fn path_parts(token: &str) -> Vec<&str> {
    let value = token.split_once('=').map(|(_, value)| value);
    let mut parts = Vec::new();
    for whole in std::iter::once(token).chain(value) {
        for part in std::iter::once(whole).chain(whole.split(';')) {
            parts.push(part);
            if let Some((before_comma, _)) = part.split_once(',') {
                parts.push(before_comma);
            }
        }
    }
    parts
}

// ---------------------------------------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------------------------------------

/// One uninstall run and what it added to the fingerprint.
#[derive(Debug, Clone)]
pub struct Uninstalled {
    /// The runner's report; `report.doc` is what `uninstall -o` writes.
    pub report: RunReport,
    /// Warnings of the pipeline and the runner.
    pub warnings: Vec<String>,
}

impl Uninstalled {
    /// Whether the run failed, was cancelled or timed out (CLI exit code 4).
    pub fn failed(&self) -> bool {
        !self.report.doc.outcome.is_success()
    }
}

/// Runs the quiet uninstaller of `program_id` (steps 2 and 3 of §3.6) through `host`.
///
/// With a fingerprint, the run uses its main exes (verify-gone) and roots (processes to report), and the
/// fingerprint is updated in place: the uninstall window `t_start`/`t_end`, the verify-gone result and the
/// co-removed products, picked from the co-product candidates computed from the fingerprint and the
/// pre-run inventory.
///
/// # Errors
///
/// [`PipelineError::Precondition`] when the program id names no single entry, the fingerprint belongs to
/// another app, or the entry has no usable quiet uninstall command (nothing is run then).
pub fn uninstall(
    sources: Sources<'_>,
    host: &mut dyn ProcessHost,
    program_id: &str,
    fp: Option<&mut Fingerprint>,
    options: &RunOptions,
    progress: Progress<'_>,
) -> Result<Uninstalled, PipelineError> {
    uninstall_in(sources, host, program_id, fp, options, None, progress)
}

/// [`uninstall`], but runs `command` instead of resolving the entry's quiet command.
///
/// The command is passed exactly as it came from [`uninstall_commands`], so the engine's
/// `uninstall.run_user` runs the string `uninstall.route` showed (the quiet or the interactive one).
pub fn uninstall_with_command(
    sources: Sources<'_>,
    host: &mut dyn ProcessHost,
    program_id: &str,
    fp: Option<&mut Fingerprint>,
    options: &RunOptions,
    command: &QuietCommand,
    progress: Progress<'_>,
) -> Result<Uninstalled, PipelineError> {
    uninstall_in(
        sources,
        host,
        program_id,
        fp,
        options,
        Some(command),
        progress,
    )
}

/// [`uninstall`]; `command`: the exact command to run instead of the entry's quiet one.
fn uninstall_in(
    sources: Sources<'_>,
    host: &mut dyn ProcessHost,
    program_id: &str,
    fp: Option<&mut Fingerprint>,
    options: &RunOptions,
    command: Option<&QuietCommand>,
    mut progress: Progress<'_>,
) -> Result<Uninstalled, PipelineError> {
    let mut step = Step::new(&mut progress);
    let mut warnings = Vec::new();
    step.say("uninstall: reading the inventory");
    let before = inventory(sources);
    warnings.extend(before.warnings.iter().map(|w| format!("inventory: {w}")));
    let entry = find_entry(&before.doc, program_id)?;
    if let Some(fp) = fp.as_deref() {
        if fp.app.program_id != entry.program_id {
            return Err(PipelineError::Precondition(format!(
                "the fingerprint is of {} ({}), not of {}",
                fp.app.program_id, fp.app.display_name, entry.program_id
            )));
        }
    } else {
        warnings.push(
            "uninstall: no fingerprint (--fp); verify-gone checks only the ARP key and MSI, and no \
             co-removed products are recorded"
                .into(),
        );
    }

    let main_exes: Vec<String> = fp
        .as_deref()
        .map(|fp| fp.main_exes().map(|e| e.path.clone()).collect())
        .unwrap_or_default();
    let roots: Vec<String> = fp
        .as_deref()
        .map(|fp| fp.roots.iter().map(|r| r.path.clone()).collect())
        .unwrap_or_default();
    // The candidates' harvests share one ownership index and one system-object index.
    let shared = SharedIndexes::new(sources, &before.doc, None);
    let co_candidates = fp
        .as_deref()
        .map(|fp| {
            let anchors = AnchorSet::from_fingerprint(fp);
            coproducts::candidates(&HarvestCtx {
                reg: sources.reg,
                fs: sources.fs,
                sys: sources.sys,
                anchors: &anchors,
                roots: &fp.roots,
                inno: &fp.inno,
                baseline: BaselineView::empty(),
                inventory: &before.doc.entries,
                target: entry,
                cutoff: None,
                shared: Some(&shared),
            })
        })
        .unwrap_or_default();
    step.done(&format!(
        "uninstall: target {} ({}), {} co-product candidate(s)",
        entry.program_id,
        entry.display_name,
        co_candidates.len()
    ));

    step.say("uninstall: running the quiet uninstaller and waiting for it");
    let request = RunRequest {
        entry,
        main_exes: &main_exes,
        roots: &roots,
        before: Some(&before.doc.entries),
        command,
    };
    let report = purge_inventory::runner::run_uninstall(
        host,
        sources.reg,
        sources.fs,
        sources.sys,
        &request,
        options,
    )
    .map_err(|e| match e {
        RunError::NoQuietCommand(q) => PipelineError::Precondition(format!(
            "{} has no usable quiet uninstall command ({q}); nothing was run",
            entry.display_name
        )),
    })?;
    warnings.extend(report.warnings.iter().map(|w| format!("uninstall: {w}")));
    let doc = &report.doc;
    step.done(&format!(
        "uninstall: outcome {:?}, exit code {}, verify-gone {}",
        doc.outcome,
        doc.exit_code
            .map_or_else(|| "none".to_owned(), |c| c.to_string()),
        if doc.verify_gone.is_passed() {
            "passed"
        } else {
            "failed"
        }
    ));
    if !doc.verify_gone.is_passed() {
        warnings.push(format!(
            "uninstall: verify-gone failed (ARP key gone: {}, MSI unknown in all contexts: {}, main exes \
             gone: {}); a scan of this run applies the forced-mode rules",
            doc.verify_gone.arp_gone,
            doc.verify_gone.msi_unknown_all_ctx,
            doc.verify_gone.main_exes_gone
        ));
    }

    if let Some(fp) = fp {
        fp.window.t_start = Some(doc.t_start);
        fp.window.t_end = Some(doc.t_end);
        fp.verify_gone = Some(doc.verify_gone);
        fp.co_removed = coproducts::co_removed(&co_candidates, &doc.co_removed);
        for gone in &doc.co_removed {
            if !fp.co_removed.iter().any(|c| &c.app.program_id == gone) {
                warnings.push(format!(
                    "uninstall: {gone} disappeared during the run but was not a co-product candidate; \
                     it is not recorded as co-removed"
                ));
            }
        }
        fp.warnings
            .extend(report.warnings.iter().map(|w| format!("uninstall: {w}")));
    }
    Ok(Uninstalled { report, warnings })
}

// ---------------------------------------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------------------------------------

/// The result of a scan: the raw scanner output and the emitted plan.
#[derive(Debug, Clone)]
pub struct Scanned {
    /// Every candidate the scanners emitted, undecided, in catalog order.
    pub candidates: Vec<Candidate>,
    /// The plan (`purge.plan/0`) and its sidecar (`purge.scan/0`).
    pub built: Built,
    /// The number of candidates each scanner emitted, in catalog order.
    pub per_scanner: Vec<(&'static str, usize)>,
    /// The residue (`purge.residue/1`): what the baseline could not answer, for the advisory model
    /// (BASELINE_LOCAL_DESIGN.md §7).
    pub residue: ResidueDoc,
    /// Warnings of the pipeline, each with its typed kind (M3-ENGINE-OUT). The text is the line the
    /// CLI prints.
    pub warnings: Vec<ScanWarning>,
    /// The trust of the baseline view's absence answers, as the policy used it
    /// ([`DecideCtx::baseline_trust`](purge_plan::decide::DecideCtx)). The broker reports it as
    /// `leftovers.scan`'s `baseline_trust`.
    pub baseline_trust: BaselineTrust,
}

/// The plan's default app id: the ARP key name, lowercased.
pub fn default_app_id(fp: &Fingerprint) -> String {
    fp.app.program_id.key_name().to_lowercase()
}

/// Scans the machine for the leftovers of the fingerprint's app and emits the plan (steps 4-7 of §3.6).
/// `app_id` is the plan's `app` field; `None` gives [`default_app_id`].
///
/// # Errors
///
/// [`PipelineError::Precondition`] for a `post` scan whose fingerprint holds no completed uninstall
/// window.
pub fn scan(
    sources: Sources<'_>,
    fp: &Fingerprint,
    mode: ScanMode,
    app_id: Option<&str>,
    settings: &Settings,
    progress: Progress<'_>,
) -> Result<Scanned, PipelineError> {
    scan_in(sources, fp, mode, app_id, settings, None, progress)
}

/// [`scan`] with the baseline view `baseline` ([`PipelineBaseline::injected`]) in place of the one the
/// engine would load; see [`harvest_with_view`]. Only with the `inject-view` feature.
///
/// # Errors
///
/// As [`scan`].
#[cfg(any(test, feature = "inject-view"))]
pub fn scan_with_view(
    sources: Sources<'_>,
    fp: &Fingerprint,
    mode: ScanMode,
    app_id: Option<&str>,
    settings: &Settings,
    baseline: &PipelineBaseline,
    progress: Progress<'_>,
) -> Result<Scanned, PipelineError> {
    scan_in(
        sources,
        fp,
        mode,
        app_id,
        settings,
        Some(baseline),
        progress,
    )
}

/// [`scan`]; `injected`: the view to work with instead of the loaded one.
fn scan_in(
    sources: Sources<'_>,
    fp: &Fingerprint,
    mode: ScanMode,
    app_id: Option<&str>,
    settings: &Settings,
    injected: Option<&PipelineBaseline>,
    progress: Progress<'_>,
) -> Result<Scanned, PipelineError> {
    let mut warnings = Vec::new();
    let verify = match mode {
        ScanMode::Post => {
            if fp.window.t_start.is_none() || fp.window.t_end.is_none() {
                return Err(PipelineError::Precondition(
                    "--mode post needs a fingerprint with a completed uninstall window: run \
                     `purge-engine uninstall <program_id> --quiet --fp <fp.json>` first, or scan with \
                     --mode external or forced"
                        .into(),
                ));
            }
            fp.verify_gone.unwrap_or_else(|| {
                warnings.push(
                    "scan: the fingerprint has an uninstall window but no verify-gone result"
                        .into(),
                );
                VerifyGone::new(false, false, false)
            })
        }
        ScanMode::External | ScanMode::Forced => {
            let main_exes: Vec<String> = fp.main_exes().map(|e| e.path.clone()).collect();
            verify_gone::check(
                sources.reg,
                sources.fs,
                sources.sys,
                &VerifyTarget {
                    arp_key: fp.app.program_id.key_path(),
                    product_code: None,
                    main_exes,
                },
            )
            .result
        }
    };
    if mode != ScanMode::Forced && !verify.is_passed() {
        warnings.push(format!(
            "scan: verify-gone failed (ARP key gone: {}, MSI unknown in all contexts: {}, main exes gone: \
             {}); forced-mode rules apply: nothing is Safe or preselected",
            verify.arp_gone, verify.msi_unknown_all_ctx, verify.main_exes_gone
        ));
    }
    let app_id = app_id.map_or_else(|| default_app_id(fp), str::to_owned);
    run_scan(
        sources,
        fp,
        mode,
        Some(verify),
        &app_id,
        settings,
        injected,
        warnings,
        progress,
    )
}

/// Scans a portable app's directory in `forced` mode (`scan --path`; minimal M1a implementation, see the
/// module documentation). `app_id` defaults to the directory's name, lowercased.
///
/// # Errors
///
/// [`PipelineError::Precondition`] when the path is not an existing directory, does not canonicalise, or
/// is refused as a root (a system location, another installed app's directory, …).
pub fn scan_path(
    sources: Sources<'_>,
    dir: &str,
    app_id: Option<&str>,
    kb: &Kb,
    settings: &Settings,
    progress: Progress<'_>,
) -> Result<Scanned, PipelineError> {
    let mut warnings = Vec::new();
    let (guard, _) = guard_env(sources.reg, sources.sys);
    let raw = dir.trim().trim_matches('"').trim_end_matches('\\');
    let long = sources.fs.long_path(raw).unwrap_or_else(|_| raw.to_owned());
    let canon = canon_path(&long, &guard, None)
        .map_err(|e| PipelineError::Precondition(format!("--path {dir:?}: {}", e.code())))?;
    if canon.needs_long_name {
        return Err(PipelineError::Precondition(format!(
            "--path {dir:?}: the 8.3 name could not be resolved"
        )));
    }
    let path = canon.path;
    match sources.fs.metadata(&path) {
        Ok(meta) if meta.is_dir() && !meta.is_reparse_point() => {}
        Ok(_) => {
            return Err(PipelineError::Precondition(format!(
                "--path {path}: not a plain directory"
            )));
        }
        Err(e) => {
            return Err(PipelineError::Precondition(format!(
                "--path {path}: cannot be read ({e})"
            )));
        }
    }
    let leaf = prefix::leaf(&path).unwrap_or("app").to_owned();

    progress("scan --path: reading the executables' version resources and signers");
    let facts = DirFacts::read(sources, &path);
    let entry = synthetic_entry(&path, &leaf, &facts)?;
    let inv = inventory(sources);
    warnings.extend(inv.warnings.iter().map(|w| format!("inventory: {w}")));
    let (cache, cache_kind) = table_cache(sources, settings);
    let cache = CountingCache::new(cache.as_ref());
    let opts = HarvestOpts {
        table_cache: Some(&cache),
        shared: None,
    };
    let report = harvest_report_with(&entry, &inv.doc, sources, BaselineView::empty(), kb, &opts);
    cache.report(cache_kind, settings);
    if report.fingerprint.roots.is_empty() {
        let why = report
            .rejected_roots
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(PipelineError::Precondition(format!(
            "--path {path} cannot be a root ({why})"
        )));
    }
    let mut fp = report.fingerprint;
    fp.warnings.push(
        "scan --path: minimal M1a implementation; identity from version resources and signers, forced mode"
            .into(),
    );
    warnings.push(
        "scan --path: minimal M1a implementation (forced mode, nothing is Safe or preselected)"
            .into(),
    );
    let app_id = app_id.map_or_else(|| leaf.to_lowercase(), str::to_owned);
    run_scan(
        sources,
        &fp,
        ScanMode::Forced,
        None,
        &app_id,
        settings,
        None,
        warnings,
        progress,
    )
}

/// What the executables directly inside a directory say about their product.
#[derive(Debug, Default)]
struct DirFacts {
    /// Canonical paths of the `.exe` files, sorted.
    exes: Vec<String>,
    /// The most frequent product name, with the first exe carrying it.
    product: Option<(String, String)>,
    /// The most frequent company name or signer.
    vendor: Option<String>,
    /// The product version of the exe the product name came from.
    version: Option<String>,
}

impl DirFacts {
    fn read(sources: Sources<'_>, dir: &str) -> Self {
        let mut exes: Vec<String> = sources
            .fs
            .list_dir(dir)
            .unwrap_or_default()
            .into_iter()
            .filter(|e| !e.meta.is_dir() && e.name.to_ascii_lowercase().ends_with(".exe"))
            .map(|e| format!("{dir}\\{}", e.name))
            .collect();
        exes.sort_by_key(|p| prefix::fold(p));
        let mut products: BTreeMap<String, (usize, String, Option<String>)> = BTreeMap::new();
        let mut vendors: BTreeMap<String, usize> = BTreeMap::new();
        for exe in &exes {
            let info = sources.fs.version_info(exe).ok().flatten();
            if let Some(info) = &info {
                if let Some(name) = info.product_name.as_deref().map(str::trim)
                    && !name.is_empty()
                {
                    let slot = products.entry(name.to_owned()).or_insert((
                        0,
                        exe.clone(),
                        info.product_version.clone(),
                    ));
                    slot.0 += 1;
                }
                if let Some(company) = info.company_name.as_deref().map(str::trim)
                    && !company.is_empty()
                {
                    *vendors.entry(company.to_owned()).or_default() += 1;
                }
            }
            if let Some(signer) = sources.fs.signer_cn(exe).ok().flatten() {
                let signer = signer.trim();
                if !signer.is_empty() {
                    *vendors.entry(signer.to_owned()).or_default() += 1;
                }
            }
        }
        // The most frequent, then the first in name order (BTreeMap order) on a tie.
        let product = products
            .iter()
            .max_by(|a, b| a.1.0.cmp(&b.1.0).then_with(|| b.0.cmp(a.0)))
            .map(|(name, (_, exe, version))| (name.clone(), exe.clone(), version.clone()));
        let vendor = vendors
            .iter()
            .max_by(|a, b| a.1.cmp(b.1).then_with(|| b.0.cmp(a.0)))
            .map(|(v, _)| v.clone());
        Self {
            exes,
            version: product.as_ref().and_then(|p| p.2.clone()),
            product: product.map(|(name, exe, _)| (name, exe)),
            vendor,
        }
    }
}

/// The inventory entry `scan --path` harvests: the directory as `InstallLocation`, the product's main exe
/// as `DisplayIcon`, no uninstaller.
fn synthetic_entry(
    path: &str,
    leaf: &str,
    facts: &DirFacts,
) -> Result<InventoryEntry, PipelineError> {
    let program_id = ProgramId::machine(View::K64, format!("{PATH_KEY_PREFIX}{leaf}"))
        .map_err(|e| PipelineError::Precondition(format!("--path {path}: {e}")))?;
    let display_name = facts
        .product
        .as_ref()
        .map_or_else(|| leaf.to_owned(), |(name, _)| name.clone());
    let icon = facts
        .product
        .as_ref()
        .map(|(_, exe)| exe.clone())
        .or_else(|| facts.exes.first().cloned());
    Ok(InventoryEntry {
        key_path: program_id.key_path(),
        program_id,
        hive_sid: None,
        view: View::K64,
        display_name,
        version: facts.version.clone(),
        publisher: facts.vendor.clone(),
        flags: RawFlags {
            has_display_name: true,
            ..RawFlags::default()
        },
        installer_kind: InstallerKind::Unknown,
        scope: InstallScope::Machine,
        product_code: None,
        upgrade_code: None,
        inno_app_id: None,
        writable_by: WritableBy::Admin,
        install_location: Some(path.to_owned()),
        uninstall_string: None,
        quiet_uninstall_string: None,
        display_icon: icon,
        install_time_evidence: Vec::new(),
        msi: None,
    })
}

#[cfg(test)]
thread_local! {
    /// Set by a test: the scan of this thread runs every scanner in catalog order, as it did before
    /// the scanners that do not read the reference walk were run ahead of the others.
    static CATALOG_ORDER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Whether the scan runs its scanners in one pass in catalog order (tests only; never in a build
/// that ships).
fn in_catalog_order() -> bool {
    #[cfg(test)]
    {
        CATALOG_ORDER.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        false
    }
}

/// The part of [`scan`] and [`scan_path`] after the mode is settled.
#[allow(clippy::too_many_arguments)]
fn run_scan(
    sources: Sources<'_>,
    fp: &Fingerprint,
    mode: ScanMode,
    verify_gone: Option<VerifyGone>,
    app_id: &str,
    settings: &Settings,
    injected: Option<&PipelineBaseline>,
    warnings: Vec<String>,
    progress: Progress<'_>,
) -> Result<Scanned, PipelineError> {
    // The threads of the reference walk, which starts before the inventory and the baseline are
    // read (`ScanExt::walk_ahead`).
    std::thread::scope(|threads| {
        run_scan_threads(
            threads,
            sources,
            fp,
            mode,
            verify_gone,
            app_id,
            settings,
            injected,
            warnings,
            progress,
        )
    })
}

/// [`run_scan`] with the thread scope its reference walk runs in.
#[allow(clippy::too_many_arguments)]
fn run_scan_threads<'scope, 'env>(
    threads: &'scope std::thread::Scope<'scope, 'env>,
    sources: Sources<'env>,
    fp: &'env Fingerprint,
    mode: ScanMode,
    verify_gone: Option<VerifyGone>,
    app_id: &str,
    settings: &Settings,
    injected: Option<&PipelineBaseline>,
    mut warnings: Vec<String>,
    mut progress: Progress<'_>,
) -> Result<Scanned, PipelineError> {
    let mut step = Step::new(&mut progress);
    if !sources.sys.elevated() {
        warnings.push(not_elevated_warning("scan"));
    }

    // Machine facts.
    step.say("scan: reading the machine facts and the inventory");
    let env = sources.sys.env().unwrap_or_else(|e| {
        warnings.push(format!("scan: the environment could not be read ({e})"));
        BTreeMap::new()
    });
    // The one reference walk of the scan needs the fingerprint and the matcher only: it starts now
    // and runs beside the inventory and the baseline load; `ScanExt::build_ahead` takes its hits.
    let app = AppIdentityView::from_fingerprint(fp, &env);
    let walk_ahead = ScanExt::walk_ahead(threads, sources.reg, fp, &app);
    let env_map: EnvMap = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (mut guard, guard_warnings) = guard_env(sources.reg, sources.sys);
    warnings.extend(guard_warnings.into_iter().map(|w| format!("scan: {w}")));
    guard.purge_dirs = canonical_dirs(&settings.purge_dirs, &guard, &mut warnings);
    if let Ok(os) = sources.sys.os_info()
        && !fp.os.edition.is_empty()
        && fp.os != os
    {
        warnings.push(format!(
            "scan: the fingerprint was harvested on {}, this is {}",
            fp.os.baseline_name(),
            os.baseline_name()
        ));
    }

    // Other apps, from a fresh inventory.
    let inv = inventory(sources);
    warnings.extend(inv.warnings.iter().map(|w| format!("inventory: {w}")));
    let mut exclude: Vec<&ProgramId> = vec![&fp.app.program_id];
    exclude.extend(fp.co_removed.iter().map(|c| &c.app.program_id));
    let base_deny = DenyList::compile(&guard);
    let others = other_apps(&inv.doc.entries, &exclude, &env_map, &guard, &base_deny);
    guard.other_app_roots = others
        .iter()
        .flat_map(|app| {
            app.roots.iter().map(|root| OtherAppRoot {
                app: app.name.clone(),
                path: root.clone(),
            })
        })
        .collect();
    let other_apps = OtherApps::new(others);
    step.done(&format!(
        "scan: {} other apps in the inventory",
        other_apps.apps().len()
    ));

    let loaded;
    let baseline = match injected {
        Some(injected) => step_injected(injected, &mut warnings, &mut step),
        None => {
            loaded = baseline_for(sources, settings, &mut warnings, &mut step);
            &loaded
        }
    };

    // Scanners. What every scanner shares is read once, before the first (C-SCANEXT): the one
    // reference walk, the MSI ownership index and the system objects.
    step.say("scan: reading the references, the MSI ownership and the system objects");
    let (cache, cache_kind) = table_cache(sources, settings);
    let cache = CountingCache::new(cache.as_ref());
    let ext = ScanExt::build_ahead(
        sources.reg,
        sources.fs,
        sources.sys,
        fp,
        &app,
        &inv.doc.entries,
        &inv.doc.msi_only,
        Some(&cache),
        OwnershipLimits::default(),
        walk_ahead,
    );
    cache.report(cache_kind, settings);
    let ctx = ScanCtx {
        reg: sources.reg,
        fs: sources.fs,
        sys: sources.sys,
        fp,
        baseline: &baseline.view,
        mode,
        verify_gone,
        env: &env,
        guard: &guard,
        other_apps: &other_apps,
        limits: ScanLimits::default(),
        ext: &ext,
    };
    // The scanners that ask nothing of the reference walk run first, while a walk started ahead is
    // still reading; then the walk is waited for, and the scanners that read its hits run. The
    // candidates, the faults and the warnings are put together in catalog order, as when every
    // scanner runs in that order.
    let scanners = all_scanners();
    let mut found_by: Vec<Option<Vec<Candidate>>> = scanners.iter().map(|_| None).collect();
    // One pass over the scanners that do not read the walk, one over those that do (a test may
    // ask for a single pass in catalog order, to hold the two against each other).
    let passes: &[Option<bool>] = if in_catalog_order() {
        &[None]
    } else {
        &[Some(false), Some(true)]
    };
    for pass in passes {
        if *pass != Some(false) {
            warnings.extend(ext_warnings(&ext));
            step.done(&format!(
                "scan: {} reference(s), {} MSI product(s), {} service(s); MSI table cache in {}",
                ext.ref_hit_count(),
                ext.ownership.stats().products,
                ext.sysobj.services.len(),
                match cache_kind {
                    TableCacheKind::Disk => "the data directory",
                    TableCacheKind::Memory => "memory",
                }
            ));
        }
        for (position, scanner) in scanners.iter().enumerate() {
            if pass.is_some_and(|reads_walk| scanner.reads_ref_walk() != reads_walk) {
                continue;
            }
            ext.at_scanner(u32::try_from(position).unwrap_or(u32::MAX));
            // `run`, not `scan`: the rule about what a value holds is applied to every candidate.
            let found = ctx.run(scanner.as_ref(), &app);
            step.done(&format!(
                "scan: {} {} candidate(s)",
                scanner.id(),
                found.len()
            ));
            found_by[position] = Some(found);
        }
    }
    let mut candidates = Vec::new();
    let mut per_scanner = Vec::new();
    for (scanner, found) in scanners.iter().zip(found_by) {
        let found = found.unwrap_or_default();
        per_scanner.push((scanner.id(), found.len()));
        candidates.extend(found);
    }
    warnings.extend(
        ext.take_faults()
            .into_iter()
            .map(|f| format!("scan: scanner fault: {f}")),
    );
    warnings.extend(
        ext.take_warnings()
            .into_iter()
            .map(|w| format!("scan: {w}")),
    );
    let unknown = ext.unknown_ownership_items();
    if unknown > 0 {
        warnings.push(format!(
            "scan: {unknown} item(s) under a Classes key kept from Safe (MsiPackageUnreadable): \
             the MSI rows of {} product(s) are unknown",
            ext.ownership.unreadable().len()
        ));
    }
    // Display only: the readable name and the program of every service, task and firewall rule
    // candidate (M3-ENGINE-OUT). Outside the plan hash and the plan itself.
    attach_object_display(&mut candidates, &ext.sysobj, &env);

    // Decide, collapse, emit.
    let deny = DenyList::compile(&guard);
    if let Some(why) = deny.invalid() {
        warnings.push(format!(
            "scan: the deny-list could not be built ({why}); every target is Blocked"
        ));
    }
    let user_sid = Some(fp.user_sid.as_str()).filter(|s| !s.is_empty());
    let baseline_trust = BaselineTrust::for_policy(
        ctx.absence_trust(),
        fp.harvest_trust(
            baseline
                .view
                .is_exact_for(&fp.os.edition, fp.os.build, fp.os.ubr),
        ),
    );
    let decide = DecideCtx {
        deny: &deny,
        mode,
        verify_gone: verify_gone.unwrap_or_else(|| VerifyGone::new(false, false, false)),
        user_sid,
        // Candidates also come from registry data, which may spell 8.3 names: keep the refusal on.
        long_names_resolved: false,
        limits: Limits::default(),
        // The M1b exemption lists, from the fingerprint and fresh queries only (R2a S9).
        m1b: m1b_lists(sources, fp, &inv),
        // P-BL-1 (BL-POLICY): the trust of the absence answers this scan consumed (presence-only:
        // Exact for an Exact view, None below it), or of the view the fingerprint was harvested
        // with when that one is inferred (not the plain minimum, see `for_policy`). A fingerprint's
        // Exact is believed only with the shipped baseline of its own Windows in hand.
        baseline_trust,
    };
    // M3-R1 M2: an id is the client's selection key. Two different targets with one id would make a
    // tick name either of them, so neither is served: drop every candidate of a colliding id and say
    // so. `purge-plan::decide::merge` refuses them as well, for callers that do not come through here.
    let colliding = colliding_ids(&candidates, &decide);
    if !colliding.is_empty() {
        for id in &colliding {
            let count = candidates.iter().filter(|c| &c.id == id).count();
            warnings.push(format!(
                "scan: dropped {count} candidate(s) whose id {} names more than one target",
                id.0
            ));
        }
        candidates.retain(|c| !colliding.contains(&c.id));
    }
    let built = build(app_id, candidates.clone(), &decide);
    let residue = ctx.residue_doc(&built.scan.plan_hash, &candidates, ext.take_unknown());
    step.done(&format!(
        "scan: plan with {} item(s), hash {}",
        built.plan.items.len(),
        built.scan.plan_hash
    ));
    Ok(Scanned {
        candidates,
        built,
        per_scanner,
        residue,
        warnings: warnings.into_iter().map(ScanWarning::classify).collect(),
        baseline_trust,
    })
}

/// The program text of `program`, for display: a resolved file, or the raw text when it could not be
/// resolved. `None` when the object names no program.
fn program_text(program: &ProgramRef) -> Option<String> {
    match program {
        ProgramRef::File(path) => Some(path.clone()),
        ProgramRef::Unresolved { raw } => Some(raw.clone()),
        ProgramRef::None => None,
    }
}

/// Fills [`Candidate::display_name`] and [`Candidate::owner_program`] for service, task and firewall
/// rule candidates (M3-ENGINE-OUT). Display only: neither field is part of the plan hash, and neither
/// reaches `purge.plan/0`.
///
/// - A service's name is its `DisplayName` (not an indirect `@resource` reference the scan cannot
///   resolve); its program is the file `ImagePath`/`ServiceDll` names.
/// - A firewall rule's name is its `Name=` field; its program is the resolved `App=`.
/// - A task has no name of its own to add (its path is the target); its program is the file of its
///   first action, when every action resolved to a file.
fn attach_object_display(
    candidates: &mut [Candidate],
    sysobj: &SysObjectIndex,
    env: &BTreeMap<String, String>,
) {
    let service = |name: &str| {
        sysobj
            .services
            .iter()
            .find(|s| s.identity.name.eq_ignore_ascii_case(name))
    };
    let rule = |id: &str| sysobj.firewall.iter().find(|r| r.identity.id == id);
    let env = purge_index::sysobj::Env::new(env.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    for candidate in candidates {
        match &candidate.target {
            Target::Service { name } => {
                let Some(facts) = service(name) else {
                    continue;
                };
                candidate.display_name = facts
                    .display_name
                    .as_deref()
                    .map(str::trim)
                    .filter(|name| !name.is_empty() && !name.starts_with('@'))
                    .map(str::to_owned);
                candidate.owner_program = program_text(&facts.program);
            }
            Target::FirewallRule { id } => {
                let Some(facts) = rule(id) else {
                    continue;
                };
                candidate.display_name = facts
                    .fields
                    .get("Name")
                    .map(str::trim)
                    .filter(|name| !name.is_empty() && !name.starts_with('@'))
                    .map(str::to_owned);
                candidate.owner_program = program_text(&facts.program);
            }
            Target::Task { path } => {
                let Some(task) = sysobj
                    .tasks
                    .iter()
                    .find(|t| t.identity.path.eq_ignore_ascii_case(path))
                else {
                    continue;
                };
                candidate.owner_program = purge_index::sysobj::task_programs(&task.identity, &env)
                    .files()
                    .and_then(|files| files.first().map(|file| (*file).to_owned()));
            }
            _ => {}
        }
    }
}

/// The M1b exemption lists of a plan (C-GUARD, R2a S9): [`M1bDecide::from_facts`] over the fingerprint,
/// with two fresh queries made now, never anything a candidate or a plan file says:
///
/// - `product_known`: Windows Installer's state of the product in every context, the fresh inventory's
///   list of every user's products, and the product's own user
///   ([`purge_scan::framework::product_known_in`], R3a B1);
/// - `bundle_known`: the bundle in the fresh inventory `inv` ([`purge_plan::decide::bundle_known`]); a
///   hive counts as read when it is loaded and no Uninstall key of it failed to list (an inventory
///   warning on that hive's Uninstall keys, or on the list of loaded hives for a user, makes it
///   unknown).
///
/// The executor never takes these lists from the plan (a plan file could then name any product or
/// Package Cache folder): `exec --fp` computes them with this function when the run starts, over the
/// app's fingerprint and a fresh inventory, and the run journals them in its `settings` record
/// (`RunSettings::gone_*`), from which its act-time gate, undo and recovery read them
/// (`GateCtx::set_gone`).
pub fn m1b_lists(sources: Sources<'_>, fp: &Fingerprint, inv: &Inventory) -> M1bDecide {
    let loaded = sources.reg.loaded_user_sids().ok();
    let hive_read = |sid: Option<&str>| -> bool {
        let unread = |prefix: &str| {
            inv.warnings.iter().any(|w| {
                w.location
                    .get(..prefix.len())
                    .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
            })
        };
        match sid {
            None => !unread("HKLM\\"),
            Some(sid) => {
                let is_loaded = loaded
                    .as_ref()
                    .is_some_and(|l| l.iter().any(|s| s.eq_ignore_ascii_case(sid)));
                is_loaded
                    && !inv.warnings.iter().any(|w| w.location == "HKU")
                    && !unread(&format!("HKU\\{sid}\\"))
            }
        }
    };
    // R3a B1: Windows Installer answers for the calling user only; the fresh inventory (every user's
    // products when elevated) and the product's own user decide the rest.
    let listed =
        |packed: &str| inventory_lists_product(&inv.doc.entries, &inv.doc.msi_only, packed);
    M1bDecide::from_facts(
        fp,
        &|code| product_known_in(sources.sys, fp, &listed, code),
        &|bundle| bundle_known(bundle, &fp.app.program_id, &inv.doc.entries, &hive_read),
    )
}

/// What the shared scan data could not read, as scan warnings: unknown MSI ownership blocks the
/// targets it may concern (`MsiPackageUnreadable`), and the user should know why.
fn ext_warnings(ext: &ScanExt) -> Vec<String> {
    let stats = ext.ownership.stats();
    let mut out = Vec::new();
    // R3a S3: a walk cut by its budget or by unreadable keys may have missed a referrer; the COM
    // scanners then stay below Tier A, and the user should know why.
    if !ext.ref_walk_complete() {
        out.push(
            "scan: the reference walk did not read every key (budget or unreadable keys); \
             registrations judged by its hits are not Safe on its word"
                .to_owned(),
        );
    }
    let unreadable = ext.ownership.unreadable();
    if !unreadable.is_empty() {
        out.push(format!(
            "scan: {} MSI package(s) could not be read; what they own is unknown",
            unreadable.len()
        ));
    }
    if !stats.incomplete.is_empty() {
        out.push(format!(
            "scan: the MSI ownership index is incomplete ({})",
            stats.incomplete.join(", ")
        ));
    }
    out.extend(stats.errors.iter().map(|e| format!("scan: ownership: {e}")));
    out.extend(
        ext.sysobj
            .errors
            .iter()
            .map(|e| format!("scan: system objects: {e}")),
    );
    out
}

/// The canonical form of each directory; ones that do not canonicalise are dropped with a warning.
pub fn canonical_dirs(
    dirs: &[String],
    guard: &GuardEnv,
    warnings: &mut Vec<String>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for dir in dirs {
        match canon_path(dir.trim_end_matches('\\'), guard, None) {
            Ok(c) if !c.needs_long_name && prefix::depth(&c.path) >= 2 => {
                if !out.iter().any(|d| prefix::is_same(d, &c.path)) {
                    out.push(c.path);
                }
            }
            _ => warnings.push(format!(
                "scan: Purge directory {dir:?} is not a canonical path; it is left out of the guard"
            )),
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------------------
// Other apps
// ---------------------------------------------------------------------------------------------------------

/// A raw registry path value made ready for canonicalisation: trimmed, one pair of quotes removed,
/// `%NAME%` references expanded.
fn clean_value(raw: &str, env: &EnvMap) -> Option<String> {
    let s = raw.trim().trim_matches('"').trim();
    if s.is_empty() {
        return None;
    }
    Some(if s.contains('%') {
        expand_with(s, env)
    } else {
        s.to_owned()
    })
}

/// The file a `DisplayIcon` value names: without a trailing `,<index>`.
fn icon_file(raw: &str) -> &str {
    let s = raw.trim().trim_matches('"');
    match s.rsplit_once(',') {
        Some((file, index))
            if !index.trim().is_empty()
                && index
                    .trim()
                    .trim_start_matches('-')
                    .bytes()
                    .all(|b| b.is_ascii_digit()) =>
        {
            file.trim().trim_matches('"')
        }
        _ => s,
    }
}

/// The canonical path of a file or directory value, when it has one.
fn canon_value(raw: &str, env: &EnvMap, guard: &GuardEnv) -> Option<String> {
    let cleaned = clean_value(raw, env)?;
    let c = canon_path(cleaned.trim_end_matches('\\'), guard, None).ok()?;
    (!c.needs_long_name && prefix::depth(&c.path) >= 2).then_some(c.path)
}

/// Whether a file name looks like an uninstaller (`unins000.exe`, `uninstall.exe`, `Uninst.exe`): such a
/// name says nothing about which app a reference belongs to.
fn uninstaller_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("unins") || lower.starts_with("uninst")
}

/// The [`OtherApp`] facts of every inventory entry not in `exclude` (see the module documentation).
pub fn other_apps(
    entries: &[InventoryEntry],
    exclude: &[&ProgramId],
    env: &EnvMap,
    guard: &GuardEnv,
    deny: &DenyList,
) -> Vec<OtherApp> {
    let mut out = Vec::new();
    for entry in entries {
        if exclude.contains(&&entry.program_id) {
            continue;
        }
        let mut app = OtherApp {
            name: entry.display_name.clone(),
            keys: vec![entry.key_path.clone()],
            ..OtherApp::default()
        };
        if let Some(root) = entry
            .install_location
            .as_deref()
            .and_then(|l| canon_value(l, env, guard))
            .filter(|dir| deny.root_rejection(dir, true).is_none())
        {
            app.roots.push(root);
        }
        let uninstaller = entry
            .uninstall_string
            .as_deref()
            .and_then(|c| purge_win::cmdline::split(c).ok())
            .and_then(|split| canon_value(&split.exe, env, guard));
        let icon = entry
            .display_icon
            .as_deref()
            .and_then(|i| canon_value(icon_file(i), env, guard));
        for file in [uninstaller, icon.clone()].into_iter().flatten() {
            let in_windows = prefix::is_same_or_inside(&file, &guard.windir);
            if !in_windows && !app.files.iter().any(|f| prefix::is_same(f, &file)) {
                app.files.push(file);
            }
        }
        if let Some(name) = icon
            .as_deref()
            .and_then(prefix::leaf)
            .filter(|n| n.to_ascii_lowercase().ends_with(".exe") && !uninstaller_name(n))
        {
            app.anchors.push(AnchorRef {
                kind: AnchorKind::Exe,
                text: name.to_owned(),
            });
        }
        out.push(app);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_model::Target;
    use purge_source::fixture::Fixture;
    use purge_source::types::{KeyInfo, MsiProductState, RegData, RegValue, SourceResult};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const SID: &str = GuardEnv::SAMPLE_SID;

    /// The scanners run through `ScanCtx::run`, which applies the rule about what a value holds
    /// to every candidate; a direct call of `Scanner::scan` here would leave that out.
    #[test]
    fn scanners_run_through_the_sealing_driver() {
        let source = include_str!("pipeline.rs");
        let direct = ["scanner", ".scan("].concat();
        let driver = ["ctx", ".run(scanner"].concat();
        assert!(
            !source.contains(&direct),
            "pipeline.rs calls a scanner directly"
        );
        assert_eq!(source.matches(&driver).count(), 1);
    }

    /// A caller-built baseline view enters only through `harvest_with_view`, `scan_with_view` and
    /// `PipelineBaseline::injected`, each behind the `inject-view` feature (the offline replay and
    /// tests). No source of the CLI or of the binary names them: the engine a user runs, as a CLI or
    /// as a server, works with the view it loads itself.
    #[test]
    fn only_the_gated_doors_take_an_injected_view() {
        let doors = [
            ["harvest", "_with_view"].concat(),
            ["scan", "_with_view"].concat(),
            ["PipelineBaseline::", "injected"].concat(),
            ["fn ", "injected("].concat(),
            ["inject", "-view"].concat(),
        ];
        let gate = ["#[cfg(any(test, feature = \"inject", "-view\"))]"].concat();
        let pipeline = include_str!("pipeline.rs");
        let baseline = include_str!("pipeline/baseline.rs");
        for (text, door, n) in [
            (pipeline, ["pub fn harvest", "_with_view("].concat(), 1),
            (pipeline, ["pub fn scan", "_with_view("].concat(), 1),
            (baseline, ["pub fn ", "injected("].concat(), 1),
        ] {
            assert_eq!(text.matches(&door).count(), n, "{door}");
            let at = text.find(&door).unwrap();
            let before = text[..at].trim_end();
            assert!(before.ends_with(&gate), "{door} is not behind the feature");
        }

        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![src.clone()];
        let mut read = 0;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let rel = path
                    .strip_prefix(&src)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                if rel == "pipeline.rs" || rel == "pipeline/baseline.rs" {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                read += 1;
                for door in &doors {
                    assert!(!text.contains(door.as_str()), "{rel} names {door}");
                }
            }
        }
        assert!(read >= 8, "{read} sources read");
    }

    /// A registry that counts the reads of one key's values. Its walker is the trait's default, which
    /// reads through the counted methods.
    struct Counting<'f> {
        inner: &'f Fixture,
        probe: &'static str,
        reads: AtomicUsize,
        /// Listings of the subkeys of [`purge_index::ownership::USERDATA`]: one per ownership build.
        userdata_lists: AtomicUsize,
    }

    impl RegistrySource for Counting<'_> {
        fn key_info(&self, key: &str) -> SourceResult<KeyInfo> {
            self.inner.key_info(key)
        }
        fn subkeys(&self, key: &str) -> SourceResult<Vec<String>> {
            if key.eq_ignore_ascii_case(purge_index::ownership::USERDATA) {
                self.userdata_lists.fetch_add(1, Ordering::SeqCst);
            }
            self.inner.subkeys(key)
        }
        fn values(&self, key: &str) -> SourceResult<Vec<RegValue>> {
            if key.eq_ignore_ascii_case(self.probe) {
                self.reads.fetch_add(1, Ordering::SeqCst);
            }
            self.inner.values(key)
        }
        fn value(&self, key: &str, name: &str) -> SourceResult<RegData> {
            self.inner.value(key, name)
        }
        fn loaded_user_sids(&self) -> SourceResult<Vec<String>> {
            self.inner.loaded_user_sids()
        }
        fn current_control_set(&self) -> SourceResult<u32> {
            self.inner.current_control_set()
        }
    }

    const PROBE: &str = r"HKLM\SOFTWARE\Acme Holder\Quiet";
    const REFERS: &str = r"HKLM\SOFTWARE\Acme Holder\Settings";
    const UNINSTALL: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Probe";

    /// A machine with one app, Probe, in `C:\Program Files\Probe`.
    fn probe_machine() -> purge_source::fixture::FixtureBuilder {
        Fixture::builder()
            .os("Professional", 26340, 9882)
            .user_sid(SID)
            .env("SYSTEMDRIVE", "C:")
            .env("WINDIR", r"C:\Windows")
            .env("PROGRAMFILES", r"C:\Program Files")
            .env("PROGRAMDATA", r"C:\ProgramData")
            .sz(
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
                "ProfilesDirectory",
                r"C:\Users",
            )
            .volume(r"C:\", Some(0x1234_5678), true, "NTFS")
            .dir(r"C:\Program Files\Probe")
            .file(r"C:\Program Files\Probe\probe.exe", 10)
            .sz(UNINSTALL, "DisplayName", "Probe")
            .sz(UNINSTALL, "InstallLocation", r"C:\Program Files\Probe")
            .sz(
                UNINSTALL,
                "DisplayIcon",
                r"C:\Program Files\Probe\probe.exe",
            )
            .sz(
                UNINSTALL,
                "UninstallString",
                r"C:\Program Files\Probe\uninst.exe",
            )
            .key(&format!(r"HKU\{SID}\Software"))
    }

    /// The scan makes the reference walk once and builds the MSI ownership index once (C-SCANEXT): the
    /// one `ScanExt::build` of the scan walks and lists `UserData`; every scanner reads its results. A
    /// key only the walk reads (it refers to nothing, so no scanner looks at it again) is read once in
    /// the whole scan; next to it, a value that refers to the app still reaches REF-ANY.
    #[test]
    fn pipeline_one_reference_walk_and_one_ownership_build() {
        let components = format!(
            r"{}\S-1-5-18\Components\0123456789ABCDEF0123456789ABCDEF",
            purge_index::ownership::USERDATA
        );
        let fixture = probe_machine()
            .sz(PROBE, "Tool", r"C:\Tools\other.exe")
            .sz(REFERS, "Tool", r"C:\Program Files\Probe\probe.exe")
            .sz(
                &components,
                "00000000000000000000000000000001",
                r"C:\Program Files\Other\o.exe",
            )
            .build();
        let counting = Counting {
            inner: &fixture,
            probe: PROBE,
            reads: AtomicUsize::new(0),
            userdata_lists: AtomicUsize::new(0),
        };
        let sources = Sources {
            reg: &counting,
            fs: &fixture,
            sys: &fixture,
        };
        let settings = Settings::default();
        let harvested = harvest(sources, "Probe", Kb::shipped(), &settings, &mut |_| {}).unwrap();
        let fp = harvested.report.fingerprint;
        counting.reads.store(0, Ordering::SeqCst);
        counting.userdata_lists.store(0, Ordering::SeqCst);
        let scanned = scan(sources, &fp, ScanMode::Forced, None, &settings, &mut |_| {}).unwrap();
        assert_eq!(
            counting.reads.load(Ordering::SeqCst),
            1,
            "the probe key is read by one walk"
        );
        assert_eq!(
            counting.userdata_lists.load(Ordering::SeqCst),
            1,
            "the ownership index is built once"
        );
        assert_eq!(scanned.per_scanner.len(), all_scanners().len());
        // The walk's hit reached REF-ANY: the value is a candidate.
        let targets: Vec<&Target> = scanned.candidates.iter().map(|c| &c.target).collect();
        assert!(
            targets.iter().any(|t| matches!(
                t,
                Target::RegValue { path, name } if path.eq_ignore_ascii_case(REFERS) && name == "Tool"
            )),
            "{targets:#?}"
        );
    }

    /// The scan runs the scanners that do not read the reference walk first and the others after
    /// it; a scan that runs every scanner in catalog order, as the engine did before, gives the
    /// same plan, sidecar, candidates, counts, residue and warnings. The machine has leftovers for
    /// both groups: a referring value (REF-ANY, after the walk) and the install directory, an App
    /// Paths key and a ProgID (before it).
    #[test]
    fn both_scanner_orders_give_the_same_plan_and_sidecar() {
        let fixture = probe_machine()
            .sz(REFERS, "Tool", r"C:\Program Files\Probe\probe.exe")
            .sz(REFERS, "Other", r"C:\Tools\other.exe")
            .sz(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\probe.exe",
                "",
                r"C:\Program Files\Probe\probe.exe",
            )
            .sz(
                r"HKLM\SOFTWARE\Classes\Probe.Document\shell\open\command",
                "",
                r#""C:\Program Files\Probe\probe.exe" "%1""#,
            )
            .sz(
                r"HKLM\SOFTWARE\Classes\.probe\OpenWithProgids",
                "Probe.Document",
                "",
            )
            .sz(
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                "Probe",
                r#""C:\Program Files\Probe\probe.exe" /tray"#,
            )
            .build();
        let sources = Sources {
            reg: &fixture,
            fs: &fixture,
            sys: &fixture,
        };
        let settings = Settings::default();
        let harvested = harvest(sources, "Probe", Kb::shipped(), &settings, &mut |_| {}).unwrap();
        let fp = harvested.report.fingerprint;
        let run = |catalog: bool| {
            CATALOG_ORDER.with(|order| order.set(catalog));
            let mut lines: Vec<String> = Vec::new();
            let scanned = scan(
                sources,
                &fp,
                ScanMode::Forced,
                None,
                &settings,
                &mut |line| {
                    // The lines without their times.
                    lines.push(
                        line.rsplit_once(" (")
                            .map_or(line, |(text, _)| text)
                            .to_owned(),
                    );
                },
            );
            CATALOG_ORDER.with(|order| order.set(false));
            (scanned.unwrap(), lines)
        };
        let (split, split_lines) = run(false);
        let (catalog, catalog_lines) = run(true);

        assert!(split.candidates.len() >= 3, "{:#?}", split.candidates);
        let by = |id: &str| split.per_scanner.iter().find(|(s, _)| *s == id).unwrap().1;
        assert!(by("REF-ANY") > 0, "{:?}", split.per_scanner);
        assert!(
            split
                .per_scanner
                .iter()
                .any(|(s, n)| *s != "REF-ANY" && *n > 0),
            "{:?}",
            split.per_scanner
        );
        assert_eq!(
            serde_json::to_string_pretty(&split.built.plan).unwrap(),
            serde_json::to_string_pretty(&catalog.built.plan).unwrap()
        );
        assert_eq!(
            serde_json::to_string_pretty(&split.built.scan).unwrap(),
            serde_json::to_string_pretty(&catalog.built.scan).unwrap()
        );
        assert_eq!(
            format!("{:#?}", split.candidates),
            format!("{:#?}", catalog.candidates)
        );
        assert_eq!(split.per_scanner, catalog.per_scanner);
        assert_eq!(
            format!("{:#?}", split.residue),
            format!("{:#?}", catalog.residue)
        );
        assert_eq!(
            format!("{:#?}", split.warnings),
            format!("{:#?}", catalog.warnings)
        );

        // The two runs did order their scanners differently, and said the same lines.
        let place = |lines: &[String], start: &str| {
            lines
                .iter()
                .position(|line| line.starts_with(start))
                .unwrap_or_else(|| panic!("no line {start:?} in {lines:#?}"))
        };
        for (lines, split) in [(&split_lines, true), (&catalog_lines, false)] {
            let summary = lines
                .iter()
                .position(|line| line.contains(" reference(s), "))
                .unwrap();
            let ref_any = place(lines, "scan: REF-ANY");
            let progid = place(lines, "scan: CLS-PROGID");
            let first = place(lines, "scan: FS-INSTALLDIR");
            assert!(ref_any > summary);
            assert_eq!(progid < ref_any, split, "{lines:#?}");
            assert_eq!(first < summary, split, "{lines:#?}");
        }
        let sorted = |lines: &[String]| {
            let mut lines = lines.to_vec();
            lines.sort();
            lines
        };
        assert_eq!(sorted(&split_lines), sorted(&catalog_lines));
    }

    /// A record of an MSI product of Probe in the fingerprint (per-machine).
    fn probe_msi(code: &str) -> purge_model::MsiFacts {
        purge_model::MsiFacts {
            product_code: code.to_owned(),
            packed_code: purge_index::ownership::pack_guid(code).unwrap(),
            upgrade_code: None,
            context: purge_model::MsiContext::Machine,
            user_sid: None,
            local_package: None,
            package_readable: false,
            components: Vec::new(),
            registry_rows: Vec::new(),
            services: Vec::new(),
            source_dirs: Vec::new(),
            custom_actions: 0,
            unresolved_rows: 0,
        }
    }

    /// The MSI exemptions (the `gone_*` lists) open only when Windows Installer answers that the product
    /// is gone; a product whose state cannot be read keeps them closed.
    #[test]
    fn pipeline_exemptions_closed_when_product_state_unknown() {
        use purge_model::MsiContext::{Machine, UserManaged, UserUnmanaged};
        const CODE: &str = "{0A0A0A0A-1111-2222-3333-444444444444}";
        let settings = Settings::default();
        let lists_of = |fixture: &Fixture| {
            let sources = Sources::of(fixture);
            let mut fp = harvest(sources, "Probe", Kb::shipped(), &settings, &mut |_| {})
                .unwrap()
                .report
                .fingerprint;
            fp.msi.push(probe_msi(CODE));
            m1b_lists(sources, &fp, &inventory(sources))
        };

        // No MSI answer at all (the product list is not captured): unknown, closed.
        let lists = lists_of(&probe_machine().with(|f| f.set_msi_products(None)).build());
        assert!(lists.gone_msi_products().is_empty(), "{lists:?}");

        // Every context answers "unknown" and nothing lists it: gone, open for this product only.
        let gone = probe_machine()
            .msi_state(CODE, Machine, MsiProductState::Unknown)
            .msi_state(CODE, UserManaged, MsiProductState::Unknown)
            .msi_state(CODE, UserUnmanaged, MsiProductState::Unknown)
            .build();
        let lists = lists_of(&gone);
        let packed = purge_index::ownership::pack_guid(CODE).unwrap();
        assert_eq!(lists.gone_msi_products(), [packed]);

        // Still installed in one context: closed.
        let installed = probe_machine()
            .msi_state(CODE, Machine, MsiProductState::Default)
            .msi_state(CODE, UserUnmanaged, MsiProductState::Unknown)
            .build();
        let lists = lists_of(&installed);
        assert!(lists.gone_msi_products().is_empty(), "{lists:?}");
    }

    /// An unelevated run keeps the MSI table cache in memory and creates no directory, even when the
    /// settings name one. Elevated, it still creates none under a data root that is not admin-only.
    #[test]
    fn pipeline_unelevated_uses_memory_cache_and_creates_no_dir() {
        let base = std::env::temp_dir().join(format!("purge-tc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dir = base.join("Purge").join("fp").join("msitables");
        let settings = Settings {
            msi_table_dir: Some(dir.clone()),
            ..Settings::default()
        };
        let unelevated = probe_machine().elevated(false).build();
        let (_, kind) = table_cache(Sources::of(&unelevated), &settings);
        assert_eq!(kind, TableCacheKind::Memory);
        assert!(
            !base.exists(),
            "an unelevated run created {}",
            dir.display()
        );

        let elevated = probe_machine().elevated(true).build();
        let (_, kind) = table_cache(Sources::of(&elevated), &settings);
        assert_eq!(kind, TableCacheKind::Memory);
        assert!(
            !base.exists(),
            "created under a data root that is not admin-only"
        );

        let (_, kind) = table_cache(Sources::of(&unelevated), &Settings::default());
        assert_eq!(kind, TableCacheKind::Memory);
    }

    /// With a table cache source (the broker's checked `fp\msitables`), the cache is the source's, or
    /// memory when it gives none, and the directory of the settings is never created or opened by path,
    /// even elevated under an admin-only data root.
    #[test]
    fn pipeline_table_cache_source_replaces_the_path() {
        struct Source(std::sync::atomic::AtomicBool);
        impl TableCacheSource for Source {
            fn open(&self) -> Option<Box<dyn TableCache>> {
                self.0
                    .load(Ordering::SeqCst)
                    .then(|| Box::new(MemTableCache::new()) as Box<dyn TableCache>)
            }
        }
        let base = std::env::temp_dir().join(format!("purge-tcs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("Purge");
        std::fs::create_dir_all(&root).unwrap();
        let dir = root.join("fp").join("msitables");
        let root_text = root.to_str().unwrap();
        let elevated = probe_machine()
            .elevated(true)
            .dir(root_text)
            .admin_only_writable(root_text, true)
            .build();
        let source = std::sync::Arc::new(Source(std::sync::atomic::AtomicBool::new(true)));
        let shared = SharedTableCacheSource(source.clone());
        assert_eq!(shared, shared.clone());
        let settings = Settings {
            msi_table_dir: Some(dir.clone()),
            msi_table_source: Some(shared),
            ..Settings::default()
        };
        let (_, kind) = table_cache(Sources::of(&elevated), &settings);
        assert_eq!(kind, TableCacheKind::Disk);
        source.0.store(false, Ordering::SeqCst);
        let (_, kind) = table_cache(Sources::of(&elevated), &settings);
        assert_eq!(kind, TableCacheKind::Memory);
        assert!(!root.join("fp").exists(), "created {}", dir.display());
        let _ = std::fs::remove_dir_all(&base);
    }

    /// BL-R1 S4: elevated, the MSI table cache is made and used only on the volume of the rule. The
    /// temp tree is on the system volume; a rule naming another volume stands for a data root on a
    /// disk written elsewhere, with descriptors the file system source calls admin-only.
    #[test]
    fn pipeline_elevated_table_cache_only_on_the_rule_s_volume() {
        let base = std::env::temp_dir().join(format!("purge-tcv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("Purge");
        std::fs::create_dir_all(&root).unwrap();
        let system = purge_win::secure::system_volume().unwrap();
        if purge_win::secure::volume_of(&root).unwrap() != system {
            let _ = std::fs::remove_dir_all(&base);
            eprintln!("the temp directory is not on the system volume: skipped");
            return;
        }
        let dir = root.join("fp").join("msitables");
        let root_text = root.to_str().unwrap();
        let elevated = probe_machine()
            .elevated(true)
            .dir(root_text)
            .admin_only_writable(root_text, true)
            .dir(dir.to_str().unwrap())
            .build();
        let with = |rule: VolumeRule| Settings {
            msi_table_dir: Some(dir.clone()),
            volume_rule: rule,
            ..Settings::default()
        };
        let other = VolumeRule::On(r"\\?\volume{00000000-0000-0000-0000-000000000000}\".into());
        for rule in [other.clone(), VolumeRule::Unreadable] {
            let (_, kind) = table_cache(Sources::of(&elevated), &with(rule.clone()));
            assert_eq!(kind, TableCacheKind::Memory, "{rule:?}");
            assert!(!dir.exists(), "{rule:?}: made {}", dir.display());
        }
        let (_, kind) = table_cache(Sources::of(&elevated), &with(VolumeRule::On(system)));
        assert_eq!(kind, TableCacheKind::Disk);
        assert!(dir.is_dir());
        // An existing cache directory on a refused volume is not used either.
        let (_, kind) = table_cache(Sources::of(&elevated), &with(other));
        assert_eq!(kind, TableCacheKind::Memory);
        let _ = std::fs::remove_dir_all(&base);
    }

    fn entry(key: &str, name: &str) -> InventoryEntry {
        let program_id = ProgramId::machine(View::K64, key).unwrap();
        InventoryEntry {
            key_path: program_id.key_path(),
            program_id,
            hive_sid: None,
            view: View::K64,
            display_name: name.into(),
            version: None,
            publisher: None,
            flags: RawFlags::default(),
            installer_kind: InstallerKind::Unknown,
            scope: InstallScope::Machine,
            product_code: None,
            upgrade_code: None,
            inno_app_id: None,
            writable_by: WritableBy::Admin,
            install_location: None,
            uninstall_string: None,
            quiet_uninstall_string: None,
            display_icon: None,
            install_time_evidence: Vec::new(),
            msi: None,
        }
    }

    fn doc(entries: Vec<InventoryEntry>) -> InventoryDoc {
        InventoryDoc {
            schema: purge_model::InventorySchema,
            entries,
            msi_only: Vec::new(),
        }
    }

    /// A machine with admin-only interpreters and one user-writable script and DLL.
    ///
    /// `C:\ProgramData` is as Windows ships it: Users may add files and folders, and a vendor folder
    /// below it inherits that (`Open`), while the files in it are admin-only themselves (review M3-R2
    /// H3). `Vendor`, `My Vendor` and `My Vendor (x64)` are vendor folders with a protected ACL of their
    /// own, so the cmd quoting cases there turn on the command line alone.
    fn route_fixture() -> Fixture {
        const ADMIN_ONLY_FILES: [&str; 4] = [
            r"C:\ProgramData\Open\unins000.exe",
            r"C:\ProgramData\Open\uninstall.cmd",
            r"C:\ProgramData\Open\vendor.dll",
            r"C:\ProgramData\Open\vendor.msi",
        ];
        let mut builder = Fixture::builder()
            .admin_only_roots(&[r"C:\Windows", r"C:\Program Files", r"C:\ProgramData"])
            .file(r"C:\Program Files\App\uninstall.cmd", 1)
            .file(r"C:\Program Files\App\uninstall.py", 1)
            .file(r"C:\Program Files\App\uninstall.js", 1)
            .file(r"C:\Program Files\App\uninstall.vbs", 1)
            .file(r"C:\Program Files\App\uninstall.jar", 1)
            .file(r"C:\Program Files\App\vendor.dll", 1)
            .file(r"C:\Program Files\Python312\python.exe", 1)
            .file(r"C:\Program Files\Python312\python3.12.exe", 1)
            .file(r"C:\Program Files\nodejs\node.exe", 1)
            .file(r"C:\Program Files\Java\bin\java.exe", 1)
            .file(r"C:\Windows\System32\wsl.exe", 1)
            .file(r"C:\Windows\System32\wscript.exe", 1)
            .file(r"C:\Windows\System32\regsvr32.exe", 1)
            .file(r"C:\Windows\System32\conhost.exe", 1)
            .file(r"C:\Windows\System32\shell32.dll", 1)
            .file(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe",
                1,
            )
            .file(r"C:\Program Files\dotnet\dotnet.exe", 1)
            .file(r"C:\Program Files\App\app.dll", 1)
            .file(r"C:\Program Files\Vendor Tools\tools.dll", 1)
            .file(r"C:\ProgramData\My Vendor\uninstall.cmd", 1)
            .file(r"C:\ProgramData\My Vendor (x64)\uninstall.cmd", 1)
            // No extension: cmd would try `uninstall.com`, `uninstall.exe`, ... (M4).
            .file(r"C:\ProgramData\Vendor\uninstall", 1)
            .file(r"C:\ProgramData\Vendor\vendor.mst", 1)
            .file(r"C:\Users\tester\AppData\Local\App\evil.mst", 1)
            .admin_only_writable(r"C:\ProgramData", false)
            .admin_only_writable(r"C:\ProgramData\Vendor", true)
            .admin_only_writable(r"C:\ProgramData\My Vendor", true)
            .admin_only_writable(r"C:\ProgramData\My Vendor (x64)", true);
        for file in ADMIN_ONLY_FILES {
            builder = builder.file(file, 1).admin_only_writable(file, true);
        }
        builder
            .file(r"C:\Windows\System32\cmd.exe", 1)
            .file(r"C:\Windows\System32\rundll32.exe", 1)
            .file(r"C:\Windows\System32\msiexec.exe", 1)
            .file(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                1,
            )
            .file(r"C:\Program Files\PowerShell\7\pwsh.exe", 1)
            .file(r"C:\Program Files\App\unins000.exe", 1)
            .file(r"C:\ProgramData\Vendor\uninstall.cmd", 1)
            .file(r"C:\ProgramData\Vendor\uninstall.ps1", 1)
            .file(r"C:\Users\tester\AppData\Local\App\evil.cmd", 1)
            .file(r"C:\Users\tester\AppData\Local\App\evil.dll", 1)
            .file(r"C:\Users\tester\AppData\Local\App\evil.ini", 1)
            .file(r"C:\ProgramData\Vendor\vendor.dll", 1)
            // A user-writable folder whose name, cut at the comma, is an admin-only one.
            .file(r"C:\ProgramData\Vendor,x\evil.msi", 1)
            .file(r"C:\ProgramData\Vendor,x\evil.cmd", 1)
            .file(r"C:\ProgramData\Vendor,x\evil.dll", 1)
            .admin_only_writable(r"C:\ProgramData\Vendor,x", false)
            .build()
    }

    fn route_entry(uninstall: &str) -> InventoryEntry {
        let mut entry = entry("App_is1", "App");
        entry.uninstall_string = Some(uninstall.to_owned());
        entry
    }

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn a_planted_user_environment_keeps_a_machine_command_medium() {
        let fs = route_fixture();
        let machine = env(&[("PROGRAMDATA", r"C:\ProgramData")]);
        let user = env(&[("PROGRAMDATA", r"C:\Users\tester\planted")]);
        let command = route_entry(
            r#""C:\Windows\System32\cmd.exe" /d /c "%ProgramData%\Vendor\uninstall.cmd""#,
        );
        assert_eq!(
            route(&command, &fs, &user, &machine),
            purge_rpc::methods::Route::Medium,
            "a value in HKCU\\Environment changed the expanded command"
        );
        assert_eq!(
            route(&command, &fs, &machine, &machine),
            purge_rpc::methods::Route::Broker
        );

        let undefined =
            route_entry(r#""C:\Windows\System32\cmd.exe" /d /c "%X%\Vendor\uninstall.cmd""#);
        assert_eq!(
            route(&undefined, &fs, &machine, &machine),
            purge_rpc::methods::Route::Medium,
            "a reference neither map defines stays medium"
        );
    }

    #[test]
    fn a_user_writable_file_loaded_by_an_admin_only_host_is_medium() {
        let fs = route_fixture();
        let machine = env(&[("PROGRAMDATA", r"C:\ProgramData")]);
        for command in [
            r#""C:\Windows\System32\cmd.exe" /d /c "C:\Users\tester\AppData\Local\App\evil.cmd""#,
            r#""C:\Windows\System32\rundll32.exe" "C:\Users\tester\AppData\Local\App\evil.dll",Entry"#,
            r#""C:\Program Files\App\unins000.exe" --config "C:\Users\tester\AppData\Local\App\evil.ini""#,
        ] {
            assert_eq!(
                route(&route_entry(command), &fs, &machine, &machine),
                purge_rpc::methods::Route::Medium,
                "{command}"
            );
        }
        assert_eq!(
            route(
                &route_entry(
                    r#""C:\Windows\System32\cmd.exe" /d /c "C:\ProgramData\Vendor\uninstall.cmd""#
                ),
                &fs,
                &machine,
                &machine
            ),
            purge_rpc::methods::Route::Broker,
            "an admin-only script is safe"
        );
        assert_eq!(
            route(
                &route_entry(
                    r#""C:\Windows\System32\cmd.exe" /d /c "C:\ProgramData\Vendor\missing.cmd""#
                ),
                &fs,
                &machine,
                &machine
            ),
            purge_rpc::methods::Route::Medium,
            "a load path that cannot be found is not provably safe"
        );
        assert_eq!(
            route(
                &route_entry(
                    r#""C:\Windows\System32\msiexec.exe" /x {11111111-1111-1111-1111-111111111111} /qn"#
                ),
                &fs,
                &machine,
                &machine
            ),
            purge_rpc::methods::Route::Broker,
            "msiexec with a ProductCode loads no client-chosen file"
        );
    }

    const POWERSHELLS: [&str; 2] = [
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r"C:\Program Files\PowerShell\7\pwsh.exe",
    ];

    fn shell_route(exe: &str, args: &str) -> purge_rpc::methods::Route {
        let machine = env(&[("PROGRAMDATA", r"C:\ProgramData")]);
        route(
            &route_entry(&format!(r#""{exe}" {args}"#)),
            &route_fixture(),
            &machine,
            &machine,
        )
    }

    #[test]
    fn inline_powershell_command_text_is_medium() {
        for exe in POWERSHELLS {
            for args in [
                r#"-NoProfile -Command ". .\cleanup.ps1""#,
                r#"-command "Import-Module VendorTools; Remove-VendorApp""#,
                r#"-c "& $env:LOCALAPPDATA\App\undo.ps1""#,
                "-ExecutionPolicy Bypass -Command Remove-Item x",
            ] {
                assert_eq!(
                    shell_route(exe, args),
                    purge_rpc::methods::Route::Medium,
                    "{exe} {args}"
                );
            }
        }
    }

    #[test]
    fn encoded_powershell_command_is_medium() {
        // `Remove-Item x` as UTF-16LE base64; its content is never read.
        let b64 = "UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAeAA=";
        for exe in POWERSHELLS {
            for switch in ["-EncodedCommand", "-encodedcommand", "-enc", "-ec", "-e"] {
                assert_eq!(
                    shell_route(exe, &format!("-NoProfile {switch} {b64}")),
                    purge_rpc::methods::Route::Medium,
                    "{exe} {switch}"
                );
            }
        }
    }

    #[test]
    fn positional_powershell_command_text_is_medium() {
        for exe in POWERSHELLS {
            for args in [
                r#""& .\uninstall.ps1""#,
                "Remove-VendorApp -Force",
                // Command text before a `-File`: the `-File` is part of the command, not a load path.
                r#"". .\evil.ps1" -File "C:\ProgramData\Vendor\uninstall.ps1""#,
                r#"-c ". .\evil.ps1" -File "C:\ProgramData\Vendor\uninstall.ps1""#,
                r#"/File "C:\ProgramData\Vendor\uninstall.ps1""#,
            ] {
                assert_eq!(
                    shell_route(exe, args),
                    purge_rpc::methods::Route::Medium,
                    "{exe} {args}"
                );
            }
        }
    }

    #[test]
    fn powershell_with_an_admin_only_file_is_still_medium() {
        // The profile and the auto-loaded modules are user-writable whatever the script is.
        for exe in POWERSHELLS {
            for args in [
                r#"-File "C:\ProgramData\Vendor\uninstall.ps1""#,
                r#"-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -file "C:\ProgramData\Vendor\uninstall.ps1" -Quiet"#,
                r#"-nop -ep Bypass -f "C:\ProgramData\Vendor\uninstall.ps1""#,
                r#"-NoProfile -File "C:\ProgramData\Vendor\uninstall.ps1""#,
                r#"-File "C:\Users\tester\AppData\Local\App\evil.cmd""#,
                r"-File .\uninstall.ps1",
                "-File",
            ] {
                assert_eq!(
                    shell_route(exe, args),
                    purge_rpc::methods::Route::Medium,
                    "{exe} {args}"
                );
            }
        }
        assert_eq!(
            shell_route(
                r"C:\Windows\System32\msiexec.exe",
                "/x {11111111-1111-1111-1111-111111111111} /qn"
            ),
            purge_rpc::methods::Route::Broker,
            "msiexec with a ProductCode is unchanged"
        );
        assert_eq!(
            shell_route(
                r"C:\Windows\System32\msiexec.exe",
                "/X{11111111-1111-1111-1111-111111111111}"
            ),
            purge_rpc::methods::Route::Broker,
            "msiexec with a ProductCode is unchanged"
        );
    }

    fn qc(exe: &str) -> QuietCommand {
        QuietCommand {
            exe: exe.to_owned(),
            args: String::new(),
            generated: false,
            kind: InstallerKind::Unknown,
        }
    }

    #[test]
    fn running_roots_leave_out_windows_hosts_and_the_windows_directory() {
        let mut entry = entry("App_is1", "App");
        // An MSI: msiexec in System32, no install location: nothing is "the program's folder".
        let msi = UninstallCommands {
            command: Some(qc(r"C:\Windows\System32\msiexec.exe")),
            quiet: Some(qc(r"C:\WINDOWS\system32\MsiExec.exe")),
        };
        assert!(running_roots(&entry, &msi, r"C:\Windows").is_empty());
        assert!(
            running_roots(&entry, &msi, "").is_empty(),
            "the host rule holds without a Windows directory"
        );
        // An old uninstaller in the Windows directory itself (IsUninst.exe) is no root either.
        let windows = UninstallCommands {
            command: Some(qc(r"C:\Windows\IsUninst.exe")),
            quiet: None,
        };
        assert!(running_roots(&entry, &windows, r"C:\Windows\").is_empty());
        // The install location and a real program folder stay; a sibling of Windows is not inside it.
        entry.install_location = Some(r"C:\Program Files\7-Zip\".to_owned());
        let app = UninstallCommands {
            command: Some(qc(r"C:\Program Files\7-Zip\Uninstall.exe")),
            quiet: Some(qc(r"C:\WindowsApps2\Vendor\unins000.exe")),
        };
        assert_eq!(
            running_roots(&entry, &app, r"C:\Windows"),
            vec![
                r"C:\Program Files\7-Zip".to_owned(),
                r"C:\WindowsApps2\Vendor".to_owned()
            ]
        );
        entry.install_location = Some(r"C:\Windows\System32".to_owned());
        assert!(
            running_roots(&entry, &msi, r"C:\Windows").is_empty(),
            "an install location inside Windows is not a program folder"
        );
    }

    const CMD: &str = r"C:\Windows\System32\cmd.exe";

    #[test]
    fn cmd_without_d_before_c_is_medium() {
        // Without `/d` cmd runs HKCU's Command Processor AutoRun first.
        for args in [
            r#"/c "C:\ProgramData\Vendor\uninstall.cmd""#,
            r#"/k "C:\ProgramData\Vendor\uninstall.cmd""#,
            r#"/r "C:\ProgramData\Vendor\uninstall.cmd""#,
            r#"/q /c "C:\ProgramData\Vendor\uninstall.cmd""#,
            // `/d` after `/c` is command text.
            r#"/c /d "C:\ProgramData\Vendor\uninstall.cmd""#,
            r#"/C "C:\ProgramData\Vendor\uninstall.cmd" /D"#,
            // A switch spelling cmd does not document ends the walk.
            r#"/d/c "C:\ProgramData\Vendor\uninstall.cmd""#,
            r#"-d /c "C:\ProgramData\Vendor\uninstall.cmd""#,
            r#""C:\ProgramData\Vendor\uninstall.cmd""#,
        ] {
            assert_eq!(
                shell_route(CMD, args),
                purge_rpc::methods::Route::Medium,
                "{args}"
            );
        }
        for args in [
            r#"/d /c "C:\ProgramData\Vendor\uninstall.cmd""#,
            r#"/D /C "C:\ProgramData\Vendor\uninstall.cmd""#,
            r#"/q /d /e:on /v:off /c "C:\ProgramData\Vendor\uninstall.cmd" /silent"#,
            r#"/d /k "C:\ProgramData\Vendor\uninstall.cmd""#,
            r#"/d /r "C:\ProgramData\Vendor\uninstall.cmd""#,
        ] {
            assert_eq!(
                shell_route(CMD, args),
                purge_rpc::methods::Route::Broker,
                "an admin-only script with /d first stays broker-route: {args}"
            );
        }
    }

    #[test]
    fn cmd_running_another_host_or_a_second_program_is_medium() {
        let b64 = "UgBlAG0AbwB2AGUALQBJAHQAZQBtACAAeAA=";
        for args in [
            format!("/d /c powershell -NoProfile -EncodedCommand {b64}"),
            format!(
                r#"/d /c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -enc {b64}"#
            ),
            r#"/d /c "C:\Program Files\PowerShell\7\pwsh.exe" -File "C:\ProgramData\Vendor\uninstall.ps1""#.into(),
            r"/d /c C:\Windows\System32\cmd.exe /c C:\ProgramData\Vendor\uninstall.cmd".into(),
            r"/d /c CMD /d /c C:\ProgramData\Vendor\uninstall.cmd".into(),
            r"/d /c msiexec /x {11111111-1111-1111-1111-111111111111}".into(),
            r"/d /c rundll32.exe C:\ProgramData\Vendor\vendor.dll,Entry".into(),
            r"/d /c C:\ProgramData\Vendor\uninstall.cmd & evil.cmd".into(),
            r"/d /c C:\ProgramData\Vendor\uninstall.cmd&&evil.cmd".into(),
            r"/d /c C:\ProgramData\Vendor\uninstall.cmd | more".into(),
            r"/d /c C:\ProgramData\Vendor\uninstall.cmd,evil".into(),
        ] {
            assert_eq!(
                shell_route(CMD, &args),
                purge_rpc::methods::Route::Medium,
                "{args}"
            );
        }
    }

    #[test]
    fn a_comma_never_turns_a_user_writable_load_path_admin_only() {
        // `C:\ProgramData\Vendor,x` is user-writable; cut at the comma it reads `C:\ProgramData\Vendor`,
        // which is admin-only.
        for (exe, args) in [
            (
                r"C:\Windows\System32\msiexec.exe",
                r#"/i "C:\ProgramData\Vendor,x\evil.msi" /qn"#,
            ),
            (CMD, r#"/d /c "C:\ProgramData\Vendor,x\evil.cmd""#),
            (
                r"C:\Windows\System32\rundll32.exe",
                r#""C:\ProgramData\Vendor,x\evil.dll",Entry"#,
            ),
        ] {
            assert_eq!(
                shell_route(exe, args),
                purge_rpc::methods::Route::Medium,
                "{exe} {args}"
            );
        }
        for args in [
            r#""C:\ProgramData\Vendor\vendor.dll",Entry"#,
            r"C:\ProgramData\Vendor\vendor.dll,Entry",
        ] {
            assert_eq!(
                shell_route(r"C:\Windows\System32\rundll32.exe", args),
                purge_rpc::methods::Route::Broker,
                "an admin-only DLL stays broker-route: {args}"
            );
        }
        for args in [
            // No extension: the loader would add `.dll`, so the path is not the one judged.
            r"C:\ProgramData\Vendor,Entry",
            r#""C:\ProgramData\Vendor\vendor.dll"#,
            "",
            // Unquoted with a space: `C:\Program` is not the admin-only DLL.
            r"C:\Program Files\Vendor Tools\tools.dll,Entry",
        ] {
            assert_eq!(
                shell_route(r"C:\Windows\System32\rundll32.exe", args),
                purge_rpc::methods::Route::Medium,
                "{args}"
            );
        }
        assert_eq!(
            shell_route(
                r"C:\Windows\System32\rundll32.exe",
                r#""C:\Program Files\Vendor Tools\tools.dll",Entry"#
            ),
            purge_rpc::methods::Route::Broker,
            "the same DLL quoted"
        );
    }

    #[test]
    fn a_file_in_a_folder_users_may_add_to_is_medium() {
        // Review M3-R2 H3: the files under `C:\ProgramData\Open` are admin-only, the folder is not.
        for (exe, args) in [
            (r"C:\ProgramData\Open\unins000.exe", "/S"),
            (CMD, r"/d /c C:\ProgramData\Open\uninstall.cmd"),
            (
                r"C:\Windows\System32\rundll32.exe",
                r"C:\ProgramData\Open\vendor.dll,Entry",
            ),
            (
                r"C:\Windows\System32\msiexec.exe",
                r"/i C:\ProgramData\Open\vendor.msi /qn",
            ),
            (
                r"C:\Program Files\App\unins000.exe",
                r"/config=C:\ProgramData\Open\vendor.dll",
            ),
        ] {
            assert_eq!(
                shell_route(exe, args),
                purge_rpc::methods::Route::Medium,
                "{exe} {args}"
            );
        }
        // Under a Program Files-like folder the same commands are broker-route.
        for (exe, args) in [
            (r"C:\Program Files\App\unins000.exe", "/S"),
            (CMD, r#"/d /c "C:\Program Files\App\uninstall.cmd""#),
            (CMD, r#"/d /c "C:\Program Files\App\uninstall.cmd" /silent"#),
        ] {
            assert_eq!(
                shell_route(exe, args),
                purge_rpc::methods::Route::Broker,
                "{exe} {args}"
            );
        }
    }

    #[test]
    fn cmd_quote_stripping_that_could_change_the_program_is_medium() {
        // Review M3-R2 M3: without these, cmd keeps the quotes; with them it strips the first and the
        // last quote, and `C:\ProgramData\My` is what runs.
        for args in [
            r#"/d /s /c "C:\ProgramData\My Vendor\uninstall.cmd""#,
            r#"/s /d /c "C:\ProgramData\My Vendor\uninstall.cmd""#,
            r#"/d /c "C:\ProgramData\My Vendor\uninstall.cmd" "/log""#,
            r#"/d /c "C:\ProgramData\My Vendor (x64)\uninstall.cmd""#,
            r#"/d /c C:\ProgramData\Vendor\uninstall.cmd "/log""#,
            r#"/d /c "C:\ProgramData\Vendor\uninstall.cmd"/log"#,
            r#"/d /c "C:\ProgramData\Vendor\uninstall.cmd"#,
            r"/d /c @C:\ProgramData\Vendor\uninstall.cmd",
            // M4: no extension.
            r"/d /c C:\ProgramData\Vendor\uninstall",
            r#"/d /c "C:\ProgramData\Vendor\uninstall""#,
            // A relative program is found through the current directory and `PATH`.
            "/d /c uninstall.cmd",
            r"/d /c Vendor\uninstall.cmd",
            // Delayed expansion.
            "/d /v:on /c x.cmd !X!",
            r"/d /v:on /c C:\ProgramData\Vendor\uninstall.cmd !X!",
            // A host, quoted and without `.exe`.
            r#"/d /c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell""#,
            r#"/d /c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell" -enc AAAA"#,
            // A quote in a switch before `/c`.
            r#"/d "/c" C:\ProgramData\Vendor\uninstall.cmd"#,
        ] {
            assert_eq!(
                shell_route(CMD, args),
                purge_rpc::methods::Route::Medium,
                "{args}"
            );
        }
        for args in [
            r#"/d /c "C:\ProgramData\My Vendor\uninstall.cmd""#,
            r#"/d /c "C:\ProgramData\My Vendor\uninstall.cmd" /log"#,
            r"/d /c C:\ProgramData\Vendor\uninstall.cmd /log",
        ] {
            assert_eq!(
                shell_route(CMD, args),
                purge_rpc::methods::Route::Broker,
                "{args}"
            );
        }
    }

    #[test]
    fn a_host_named_in_a_launchers_arguments_is_medium() {
        // Review M3-R2 M7: the launcher is admin-only, the interpreter it starts is not judged.
        for (exe, args) in [
            (
                r"C:\Windows\System32\conhost.exe",
                r#"--headless powershell.exe -ExecutionPolicy Bypass -File "C:\Program Files\App\un.ps1""#,
            ),
            (
                r"C:\Windows\System32\rundll32.exe",
                r"C:\Windows\System32\shell32.dll,ShellExec_RunDLL powershell.exe -enc AAAA",
            ),
            (
                CMD,
                r"/d /c C:\Windows\System32\conhost.exe --headless powershell -enc AAAA",
            ),
            (
                r"C:\Windows\System32\conhost.exe",
                r#"--headless "C:\Program Files\nodejs\node.exe" x.js"#,
            ),
            (
                r"C:\Windows\System32\rundll32.exe",
                r"C:\Windows\System32\shell32.dll,ShellExec_RunDLL,python",
            ),
            (
                r"C:\Program Files\App\unins000.exe",
                r"/RUNAFTER=C:\Windows\System32\cmd.exe",
            ),
            (
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe",
                r#""C:\Program Files\App\un.ps1""#,
            ),
            (r"C:\Program Files\dotnet\dotnet.exe", "app.dll"),
            (
                r"C:\Program Files\dotnet\dotnet.exe",
                r#""C:\Program Files\App\app.dll""#,
            ),
        ] {
            assert_eq!(
                shell_route(exe, args),
                purge_rpc::methods::Route::Medium,
                "{exe} {args}"
            );
        }
        // Ordinary vendor arguments, and names that merely contain a host's, are not hosts.
        for args in [
            r#"/S /LOG="C:\Program Files\App\u.log""#,
            "--uninstall /VERYSILENT /SUPPRESSMSGBOXES",
            "--remove-node-modules /python-cleanup -sh",
            r#""/D=C:\Program Files\App""#,
        ] {
            assert_eq!(
                shell_route(r"C:\Program Files\App\unins000.exe", args),
                purge_rpc::methods::Route::Broker,
                "{args}"
            );
        }
        for token in [
            "powershell.exe",
            r"C:\x\NODE.EXE",
            "a.dll,Entry,pwsh",
            "X=cscript",
        ] {
            assert!(token_names_a_host(token), "{token}");
        }
        for token in [
            "/S",
            "-py",
            "/sh",
            "--node",
            "powershell-tools",
            "unins000.exe",
        ] {
            assert!(!token_names_a_host(token), "{token}");
        }
    }

    #[test]
    fn a_host_after_a_colon_or_behind_a_short_name_is_medium() {
        // Fable's optional follow-ups to the sixth review: `:` parts and 8.3 names.
        const UNINS: &str = r"C:\Program Files\App\unins000.exe";
        for (exe, args) in [
            (UNINS, "/RUN:powershell"),
            (UNINS, "/RUN:powershell.exe -enc AAAA"),
            (UNINS, r"--exec:C:\Windows\System32\cmd.exe"),
            (UNINS, "-shell:pwsh"),
            (
                UNINS,
                r"/RUN:C:\Windows\System32\WindowsPowerShell\v1.0\POWERS~1.EXE",
            ),
            (
                r"C:\Windows\System32\conhost.exe",
                "--headless POWERS~1.EXE",
            ),
            (
                r"C:\Windows\System32\conhost.exe",
                r"--headless C:\Windows\System32\WindowsPowerShell\v1.0\POWERS~1.EXE",
            ),
            (
                r"C:\Windows\System32\WindowsPowerShell\v1.0\POWERS~1.EXE",
                "-enc AAAA",
            ),
            (r"C:\Program Files\App\UNINST~1.EXE", "/S"),
            (
                r"C:\Windows\System32\conhost.exe",
                "--headless powershell.exe.",
            ),
            (
                r"C:\Windows\System32\conhost.exe",
                r#"--headless "powershell.exe ""#,
            ),
        ] {
            assert_eq!(
                shell_route(exe, args),
                purge_rpc::methods::Route::Medium,
                "{exe} {args}"
            );
        }
        for args in [
            "/S",
            "/x /S",
            "-key:value /mode:silent",
            "--url=http://example.com/a",
            r#""/LOG=C:\Program Files\App\u.log""#,
            r#"/LOG:"C:\Program Files\App\u.log""#,
        ] {
            assert_eq!(
                shell_route(UNINS, args),
                purge_rpc::methods::Route::Broker,
                "{args}"
            );
        }
        for name in [
            "powershell.exe.",
            "powershell.exe ",
            r"C:\x\PowerShell.EXE. .",
            "pwsh.",
        ] {
            assert!(is_interpreter(name), "{name:?}");
        }
        assert_eq!(
            program_parts(r"/RUN:C:\x\a.exe"),
            [r"/RUN:C:\x\a.exe", r"C:\x\a.exe"]
        );
        assert_eq!(program_parts(r"C:\x\a.exe"), [r"C:\x\a.exe"]);
        assert!(is_short_name(r"C:\x\POWERS~1.EXE"));
        assert!(!is_short_name(r"C:\PROGRA~1\App\unins000.exe"));
        assert!(!is_short_name("a~b.txt"));
    }

    #[test]
    fn interpreters_and_script_hosts_are_medium() {
        // Coordinator ruling after the fourth Fable review: an interpreter also loads code from
        // per-user places (Python's user site-packages, ...), so an admin-only script is not enough.
        for (exe, args) in [
            (
                r"C:\Program Files\Python312\python.exe",
                r#""C:\Program Files\App\uninstall.py""#,
            ),
            (
                r"C:\Program Files\Python312\python3.12.exe",
                r#"-I "C:\Program Files\App\uninstall.py""#,
            ),
            (
                r"C:\Program Files\nodejs\node.exe",
                r#""C:\Program Files\App\uninstall.js""#,
            ),
            (
                r"C:\Program Files\Java\bin\java.exe",
                r#"-jar "C:\Program Files\App\uninstall.jar""#,
            ),
            (r"C:\Windows\System32\wsl.exe", "-e /opt/app/uninstall.sh"),
            (
                r"C:\Windows\System32\wscript.exe",
                r#""C:\Program Files\App\uninstall.vbs""#,
            ),
            (CMD, r#"/d /c python "C:\Program Files\App\uninstall.py""#),
            (
                CMD,
                r#"/d /c "C:\Program Files\nodejs\node.exe" "C:\Program Files\App\uninstall.js""#,
            ),
            (CMD, r"/d /c wsl.exe -e /opt/app/uninstall.sh"),
        ] {
            assert_eq!(
                shell_route(exe, args),
                purge_rpc::methods::Route::Medium,
                "{exe} {args}"
            );
        }
        for name in [
            "python",
            "PYTHONW.EXE",
            "python3.11.exe",
            "py",
            r"C:\x\node.exe",
            "forfiles",
            "msbuild.exe",
            "cmstp",
            "sdbinst.exe",
        ] {
            assert!(is_interpreter(name), "{name}");
        }
        for name in [
            "unins000.exe",
            "cmd.exe",
            "msiexec",
            "rundll32.exe",
            "pyinstaller-app.exe",
            "python-3.12.0-amd64.exe",
        ] {
            assert!(!is_interpreter(name), "{name}");
        }
        // The judged hosts keep their rules.
        assert_eq!(
            shell_route(
                r"C:\Windows\System32\regsvr32.exe",
                r#"/u /s "C:\Program Files\App\vendor.dll""#
            ),
            purge_rpc::methods::Route::Broker,
            "regsvr32 with an admin-only DLL"
        );
    }

    #[test]
    fn a_missing_argument_file_is_judged_by_its_nearest_existing_folder() {
        // Review M3-R2 M5: a file that does not exist yet can be created while the dialog is open.
        const UNINS: &str = r"C:\Program Files\App\unins000.exe";
        for args in [
            r"/LOADINF=C:\Users\tester\AppData\Local\App\new.inf",
            r"/LOADINF=C:\Users\tester\new\deeper\new.inf",
            r#""/LOG=C:\Users\tester\AppData\Local\App\uninstall.log""#,
            // `C:\ProgramData` lets users add files and folders.
            r"/LOG=C:\ProgramData\uninstall.log",
            r"/LOG=C:\ProgramData\NewVendor\uninstall.log",
            r"/LOADINF=\\server\share\new.inf",
            r"/LOADINF=Q:\nowhere\new.inf",
            // L4: a leading `//` is a UNC path too.
            "/LOADINF=//localhost/c$/Users/tester/new.inf",
            "//example.com/c",
            // Unquoted with a space: the uninstaller reads `C:\Program`, whose folder is `C:\`.
            r"/LOADINF=C:\Program Files\App\new.inf",
        ] {
            assert_eq!(
                shell_route(UNINS, args),
                purge_rpc::methods::Route::Medium,
                "{args}"
            );
        }
        for args in [
            r#""/LOADINF=C:\Program Files\App\new.inf""#,
            r#""/LOG=C:\Program Files\App\logs\deeper\uninstall.log""#,
            r#"/LOG="C:/Program Files/App/uninstall.log""#,
            // Not paths: switches, values with a colon, URLs, a GUID, a relative name.
            "/S /VERYSILENT",
            "-key:value --mode:quiet x:1 /D=x:1",
            "--url=http://example.com/a;https://example.com/b",
            "{11111111-1111-1111-1111-111111111111} logs\\uninstall.log",
        ] {
            assert_eq!(
                shell_route(UNINS, args),
                purge_rpc::methods::Route::Broker,
                "{args}"
            );
        }
    }

    #[test]
    fn a_user_writable_file_in_a_name_value_argument_is_medium() {
        // Review M3-R2 L3: the value after `=` and each `;`-separated part are judged.
        for args in [
            r"/x {11111111-1111-1111-1111-111111111111} TRANSFORMS=C:\Users\tester\AppData\Local\App\evil.mst;b.mst",
            r"/x {11111111-1111-1111-1111-111111111111} TRANSFORMS=C:\Users\tester\AppData\Local\App\evil.mst",
            r"/x {11111111-1111-1111-1111-111111111111} TRANSFORMS=C:\ProgramData\Vendor\vendor.mst;C:\Users\tester\AppData\Local\App\evil.mst",
            r#"/x {11111111-1111-1111-1111-111111111111} "TRANSFORMS=C:\ProgramData\Vendor\vendor.mst;C:\Users\tester\AppData\Local\App\evil.mst""#,
        ] {
            assert_eq!(
                shell_route(r"C:\Windows\System32\msiexec.exe", args),
                purge_rpc::methods::Route::Medium,
                "{args}"
            );
        }
        assert_eq!(
            shell_route(
                r"C:\Windows\System32\msiexec.exe",
                r"/x {11111111-1111-1111-1111-111111111111} TRANSFORMS=C:\ProgramData\Vendor\vendor.mst /qn"
            ),
            purge_rpc::methods::Route::Broker,
            "an admin-only transform"
        );
        assert_eq!(
            path_parts(r"A=C:\a;C:\b,c"),
            [
                r"A=C:\a;C:\b,c",
                r"A=C:\a;C:\b",
                r"A=C:\a",
                r"C:\b,c",
                r"C:\b",
                r"C:\a;C:\b,c",
                r"C:\a;C:\b",
                r"C:\a",
                r"C:\b,c",
                r"C:\b",
            ]
        );
    }

    #[test]
    fn program_ids_resolve_by_full_id_or_unique_key_name() {
        let mut user = entry("Dup", "Dup (user)");
        user.program_id = ProgramId::user(SID, View::K64, "Dup").unwrap();
        let inv = doc(vec![entry("Git_is1", "Git"), entry("Dup", "Dup"), user]);
        assert_eq!(
            find_entry(&inv, "HKLM|64|Git_is1").unwrap().display_name,
            "Git"
        );
        assert_eq!(find_entry(&inv, "git_IS1").unwrap().display_name, "Git");
        assert!(matches!(
            find_entry(&inv, "HKLM|32|Git_is1"),
            Err(PipelineError::Precondition(_))
        ));
        let err = find_entry(&inv, "Dup").unwrap_err().to_string();
        assert!(err.contains("2 inventory entries"), "{err}");
        assert!(find_entry(&inv, "nothing").is_err());
    }

    #[test]
    fn time_zone_bias_is_read_as_signed_minutes() {
        let mut f = Fixture::new();
        assert_eq!(utc_offset_secs(&f), 0);
        let key = r"HKLM\SYSTEM\ControlSet001\Control\TimeZoneInformation";
        f.set_value(key, "ActiveTimeBias", RegData::from_dword((-60i32) as u32));
        assert_eq!(utc_offset_secs(&f), 3600);
        f.set_value(key, "ActiveTimeBias", RegData::from_dword(300));
        assert_eq!(utc_offset_secs(&f), -5 * 3600);
    }

    #[test]
    fn other_apps_take_roots_files_keys_and_icon_names() {
        let guard = GuardEnv::sample();
        let deny = DenyList::compile(&guard);
        let env: EnvMap = [("PROGRAMFILES", r"C:\Program Files")]
            .into_iter()
            .collect();
        let mut mail = entry("Mail", "Example Mail");
        mail.install_location = Some(r"%PROGRAMFILES%\Example Mail\".into());
        mail.uninstall_string =
            Some(r#""C:\Program Files\Example Mail\uninstall\helper.exe""#.into());
        mail.display_icon = Some(r"C:\Program Files\Example Mail\mail.exe,0".into());
        let mut broad = entry("Broad", "Broad");
        broad.install_location = Some(r"C:\Program Files".into());
        broad.uninstall_string = Some(r"MsiExec.exe /X{1}".into());
        broad.display_icon = Some(r"C:\Windows\System32\shell32.dll,3".into());
        let target = entry("Target", "Target");
        let excluded = target.program_id.clone();
        let apps = other_apps(&[mail, broad, target], &[&excluded], &env, &guard, &deny);
        assert_eq!(apps.len(), 2);
        let mail = &apps[0];
        assert_eq!(mail.roots, [r"C:\Program Files\Example Mail"]);
        assert_eq!(
            mail.files,
            [
                r"C:\Program Files\Example Mail\uninstall\helper.exe",
                r"C:\Program Files\Example Mail\mail.exe"
            ]
        );
        assert_eq!(
            mail.keys,
            [r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Mail"]
        );
        assert_eq!(
            mail.anchors,
            [AnchorRef {
                kind: AnchorKind::Exe,
                text: "mail.exe".into()
            }]
        );
        // Program Files itself is no root; a relative uninstaller and a file in Windows are no anchors.
        let broad = &apps[1];
        assert!(broad.roots.is_empty() && broad.files.is_empty() && broad.anchors.is_empty());
    }

    #[test]
    fn icon_values_lose_their_index_and_uninstallers_are_not_named_anchors() {
        assert_eq!(icon_file(r#""C:\A\b.exe",-3"#), r"C:\A\b.exe");
        assert_eq!(icon_file(r"C:\A,B\b.exe"), r"C:\A,B\b.exe");
        assert!(uninstaller_name("unins000.exe") && uninstaller_name("Uninstall.exe"));
        assert!(!uninstaller_name("firefox.exe"));
    }

    #[test]
    fn purge_dirs_that_do_not_canonicalise_are_dropped() {
        let guard = GuardEnv::sample();
        let mut warnings = Vec::new();
        let dirs = canonical_dirs(
            &[
                r"C:\cr\bin\".into(),
                r"\\server\share\x".into(),
                "relative".into(),
                r"c:\CR\bin".into(),
                r"\\?\C:\ProgramData\Purge".into(),
            ],
            &guard,
            &mut warnings,
        );
        assert_eq!(dirs, [r"C:\cr\bin", r"C:\ProgramData\Purge"]);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
    }

    /// Without `PURGE_TIMING` the line of a loaded baseline is the one the engine printed before the
    /// timing counters existed (review M6); with it, the record counts follow.
    #[test]
    fn baseline_line_carries_counts_only_with_timing() {
        let n = RecordCounts {
            keys: 1,
            values: 2,
            dirs: 3,
            files: 4,
        };
        assert_eq!(
            baseline_loaded("Professional-1.2", n, false),
            "baseline Professional-1.2 loaded"
        );
        assert_eq!(
            baseline_loaded("Professional-1.2", n, true),
            "baseline Professional-1.2 loaded: 1 keys, 2 values, 3 dirs, 4 files"
        );
    }

    /// The `PURGE_TIMING` line of the MSI table cache names the cache and counts its lookups, without
    /// changing what the cache answers.
    #[test]
    fn table_cache_timing_line_counts_hits_and_misses() {
        let inner = MemTableCache::new();
        let cache = CountingCache::new(&inner);
        let key = CacheKey {
            local_package: r"C:\Windows\Installer\1a2b.msi".into(),
            size: 10,
            mtime: 20,
        };
        assert!(cache.get(&key).is_none());
        let tables = MsiTables {
            custom_action_count: 3,
            ..MsiTables::default()
        };
        cache.put(&key, &tables);
        assert_eq!(cache.get(&key), Some(tables.clone()));
        assert_eq!(inner.get(&key), Some(tables));
        let settings = Settings {
            msi_table_dir: Some(PathBuf::from(r"C:\ProgramData\Purge\fp\msitables")),
            ..Settings::default()
        };
        assert_eq!(
            cache.timing_line(TableCacheKind::Memory, &settings),
            "msi_table_cache memory hits=1 misses=1"
        );
        assert_eq!(
            cache.timing_line(TableCacheKind::Disk, &settings),
            r"msi_table_cache disk C:\ProgramData\Purge\fp\msitables hits=1 misses=1"
        );
    }

    #[test]
    fn baselines_are_only_used_for_an_exact_match() {
        let os = OsInfo {
            edition: "Professional".into(),
            build: 1,
            ubr: 2,
        };
        let mut warnings = Vec::new();
        assert!(load_baseline(None, &os, &mut warnings).is_none());
        assert!(warnings.is_empty());
        let dir = std::env::temp_dir();
        assert!(load_baseline(Some(&dir), &os, &mut warnings).is_none());
        assert!(
            warnings[0].contains("Professional-1.2.tsv.gz"),
            "{warnings:?}"
        );
    }
}
