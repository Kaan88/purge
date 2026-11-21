//! The baseline of a pipeline step: the view, its cache and the background build
//! (BASELINE_LOCAL_DESIGN.md §4.1, §5; package BL-CACHE; DECISIONS 2026-11-21).
//!
//! # What a step gets ([`load`])
//!
//! | Case | View | What happens |
//! |---|---|---|
//! | A shipped baseline of exactly this Windows | Exact | That file is loaded as before. No cache directory is opened or created, no source id is read, nothing is built (L3). |
//! | No exact one, cached local baseline | Merged or Local when the engine is elevated and every part is current and complete; None otherwise | The parts are loaded (the S1 part from its derived binary form), `HKU\.DEFAULT` is read live, the neighbours are loaded through their derived forms. |
//! | No exact one, no cache, elevated | None | The view holds the neighbours. The background build ([`start_local_build`]) makes the parts; this step does not wait for it, tells the build that a scan is waiting (it leaves background priority) and says in a warning that a later scan uses the result. |
//! | No exact one, no cache, not elevated | None | The view holds the neighbours. Nothing is built or written; a warning says so. |
//!
//! An engine that is not elevated never has a complete local baseline: it cannot read all of
//! `HKU\.DEFAULT` and cannot check the S4 part against every user's packages
//! (`purge_index::local_baseline::cache`). Its view is None and still answers presence from all it
//! has.
//!
//! # The shipped directory
//!
//! With [`Settings::check_shipped_dir`] (the live engine sets it), an elevated engine uses
//! `kb\baselines` only when the file system source says that administrators and the system alone can
//! write it and every ancestor. Otherwise no shipped baseline is used at all, exact or neighbour, and
//! a warning says why: a standard user who could change those files could remove a line and make a
//! Windows key look absent. The two files an absence answer rests on, the exact baseline and
//! `view.json`, are then judged themselves as well ([`shipped_file_trusted`]): the directory's answer
//! says who can add or remove files, not who can write a file that was moved into it. A neighbour
//! only ever adds presence, so its file is not judged.
//!
//! # The background build (W4 as restated 2026-11-21)
//!
//! [`start_local_build`] is called once when the engine starts (the CLI: at the start of `harvest`,
//! `uninstall` and `scan`; the broker in M3). It returns at once. On a thread of the caller's scope it
//! decides whether anything is missing and builds the missing parts at background priority, the
//! cheap ones first. It never runs at logon: only an engine that was started builds. [`LocalBuild`]
//! is its state for `engine.hello` ([`PipelineBaseline::status`]).

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::Scope;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use purge_index::baseline::{Baseline, RecordCounts};
use purge_index::baseline_view::{BaselineView, HostOs, VIEW_FILE_NAME, ViewRules};
use purge_index::local_baseline::cache::{load_neighbours, read_live_s3};
use purge_index::local_baseline::{
    BuildControl, BuildOptions, FileStamps, LocalCache, LocalSource, PartIds, PartState,
    SealFloors, build_part, iso_utc,
};
use purge_model::{BaselineTrust, BaselineViewRef, OsInfo};
use purge_rpc::{BaselineBuild, BaselineStatus};
use purge_source::local_baseline::LocalSources;
use purge_win::sxs::SxsBase;

use super::{Settings, Sources, load_baseline};

/// What a pipeline step knows about "Windows' own": the view, and how it came about.
#[derive(Debug, Clone)]
pub struct PipelineBaseline {
    /// The view the harvest and the scan work with. Exact: the shipped baseline of this Windows
    /// and nothing else.
    pub view: BaselineView,
    /// The record counts of the exact shipped baseline, when the view is Exact (the progress line).
    exact_counts: Option<RecordCounts>,
    /// A baseline directory is configured.
    configured: bool,
    /// How each cached part of the local baseline answered; `None` when no cache was opened.
    pub parts: Option<[(LocalSource, PartState); 3]>,
}

impl PipelineBaseline {
    /// No baseline directory: an empty view of trust None, as the engine was without one.
    pub fn unconfigured() -> PipelineBaseline {
        PipelineBaseline {
            view: BaselineView::none(
                &HostOs::new("", 0, 0),
                None,
                Vec::new(),
                &ViewRules::closed(),
            ),
            exact_counts: None,
            configured: false,
            parts: None,
        }
    }

    /// The record counts of the exact shipped baseline, when the view is Exact.
    pub fn exact_counts(&self) -> Option<RecordCounts> {
        self.exact_counts
    }

    /// The view's trust.
    pub fn trust(&self) -> BaselineTrust {
        self.view.trust()
    }

    /// The view as `engine.hello` names it, with the view's own trust; `None` without a baseline
    /// directory. (What a fingerprint records is `purge_harvest::harvest::baseline_view_ref`.)
    pub fn view_ref(&self) -> Option<BaselineViewRef> {
        self.configured.then(|| BaselineViewRef {
            name: self.view.name(),
            trust: self.trust(),
            local_id: self.view.local_id().map(str::to_owned),
        })
    }

    /// The baseline fields of `engine.hello`. `build`: this process's background build, if one was
    /// started.
    pub fn status(&self, build: Option<&LocalBuild>) -> BaselineStatus {
        BaselineStatus {
            baseline_available: self.trust() == BaselineTrust::Exact,
            baseline_trust: self.trust(),
            baseline_view: self.view_ref(),
            baseline_build: build.map_or_else(
                || BaselineBuild::None {
                    reason: "no build was started in this process".into(),
                },
                LocalBuild::state,
            ),
        }
    }
}

/// Whether the shipped baseline directory may be used: always, unless the settings ask for the
/// check and the engine is elevated; then only when it is admin-only writable.
fn shipped_dir_trusted(sources: Sources<'_>, settings: &Settings, dir: &Path) -> bool {
    !settings.check_shipped_dir
        || !sources.sys.elevated()
        || dir
            .to_str()
            .is_some_and(|d| sources.fs.is_admin_only_writable(d) == Ok(true))
}

/// Whether one file of a shipped directory that passed [`shipped_dir_trusted`] may be used: under
/// the same conditions, only when the file itself is admin-only writable. The directory's answer
/// does not cover it: a file moved into the directory keeps the owner and the grants it had where
/// it came from, a hard link shares them with its other name, and an inherit-only grant on the
/// directory reaches the files and not the directory.
fn shipped_file_trusted(sources: Sources<'_>, settings: &Settings, file: &Path) -> bool {
    !settings.check_shipped_dir
        || !sources.sys.elevated()
        || file
            .to_str()
            .is_some_and(|f| sources.fs.is_admin_only_writable(f) == Ok(true))
}

/// The shipped baseline of exactly `os` in the trusted directory `dir`, when its file exists and
/// may be used: `Ok(Some(path))`. `Ok(None)`: there is no such file. `Err(path)`: the file is there
/// and a standard user can write it.
fn exact_file(
    sources: Sources<'_>,
    settings: &Settings,
    dir: &Path,
    os: &OsInfo,
) -> Result<Option<PathBuf>, PathBuf> {
    let file = dir.join(Baseline::file_name(&os.edition, os.build, os.ubr));
    if !file.is_file() {
        Ok(None)
    } else if shipped_file_trusted(sources, settings, &file) {
        Ok(Some(file))
    } else {
        Err(file)
    }
}

fn user_writable_warning(file: &Path) -> String {
    format!(
        "baseline: {} can be written by a standard user (or its protection could not be read); \
         it is not used",
        file.display()
    )
}

/// The local baseline cache of [`Settings::local_baseline_dir`], when the directory rule accepts it
/// (`LocalCache::open`). The directory is created only by an elevated engine and only inside a data
/// root (its parent, `<ProgramData>\Purge`) that exists and is itself admin-only writable; a
/// directory that fails the rule is ignored, never repaired. Writable only when elevated.
pub fn local_cache(sources: Sources<'_>, settings: &Settings) -> Option<LocalCache> {
    let dir = settings.local_baseline_dir.as_deref()?;
    let elevated = sources.sys.elevated();
    let admin_only = |p: &Path| {
        p.to_str()
            .is_some_and(|s| sources.fs.is_admin_only_writable(s) == Ok(true))
    };
    if elevated && !dir.is_dir() && dir.parent().is_some_and(admin_only) {
        // Failing to create it leaves the engine without a cache; the next run tries again.
        let _ = std::fs::create_dir(dir);
    }
    LocalCache::open(dir, sources.fs, elevated)
}

/// The baseline of a step for the Windows `os`. See the module documentation. Everything that
/// lowered the trust or was left out is a line in `warnings`.
pub fn load(
    sources: Sources<'_>,
    settings: &Settings,
    os: &OsInfo,
    warnings: &mut Vec<String>,
) -> PipelineBaseline {
    load_with(sources, settings, os, warnings, &local_cache)
}

/// [`load`] with the way the cache is opened, which is called only below Exact.
fn load_with(
    sources: Sources<'_>,
    settings: &Settings,
    os: &OsInfo,
    warnings: &mut Vec<String>,
    open_cache: &dyn Fn(Sources<'_>, &Settings) -> Option<LocalCache>,
) -> PipelineBaseline {
    let Some(dir) = settings.baseline_dir.as_deref() else {
        return PipelineBaseline::unconfigured();
    };
    let shipped = shipped_dir_trusted(sources, settings, dir);
    if !shipped {
        warnings.push(format!(
            "baseline: {} can be written by a standard user (or its protection could not be read); \
             no shipped baseline is used",
            dir.display()
        ));
    }
    let exact = if !shipped {
        None
    } else {
        match exact_file(sources, settings, dir, os) {
            Err(file) => {
                warnings.push(user_writable_warning(&file));
                None
            }
            // A missing file is `load_baseline`'s to report.
            Ok(_) => load_baseline(Some(dir), os, warnings),
        }
    };
    if let Some(exact) = exact {
        return PipelineBaseline {
            exact_counts: Some(exact.counts()),
            view: BaselineView::exact(exact),
            configured: true,
            parts: None,
        };
    }

    // Below Exact: the neighbours, and the local baseline from the cache.
    let started = Instant::now();
    let host = HostOs::from(os);
    let cache = open_cache(sources, settings);
    let cache = cache.as_ref();
    let (rules, neighbours, mut shipped_warnings, loaded, ids) = std::thread::scope(|scope| {
        let s3 = cache.map(|_| scope.spawn(|| read_live_s3(sources.reg)));
        let shipped_part = scope.spawn(|| {
            let mut w = Vec::new();
            if shipped {
                let view_file = dir.join(VIEW_FILE_NAME);
                let rules = if view_file.is_file()
                    && !shipped_file_trusted(sources, settings, &view_file)
                {
                    w.push(user_writable_warning(&view_file));
                    ViewRules::closed()
                } else {
                    ViewRules::load_or_closed(dir, &mut w)
                };
                let neighbours = load_neighbours(cache, dir, &host, rules.neighbours(), &mut w);
                (rules, neighbours, w)
            } else {
                (ViewRules::closed(), Vec::new(), w)
            }
        });
        let ids = cache.map(|_| PartIds::read(sources.reg, sources.fs, sources.sys));
        let loaded = match (cache, &ids, s3) {
            (Some(cache), Some(ids), Some(s3)) => {
                let s3 = s3
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
                Some(cache.load(os, ids, s3))
            }
            _ => None,
        };
        let (rules, neighbours, w) = shipped_part
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic));
        (rules, neighbours, w, loaded, ids)
    });
    warnings.append(&mut shipped_warnings);
    if let Some(ids) = &ids {
        warnings.extend(
            ids.problems
                .iter()
                .map(|p| format!("baseline: local baseline: {p}")),
        );
    }
    let (local, parts) = match loaded {
        Some(loaded) => {
            warnings.extend(
                loaded
                    .notes
                    .iter()
                    .map(|n| format!("baseline: local baseline cache: {n}")),
            );
            (loaded.local, Some(loaded.parts))
        }
        None => (None, None),
    };
    let view = BaselineView::assemble(&host, local, neighbours, &rules);
    warnings.extend(view.warnings().iter().cloned());
    cache_warning(sources, settings, cache, parts.as_ref(), warnings);
    warnings.push(format!(
        "baseline: the view {} has trust {}",
        view.name(),
        view.trust()
    ));
    if purge_source::metered::installed().is_some() {
        eprintln!(
            "timing: baseline.view.load {:.3} s ({}, trust {}, parts {})",
            started.elapsed().as_secs_f64(),
            view.name(),
            view.trust(),
            parts.as_ref().map_or_else(
                || "no cache".to_owned(),
                |parts| parts
                    .iter()
                    .map(|(source, state)| format!("{source}={state:?}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        );
    }
    PipelineBaseline {
        view,
        exact_counts: None,
        configured: true,
        parts,
    }
}

/// The warning that says why the local baseline is not there or not whole, and what happens next.
fn cache_warning(
    sources: Sources<'_>,
    settings: &Settings,
    cache: Option<&LocalCache>,
    parts: Option<&[(LocalSource, PartState); 3]>,
    warnings: &mut Vec<String>,
) {
    let elevated = sources.sys.elevated();
    let Some(dir) = settings.local_baseline_dir.as_deref() else {
        return;
    };
    let missing: Vec<String> = match (cache, parts) {
        (Some(_), Some(parts)) => parts
            .iter()
            .filter(|(_, state)| *state == PartState::Missing)
            .map(|(source, _)| source.to_string())
            .collect(),
        _ => {
            warnings.push(format!(
                "baseline: the local baseline cache {} is not used: it does not exist, this engine \
                 cannot read it, or a standard user can write it{}",
                dir.display(),
                if elevated {
                    ""
                } else {
                    "; the engine is not elevated, so it builds none"
                }
            ));
            return;
        }
    };
    if missing.is_empty() {
        return;
    }
    let missing = missing.join(", ");
    if !elevated {
        warnings.push(format!(
            "baseline: the cached local baseline lacks {missing}; the engine is not elevated, so \
             it builds nothing (an elevated run does)"
        ));
        return;
    }
    match &settings.local_build {
        Some(build) if build.in_progress() => {
            // A scan is waiting for what the build makes: the build stops yielding to other I/O.
            build.scan_waiting();
            warnings.push(format!(
                "baseline: this PC's local baseline is being built in the background ({missing} \
                 missing); this run does not wait for it and uses what exists. Scan again when \
                 the build has finished"
            ));
        }
        Some(build) => {
            build.scan_waiting();
            let why = match build.state() {
                BaselineBuild::Failed { reason } => format!("its build failed: {reason}"),
                BaselineBuild::Done { .. } => "its build ended after this run read the cache; \
                                               scan again"
                    .to_owned(),
                BaselineBuild::None { reason } => format!("nothing is built: {reason}"),
                _ => "its build has not finished".to_owned(),
            };
            warnings.push(format!(
                "baseline: the cached local baseline lacks {missing}; {why}"
            ));
        }
        None => warnings.push(format!(
            "baseline: the cached local baseline lacks {missing}; no build runs in this engine"
        )),
    }
}

// ---------------------------------------------------------------------------------------------------
// The background build

struct Shared {
    state: Mutex<BaselineBuild>,
    changed: Condvar,
    control: BuildControl,
    scan_seen: AtomicBool,
}

/// The background build of this engine process: its state, and the way a scan tells it that it is
/// waiting. Cloning gives another handle to the same build.
#[derive(Clone)]
pub struct LocalBuild {
    shared: Arc<Shared>,
}

impl fmt::Debug for LocalBuild {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("LocalBuild").field(&self.state()).finish()
    }
}

impl PartialEq for LocalBuild {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }
}

impl Eq for LocalBuild {}

impl LocalBuild {
    fn new(state: BaselineBuild) -> LocalBuild {
        LocalBuild {
            shared: Arc::new(Shared {
                state: Mutex::new(state),
                changed: Condvar::new(),
                control: BuildControl::new(),
                scan_seen: AtomicBool::new(false),
            }),
        }
    }

    /// The state now.
    pub fn state(&self) -> BaselineBuild {
        self.shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether the build is still deciding or building.
    pub fn in_progress(&self) -> bool {
        matches!(
            self.state(),
            BaselineBuild::Checking | BaselineBuild::Building { .. }
        )
    }

    /// A scan asked for the view and did not get the whole local baseline: the build's threads
    /// leave background priority, and the final state says that a rescan is worth it.
    pub fn scan_waiting(&self) {
        self.shared.scan_seen.store(true, Ordering::Relaxed);
        self.shared.control.raise_priority();
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let BaselineBuild::Building { scan_waiting, .. } = &mut *state {
            *scan_waiting = true;
        }
    }

    /// The build's threads leave background priority (nothing says that a scan is waiting).
    pub fn raise_priority(&self) {
        self.shared.control.raise_priority();
    }

    /// Blocks until the build is neither deciding nor building, and returns the final state. A scan
    /// never calls this; the CLI does before its process ends, so that the build it started is not
    /// lost.
    pub fn wait(&self) -> BaselineBuild {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        while matches!(
            *state,
            BaselineBuild::Checking | BaselineBuild::Building { .. }
        ) {
            state = self
                .shared
                .changed
                .wait(state)
                .unwrap_or_else(PoisonError::into_inner);
        }
        state.clone()
    }

    fn set(&self, state: BaselineBuild) {
        *self
            .shared
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = state;
        self.shared.changed.notify_all();
    }

    fn scan_seen(&self) -> bool {
        self.shared.scan_seen.load(Ordering::Relaxed)
    }
}

/// Starts the local baseline's background build for this engine process and returns at once.
///
/// `None`: no cache directory is configured. An engine that is not elevated gets a handle that says
/// so and starts no thread (it never builds and never writes). Otherwise a thread of `scope` decides
/// and builds: nothing when a shipped baseline of exactly this Windows exists (L3) or when every
/// part is cached; else the missing parts, read through `local` (with `base`, the delta base of the
/// component manifests, taken only when S1 is built), stored in the cache. Put the handle into
/// [`Settings::local_build`] so that the steps of this process see the build.
pub fn start_local_build<'scope, 'env, B>(
    scope: &'scope Scope<'scope, 'env>,
    sources: Sources<'env>,
    settings: &Settings,
    local: &'env dyn LocalSources,
    base: B,
) -> Option<LocalBuild>
where
    B: FnOnce() -> Result<SxsBase, String> + Send + 'scope,
{
    settings.local_baseline_dir.as_ref()?;
    if !sources.sys.elevated() {
        return Some(LocalBuild::new(BaselineBuild::None {
            reason: "the engine is not elevated".into(),
        }));
    }
    let build = LocalBuild::new(BaselineBuild::Checking);
    let handle = build.clone();
    let settings = Settings {
        local_build: None,
        ..settings.clone()
    };
    scope.spawn(move || {
        let end = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_build(&handle, sources, &settings, local, base)
        }))
        .unwrap_or_else(|_| BaselineBuild::Failed {
            reason: "the build thread panicked".into(),
        });
        handle.set(end);
    });
    Some(build)
}

/// The build thread: decides, builds, and returns the final state.
fn run_build<B>(
    build: &LocalBuild,
    sources: Sources<'_>,
    settings: &Settings,
    local: &dyn LocalSources,
    base: B,
) -> BaselineBuild
where
    B: FnOnce() -> Result<SxsBase, String>,
{
    let none = |reason: String| BaselineBuild::None { reason };
    let os = match sources.sys.os_info() {
        Ok(os) if !os.edition.is_empty() => os,
        _ => return none("the Windows edition and build are unknown".into()),
    };
    if let Some(dir) = settings.baseline_dir.as_deref()
        && shipped_dir_trusted(sources, settings, dir)
        && matches!(exact_file(sources, settings, dir, &os), Ok(Some(_)))
    {
        return none(format!(
            "a shipped baseline of exactly {} exists",
            os.baseline_name()
        ));
    }
    let Some(cache) = local_cache(sources, settings) else {
        return none(
            "the cache directory does not exist under an admin-only data root, or a standard \
             user can write it"
                .into(),
        );
    };
    let ids = PartIds::read(sources.reg, sources.fs, sources.sys);
    let mut problems = ids.problems.clone();
    // The cheap parts first, so that a scan that starts meanwhile already finds them.
    let mut todo: Vec<(LocalSource, String)> = Vec::new();
    for source in [LocalSource::S2, LocalSource::S4, LocalSource::S1] {
        match ids.get(source) {
            Some(id) if cache.has_part(&os, source, id) => {}
            Some(id) => todo.push((source, id.to_owned())),
            None => problems.push(format!("{source}: its source could not be stamped")),
        }
    }
    if todo.is_empty() {
        return if problems.is_empty() {
            none("the cached local baseline is current".into())
        } else {
            BaselineBuild::Failed {
                reason: problems.join("; "),
            }
        };
    }
    let building = |left: &[(LocalSource, String)]| BaselineBuild::Building {
        parts: left.iter().map(|(source, _)| source.to_string()).collect(),
        scan_waiting: build.scan_seen(),
    };
    build.set(building(&todo));

    let computer = sources
        .sys
        .env()
        .ok()
        .and_then(|e| e.get("COMPUTERNAME").cloned())
        .unwrap_or_default();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    let mut opts = BuildOptions {
        built_at: iso_utc(now),
        computer,
        base: Err("not read: this part has no component manifests".into()),
        stamps: FileStamps::default(),
        threads: 0,
        background: true,
        floors: SealFloors::default(),
    };
    let mut base = Some(base);
    let timing = purge_source::metered::installed().is_some();
    for at in 0..todo.len() {
        let (source, id) = &todo[at];
        if *source == LocalSource::S1
            && let Some(base) = base.take()
        {
            opts.base = base();
        }
        let stored =
            build_part(local, &os, &opts, *source, id, &build.shared.control).and_then(|part| {
                if timing {
                    for line in part.timings.lines(part.threads) {
                        eprintln!("{line} ({source})");
                    }
                }
                cache.store_part(&os, &part)
            });
        if let Err(e) = stored {
            problems.push(format!("{source}: {e}"));
        }
        if at + 1 < todo.len() {
            build.set(building(&todo[at + 1..]));
        }
    }
    if problems.is_empty() {
        BaselineBuild::Done {
            rescan: build.scan_seen(),
        }
    } else {
        BaselineBuild::Failed {
            reason: problems.join("; "),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::time::Duration;

    use purge_index::baseline::HashedSets;
    use purge_index::local_baseline::{LocalBaseline, LocalHeader, SourceLine, SourceStatus};
    use purge_source::fixture::{Fixture, HiveFixture};
    use purge_source::local_baseline::{
        HiveEntry, HiveWalk, InboxPackages, ManifestIter, PROFILE_LIST,
    };
    use purge_source::metered::{Meter, MeteredFileSystem, MeteredRegistry, MeteredSystem, Op};
    use purge_source::types::{PackageInfo, PackageSignatureKind, SourceResult};

    use super::*;

    const HIVE: &str = r"C:\Users\Default\NTUSER.DAT";
    const MANIFEST: &str = r#"<assembly><assemblyIdentity name="a" processorArchitecture="amd64"/><registryKeys><registryKey keyName="HKEY_LOCAL_MACHINE\SOFTWARE\PurgeS1Key"/></registryKeys></assembly>"#;
    const APPX: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Applications><Application Id="App"><Extensions>
    <uap:Extension Category="windows.protocol"><uap:Protocol Name="ms-purgetest"/></uap:Extension>
  </Extensions></Application></Applications>
</Package>
"#;

    /// A scratch tree: `kb` for the shipped baselines, `Purge` as the data root (the cache directory
    /// `Purge\baseline` is not created).
    struct Tree {
        kb: PathBuf,
        root: PathBuf,
        cache: PathBuf,
    }

    fn tree(name: &str) -> Tree {
        let base =
            std::env::temp_dir().join(format!("purge-engine-view-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (kb, root) = (base.join("kb"), base.join("Purge"));
        std::fs::create_dir_all(&kb).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        Tree {
            cache: root.join("baseline"),
            kb,
            root,
        }
    }

    impl Tree {
        fn shipped(&self, name: &str, header: &str, key: &str) {
            std::fs::write(
                self.kb.join(format!("{name}.tsv.gz")),
                format!("#purge-baseline 1\tT\tPC\t{header}\nK\t{key}\n"),
            )
            .unwrap();
        }

        fn settings(&self) -> Settings {
            Settings {
                baseline_dir: Some(self.kb.clone()),
                local_baseline_dir: Some(self.cache.clone()),
                ..Settings::default()
            }
        }

        /// Windows Professional 26100.9711 with a little of every local source. `root_admin_only`:
        /// what its file system says about the data root (and so about the cache directory in it).
        fn machine(&self, elevated: bool, root_admin_only: bool) -> Fixture {
            let (root, cache) = (self.root.to_str().unwrap(), self.cache.to_str().unwrap());
            let mut f = Fixture::builder()
                .os("Professional", 26100, 9711)
                .elevated(elevated)
                .env("SystemRoot", r"C:\Windows")
                .env("SystemDrive", "C:")
                .env("COMPUTERNAME", "BOX")
                .file_content(r"C:\Windows\WinSxS\Manifests\a.manifest", MANIFEST)
                .expand_sz(PROFILE_LIST, "Default", r"C:\Users\Default")
                .file(HIVE, 4096)
                .sz(r"HKU\.DEFAULT\Software\PurgeS3Key", "x", "1")
                .package(PackageInfo {
                    full_name: "Microsoft.Windows.Shell_10.0.1.0_neutral_neutral_cw5n1h2txyewy"
                        .into(),
                    family: "Microsoft.Windows.Shell_cw5n1h2txyewy".into(),
                    install_location: Some(r"C:\Windows\SystemApps\Shell".into()),
                    external_location: None,
                    sparse: false,
                    users: Vec::new(),
                    is_framework: false,
                    is_resource: false,
                    signature_kind: PackageSignatureKind::System,
                })
                .file_content(r"C:\Windows\SystemApps\Shell\AppxManifest.xml", APPX)
                .dir(root)
                .admin_only_writable(root, root_admin_only)
                .dir(cache)
                .build();
            f.set_offline_hive(HIVE, HiveFixture::new().key(r"Software\PurgeS2Key"));
            f
        }
    }

    fn os() -> OsInfo {
        OsInfo {
            edition: "Professional".into(),
            build: 26100,
            ubr: 9711,
        }
    }

    fn no_base() -> Result<SxsBase, String> {
        Err("not in a fixture".into())
    }

    fn has(warnings: &[String], text: &str) -> bool {
        warnings.iter().any(|w| w.contains(text))
    }

    /// Starts the build over `f` and waits for its end.
    fn build_to_end(f: &Fixture, settings: &Settings) -> BaselineBuild {
        std::thread::scope(|scope| {
            start_local_build(scope, Sources::of(f), settings, f, no_base)
                .expect("a cache directory is configured")
                .wait()
        })
    }

    /// L3: with a shipped baseline of exactly this Windows the view is that baseline, and neither a
    /// load nor the engine's start reads a local source, opens the cache or creates its directory.
    #[test]
    fn an_exact_host_builds_nothing_and_reads_no_cache() {
        let t = tree("exact");
        t.shipped(
            "Professional-26100.9711",
            "Professional\t26100.9711",
            r"hklm\\software\\exactkey",
        );
        t.shipped(
            "Professional-26100.1",
            "Professional\t26100.1",
            r"hklm\\software\\neighbourkey",
        );
        let f = t.machine(true, true);
        let meter = Meter::new();
        let (reg, fs, sys) = (
            MeteredRegistry::new(&f, &meter),
            MeteredFileSystem::new(&f, &meter),
            MeteredSystem::new(&f, &meter),
        );
        let sources = Sources {
            reg: &reg,
            fs: &fs,
            sys: &sys,
        };
        let settings = t.settings();
        let mut warnings = Vec::new();
        let loaded = load(sources, &settings, &os(), &mut warnings);
        assert!(warnings.is_empty(), "{warnings:?}");
        assert_eq!(loaded.trust(), BaselineTrust::Exact);
        assert_eq!(loaded.view.name(), "Professional-26100.9711");
        assert!(loaded.exact_counts().is_some_and(|n| n.keys == 1));
        assert!(loaded.view.has_key(r"HKLM\SOFTWARE\ExactKey"));
        assert!(loaded.view.is_exact_for("Professional", 26100, 9711));
        // The neighbour is not mixed in.
        assert!(!loaded.view.has_key(r"HKLM\SOFTWARE\NeighbourKey"));
        assert!(loaded.parts.is_none());

        let end = std::thread::scope(|scope| {
            start_local_build(scope, sources, &settings, &f, no_base)
                .unwrap()
                .wait()
        });
        assert!(
            matches!(&end, BaselineBuild::None { reason } if reason.contains("exactly Professional-26100.9711")),
            "{end:?}"
        );
        assert!(!t.cache.exists(), "the cache directory was created");
        // Nothing but the Windows version and the elevation was asked of the machine.
        let snap = meter.snapshot();
        for op in Op::ALL {
            let calls = snap.get(op).calls;
            if op == Op::System {
                assert!(calls <= 3, "{} system calls", calls);
            } else {
                assert_eq!(calls, 0, "{} was called", op.name());
            }
        }
        let status = loaded.status(None);
        assert!(status.baseline_available);
        assert_eq!(status.baseline_trust, BaselineTrust::Exact);
        assert_eq!(
            status.baseline_view,
            Some(BaselineViewRef {
                name: "Professional-26100.9711".into(),
                trust: BaselineTrust::Exact,
                local_id: None,
            })
        );
    }

    #[test]
    fn unelevated_without_a_cache_is_trust_none_with_a_warning() {
        let t = tree("unelevated");
        t.shipped(
            "Professional-26100.1",
            "Professional\t26100.1",
            r"hklm\\software\\neighbourkey",
        );
        let f = t.machine(false, true);
        let settings = t.settings();
        let mut warnings = Vec::new();
        let loaded = load(Sources::of(&f), &settings, &os(), &mut warnings);
        assert_eq!(loaded.trust(), BaselineTrust::None);
        assert_eq!(loaded.view.name(), "none+1");
        // Presence from the neighbour, the old line about the missing exact file, and why there is
        // no local baseline.
        assert!(loaded.view.has_key(r"HKLM\SOFTWARE\NeighbourKey"));
        assert!(loaded.exact_counts().is_none());
        assert!(
            has(&warnings, "no Professional-26100.9711.tsv.gz in"),
            "{warnings:?}"
        );
        assert!(
            has(&warnings, "the engine is not elevated, so it builds none"),
            "{warnings:?}"
        );
        assert!(
            has(&warnings, "the view none+1 has trust none"),
            "{warnings:?}"
        );
        // It builds nothing and creates nothing.
        let end = build_to_end(&f, &settings);
        assert!(
            matches!(&end, BaselineBuild::None { reason } if reason == "the engine is not elevated"),
            "{end:?}"
        );
        assert!(!t.cache.exists());
        let status = loaded.status(None);
        assert!(!status.baseline_available);
        assert_eq!(status.baseline_trust, BaselineTrust::None);
        assert_eq!(status.baseline_view.unwrap().name, "none+1");
    }

    #[test]
    fn an_elevated_engine_uses_the_shipped_directory_only_when_it_is_admin_only() {
        let t = tree("shipped");
        t.shipped(
            "Professional-26100.9711",
            "Professional\t26100.9711",
            r"hklm\\software\\exactkey",
        );
        t.shipped(
            "Professional-26100.1",
            "Professional\t26100.1",
            r"hklm\\software\\neighbourkey",
        );
        let kb = t.kb.to_str().unwrap();
        let settings = Settings {
            check_shipped_dir: true,
            local_baseline_dir: None,
            ..t.settings()
        };
        let exact_file = format!(r"{kb}\Professional-26100.9711.tsv.gz");
        let machine = |elevated: bool, kb_admin_only: Option<bool>| {
            let mut f = t.machine(elevated, true);
            if let Some(flag) = kb_admin_only {
                f.add_dir(kb);
                f.set_admin_only_writable(kb, flag);
                // The files take the directory's answer unless they have their own.
                f.add_file(&exact_file, 1);
                f.add_file(&format!(r"{kb}\Professional-26100.1.tsv.gz"), 1);
            }
            f
        };
        // Writable by Users, or unknown to the file system: no shipped baseline at all.
        for kb_state in [Some(false), None] {
            let f = machine(true, kb_state);
            let mut warnings = Vec::new();
            let loaded = load(Sources::of(&f), &settings, &os(), &mut warnings);
            assert_eq!(loaded.trust(), BaselineTrust::None, "{kb_state:?}");
            assert!(loaded.exact_counts().is_none());
            assert_eq!(loaded.view.name(), "none");
            assert!(!loaded.view.has_key(r"HKLM\SOFTWARE\ExactKey"));
            assert!(!loaded.view.has_key(r"HKLM\SOFTWARE\NeighbourKey"));
            assert!(
                has(&warnings, "no shipped baseline is used"),
                "{warnings:?}"
            );
        }
        // Admin-only: used.
        let f = machine(true, Some(true));
        let mut warnings = Vec::new();
        let loaded = load(Sources::of(&f), &settings, &os(), &mut warnings);
        assert_eq!(loaded.trust(), BaselineTrust::Exact);
        assert!(warnings.is_empty(), "{warnings:?}");
        // The directory is admin-only, the exact baseline's own file is not (moved in from a user's
        // folder, it kept its owner): that file proves no absence. The view is what it is without
        // it, and the engine does not take this Windows for one with an exact baseline.
        let mut f = machine(true, Some(true));
        f.set_admin_only_writable(&exact_file, false);
        let mut warnings = Vec::new();
        let loaded = load(Sources::of(&f), &settings, &os(), &mut warnings);
        assert_eq!(loaded.trust(), BaselineTrust::None);
        assert!(loaded.exact_counts().is_none());
        assert_eq!(loaded.view.name(), "none+1");
        assert!(!loaded.view.has_key(r"HKLM\SOFTWARE\ExactKey"));
        assert!(loaded.view.has_key(r"HKLM\SOFTWARE\NeighbourKey"));
        assert!(
            has(
                &warnings,
                "Professional-26100.9711.tsv.gz can be written by a standard user"
            ),
            "{warnings:?}"
        );
        let end = build_to_end(
            &f,
            &Settings {
                local_baseline_dir: Some(t.cache.clone()),
                ..settings.clone()
            },
        );
        assert!(
            !matches!(&end, BaselineBuild::None { reason } if reason.contains("exactly")),
            "{end:?}"
        );
        // Not elevated: the directory is not judged.
        let f = machine(false, Some(false));
        let loaded = load(Sources::of(&f), &settings, &os(), &mut Vec::new());
        assert_eq!(loaded.trust(), BaselineTrust::Exact);
        // Without the setting (fixtures, replays) it is not judged either.
        let f = machine(true, Some(false));
        let loaded = load(Sources::of(&f), &t.settings(), &os(), &mut Vec::new());
        assert_eq!(loaded.trust(), BaselineTrust::Exact);
    }

    /// Local sources whose manifest listing waits until the test lets it go.
    struct Gated<'a> {
        inner: &'a Fixture,
        gate: Mutex<mpsc::Receiver<()>>,
    }

    impl LocalSources for Gated<'_> {
        fn manifests(&self) -> SourceResult<ManifestIter<'_>> {
            let _ = self
                .gate
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(60));
            self.inner.manifests()
        }

        fn default_hive(&self, visit: &mut dyn FnMut(HiveEntry<'_>)) -> SourceResult<HiveWalk> {
            self.inner.default_hive(visit)
        }

        fn system_default(&self, visit: &mut dyn FnMut(HiveEntry<'_>)) -> SourceResult<HiveWalk> {
            self.inner.system_default(visit)
        }

        fn inbox_packages(&self) -> SourceResult<InboxPackages> {
            self.inner.inbox_packages()
        }
    }

    /// W4: the build starts with the engine and never blocks a scan. A scan that comes first runs
    /// with what exists, raises the build's priority and is told to come again; after the build the
    /// cache answers.
    #[test]
    fn an_elevated_engine_builds_in_the_background_and_a_scan_does_not_wait() {
        let t = tree("build");
        t.shipped(
            "Professional-26100.1",
            "Professional\t26100.1",
            r"hklm\\software\\neighbourkey",
        );
        let f = t.machine(true, true);
        let (go, gate) = mpsc::channel();
        let gated = Gated {
            inner: &f,
            gate: Mutex::new(gate),
        };
        let mut settings = t.settings();
        std::thread::scope(|scope| {
            let build =
                start_local_build(scope, Sources::of(&f), &settings, &gated, no_base).unwrap();
            settings.local_build = Some(build.clone());
            // The cheap parts are built first; S1 waits at the gate.
            let s1_left = BaselineBuild::Building {
                parts: vec!["S1".into()],
                scan_waiting: false,
            };
            let started = Instant::now();
            while build.state() != s1_left {
                assert!(
                    started.elapsed() < Duration::from_secs(30),
                    "{:?}",
                    build.state()
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(
                t.cache.is_dir(),
                "the elevated engine creates the cache directory"
            );

            // A scan now: it does not wait, and says so.
            let mut warnings = Vec::new();
            let loaded = load(Sources::of(&f), &settings, &os(), &mut warnings);
            assert_eq!(loaded.trust(), BaselineTrust::None);
            let parts = loaded.parts.unwrap();
            assert_eq!(parts[0], (LocalSource::S1, PartState::Missing));
            assert_eq!(parts[1].1, PartState::Hit { derived: false });
            assert_eq!(parts[2].1, PartState::Hit { derived: false });
            assert!(
                has(&warnings, "is being built in the background (S1 missing)"),
                "{warnings:?}"
            );
            assert!(
                has(&warnings, "Scan again when the build has finished"),
                "{warnings:?}"
            );
            // What exists is used: S2 from the cache, S3 live, the neighbour.
            assert!(
                loaded
                    .view
                    .has_key(r"HKU\S-1-5-21-1-2-3-1001\Software\PurgeS2Key")
            );
            assert!(loaded.view.has_key(r"HKU\.DEFAULT\Software\PurgeS3Key"));
            assert!(loaded.view.has_key(r"HKLM\SOFTWARE\NeighbourKey"));
            assert!(!loaded.view.has_key(r"HKLM\SOFTWARE\PurgeS1Key"));
            // The build knows that a scan is waiting, and runs at normal priority from here.
            assert_eq!(
                build.state(),
                BaselineBuild::Building {
                    parts: vec!["S1".into()],
                    scan_waiting: true,
                }
            );
            assert!(build.shared.control.raised());
            let status = loaded.status(Some(&build));
            assert_eq!(status.baseline_build, build.state());

            go.send(()).unwrap();
            assert_eq!(build.wait(), BaselineBuild::Done { rescan: true });
        });

        // The rescan: every part is there, the S1 part through its derived form.
        let mut warnings = Vec::new();
        let loaded = load(Sources::of(&f), &settings, &os(), &mut warnings);
        let parts = loaded.parts.unwrap();
        assert_eq!(parts[0].1, PartState::Hit { derived: true });
        assert!(!has(&warnings, "lacks"), "{warnings:?}");
        assert!(!has(&warnings, "being built"), "{warnings:?}");
        assert!(loaded.view.has_key(r"HKLM\SOFTWARE\PurgeS1Key"));
        assert_eq!(loaded.view.name(), "local-Professional-26100.9711+1");
        assert!(loaded.view.local_id().is_some());
        // One manifest is far below the seal's floors: presence only (L2), and the warning says why.
        assert_eq!(loaded.trust(), BaselineTrust::None);
        assert!(
            has(&warnings, "the local baseline is incomplete"),
            "{warnings:?}"
        );
        assert_eq!(
            loaded.view_ref().unwrap().local_id.as_deref(),
            loaded.view.local_id()
        );

        // The next engine start finds the cache and builds nothing.
        settings.local_build = None;
        let end = build_to_end(&f, &settings);
        assert!(
            matches!(&end, BaselineBuild::None { reason } if reason.contains("is current")),
            "{end:?}"
        );
        // An engine that is not elevated reads the same cache, builds nothing, and has no complete
        // local baseline (it cannot check S4).
        let unelevated = t.machine(false, true);
        let mut warnings = Vec::new();
        let loaded = load(Sources::of(&unelevated), &settings, &os(), &mut warnings);
        assert_eq!(loaded.parts.unwrap()[2].1, PartState::Unverified);
        assert_eq!(loaded.trust(), BaselineTrust::None);
        assert!(loaded.view.has_key(r"HKLM\SOFTWARE\PurgeS1Key"));

        // An inbox package update: only S4 is built again.
        let mut updated = t.machine(true, true);
        updated.add_package(PackageInfo {
            full_name: "Microsoft.Windows.Other_10.0.2.0_neutral_neutral_cw5n1h2txyewy".into(),
            family: "Microsoft.Windows.Other_cw5n1h2txyewy".into(),
            install_location: None,
            external_location: None,
            sparse: false,
            users: Vec::new(),
            is_framework: false,
            is_resource: false,
            signature_kind: PackageSignatureKind::System,
        });
        let before = std::fs::read_dir(&t.cache).unwrap().count();
        let loaded = load(Sources::of(&updated), &settings, &os(), &mut Vec::new());
        let parts = loaded.parts.unwrap();
        assert_eq!(
            [parts[0].1, parts[1].1, parts[2].1],
            [
                PartState::Hit { derived: true },
                PartState::Hit { derived: false },
                PartState::Missing
            ]
        );
        assert_eq!(
            build_to_end(&updated, &settings),
            BaselineBuild::Done { rescan: false }
        );
        assert_eq!(std::fs::read_dir(&t.cache).unwrap().count(), before + 1);
        let loaded = load(Sources::of(&updated), &settings, &os(), &mut Vec::new());
        assert!(
            loaded
                .parts
                .unwrap()
                .iter()
                .all(|(_, s)| *s != PartState::Missing)
        );
    }

    #[test]
    fn a_data_root_a_user_can_write_gets_no_cache() {
        let t = tree("weak");
        let f = t.machine(true, false);
        let settings = t.settings();
        let end = build_to_end(&f, &settings);
        assert!(
            matches!(&end, BaselineBuild::None { reason } if reason.contains("admin-only data root")),
            "{end:?}"
        );
        assert!(
            !t.cache.exists(),
            "created under a data root that is not admin-only"
        );
        let mut warnings = Vec::new();
        let loaded = load(Sources::of(&f), &settings, &os(), &mut warnings);
        assert_eq!(loaded.trust(), BaselineTrust::None);
        assert!(loaded.parts.is_none());
        assert!(has(&warnings, "is not used"), "{warnings:?}");
        // No cache directory configured: nothing is started and nothing is said about a cache.
        let none = Settings {
            local_baseline_dir: None,
            ..t.settings()
        };
        std::thread::scope(|scope| {
            assert!(start_local_build(scope, Sources::of(&f), &none, &f, no_base).is_none());
        });
        let mut warnings = Vec::new();
        load(Sources::of(&f), &none, &os(), &mut warnings);
        assert!(!has(&warnings, "cache"), "{warnings:?}");
        // No baseline directory: the engine as it was, without a word.
        let mut warnings = Vec::new();
        let loaded = load(Sources::of(&f), &Settings::default(), &os(), &mut warnings);
        assert!(warnings.is_empty());
        assert_eq!(loaded.trust(), BaselineTrust::None);
        assert_eq!(loaded.view_ref(), None);
        assert_eq!(loaded.status(None).baseline_view, None);
    }

    /// A cache directory that fails the rule is ignored and never repaired, whatever it holds. The
    /// parts here are good ones (every id in them can be computed by a standard user, so their
    /// content proves nothing): once the file system says that a standard user can write the
    /// directory, no engine reads them, and the elevated one neither builds into the directory nor
    /// removes anything from it.
    #[test]
    fn a_cache_directory_a_user_can_write_is_ignored_and_never_repaired() {
        let t = tree("planted");
        t.shipped(
            "Professional-26100.1",
            "Professional\t26100.1",
            r"hklm\\software\\neighbourkey",
        );
        let settings = t.settings();
        let good = t.machine(true, true);
        assert_eq!(
            build_to_end(&good, &settings),
            BaselineBuild::Done { rescan: false }
        );
        let listing = || {
            let mut names: Vec<(String, u64)> = std::fs::read_dir(&t.cache)
                .unwrap()
                .map(|e| {
                    let e = e.unwrap();
                    (
                        e.file_name().into_string().unwrap(),
                        e.metadata().unwrap().len(),
                    )
                })
                .collect();
            names.sort();
            names
        };
        let loaded = load(Sources::of(&good), &settings, &os(), &mut Vec::new());
        assert!(loaded.view.has_key(r"HKLM\SOFTWARE\PurgeS1Key"));
        // Three parts, and the derived forms of the S1 part and of the neighbour.
        let before = listing();
        assert_eq!(before.len(), 5, "{before:?}");

        for elevated in [true, false] {
            let mut weak = t.machine(elevated, true);
            weak.set_admin_only_writable(t.cache.to_str().unwrap(), false);
            let mut warnings = Vec::new();
            let loaded = load(Sources::of(&weak), &settings, &os(), &mut warnings);
            assert_eq!(loaded.trust(), BaselineTrust::None);
            assert!(loaded.parts.is_none(), "elevated {elevated}");
            assert!(loaded.view.local_id().is_none());
            assert!(!loaded.view.has_key(r"HKLM\SOFTWARE\PurgeS1Key"));
            // The neighbour still answers presence.
            assert!(loaded.view.has_key(r"HKLM\SOFTWARE\NeighbourKey"));
            assert!(
                has(&warnings, "a standard user can write it"),
                "{warnings:?}"
            );
            let end = build_to_end(&weak, &settings);
            assert!(
                matches!(&end, BaselineBuild::None { .. }),
                "elevated {elevated}: {end:?}"
            );
            assert_eq!(listing(), before, "elevated {elevated}");
        }
    }

    /// The view's trust reaches the policy and `engine.hello` in the model's vocabulary.
    #[test]
    fn a_merged_view_reports_merged() {
        let line = |source| SourceLine {
            source,
            status: SourceStatus::Ok,
            items: 1,
            records: 1,
            skipped: 0,
            reasons: Vec::new(),
            facts: vec![("unreadable".into(), "0".into())],
        };
        let local = LocalBaseline::from_hashed_sets(
            LocalHeader {
                built_at: "T".into(),
                computer: "PC".into(),
                edition: "Professional".into(),
                build: 26100,
                ubr: 9711,
                builder_version: purge_index::local_baseline::BUILDER_VERSION.into(),
                source_id: "0123456789abcdef".into(),
            },
            LocalSource::REQUIRED.map(line).to_vec(),
            HashedSets::default(),
        )
        .unwrap();
        let host = HostOs::new("Professional", 26100, 9711);
        let neighbour = purge_index::baseline_view::Neighbour::from_hashed_sets(
            "Professional",
            26100,
            1,
            HashedSets::default(),
        )
        .unwrap();
        let merged = PipelineBaseline {
            view: BaselineView::merged(&host, local, vec![neighbour], &ViewRules::closed()),
            exact_counts: None,
            configured: true,
            parts: None,
        };
        assert_eq!(merged.trust(), BaselineTrust::Merged);
        let status = merged.status(None);
        assert!(!status.baseline_available);
        assert_eq!(status.baseline_trust, BaselineTrust::Merged);
        let view = status.baseline_view.unwrap();
        assert_eq!(view.name, "local-Professional-26100.9711+1");
        assert_eq!(view.local_id.as_deref(), Some("0123456789abcdef"));
        // The policy's trust is that of the absence answers a scan consumed
        // (`ScanCtx::absence_trust`): presence-only, a Merged view answers none.
        assert_eq!(merged.trust().presence_only(), BaselineTrust::None);
        assert_eq!(
            BaselineTrust::for_policy(merged.trust().presence_only(), BaselineTrust::None),
            BaselineTrust::None
        );
        // Were inferred absence ever consumed, the cap would hold.
        assert_eq!(
            BaselineTrust::for_policy(merged.trust(), BaselineTrust::None),
            BaselineTrust::Merged
        );
    }

    /// A measurement on the machine the test runs on, not a test of anything: the warm load of the
    /// view (design §5 "Budget": 1.5 s, 80 MB) over this Windows' own local baseline and the shipped
    /// neighbours of `kb/baselines`. It reads the live machine and writes only into the directory
    /// `PURGE_BL_MEASURE_DIR` names, which it treats as an accepted cache directory:
    ///
    /// ```text
    /// set PURGE_BL_MEASURE_DIR=<an empty scratch directory>
    /// cargo test --release -p purge-engine --lib -- --ignored host_view_load --nocapture
    /// ```
    ///
    /// The first run builds the missing parts (minutes on a cold machine) and prints the build's
    /// timings; every run then loads the view five times and prints each time.
    #[test]
    #[ignore = "host measurement: reads the live machine, needs PURGE_BL_MEASURE_DIR"]
    fn host_view_load() {
        use purge_index::local_baseline::cache::inbox_package_names;
        use purge_index::local_baseline::file_stamps;
        let Some(dir) = std::env::var_os("PURGE_BL_MEASURE_DIR").map(PathBuf::from) else {
            eprintln!("PURGE_BL_MEASURE_DIR is not set; nothing measured");
            return;
        };
        std::fs::create_dir_all(&dir).unwrap();
        let live = purge_source::live::Live::new();
        let local = purge_source::live::LiveLocal::new();
        let sources = Sources {
            reg: &live.registry,
            fs: &live.fs,
            sys: &live.system,
        };
        let os = live_os(sources);
        // The directory is this test's own: a fixture file system vouches for it.
        let d = dir.to_str().unwrap();
        let vouch = Fixture::builder()
            .dir(d)
            .admin_only_writable(d, true)
            .build();
        let cache = LocalCache::open(&dir, &vouch, true).unwrap();
        let elevated = sources.sys.elevated();

        // Build what is missing. Not elevated, the S4 id is made from this account's packages.
        let mut ids = PartIds::read(sources.reg, sources.fs, sources.sys);
        if ids.s4.is_none() {
            let stamps = file_stamps(sources.fs, sources.reg, sources.sys);
            let names = inbox_package_names(sources.reg, sources.sys).unwrap();
            ids.s4 = PartIds::from_stamps(&stamps, Some(&names)).s4;
        }
        let opts = BuildOptions {
            built_at: iso_utc(0),
            computer: "measure".into(),
            base: purge_win::sxs::find_base().map_err(|e| e.to_string()),
            stamps: FileStamps::default(),
            threads: 0,
            background: true,
            floors: SealFloors::default(),
        };
        if std::env::var_os("PURGE_BL_MEASURE_LOAD_ONLY").is_none() {
            for source in [LocalSource::S2, LocalSource::S4, LocalSource::S1] {
                let id = ids.get(source).unwrap();
                if cache.has_part(&os, source, id) {
                    continue;
                }
                let t = Instant::now();
                let part =
                    build_part(&local, &os, &opts, source, id, &BuildControl::new()).unwrap();
                eprintln!(
                    "built {source}: {:.3} s, {} records, {} bytes, {}",
                    t.elapsed().as_secs_f64(),
                    part.record_count,
                    part.bytes.len(),
                    part.line.status.as_str()
                );
                for line in part.timings.lines(part.threads) {
                    eprintln!("  {line}");
                }
                let t = Instant::now();
                cache.store_part(&os, &part).unwrap();
                eprintln!("stored {source}: {:.3} s", t.elapsed().as_secs_f64());
            }
        }

        let settings = Settings {
            baseline_dir: Some(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../kb/baselines"),
            ),
            local_baseline_dir: Some(dir.clone()),
            ..Settings::default()
        };
        let writable = std::env::var_os("PURGE_BL_MEASURE_READONLY").is_none();
        for round in 0..5 {
            let mut warnings = Vec::new();
            let t = Instant::now();
            let loaded = load_with(sources, &settings, &os, &mut warnings, &|_, _| {
                LocalCache::open(&dir, &vouch, writable)
            });
            let secs = t.elapsed().as_secs_f64();
            eprintln!(
                "load {round}: {secs:.3} s; view {} trust {}; parts {:?}; elevated {elevated}",
                loaded.view.name(),
                loaded.view.trust(),
                loaded.parts
            );
            if round == 0 {
                for w in &warnings {
                    eprintln!("  warning: {w}");
                }
            }
            // With PURGE_BL_MEASURE_HOLD the last view is kept for two seconds, so that a watcher
            // of the process sees what the loaded view holds resident.
            if round == 4 && std::env::var_os("PURGE_BL_MEASURE_HOLD").is_some() {
                std::thread::sleep(Duration::from_secs(2));
            }
            drop(loaded);
        }
        let t = Instant::now();
        let names = inbox_package_names(sources.reg, sources.sys).map(|n| n.len());
        eprintln!(
            "inbox package names (the S4 id's input): {names:?} in {:.3} s",
            t.elapsed().as_secs_f64()
        );
    }

    fn live_os(sources: Sources<'_>) -> OsInfo {
        sources.sys.os_info().unwrap()
    }
}
