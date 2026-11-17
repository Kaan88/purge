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
//! - the clean-Windows baseline of exactly this (edition, build.ubr), when the baseline directory holds
//!   one; otherwise none, and the scan works values-only.
//!
//! Nothing here fails because a fact could not be read: what is missing becomes a warning line and the
//! pipeline goes on with less. Only a broken precondition (an unknown program id, a fingerprint of another
//! app, a post scan without an uninstall) is an error.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Instant;

use purge_guard::canon::{GuardEnv, OtherAppRoot, canon_path};
use purge_guard::deny::DenyList;
use purge_guard::prefix;
use purge_harvest::coproducts;
use purge_harvest::harvest::{HarvestReport, harvest_report};
use purge_harvest::refsnap::HarvestCtx;
use purge_harvest::roots::guard_env;
use purge_identity::kbdata::Kb;
use purge_index::baseline::{Baseline, RecordCounts};
use purge_index::matcher::AnchorSet;
use purge_index::ownership::OwnershipLimits;
use purge_inventory::arp::Inventory;
use purge_inventory::runner::{ProcessHost, RunError, RunOptions, RunReport, RunRequest};
use purge_inventory::verify_gone::{self, VerifyTarget};
use purge_model::{
    AnchorKind, AnchorRef, Candidate, Fingerprint, InstallScope, InstallerKind, InventoryDoc,
    InventoryEntry, OsInfo, ProgramId, RawFlags, ScanMode, VerifyGone, View, WritableBy,
};
use purge_plan::decide::{DecideCtx, Limits};
use purge_plan::emit::{Built, build};
use purge_scan::catalog::all_scanners;
use purge_scan::framework::{AppIdentityView, OtherApp, OtherApps, ScanCtx, ScanExt, ScanLimits};
use purge_source::registry::RegistrySource;
use purge_win::env::{EnvMap, expand_with};

pub use purge_harvest::harvest::Sources;

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

    let baseline = baseline_for(sources, settings, &mut warnings, &mut step);
    step.say("harvest: reading roots, Inno log, anchors and the reference snapshot");
    let mut report = harvest_report(entry, &inv.doc, sources, baseline.as_ref(), kb);
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

/// Loads the baseline for the Windows the sources describe, with progress.
fn baseline_for(
    sources: Sources<'_>,
    settings: &Settings,
    warnings: &mut Vec<String>,
    step: &mut Step<'_, '_>,
) -> Option<Baseline> {
    settings.baseline_dir.as_ref()?;
    let os = match sources.sys.os_info() {
        Ok(os) => os,
        Err(e) => {
            warnings.push(format!(
                "baseline: the Windows edition and build could not be read ({e}); no baseline is used"
            ));
            return None;
        }
    };
    step.say(&format!("loading the baseline {}", os.baseline_name()));
    let baseline = load_baseline(settings.baseline_dir.as_deref(), &os, warnings);
    if let Some(b) = &baseline {
        let timing = purge_source::metered::installed().is_some();
        step.done(&baseline_loaded(&os.baseline_name(), b.counts(), timing));
    }
    baseline
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
                baseline: None,
                inventory: &before.doc.entries,
                target: entry,
                cutoff: None,
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
    /// Warnings of the pipeline.
    pub warnings: Vec<String>,
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
    let report = harvest_report(&entry, &inv.doc, sources, None, kb);
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

/// The part of [`scan`] and [`scan_path`] after the mode is settled.
#[allow(clippy::too_many_arguments)]
fn run_scan(
    sources: Sources<'_>,
    fp: &Fingerprint,
    mode: ScanMode,
    verify_gone: Option<VerifyGone>,
    app_id: &str,
    settings: &Settings,
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

    let baseline = baseline_for(sources, settings, &mut warnings, &mut step);

    // Scanners. What every scanner shares is read once, before the first (C-SCANEXT): the one
    // reference walk, the MSI ownership index and the system objects.
    let app = AppIdentityView::from_fingerprint(fp, &env);
    step.say("scan: reading the references, the MSI ownership and the system objects");
    let ext = ScanExt::build(
        sources.reg,
        sources.fs,
        sources.sys,
        fp,
        &app,
        &inv.doc.entries,
        None,
        OwnershipLimits::default(),
    );
    warnings.extend(ext_warnings(&ext));
    step.done(&format!(
        "scan: {} reference(s), {} MSI product(s), {} service(s)",
        ext.ref_hits.as_ref().map_or(0, Vec::len),
        ext.ownership.stats().products,
        ext.sysobj.services.len()
    ));
    let ctx = ScanCtx {
        reg: sources.reg,
        fs: sources.fs,
        sys: sources.sys,
        fp,
        baseline: baseline.as_ref(),
        mode,
        verify_gone,
        env: &env,
        guard: &guard,
        other_apps: &other_apps,
        limits: ScanLimits::default(),
        ext: &ext,
    };
    let mut candidates = Vec::new();
    let mut per_scanner = Vec::new();
    for scanner in all_scanners() {
        // `run`, not `scan`: the rule about what a value holds is applied to every candidate.
        let found = ctx.run(scanner.as_ref(), &app);
        step.done(&format!(
            "scan: {} {} candidate(s)",
            scanner.id(),
            found.len()
        ));
        per_scanner.push((scanner.id(), found.len()));
        candidates.extend(found);
    }
    warnings.extend(
        ext.take_faults()
            .into_iter()
            .map(|f| format!("scan: scanner fault: {f}")),
    );

    // Decide, collapse, emit.
    let deny = DenyList::compile(&guard);
    if let Some(why) = deny.invalid() {
        warnings.push(format!(
            "scan: the deny-list could not be built ({why}); every target is Blocked"
        ));
    }
    let user_sid = Some(fp.user_sid.as_str()).filter(|s| !s.is_empty());
    let decide = DecideCtx {
        deny: &deny,
        mode,
        verify_gone: verify_gone.unwrap_or_else(|| VerifyGone::new(false, false, false)),
        user_sid,
        // Candidates also come from registry data, which may spell 8.3 names: keep the refusal on.
        long_names_resolved: false,
        limits: Limits::default(),
        // M1b lists stay closed until M1B-SCAN-INTEG calls `M1bDecide::from_facts` here.
        m1b: Default::default(),
    };
    let built = build(app_id, candidates.clone(), &decide);
    step.done(&format!(
        "scan: plan with {} item(s), hash {}",
        built.plan.items.len(),
        built.scan.plan_hash
    ));
    Ok(Scanned {
        candidates,
        built,
        per_scanner,
        warnings,
    })
}

/// What the shared scan data could not read, as scan warnings: unknown MSI ownership blocks the
/// targets it may concern (`MsiPackageUnreadable`), and the user should know why.
fn ext_warnings(ext: &ScanExt) -> Vec<String> {
    let stats = ext.ownership.stats();
    let mut out = Vec::new();
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
pub(crate) fn canonical_dirs(
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
    use purge_source::types::{KeyInfo, RegData, RegValue, SourceResult};
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

    /// A registry that counts the reads of one key's values. Its walker is the trait's default, which
    /// reads through the counted methods.
    struct Counting<'f> {
        inner: &'f Fixture,
        probe: &'static str,
        reads: AtomicUsize,
    }

    impl RegistrySource for Counting<'_> {
        fn key_info(&self, key: &str) -> SourceResult<KeyInfo> {
            self.inner.key_info(key)
        }
        fn subkeys(&self, key: &str) -> SourceResult<Vec<String>> {
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

    /// The scan makes the reference walk once (C-SCANEXT): `ScanExt::build` walks, REF-ANY reads its
    /// hits. A key only the walk reads (it refers to nothing, so no scanner looks at it again) is read
    /// once in the whole scan; next to it, a value that refers to the app still reaches REF-ANY.
    #[test]
    fn pipeline_runs_one_reference_walk() {
        const PROBE: &str = r"HKLM\SOFTWARE\Acme Holder\Quiet";
        const REFERS: &str = r"HKLM\SOFTWARE\Acme Holder\Settings";
        const UNINSTALL: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Probe";
        let fixture = Fixture::builder()
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
            .sz(PROBE, "Tool", r"C:\Tools\other.exe")
            .sz(REFERS, "Tool", r"C:\Program Files\Probe\probe.exe")
            .key(&format!(r"HKU\{SID}\Software"))
            .build();
        let counting = Counting {
            inner: &fixture,
            probe: PROBE,
            reads: AtomicUsize::new(0),
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
        let scanned = scan(sources, &fp, ScanMode::Forced, None, &settings, &mut |_| {}).unwrap();
        assert_eq!(
            counting.reads.load(Ordering::SeqCst),
            1,
            "the probe key is read by one walk"
        );
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
