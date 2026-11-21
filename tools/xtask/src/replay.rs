//! `replay` and `replay-all`: the engine pipeline run offline over a frozen rig run (vm/RIG.md §2, §3).
//!
//! A rig run directory holds `run.json`, the snapshots `snap-<run>-<phase>.tsv.gz` and their lists
//! `lists-<run>-<phase>.json` (phase 1 = installed and used, phase 2 = after the uninstaller). The replay:
//!
//! 1. builds `Fixture::from_snap` for phase 1 and phase 2 (with their lists, and an optional overlay of
//!    file contents in the drive-letter layout `<overlay>\C\Program Files\…`);
//! 2. finds the app's inventory entry at phase 1 from `run.json` `main.key` and harvests it there;
//! 3. stands in for the uninstall step: the window is `run.json` `uninstall.t0`/`t1`, verify-gone is
//!    checked against the phase-2 fixture, and the co-removed products are the harvest's co-product
//!    candidates whose Uninstall key is absent at phase 2;
//! 4. scans the phase-2 fixture in `post` mode and writes the `purge.plan/0` document.
//!
//! What a snapshot cannot give limits the result (printed with every replay): file contents, version
//! resources and signers are unknown unless overlaid (so no Inno log without `unins000.dat` in the
//! overlay), REG_BINARY and other non-string data are unknown, and string previews are cut at 1024
//! characters.
//!
//! `replay --live` is the scan of the still-installed app instead (the rig's `engine-scan-live`, vm/RIG.md
//! §4b): the phase-1 fixture is scanned in `external` mode with the fingerprint as harvested, so there is
//! no uninstall window, no verify-gone result and no co-removed product.
//!
//! `--fp <fp.json>` scans with a recorded fingerprint (the run's own `fp.json`, harvested in the VM, which
//! holds the installer log a snapshot cannot give) instead of the one harvested offline. What the
//! uninstall step wrote into it (window end points, verify-gone, co-removed products) is dropped and set
//! again from the replay.
//!
//! `replay` also writes the scan sidecar `<plan>.scan.json` next to the plan; `replay-all` does not (its
//! plans sit in the run's `plans` directory, which the scorer reads).
//!
//! `--baseline-view exact|merged|local|none` (docs/BASELINE_LOCAL_DESIGN.md §8.1, run R3) picks the baseline view
//! the replay **harvests and scans** with: `exact` (the default) is today's exact-match selection from
//! `--baselines`; `none` works with no baseline at all (the values-only path, the reference of invariant L5).
//! `merged` (`--local <file>` and one to three `--neighbour <shipped file>`) and `local` (`--local <file>` only)
//! check their inputs (the local file's `#end` line and seal, each neighbour's header, leave-one-out), put the
//! view together for the snap's Windows and hand it to the engine in place of the one it would load
//! (`pipeline::harvest_with_view`, `pipeline::scan_with_view`; purge-engine's `inject-view` feature, which
//! only this tool and tests use). No cache is opened and no directory is checked. The areas and the neighbour
//! rule come from the repository's `kb/baselines/view.json`. A view that does not come out with the trust the
//! flag names, or that leaves a given neighbour out, ends the replay with the reason. `none` with `--local`
//! and/or `--neighbour` is the view of trust None that still answers presence from those parts.
//! [`ViewArgs`] holds the flags, [`l5_violations`] is invariant L5 over two plans.
//!
//! `--l5-against <plan.json>` (with `merged`, `local` or `none` and parts) reads the plan a replay of the same
//! run made with `--baseline-view none` and checks invariant L5 against it: every item of the new plan must be
//! offered at least as strongly by the no-baseline plan. Each violation is printed and the command fails. This
//! is how R3 judges S4 of the design (§8.3).
//!
//! `replay-all` replays the frozen M0 runs [`M0_RUNS`] into `vm/runs/<id>/plans/purge-replay.json` (the
//! runs directory is git-ignored; the plan is a new file next to the other tools' plans) and then, when
//! `vm/rigtool/target/release/rigtool(.exe)` exists, prints `rigtool score --set …` over them.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use purge_engine::cli::output;
use purge_engine::pipeline::{self, PipelineBaseline, Scanned, Settings, Sources};
use purge_guard::prefix;
use purge_harvest::coproducts;
use purge_identity::kbdata::Kb;
use purge_index::baseline::Baseline;
use purge_index::baseline_view::{BaselineView, HostOs, Neighbour, ViewRules};
use purge_index::local_baseline::LocalBaseline;
use purge_inventory::verify_gone::{self, VerifyTarget};
use purge_model::{Band, BaselineTrust, FileTime, InventoryEntry, OsInfo, ScanMode, Target};
use purge_source::fixture::Fixture;
use purge_source::snapfixture::parse_iso8601;
use purge_source::system::SystemSource;
use serde::Deserialize;

/// The frozen M0 runs `replay-all` replays (directory name = truth id).
pub const M0_RUNS: &[&str] = &["vscode", "git", "firefox", "npp"];

/// The plan file `replay-all` writes inside each run's `plans` directory.
pub const REPLAY_PLAN: &str = "purge-replay.json";

/// The environment variable naming the runs directory (also used by the ignored test).
pub const RUNS_DIR_VAR: &str = "PURGE_RUNS_DIR";

const REPLAY_USAGE: &str = "usage: cargo xtask replay --run <vm/runs/<id>> --app <truth id> -o <plan.json> \
                            [--overlay <dir>] [--baselines <dir>] [--fp <fp.json>] [--live] \
                            [--baseline-view exact|merged|local|none] [--local <file>] [--neighbour <file>]... \
                            [--l5-against <plan of --baseline-view none>]";
const REPLAY_ALL_USAGE: &str = "usage: cargo xtask replay-all [--runs <vm/runs>] [--overlay-root <dir>] [--if-present] [--no-score]";

// ---------------------------------------------------------------------------------------------------------
// run.json
// ---------------------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RunJson {
    id: Option<String>,
    run: Option<String>,
    user_sid: Option<String>,
    sid: Option<String>,
    main: Option<RunMain>,
    uninstall: Option<RunUninstall>,
}

#[derive(Debug, Deserialize)]
struct RunMain {
    key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RunUninstall {
    t0: Option<String>,
    t1: Option<String>,
}

/// What the replay needs from `run.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunInfo {
    /// The run name used in the snapshot file names (`snap-<run>-<phase>.tsv.gz`).
    pub run: String,
    /// The app's Uninstall key, with `HKCU\` resolved to `HKU\<user SID>\`.
    pub main_key: String,
    /// Start of the uninstall window.
    pub t_start: FileTime,
    /// End of the uninstall window.
    pub t_end: FileTime,
}

/// Parses a rig `run.json` (`purge.rig.run/1`; a leading byte-order mark is accepted, as PowerShell
/// writes one).
pub fn parse_run_json(text: &str) -> Result<RunInfo> {
    let doc: RunJson = serde_json::from_str(text.trim_start_matches('\u{feff}'))
        .context("run.json is not valid JSON of the expected shape")?;
    let run = doc
        .run
        .or(doc.id)
        .filter(|r| !r.trim().is_empty())
        .ok_or_else(|| anyhow!("run.json has neither `run` nor `id`"))?;
    let key = doc
        .main
        .and_then(|m| m.key)
        .filter(|k| !k.trim().is_empty())
        .ok_or_else(|| anyhow!("run.json has no `main.key` (no app entry was recorded)"))?;
    let main_key = match prefix::strip_prefix(&key, "HKCU") {
        Some(rest) => {
            let sid = doc
                .user_sid
                .or(doc.sid)
                .ok_or_else(|| anyhow!("run.json `main.key` is under HKCU but no `user_sid`"))?;
            format!(r"HKU\{sid}\{}", rest.trim_start_matches('\\'))
        }
        None => key,
    };
    let un = doc
        .uninstall
        .ok_or_else(|| anyhow!("run.json has no `uninstall` section"))?;
    let time = |name: &str, v: Option<String>| -> Result<FileTime> {
        let s = v.ok_or_else(|| anyhow!("run.json has no `uninstall.{name}`"))?;
        parse_iso8601(&s)
            .ok_or_else(|| anyhow!("run.json `uninstall.{name}` {s:?} is not ISO 8601"))
    };
    let t_start = time("t0", un.t0)?;
    let t_end = time("t1", un.t1)?;
    if t_end < t_start {
        bail!("run.json `uninstall.t1` is before `uninstall.t0`");
    }
    Ok(RunInfo {
        run,
        main_key,
        t_start,
        t_end,
    })
}

// ---------------------------------------------------------------------------------------------------------
// Replay
// ---------------------------------------------------------------------------------------------------------

/// One replay's inputs.
#[derive(Debug, Clone)]
pub struct ReplayOpts {
    /// The rig run directory (`vm/runs/<id>`).
    pub run_dir: PathBuf,
    /// The plan's `app` field (the truth id).
    pub app: String,
    /// Where the plan is written.
    pub out: PathBuf,
    /// Overlay of file contents in the drive-letter layout, if any.
    pub overlay: Option<PathBuf>,
    /// The baseline directory (`kb/baselines`).
    pub baselines: Option<PathBuf>,
    /// A recorded fingerprint to scan with instead of the one harvested offline.
    pub fp: Option<PathBuf>,
    /// Also write the scan sidecar (`<plan>.scan.json`: evidence, blockers, notes) next to the plan.
    pub sidecar: bool,
    /// Scan the still-installed app (phase 1, `external` mode) instead of the state after the uninstall.
    pub live: bool,
    /// The parts of a baseline view to harvest and scan with in place of the one the engine loads from
    /// `baselines` (`--baseline-view merged|local`, and `none` with `--local` or `--neighbour`).
    pub view: Option<ViewInputs>,
}

/// A replay's result, for the summary.
#[derive(Debug, Clone)]
pub struct Replayed {
    /// The plan as written.
    pub plan: purge_model::Plan,
    /// Pipeline and harvest warnings.
    pub warnings: Vec<String>,
    /// One line per limit of the snapshot data.
    pub limits: Vec<String>,
    /// Whether verify-gone passed at phase 2.
    pub verify_passed: bool,
    /// Co-removed products recorded.
    pub co_removed: usize,
    /// The fingerprint's roots read from MSI component paths (`RootSource::MsiComponent`), for
    /// `replay-diff`'s reason `msi_root_added`.
    pub msi_roots: Vec<String>,
    /// The fingerprint the scan ran with.
    #[cfg(test)]
    pub fingerprint: purge_model::Fingerprint,
}

/// The fingerprint's roots that come from MSI component paths.
fn msi_roots(fp: &purge_model::Fingerprint) -> Vec<String> {
    fp.roots
        .iter()
        .filter(|r| r.source == purge_model::RootSource::MsiComponent)
        .map(|r| r.path.clone())
        .collect()
}

fn load_phase(dir: &Path, run: &str, phase: u32, overlay: Option<&Path>) -> Result<Fixture> {
    let snap = dir.join(format!("snap-{run}-{phase}.tsv.gz"));
    let lists = dir.join(format!("lists-{run}-{phase}.json"));
    if !snap.is_file() {
        bail!("{} is missing", snap.display());
    }
    eprintln!("replay: loading {}", snap.display());
    Fixture::from_snap(&snap, lists.is_file().then_some(lists.as_path()), overlay)
        .map_err(|e| anyhow!("cannot load {}: {e}", snap.display()))
}

/// The inventory entry of `key` at phase 1: the same Uninstall key, else the only entry with its key name.
fn entry_for<'d>(entries: &'d [InventoryEntry], key: &str) -> Result<&'d InventoryEntry> {
    if let Some(e) = entries.iter().find(|e| prefix::is_same(&e.key_path, key)) {
        return Ok(e);
    }
    let name = key.rsplit('\\').next().unwrap_or(key);
    let hits: Vec<&InventoryEntry> = entries
        .iter()
        .filter(|e| e.program_id.key_name().eq_ignore_ascii_case(name))
        .collect();
    match hits.as_slice() {
        [one] => Ok(one),
        [] => bail!("no inventory entry at phase 1 has the Uninstall key {key}"),
        _ => bail!("{} phase-1 entries have the key name {name:?}", hits.len()),
    }
}

fn write_plan(
    opts: &ReplayOpts,
    plan: &purge_model::Plan,
    scan: &impl serde::Serialize,
) -> Result<()> {
    let out = &opts.out;
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    output::write_atomic(out, &output::json_text(plan))
        .with_context(|| format!("writing {}", out.display()))?;
    if opts.sidecar {
        let sidecar = output::sidecar_path(out);
        output::write_atomic(&sidecar, &output::json_text(scan))
            .with_context(|| format!("writing {}", sidecar.display()))?;
    }
    Ok(())
}

fn limits(before: &Fixture, after: Option<&Fixture>, overlay: Option<&Path>) -> Vec<String> {
    let mut out = vec![match overlay {
        Some(o) => format!(
            "file contents, version info and signers come only from the overlay {} (no Inno log unless \
             unins000.dat is in it)",
            o.display()
        ),
        None => {
            "no overlay: file contents, version info and signers are unknown (no Inno log)".into()
        }
    }];
    for (phase, f) in [(1, Some(before)), (2, after)] {
        if let Some(st) = f.and_then(Fixture::snap_stats) {
            out.push(format!(
                "phase {phase}: {} keys, {} values ({} with unknown data such as REG_BINARY, {} previews \
                 cut at 1024 characters), {} dirs, {} files, {} denied, {} errors",
                st.keys,
                st.values,
                st.unknown_values,
                st.truncated_values,
                st.dirs,
                st.files,
                st.denied,
                st.errors
            ));
        }
    }
    out
}

/// One replay over two machines that are already in memory: what [`replay`] does after it has read the run
/// directory, and what a test runs over fixture machines.
#[derive(Clone, Copy)]
pub struct Case<'a> {
    /// The machine with the app installed (phase 1).
    pub before: &'a Fixture,
    /// The machine after the uninstaller (phase 2); `None`: scan `before` in `external` mode (`--live`).
    pub after: Option<&'a Fixture>,
    /// The app's Uninstall key.
    pub main_key: &'a str,
    /// The uninstall window.
    pub window: (FileTime, FileTime),
    /// The plan's `app` field.
    pub app: &'a str,
    /// The baseline directory the engine loads from; not read when `view` is set.
    pub baselines: Option<&'a Path>,
    /// A recorded fingerprint to scan with instead of the harvested one.
    pub fp: Option<&'a Path>,
    /// The overlay the machines were loaded with (for the limits lines only).
    pub overlay: Option<&'a Path>,
    /// The baseline view to harvest **and** scan with, in place of the one the engine loads.
    pub view: Option<&'a PipelineBaseline>,
}

/// Runs the engine pipeline over the two machines of `case`: harvest at `before`, the stand-in for the
/// uninstall step, scan at `after`. With [`Case::view`] both the harvest and the scan work with that view
/// (`pipeline::harvest_with_view`, `pipeline::scan_with_view`).
pub fn replay_case(case: &Case<'_>) -> Result<(Replayed, Scanned)> {
    let settings = Settings {
        baseline_dir: case.baselines.map(Path::to_path_buf),
        purge_dirs: Vec::new(),
        msi_table_dir: None,
        ..Settings::default()
    };
    let mut progress = |line: &str| eprintln!("replay: {line}");
    let before = case.before;

    let inv1 = pipeline::inventory(Sources::of(before));
    let entry = entry_for(&inv1.doc.entries, case.main_key)?;
    let program_id = entry.program_id.to_string();
    let harvested = match case.view {
        Some(view) => pipeline::harvest_with_view(
            Sources::of(before),
            &program_id,
            Kb::shipped(),
            &settings,
            view,
            &mut progress,
        ),
        None => pipeline::harvest(
            Sources::of(before),
            &program_id,
            Kb::shipped(),
            &settings,
            &mut progress,
        ),
    }
    .map_err(|e| anyhow!("harvest at phase 1: {e}"))?;
    let mut warnings = harvested.warnings;
    let report = harvested.report;
    let mut fp = report.fingerprint;
    if let Some(path) = case.fp {
        fp = output::read_json(path).map_err(|e| anyhow!("fingerprint {e}"))?;
        fp.window.t_start = None;
        fp.window.t_end = None;
        fp.verify_gone = None;
        fp.co_removed.clear();
        progress(&format!("fingerprint from {}", path.display()));
    }
    let mut scan =
        |machine: &Fixture, fp: &purge_model::Fingerprint, mode: ScanMode| match case.view {
            Some(view) => pipeline::scan_with_view(
                Sources::of(machine),
                fp,
                mode,
                Some(case.app),
                &settings,
                view,
                &mut progress,
            ),
            None => pipeline::scan(
                Sources::of(machine),
                fp,
                mode,
                Some(case.app),
                &settings,
                &mut progress,
            ),
        };

    let Some(after) = case.after else {
        eprintln!("replay: live: scanning phase 1 (the app is still installed), no uninstall step");
        let mut scanned =
            scan(before, &fp, ScanMode::External).map_err(|e| anyhow!("scan at phase 1: {e}"))?;
        warnings.append(&mut scanned.warnings);
        let replayed = Replayed {
            plan: scanned.built.plan.clone(),
            warnings,
            limits: limits(before, None, case.overlay),
            verify_passed: false,
            co_removed: 0,
            msi_roots: msi_roots(&fp),
            #[cfg(test)]
            fingerprint: fp,
        };
        return Ok((replayed, scanned));
    };

    let verify = verify_gone::check(
        after,
        after,
        after,
        &VerifyTarget {
            arp_key: entry.key_path.clone(),
            product_code: entry.product_code.clone(),
            main_exes: fp.main_exes().map(|e| e.path.clone()).collect(),
        },
    )
    .result;
    let disappeared = verify_gone::disappeared(after, &inv1.doc.entries, &entry.program_id);
    fp.window.t_start = Some(case.window.0);
    fp.window.t_end = Some(case.window.1);
    fp.verify_gone = Some(verify);
    fp.co_removed = coproducts::co_removed(&report.co_candidates, &disappeared);
    eprintln!(
        "replay: uninstall window from run.json; verify-gone at phase 2 {} (ARP key gone: {}, MSI unknown: {}, \
         main exes gone: {}); {} co-removed of {} candidate(s)",
        if verify.is_passed() {
            "passed"
        } else {
            "failed"
        },
        verify.arp_gone,
        verify.msi_unknown_all_ctx,
        verify.main_exes_gone,
        fp.co_removed.len(),
        report.co_candidates.len()
    );

    let mut scanned =
        scan(after, &fp, ScanMode::Post).map_err(|e| anyhow!("scan at phase 2: {e}"))?;
    warnings.append(&mut scanned.warnings);
    let replayed = Replayed {
        plan: scanned.built.plan.clone(),
        warnings,
        limits: limits(before, Some(after), case.overlay),
        verify_passed: verify.is_passed(),
        co_removed: fp.co_removed.len(),
        msi_roots: msi_roots(&fp),
        #[cfg(test)]
        fingerprint: fp,
    };
    Ok((replayed, scanned))
}

/// Replays one rig run and writes its plan.
pub fn replay(opts: &ReplayOpts) -> Result<Replayed> {
    let run_json = opts.run_dir.join("run.json");
    let text = std::fs::read_to_string(&run_json)
        .with_context(|| format!("reading {}", run_json.display()))?;
    let info = parse_run_json(&text).with_context(|| format!("in {}", run_json.display()))?;
    let overlay = opts.overlay.as_deref();

    let before = load_phase(&opts.run_dir, &info.run, 1, overlay)?;
    // The view is put together for the snap's Windows before anything is harvested: a view that does not
    // have the trust the flag names ends the replay here.
    let view = match &opts.view {
        Some(inputs) => {
            let os = SystemSource::os_info(&before)
                .map_err(|e| anyhow!("the snap's Windows edition and build are unknown ({e})"))?;
            let view = inputs.view(&os)?;
            eprintln!(
                "replay: baseline view {} (trust {}) for harvest and scan",
                view.name(),
                view.trust()
            );
            Some(PipelineBaseline::injected(view))
        }
        None => None,
    };
    let after = if opts.live {
        None
    } else {
        Some(load_phase(&opts.run_dir, &info.run, 2, overlay)?)
    };
    let (replayed, scanned) = replay_case(&Case {
        before: &before,
        after: after.as_ref(),
        main_key: &info.main_key,
        window: (info.t_start, info.t_end),
        app: &opts.app,
        baselines: opts.baselines.as_deref(),
        fp: opts.fp.as_deref(),
        overlay,
        view: view.as_ref(),
    })?;
    write_plan(opts, &scanned.built.plan, &scanned.built.scan)?;
    Ok(replayed)
}

// ---------------------------------------------------------------------------------------------------------
// Invariant L5 at plan level (BASELINE_LOCAL_DESIGN.md §2 L5, §8.3 S4)
// ---------------------------------------------------------------------------------------------------------

/// How strongly a plan offers an item: Blocked 1, Weak 2, Likely 3, Safe 4. A target the plan does not list
/// has 0.
pub fn band_rank(band: Band) -> u8 {
    match band {
        Band::Blocked => 1,
        Band::Weak => 2,
        Band::Likely => 3,
        Band::Safe => 4,
    }
}

/// The registry key a registry target is or lies in.
fn target_reg_key(target: &Target) -> Option<&str> {
    match target {
        Target::RegKey { path }
        | Target::RegValue { path, .. }
        | Target::RegValueChanged { path, .. }
        | Target::RegMultiSzSegment { path, .. } => Some(path),
        _ => None,
    }
}

/// Whether removing `outer` removes `inner` too: the same target (names compare without case), a registry
/// key with a key at or below it or with a value (or a segment of a value) of such a key, or a directory with
/// a path at or below it.
pub fn covers(outer: &Target, inner: &Target) -> bool {
    match (outer, inner) {
        (Target::RegKey { path: outer }, inner) if target_reg_key(inner).is_some() => {
            target_reg_key(inner).is_some_and(|key| prefix::is_same_or_inside(key, outer))
        }
        (Target::Path { path: outer }, Target::Path { path: inner }) => {
            prefix::is_same_or_inside(inner, outer)
        }
        _ => same_target(outer, inner),
    }
}

/// Whether two targets are one target; names compare without case.
fn same_target(a: &Target, b: &Target) -> bool {
    let key = |t: &Target| {
        serde_json::to_string(t)
            .unwrap_or_else(|_| format!("{t:?}"))
            .to_lowercase()
    };
    key(a) == key(b)
}

/// Invariant L5 for two plans of the same app and machines (BASELINE_LOCAL_DESIGN.md §2): `none` made
/// without any baseline, `below` made with a view below Exact in the harvest and in the scan. The local
/// baseline is presence-only, so a view below Exact may only take away: **what `below` offers, `none`
/// offers at least as strongly.** For every item of `below` there is an item of `none` that
///
/// 1. has the same target or, when `none` has no item of that target, a target that contains it
///    ([`covers`]: a key, a directory). Nothing new is offered, not even as Blocked. The containing case is
///    the one named exception to "the same target": a scanner that is told a key is Windows' own no longer
///    offers the key and offers the app's values in it instead, which removes less;
/// 2. has a band at least as high ([`band_rank`]): no band is raised;
/// 3. is preselected if the item of `below` is.
///
/// A target `none` lists and `below` does not is fine (a scanner may withhold what Windows owns). The
/// scanner tests check the same property per scanner (`purge-scan` `tests/shared/l5.rs`). Returns one line
/// per violation; empty means the invariant holds.
pub fn l5_violations(none: &purge_model::Plan, below: &purge_model::Plan) -> Vec<String> {
    let mut out = Vec::new();
    for item in &below.items {
        let what = format!("{} {:?}", item.scanner, item.target);
        let rank = band_rank(item.band);
        let same: Vec<&purge_model::PlanItem> = none
            .items
            .iter()
            .filter(|n| same_target(&n.target, &item.target))
            .collect();
        // The item of the same target decides when there is one; a container only stands in for a
        // target `none` does not list.
        let covering: Vec<&purge_model::PlanItem> = if same.is_empty() {
            none.items
                .iter()
                .filter(|n| covers(&n.target, &item.target))
                .collect()
        } else {
            same
        };
        if covering.is_empty() {
            out.push(format!(
                "new item below Exact ({:?}{}): {what}",
                item.band,
                if item.preselected {
                    ", preselected"
                } else {
                    ""
                }
            ));
        } else if !covering.iter().any(|n| band_rank(n.band) >= rank) {
            out.push(format!(
                "band raised below Exact (to {:?}, over {:?}): {what}",
                item.band,
                covering.iter().map(|n| n.band).collect::<Vec<_>>()
            ));
        } else if item.preselected
            && !covering
                .iter()
                .any(|n| n.preselected && band_rank(n.band) >= rank)
        {
            out.push(format!("preselected below Exact only: {what}"));
        }
    }
    out
}
fn summary(r: &Replayed) -> String {
    let count = |band| r.plan.items.iter().filter(|i| i.band == band).count();
    format!(
        "{} item(s): {} Safe ({} preselected), {} Likely, {} Weak, {} Blocked; verify-gone {}; {} co-removed",
        r.plan.items.len(),
        count(Band::Safe),
        r.plan.items.iter().filter(|i| i.preselected).count(),
        count(Band::Likely),
        count(Band::Weak),
        count(Band::Blocked),
        if r.verify_passed { "passed" } else { "failed" },
        r.co_removed
    )
}

fn report(app: &str, out: &Path, r: &Replayed) {
    for w in &r.warnings {
        eprintln!("replay: {app}: warning: {w}");
    }
    for l in &r.limits {
        println!("replay: {app}: limit: {l}");
    }
    println!("replay: {app}: {} -> {}", summary(r), out.display());
}

// ---------------------------------------------------------------------------------------------------------
// Baseline view (BASELINE_LOCAL_DESIGN.md §8.1, R3; BL-RIG-DIFF wave 2, completed by BL-FRAMEWORK in wave 5)
// ---------------------------------------------------------------------------------------------------------

/// `--baseline-view`: the trust level of the view a replay scans with (design §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    /// The shipped baseline of exactly the snap's Windows, from `--baselines` (today's behaviour).
    Exact,
    /// The local baseline merged with shipped neighbours.
    Merged,
    /// The local baseline alone.
    Local,
    /// No baseline: values-only.
    None,
}

impl ViewMode {
    fn parse(text: &str) -> Result<ViewMode> {
        Ok(match text {
            "exact" => ViewMode::Exact,
            "merged" => ViewMode::Merged,
            "local" => ViewMode::Local,
            "none" => ViewMode::None,
            other => bail!(
                "--baseline-view {other:?}: one of exact, merged, local, none\n{REPLAY_USAGE}"
            ),
        })
    }

    fn name(self) -> &'static str {
        match self {
            ViewMode::Exact => "exact",
            ViewMode::Merged => "merged",
            ViewMode::Local => "local",
            ViewMode::None => "none",
        }
    }
}

/// At most this many neighbours in a merged view (design §4.1 rule 3).
pub const MAX_NEIGHBOURS: usize = 3;

/// The baseline-view flags of `replay`.
#[derive(Debug, Clone)]
pub struct ViewArgs {
    /// `--baseline-view` (default [`ViewMode::Exact`]).
    pub mode: ViewMode,
    /// `--local`: a local baseline file (`purge-engine baseline build`).
    pub local: Option<PathBuf>,
    /// `--neighbour`: shipped baseline files, in the order given.
    pub neighbours: Vec<PathBuf>,
}

/// What the baseline-view flags resolve to ([`ViewArgs::resolve`]).
#[derive(Debug, Clone)]
pub struct ViewChoice {
    /// The baseline directory the engine loads from: `--baselines` for `exact`, none otherwise.
    pub baselines: Option<PathBuf>,
    /// The parts of the view the replay injects; `None` for `exact`, and for `none` without parts.
    pub inject: Option<ViewInputs>,
}

/// The loaded parts of an injected view (`merged`, `local`, or `none` with parts). The view itself is put
/// together for the snap's Windows ([`ViewInputs::view`]).
#[derive(Clone)]
pub struct ViewInputs {
    /// The trust the view must come out with: Merged, Local or None.
    pub mode: ViewMode,
    /// `--local`.
    pub local: Option<LocalBaseline>,
    /// `--neighbour`, in the order given.
    pub neighbours: Vec<Neighbour>,
    /// The areas and the neighbour rule (`view.json`).
    pub rules: ViewRules,
}

impl std::fmt::Debug for ViewInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ViewInputs")
            .field("mode", &self.mode)
            .field(
                "local",
                &self.local.as_ref().map(|l| {
                    let h = l.header();
                    format!("{}-{}.{}", h.edition, h.build, h.ubr)
                }),
            )
            .field(
                "neighbours",
                &self
                    .neighbours
                    .iter()
                    .map(Neighbour::name)
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl ViewInputs {
    /// The view for the Windows `os` (the snap's). An error when the parts do not give the trust the mode
    /// names for that Windows (a local baseline of another Windows, a neighbour beyond the rule's distance),
    /// or when a neighbour is left out: the replay would then measure another view than the one asked for.
    pub fn view(&self, os: &OsInfo) -> Result<BaselineView> {
        let host = HostOs::from(os);
        let (local, neighbours) = (self.local.clone(), self.neighbours.clone());
        let (want, view) = match self.mode {
            ViewMode::Merged => (
                BaselineTrust::Merged,
                BaselineView::assemble(&host, local, neighbours, &self.rules),
            ),
            ViewMode::Local => (
                BaselineTrust::Local,
                BaselineView::assemble(&host, local, neighbours, &self.rules),
            ),
            ViewMode::None => (
                BaselineTrust::None,
                BaselineView::none(&host, local, neighbours, &self.rules),
            ),
            ViewMode::Exact => bail!("--baseline-view exact injects no view"),
        };
        let mode = self.mode.name();
        if view.trust() != want {
            bail!(
                "--baseline-view {mode}: for the snap's Windows {} the parts give the view {} of trust {}, not \
                 {want}: {}",
                host.name(),
                view.name(),
                view.trust(),
                view.warnings().join("; ")
            );
        }
        if view.neighbour_names().len() != self.neighbours.len() {
            bail!(
                "--baseline-view {mode}: for the snap's Windows {} a neighbour is left out: {}",
                host.name(),
                view.warnings().join("; ")
            );
        }
        Ok(view)
    }
}

impl ViewArgs {
    /// Checks the flags and loads their files. `baselines`: the baseline directory (`--baselines`, or the
    /// repository's `kb/baselines`); `exact` scans with it, the injected modes read only its `view.json`.
    /// `baselines_given`: `--baselines` was on the command line (it contradicts every mode but `exact`).
    pub fn resolve(&self, baselines: Option<PathBuf>, baselines_given: bool) -> Result<ViewChoice> {
        let mode = self.mode.name();
        if self.mode != ViewMode::Exact && baselines_given {
            bail!(
                "--baseline-view {mode} hides the exact baseline; --baselines does not go with it"
            );
        }
        match self.mode {
            ViewMode::Exact => {
                if self.local.is_some() || !self.neighbours.is_empty() {
                    bail!("--baseline-view {mode} takes no --local or --neighbour");
                }
                return Ok(ViewChoice {
                    baselines,
                    inject: None,
                });
            }
            ViewMode::None if self.local.is_none() && self.neighbours.is_empty() => {
                return Ok(ViewChoice {
                    baselines: None,
                    inject: None,
                });
            }
            ViewMode::Local if !self.neighbours.is_empty() => {
                bail!("--baseline-view local takes no --neighbour (that is merged)")
            }
            ViewMode::Merged if self.neighbours.is_empty() => {
                bail!("--baseline-view merged needs at least one --neighbour <shipped baseline>")
            }
            ViewMode::Merged | ViewMode::None if self.neighbours.len() > MAX_NEIGHBOURS => {
                bail!("--baseline-view {mode} takes at most {MAX_NEIGHBOURS} --neighbour files")
            }
            ViewMode::Local | ViewMode::Merged | ViewMode::None => {}
        }
        let local = match &self.local {
            Some(path) => Some(
                LocalBaseline::load(path)
                    .map_err(|e| anyhow!("--local {}: {e}", path.display()))?,
            ),
            None if self.mode == ViewMode::None => None,
            None => bail!("--baseline-view {mode} needs --local <local baseline file>"),
        };
        if let (Some(local), Some(path)) = (&local, &self.local)
            && self.mode != ViewMode::None
            && !local.complete()
        {
            bail!(
                "--local {}: the local baseline is incomplete ({}); an incomplete local baseline gives trust None \
                 (design L2): use --baseline-view none",
                path.display(),
                local.incomplete_reasons().join("; ")
            );
        }
        let mut neighbours = Vec::new();
        for n in &self.neighbours {
            let b = Baseline::load(n).map_err(|e| anyhow!("--neighbour {}: {e}", n.display()))?;
            if let Some(h) = local.as_ref().map(LocalBaseline::header)
                && b.is_for(&h.edition, h.build, h.ubr)
            {
                bail!(
                    "--neighbour {}: it is the exact baseline of the local file's Windows ({} {}.{}); a view below \
                     Exact leaves it out",
                    n.display(),
                    h.edition,
                    h.build,
                    h.ubr
                );
            }
            neighbours.push(Neighbour::from_baseline(b));
        }
        let mut warnings = Vec::new();
        let rules = match &baselines {
            Some(dir) => ViewRules::load_or_closed(dir, &mut warnings),
            None => ViewRules::closed(),
        };
        for w in warnings {
            eprintln!("replay: warning: {w}");
        }
        Ok(ViewChoice {
            baselines: None,
            inject: Some(ViewInputs {
                mode: self.mode,
                local,
                neighbours,
                rules,
            }),
        })
    }
}
// ---------------------------------------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------------------------------------

/// Minimal flag parser: `--name value` pairs and bare switches.
struct Flags {
    pairs: Vec<(String, String)>,
    switches: Vec<String>,
}

impl Flags {
    fn parse(args: &[String], valued: &[&str], switches: &[&str], usage: &str) -> Result<Self> {
        let mut out = Flags {
            pairs: Vec::new(),
            switches: Vec::new(),
        };
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if valued.contains(&a.as_str()) {
                let v = it
                    .next()
                    .with_context(|| format!("{a} needs a value\n{usage}"))?;
                out.pairs.push((a.clone(), v.clone()));
            } else if switches.contains(&a.as_str()) {
                out.switches.push(a.clone());
            } else {
                bail!("unknown argument {a:?}\n{usage}");
            }
        }
        Ok(out)
    }

    fn get(&self, names: &[&str]) -> Option<&str> {
        self.pairs
            .iter()
            .rev()
            .find(|(k, _)| names.contains(&k.as_str()))
            .map(|(_, v)| v.as_str())
    }

    fn has(&self, name: &str) -> bool {
        self.switches.iter().any(|s| s == name)
    }

    /// Every value of a repeatable flag, in order.
    fn all(&self, name: &str) -> Vec<&str> {
        self.pairs
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

pub(crate) fn default_baselines(root: &Path) -> Option<PathBuf> {
    let dir = root.join("kb").join("baselines");
    dir.is_dir().then_some(dir)
}

/// `cargo xtask replay …`.
pub fn run_one(root: &Path, args: &[String]) -> Result<bool> {
    let f = Flags::parse(
        args,
        &[
            "--run",
            "--run-dir",
            "--app",
            "-o",
            "--out",
            "--overlay",
            "--baselines",
            "--fp",
            "--baseline-view",
            "--local",
            "--neighbour",
            "--l5-against",
        ],
        &["--live"],
        REPLAY_USAGE,
    )?;
    let view = ViewArgs {
        mode: f
            .get(&["--baseline-view"])
            .map_or(Ok(ViewMode::Exact), ViewMode::parse)?,
        local: f.get(&["--local"]).map(PathBuf::from),
        neighbours: f
            .all("--neighbour")
            .into_iter()
            .map(PathBuf::from)
            .collect(),
    };
    let choice = view.resolve(
        f.get(&["--baselines"])
            .map(PathBuf::from)
            .or_else(|| default_baselines(root)),
        f.get(&["--baselines"]).is_some(),
    )?;
    let run_dir = f
        .get(&["--run", "--run-dir"])
        .with_context(|| format!("--run is required\n{REPLAY_USAGE}"))?;
    let app = f
        .get(&["--app"])
        .with_context(|| format!("--app is required\n{REPLAY_USAGE}"))?;
    let out = f
        .get(&["-o", "--out"])
        .with_context(|| format!("-o is required\n{REPLAY_USAGE}"))?;
    let opts = ReplayOpts {
        run_dir: PathBuf::from(run_dir),
        app: app.to_owned(),
        out: PathBuf::from(out),
        overlay: f.get(&["--overlay"]).map(PathBuf::from),
        baselines: choice.baselines,
        fp: f.get(&["--fp"]).map(PathBuf::from),
        sidecar: true,
        live: f.has("--live"),
        view: choice.inject,
    };
    // The reference is read before the replay, so a wrong path costs nothing.
    let reference: Option<(PathBuf, purge_model::Plan)> = match f.get(&["--l5-against"]) {
        None => None,
        Some(_) if opts.view.is_none() => bail!(
            "--l5-against compares a plan made with a view below Exact (--baseline-view merged, local, or none \
             with --local or --neighbour) with the no-baseline plan\n{REPLAY_USAGE}"
        ),
        Some(path) => {
            let plan = output::read_json(Path::new(path))
                .map_err(|e| anyhow!("--l5-against: plan {e}"))?;
            Some((PathBuf::from(path), plan))
        }
    };
    let r = replay(&opts)?;
    report(app, &opts.out, &r);
    let Some((path, none)) = reference else {
        return Ok(true);
    };
    let violations = l5_violations(&none, &r.plan);
    for v in &violations {
        eprintln!("replay: {app}: L5: {v}");
    }
    println!(
        "replay: {app}: L5 against {}: {} item(s) below Exact, {} without a baseline, {} violation(s)",
        path.display(),
        r.plan.items.len(),
        none.items.len(),
        violations.len()
    );
    Ok(violations.is_empty())
}

/// `cargo xtask replay-all …`.
pub fn run_all(root: &Path, args: &[String]) -> Result<bool> {
    let f = Flags::parse(
        args,
        &["--runs", "--overlay-root"],
        &["--if-present", "--no-score"],
        REPLAY_ALL_USAGE,
    )?;
    let runs = f
        .get(&["--runs"])
        .map(PathBuf::from)
        .or_else(|| std::env::var_os(RUNS_DIR_VAR).map(PathBuf::from))
        .unwrap_or_else(|| root.join("vm").join("runs"));
    if !runs.is_dir() {
        let msg = format!(
            "replay-all: no runs directory {} (the frozen rig runs are git-ignored; pass --runs or set \
             {RUNS_DIR_VAR})",
            runs.display()
        );
        if f.has("--if-present") {
            println!("{msg}; nothing to do");
            return Ok(true);
        }
        bail!(msg);
    }
    let mut ok = true;
    let mut dirs = Vec::new();
    for id in M0_RUNS {
        let dir = runs.join(id);
        if !dir.join("run.json").is_file() {
            eprintln!("replay-all: {id}: no run.json in {}", dir.display());
            ok = false;
            continue;
        }
        let opts = ReplayOpts {
            run_dir: dir.clone(),
            app: (*id).to_owned(),
            out: dir.join("plans").join(REPLAY_PLAN),
            overlay: f
                .get(&["--overlay-root"])
                .map(|o| Path::new(o).join(id))
                .filter(|o| o.is_dir()),
            baselines: default_baselines(root),
            fp: None,
            sidecar: false,
            live: false,
            view: None,
        };
        match replay(&opts) {
            Ok(r) => {
                report(id, &opts.out, &r);
                dirs.push(dir);
            }
            Err(e) => {
                eprintln!("replay-all: {id}: {e:#}");
                ok = false;
            }
        }
    }
    if f.has("--no-score") || dirs.is_empty() {
        return Ok(ok);
    }
    let rigtool_dir = root
        .join("vm")
        .join("rigtool")
        .join("target")
        .join("release");
    let rigtool = ["rigtool.exe", "rigtool"]
        .iter()
        .map(|n| rigtool_dir.join(n))
        .find(|p| p.is_file());
    match rigtool {
        None => println!(
            "replay-all: {} has no rigtool binary; build it (cargo build --release in vm/rigtool) to \
             score the plans",
            rigtool_dir.display()
        ),
        Some(exe) => {
            let mut cmd = Command::new(&exe);
            cmd.arg("score").arg("--set").args(&dirs);
            println!("replay-all: {} score --set …", exe.display());
            let status = cmd
                .status()
                .with_context(|| format!("running {}", exe.display()))?;
            if !status.success() {
                eprintln!("replay-all: rigtool score failed ({status})");
                ok = false;
            }
        }
    }
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\u{feff}{
        \"schema\": \"purge.rig.run/1\",
        \"id\": \"git\",
        \"run\": \"git\",
        \"user_sid\": \"S-1-5-21-1-2-3-1000\",
        \"main\": {
            \"key\": \"HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\Git_is1\",
            \"name\": \"Git\"
        },
        \"uninstall\": {
            \"cmd\": \"x\",
            \"t0\": \"2026-11-11T08:09:43.1776380-08:00\",
            \"t1\": \"2026-11-11T08:09:49.0887115-08:00\",
            \"exit\": 0
        }
    }";

    #[test]
    fn parses_a_run_json_with_a_bom() {
        let info = parse_run_json(SAMPLE).unwrap();
        assert_eq!(info.run, "git");
        assert_eq!(
            info.main_key,
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Git_is1"
        );
        assert_eq!(
            Some(info.t_start),
            parse_iso8601("2026-11-11T16:09:43.1776380Z")
        );
        // 5.9110735 s later, in 100 ns ticks.
        assert_eq!(info.t_end.0 - info.t_start.0, 59_110_735);
    }

    #[test]
    fn resolves_hkcu_to_the_user_hive() {
        let text = SAMPLE.replace(r"HKLM\\SOFTWARE", r"HKCU\\Software");
        let info = parse_run_json(&text).unwrap();
        assert_eq!(
            info.main_key,
            r"HKU\S-1-5-21-1-2-3-1000\Software\Microsoft\Windows\CurrentVersion\Uninstall\Git_is1"
        );
    }

    #[test]
    fn rejects_runs_without_an_app_or_a_window() {
        let no_main = SAMPLE.replace("\"main\"", "\"other\"");
        assert!(parse_run_json(&no_main).is_err());
        let no_t1 = SAMPLE.replace("\"t1\"", "\"t9\"");
        assert!(parse_run_json(&no_t1).is_err());
        let bad_t0 = SAMPLE.replace("2026-11-11T08:09:43", "yesterday");
        assert!(parse_run_json(&bad_t0).is_err());
        let swapped = SAMPLE
            .replace("08:09:43.1776380", "XX")
            .replace("08:09:49.0887115", "08:09:43.1776380")
            .replace("XX", "08:09:49.0887115");
        assert!(parse_run_json(&swapped).is_err());
    }

    #[test]
    fn flags_parse_values_and_switches() {
        let args: Vec<String> = ["--runs", "x", "--if-present"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        let f = Flags::parse(&args, &["--runs"], &["--if-present"], "u").unwrap();
        assert_eq!(f.get(&["--runs"]), Some("x"));
        assert!(f.has("--if-present"));
        assert!(Flags::parse(&args, &[], &[], "u").is_err());
        assert!(Flags::parse(&["--runs".to_owned()], &["--runs"], &[], "u").is_err());
    }

    fn view(mode: ViewMode, local: Option<&Path>, neighbours: &[&Path]) -> ViewArgs {
        ViewArgs {
            mode,
            local: local.map(Path::to_path_buf),
            neighbours: neighbours.iter().map(|p| p.to_path_buf()).collect(),
        }
    }

    /// A local baseline file of Professional 26340.9882 with one key; `complete`: every source ok.
    fn local_file(dir: &Path, complete: bool) -> PathBuf {
        use purge_index::local_baseline::file::encode;
        use purge_index::local_baseline::{
            BUILDER_VERSION, LocalHeader, LocalSource, Records, SourceLine, SourceStatus,
        };
        let header = LocalHeader {
            built_at: "2026-11-21T00:00:00Z".into(),
            computer: "PC".into(),
            edition: "Professional".into(),
            build: 26340,
            ubr: 9882,
            builder_version: BUILDER_VERSION.into(),
            source_id: "abc".into(),
        };
        let ok = |s: LocalSource| complete || s != LocalSource::S4;
        let sources: Vec<SourceLine> = LocalSource::REQUIRED
            .iter()
            .map(|s| SourceLine {
                source: *s,
                status: if ok(*s) {
                    SourceStatus::Ok
                } else {
                    SourceStatus::Incomplete
                },
                items: 1,
                records: 1,
                skipped: 0,
                reasons: if ok(*s) {
                    vec![]
                } else {
                    vec!["not elevated".into()]
                },
                facts: vec![],
            })
            .collect();
        let mut records = Records::new();
        records.add_key("HKLM\\SOFTWARE\\A");
        let enc = encode(&header, &sources, &records).unwrap();
        let p = dir.join(format!("local-{complete}.tsv.gz"));
        std::fs::write(&p, enc.bytes).unwrap();
        p
    }

    fn shipped_file(dir: &Path, edition: &str, os: &str) -> PathBuf {
        let p = dir.join(format!("{edition}-{os}.tsv"));
        std::fs::write(
            &p,
            format!(
                "#purge-baseline 1\t2026-11-21T00:00:00Z\tPC\t{edition}\t{os}\n#source\tx\nK\tHKLM\\\\SOFTWARE\\\\A\n"
            ),
        )
        .unwrap();
        p
    }

    fn os(edition: &str, build: u32, ubr: u32) -> OsInfo {
        OsInfo {
            edition: edition.into(),
            build,
            ubr,
        }
    }

    #[test]
    fn baseline_view_flags() {
        let dir = std::env::temp_dir().join(format!("purge-xtask-view-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kb = default_baselines(&crate::workspace_root());
        assert!(kb.is_some(), "kb/baselines with its view.json");
        let err =
            |v: &ViewArgs, given: bool| format!("{:#}", v.resolve(kb.clone(), given).unwrap_err());
        assert_eq!(ViewMode::parse("merged").unwrap(), ViewMode::Merged);
        assert!(ViewMode::parse("exactly").is_err());
        // exact: today's directory; none: no baseline, nothing injected.
        let exact = view(ViewMode::Exact, None, &[])
            .resolve(kb.clone(), true)
            .unwrap();
        assert_eq!(exact.baselines, kb);
        assert!(exact.inject.is_none());
        let none = view(ViewMode::None, None, &[]);
        let plain = none.resolve(kb.clone(), false).unwrap();
        assert!(plain.baselines.is_none() && plain.inject.is_none());
        assert!(err(&none, true).contains("--baselines does not go"));
        let full = local_file(&dir, true);
        let part = local_file(&dir, false);
        let nb = shipped_file(&dir, "Professional", "26340.9000");
        let far = shipped_file(&dir, "Professional", "22000.1");
        let same = shipped_file(&dir, "Professional", "26340.9882");
        let e = |m, l: Option<&Path>, n: &[&Path]| err(&view(m, l, n), false);
        assert!(e(ViewMode::Exact, Some(&full), &[]).contains("takes no --local"));
        assert!(e(ViewMode::Merged, Some(&full), &[]).contains("at least one --neighbour"));
        assert!(e(ViewMode::Merged, None, &[&nb]).contains("needs --local"));
        assert!(e(ViewMode::Local, Some(&full), &[&nb]).contains("takes no --neighbour"));
        assert!(e(ViewMode::Merged, Some(&full), &[&nb, &nb, &nb, &nb]).contains("at most 3"));
        assert!(e(ViewMode::Local, Some(&part), &[]).contains("incomplete"));
        assert!(e(ViewMode::Merged, Some(&full), &[&same]).contains("leaves it out"));
        // A shipped file is no local baseline (L6).
        assert!(e(ViewMode::Local, Some(&nb), &[]).starts_with("--local"));

        // The injected modes: no baseline directory for the engine, the parts for the view.
        let host = os("Professional", 26340, 9882);
        let inputs = |m, l: Option<&Path>, n: &[&Path]| {
            let choice = view(m, l, n).resolve(kb.clone(), false).unwrap();
            assert!(choice.baselines.is_none());
            choice.inject.expect("a view to inject")
        };
        let merged = inputs(ViewMode::Merged, Some(&full), &[&nb]);
        let v = merged.view(&host).unwrap();
        assert_eq!(v.trust(), BaselineTrust::Merged);
        assert_eq!(v.neighbour_names(), ["Professional-26340.9000"]);
        assert!(v.has_key(r"HKLM\SOFTWARE\A"));
        let local = inputs(ViewMode::Local, Some(&full), &[]);
        assert_eq!(local.view(&host).unwrap().trust(), BaselineTrust::Local);
        // `none` with parts: presence from them, trust None, also from an incomplete local baseline.
        let presence = inputs(ViewMode::None, Some(&part), &[&nb]);
        let v = presence.view(&host).unwrap();
        assert_eq!(v.trust(), BaselineTrust::None);
        assert!(v.has_key(r"HKLM\SOFTWARE\A") && !v.holds_nothing());
        let only_nb = inputs(ViewMode::None, None, &[&nb]);
        assert_eq!(only_nb.view(&host).unwrap().trust(), BaselineTrust::None);

        // A snap of another Windows than the local file's: the view is not the one asked for.
        let other = format!(
            "{:#}",
            merged.view(&os("Professional", 26100, 1)).unwrap_err()
        );
        assert!(other.contains("not merged"), "{other}");
        // A neighbour the rule does not take.
        let dropped = inputs(ViewMode::Merged, Some(&full), &[&nb, &far]);
        let why = format!("{:#}", dropped.view(&host).unwrap_err());
        assert!(why.contains("left out"), "{why}");
        // The neighbour is the exact baseline of the snap's Windows (no local file to tell beforehand).
        let exact_nb = inputs(ViewMode::None, None, &[&same]);
        let why = format!("{:#}", exact_nb.view(&host).unwrap_err());
        assert!(why.contains("left out"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------------------------------------------
    // Invariant L5 at plan level, with the view injected into harvest and scan
    // -----------------------------------------------------------------------------------------------------

    fn plan_item(path: &str, band: Band, preselected: bool) -> purge_model::PlanItem {
        purge_model::PlanItem {
            target: purge_model::Target::RegKey { path: path.into() },
            band,
            preselected,
            scanner: "REG-SOFTWARE".into(),
            category: purge_model::Category::Registration,
        }
    }

    fn plan_of(items: Vec<purge_model::PlanItem>) -> purge_model::Plan {
        purge_model::Plan {
            schema: purge_model::PlanSchema,
            app: "x".into(),
            tool: purge_model::Tool::Purge,
            mode: ScanMode::Post,
            items,
        }
    }

    /// `--l5-against` needs a plan made with a view below Exact to compare, and a readable reference;
    /// both are refused before anything is replayed.
    #[test]
    fn l5_against_is_refused_without_an_injected_view_or_a_readable_plan() {
        let root = crate::workspace_root();
        let args = |extra: &[&str]| -> Vec<String> {
            ["--run", "no-such-run", "--app", "a", "-o", "p.json"]
                .iter()
                .chain(extra)
                .map(|s| (*s).to_owned())
                .collect()
        };
        for extra in [
            &["--l5-against", "none.json"][..],
            &["--l5-against", "none.json", "--baseline-view", "none"][..],
        ] {
            let e = run_one(&root, &args(extra)).unwrap_err().to_string();
            assert!(e.contains("--l5-against compares a plan"), "{e}");
        }
        let shipped = root
            .join("kb")
            .join("baselines")
            .join("Professional-26340.9882.tsv.gz");
        let e = run_one(
            &root,
            &args(&[
                "--l5-against",
                "no-such-plan.json",
                "--baseline-view",
                "none",
                "--neighbour",
                shipped.to_str().unwrap(),
            ]),
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("--l5-against: plan"), "{e}");
    }

    #[test]
    fn l5_violations_names_new_raised_and_preselected_items() {
        let none = plan_of(vec![
            plan_item(r"HKLM\SOFTWARE\A", Band::Safe, true),
            plan_item(r"HKLM\SOFTWARE\B", Band::Likely, false),
            plan_item(r"HKLM\SOFTWARE\C", Band::Blocked, false),
            plan_item(r"HKLM\SOFTWARE\D", Band::Weak, false),
        ]);
        assert!(l5_violations(&none, &none).is_empty());
        // Taking away: lower bands, no tick, items gone; the letter case of a target does not matter.
        let less = plan_of(vec![
            plan_item(r"hklm\software\a", Band::Safe, false),
            plan_item(r"HKLM\SOFTWARE\B", Band::Blocked, false),
        ]);
        assert_eq!(l5_violations(&none, &less), Vec::<String>::new());
        assert!(l5_violations(&none, &plan_of(Vec::new())).is_empty());
        let one = |item| l5_violations(&none, &plan_of(vec![item]));
        let v = one(plan_item(r"HKLM\SOFTWARE\E", Band::Blocked, false));
        assert!(v.len() == 1 && v[0].starts_with("new item"), "{v:?}");
        let v = one(plan_item(r"HKLM\SOFTWARE\C", Band::Weak, false));
        assert!(v.len() == 1 && v[0].starts_with("band raised"), "{v:?}");
        let v = one(plan_item(r"HKLM\SOFTWARE\B", Band::Safe, false));
        assert!(v.len() == 1 && v[0].starts_with("band raised"), "{v:?}");
        let v = one(plan_item(r"HKLM\SOFTWARE\B", Band::Likely, true));
        assert!(v.len() == 1 && v[0].starts_with("preselected"), "{v:?}");
        // What lies in an offered key or directory is covered by it, up to its band and its tick.
        let value = |key: &str, band, preselected| purge_model::PlanItem {
            target: Target::RegValue {
                path: key.into(),
                name: "v".into(),
            },
            ..plan_item("", band, preselected)
        };
        assert!(one(value(r"HKLM\SOFTWARE\A", Band::Safe, true)).is_empty());
        assert!(one(value(r"hklm\software\a\Sub", Band::Likely, false)).is_empty());
        assert!(one(plan_item(r"HKLM\SOFTWARE\A\Sub", Band::Safe, true)).is_empty());
        let v = one(value(r"HKLM\SOFTWARE\B", Band::Safe, false));
        assert!(v.len() == 1 && v[0].starts_with("band raised"), "{v:?}");
        let v = one(value(r"HKLM\SOFTWARE\B", Band::Likely, true));
        assert!(v.len() == 1 && v[0].starts_with("preselected"), "{v:?}");
        // The item of the same target decides when the no-baseline plan has one: a value it lists as
        // Blocked is not covered by the Safe key around it.
        let with_value = plan_of(vec![
            plan_item(r"HKLM\SOFTWARE\A", Band::Safe, true),
            value(r"HKLM\SOFTWARE\A", Band::Blocked, false),
        ]);
        let v = l5_violations(
            &with_value,
            &plan_of(vec![value(r"HKLM\SOFTWARE\A", Band::Likely, false)]),
        );
        assert!(v.len() == 1 && v[0].starts_with("band raised"), "{v:?}");
        // Not the other way round, and not a name that only starts alike.
        let v = one(plan_item(r"HKLM\SOFTWARE", Band::Blocked, false));
        assert!(v.len() == 1 && v[0].starts_with("new item"), "{v:?}");
        let v = one(plan_item(r"HKLM\SOFTWARE\AB", Band::Blocked, false));
        assert!(v.len() == 1 && v[0].starts_with("new item"), "{v:?}");
        let path = |p: &str| Target::Path { path: p.into() };
        assert!(covers(&path(r"C:\App"), &path(r"c:\app\bin\x.dll")));
        assert!(!covers(&path(r"C:\App\bin"), &path(r"C:\App")));
        assert!(!covers(&path(r"C:\App"), &path(r"C:\Apple")));
        assert!(!covers(
            &value(r"HKLM\SOFTWARE\A", Band::Safe, true).target,
            &plan_item(r"HKLM\SOFTWARE\A", Band::Safe, true).target
        ));
    }

    /// The registry keys and the directories and files a replay named: every string of the plan's targets
    /// and of the fingerprint that is spelled as a key (`HKLM\…`, `HKU\…`) or as a drive path, each key
    /// with its ancestors down to depth 3. What a view below Exact can be told Windows owns.
    fn named(replayed: &Replayed) -> Vec<String> {
        fn walk(v: &serde_json::Value, out: &mut std::collections::BTreeSet<String>) {
            match v {
                serde_json::Value::String(s) => {
                    let upper = s.to_ascii_uppercase();
                    let b = s.as_bytes();
                    if upper.starts_with("HKLM\\") || upper.starts_with("HKU\\") {
                        let segs: Vec<&str> = s.split('\\').filter(|p| !p.is_empty()).collect();
                        for depth in 3..=segs.len() {
                            out.insert(segs[..depth].join("\\"));
                        }
                    } else if b.len() > 3
                        && b[0].is_ascii_alphabetic()
                        && b[1] == b':'
                        && b[2] == b'\\'
                        && !s.contains(['"', '*', '?', '<', '>', '|'])
                    {
                        out.insert(s.trim_end_matches('\\').to_owned());
                    }
                }
                serde_json::Value::Array(items) => items.iter().for_each(|i| walk(i, out)),
                serde_json::Value::Object(map) => map.values().for_each(|i| walk(i, out)),
                _ => {}
            }
        }
        let mut out = std::collections::BTreeSet::new();
        walk(&serde_json::to_value(&replayed.plan).unwrap(), &mut out);
        walk(
            &serde_json::to_value(&replayed.fingerprint).unwrap(),
            &mut out,
        );
        out.into_iter().collect()
    }

    /// What the harvest found, without what it says about how it ran (its warnings, the view it names),
    /// in the fingerprint and in the fingerprints of its co-removed products.
    fn harvest_facts(fp: &purge_model::Fingerprint) -> serde_json::Value {
        fn strip(fp: &mut serde_json::Value) {
            let Some(map) = fp.as_object_mut() else {
                return;
            };
            map.remove("warnings");
            map.remove("baseline_view");
            if let Some(co) = map.get_mut("co_removed").and_then(|c| c.as_array_mut()) {
                for product in co {
                    if let Some(inner) = product.get_mut("fingerprint") {
                        strip(inner);
                    }
                }
            }
        }
        let mut v = serde_json::to_value(fp).unwrap();
        strip(&mut v);
        v
    }

    /// xorshift64*: deterministic subsets.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
    }

    /// What one case showed.
    #[derive(Debug, Default)]
    struct L5Seen {
        none_items: usize,
        none_preselected: usize,
        views: usize,
        /// Views whose plan differs from the no-baseline plan.
        changed: usize,
        /// Views whose fingerprint differs from the no-baseline fingerprint.
        fingerprint_changed: usize,
    }

    /// Invariant L5 for one case, end to end: the no-baseline replay against replays whose harvest **and**
    /// scan run with an injected view below Exact.
    ///
    /// 1. A Merged, a Local and a None view that hold nothing give the no-baseline fingerprint and plan.
    /// 2. Views that say "Windows has it" of what the no-baseline replay names (all of it, each single
    ///    name when there are few, `draws` seeded random subsets), as a Merged view through its local
    ///    baseline, as a Merged view through its neighbour, as a Local view and as a None view with a
    ///    neighbour: [`l5_violations`] is empty.
    fn check_l5(what: &str, case: &Case<'_>, draws: usize) -> L5Seen {
        use purge_index::baseline_view::fixture;
        assert!(case.view.is_none() && case.baselines.is_none());
        let (none, _) = replay_case(case).unwrap();
        let os = SystemSource::os_info(case.before).unwrap();
        let with = |view: BaselineView| {
            let injected = PipelineBaseline::injected(view);
            replay_case(&Case {
                view: Some(&injected),
                ..*case
            })
            .unwrap()
            .0
        };
        let mut seen = L5Seen {
            none_items: none.plan.items.len(),
            none_preselected: none.plan.items.iter().filter(|i| i.preselected).count(),
            ..L5Seen::default()
        };

        for which in 1..fixture::BELOW_EXACT {
            let view = fixture::below_exact(which, &os).unwrap();
            let trust = view.trust();
            let below = with(view);
            assert_eq!(
                below.plan, none.plan,
                "{what}: a {trust} view that holds nothing changes the plan"
            );
            assert_eq!(
                harvest_facts(&below.fingerprint),
                harvest_facts(&none.fingerprint),
                "{what}: a {trust} view that holds nothing changes the harvest"
            );
        }

        let names = named(&none);
        let mut sets: Vec<(String, Vec<&str>)> = vec![(
            "everything".to_owned(),
            names.iter().map(String::as_str).collect(),
        )];
        if names.len() <= 80 {
            sets.extend(
                names
                    .iter()
                    .map(|n| (format!("only {n}"), vec![n.as_str()])),
            );
        }
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ names.len() as u64);
        for draw in 0..draws {
            // A third, a half or two thirds of the names.
            let (num, den) = [(1, 3), (1, 2), (2, 3)][draw % 3];
            let subset: Vec<&str> = names
                .iter()
                .filter(|_| rng.next() % den < num)
                .map(String::as_str)
                .collect();
            sets.push((format!("draw {draw} ({} names)", subset.len()), subset));
        }
        let (e, b, u) = (os.edition.as_str(), os.build, os.ubr);
        for (i, (label, keys)) in sets.iter().enumerate() {
            // Every shape of view for the full set; the shapes in turn for the others.
            let shapes: Vec<usize> = if i == 0 {
                vec![0, 1, 2, 3]
            } else {
                vec![i % 4]
            };
            for shape in shapes {
                let (name, view) = match shape {
                    0 => (
                        "merged, local has",
                        fixture::merged_view(e, b, u, keys, &[]),
                    ),
                    1 => (
                        "merged, neighbour has",
                        fixture::merged_view(e, b, u, &[], keys),
                    ),
                    2 => ("local", fixture::local_view(e, b, u, keys)),
                    _ => ("none with a neighbour", fixture::none_view(e, b, u, keys)),
                };
                let below = with(view);
                let violations = l5_violations(&none.plan, &below.plan);
                assert!(
                    violations.is_empty(),
                    "{what}: L5 broken under the view {name} holding {label}:\n{}",
                    violations.join("\n")
                );
                seen.views += 1;
                seen.changed += usize::from(below.plan != none.plan);
                seen.fingerprint_changed += usize::from(
                    harvest_facts(&below.fingerprint) != harvest_facts(&none.fingerprint),
                );
            }
        }
        eprintln!("L5 {what}: {seen:?}");
        seen
    }

    /// The Tidy Notes machine of the engine's tests (`bins/purge-engine/tests/fixtures/inno.*.json`):
    /// before, and after its uninstaller ran. Without the Inno uninstall log, as a snapshot without an
    /// overlay has none.
    fn tidy_notes() -> (Fixture, Fixture) {
        #[derive(Deserialize)]
        struct Delta {
            remove_keys: Vec<String>,
            #[serde(default)]
            remove_values: Vec<(String, String)>,
            remove_paths: Vec<String>,
        }
        let dir = crate::workspace_root()
            .join("bins")
            .join("purge-engine")
            .join("tests")
            .join("fixtures");
        let before = Fixture::from_json_file(&dir.join("inno.before.json")).unwrap();
        let text = std::fs::read_to_string(dir.join("inno.uninstall.json")).unwrap();
        let delta: Delta = serde_json::from_str(&text).unwrap();
        let mut after = before.clone();
        for key in &delta.remove_keys {
            assert!(after.remove_key(key), "no key {key}");
        }
        for (key, value) in &delta.remove_values {
            assert!(after.remove_value(key, value), "no value {key} : {value}");
        }
        for path in &delta.remove_paths {
            // The engine's test adds the Inno log (`unins000.dat`) the delta names; this machine has none.
            let _ = after.remove_path(path);
        }
        (before, after)
    }

    /// A replay case with a view below Exact injected into harvest and scan: the plan is the no-baseline
    /// plan with things taken away, never with anything added, raised or newly ticked (L5).
    #[test]
    fn l5_holds_for_a_replay_with_an_injected_view() {
        let (before, after) = tidy_notes();
        let t0 = parse_iso8601("2026-11-08T10:00:00Z").unwrap();
        let case = Case {
            before: &before,
            after: Some(&after),
            main_key: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{6F1B2C3D-4E5F-4A6B-8C7D-9E0F1A2B3C4D}_is1",
            window: (t0, FileTime(t0.0 + 20_000_000)),
            app: "tidynotes",
            baselines: None,
            fp: None,
            overlay: None,
            view: None,
        };
        let seen = check_l5("tidy notes", &case, 12);
        // The case says something: the reference plan ticks items, and telling the view that Windows has
        // them changes the plan and the harvest.
        assert!(
            seen.none_items >= 8 && seen.none_preselected >= 2,
            "{seen:?}"
        );
        assert!(seen.views >= 16 && seen.changed >= 8, "{seen:?}");
        assert!(seen.fingerprint_changed >= 1, "{seen:?}");

        // The scan really ran with the injected view, and said so.
        let view = PipelineBaseline::injected(purge_index::baseline_view::fixture::merged_view(
            "Professional",
            26340,
            9882,
            &[],
            &[],
        ));
        let (replayed, _) = replay_case(&Case {
            view: Some(&view),
            // A directory that does not exist: an injected view never reads it.
            baselines: Some(Path::new(r"Z:\no\such\baselines")),
            ..case
        })
        .unwrap();
        let injected: Vec<&String> = replayed
            .warnings
            .iter()
            .filter(|w| w.contains("injected by the caller"))
            .collect();
        assert_eq!(injected.len(), 2, "{:?}", replayed.warnings);
        assert!(
            injected.iter().all(|w| w.contains("trust merged")),
            "{injected:?}"
        );
        assert!(
            !replayed.warnings.iter().any(|w| w.contains("baselines")),
            "{:?}",
            replayed.warnings
        );
    }

    /// Replays the frozen git run into the temp directory (never into vm/runs).
    #[test]
    #[ignore = "needs PURGE_RUNS_DIR with the frozen rig runs"]
    fn replays_the_git_run() {
        let Some(runs) = std::env::var_os(RUNS_DIR_VAR) else {
            eprintln!("{RUNS_DIR_VAR} not set; skipping");
            return;
        };
        let out = std::env::temp_dir().join("purge-xtask-replay-git.json");
        let r = replay(&ReplayOpts {
            run_dir: Path::new(&runs).join("git"),
            app: "git".into(),
            out: out.clone(),
            overlay: None,
            baselines: default_baselines(&crate::workspace_root()),
            fp: None,
            sidecar: false,
            live: false,
            view: None,
        })
        .unwrap();
        assert!(r.verify_passed, "{:?}", r.warnings);
        assert!(!r.plan.items.is_empty());
        let text = std::fs::read_to_string(&out).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["schema"], "purge.plan/0");
        assert_eq!(v["app"], "git");
        assert_eq!(v["tool"], "purge");
        assert_eq!(v["mode"], "post");
        let _ = std::fs::remove_file(&out);
    }

    /// With `PURGE_RUNS_DIR`: invariant L5 end to end over the frozen M0 runs ([`M0_RUNS`]), the view
    /// injected into harvest and scan (design §8.3 S4 on synthetic views; BL-GATE's R3 repeats it with the
    /// rig's local baselines through `replay --baseline-view`). `PURGE_L5_DRAWS` sets the number of random
    /// subsets per run (default 6).
    #[test]
    #[ignore = "needs PURGE_RUNS_DIR with the frozen rig runs"]
    fn l5_holds_for_the_frozen_runs_with_an_injected_view() {
        let Some(runs) = std::env::var_os(RUNS_DIR_VAR) else {
            eprintln!("{RUNS_DIR_VAR} not set; skipping");
            return;
        };
        let draws = std::env::var("PURGE_L5_DRAWS")
            .ok()
            .and_then(|d| d.parse().ok())
            .unwrap_or(6);
        let mut changed = 0;
        for id in M0_RUNS {
            let dir = Path::new(&runs).join(id);
            let text = std::fs::read_to_string(dir.join("run.json")).unwrap();
            let info = parse_run_json(&text).unwrap();
            let before = load_phase(&dir, &info.run, 1, None).unwrap();
            let after = load_phase(&dir, &info.run, 2, None).unwrap();
            let seen = check_l5(
                id,
                &Case {
                    before: &before,
                    after: Some(&after),
                    main_key: &info.main_key,
                    window: (info.t_start, info.t_end),
                    app: id,
                    baselines: None,
                    fp: None,
                    overlay: None,
                    view: None,
                },
                draws,
            );
            // A run whose plan is small without an overlay (git: three items, none ticked) may show no
            // change; the runs together must.
            assert!(seen.none_items > 0, "{id}: {seen:?}");
            changed += seen.changed;
        }
        assert!(changed > 0, "no view changed any plan");
    }
}
