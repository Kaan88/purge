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
//! the replay scans with: `exact` (the default) is today's exact-match selection from `--baselines`; `none` scans
//! with no baseline at all (the values-only path, the reference of invariant L5). `merged` (`--local <file>` and one
//! to three `--neighbour <shipped file>`) and `local` (`--local <file>` only) check their inputs (the local file's
//! `#end` line and seal, each neighbour's header, leave-one-out) and then stop: the engine takes an injected view
//! only from BL-VIEW and BL-FRAMEWORK on (wave 5), which complete them. [`ViewArgs`] holds the flags.
//!
//! `replay-all` replays the frozen M0 runs [`M0_RUNS`] into `vm/runs/<id>/plans/purge-replay.json` (the
//! runs directory is git-ignored; the plan is a new file next to the other tools' plans) and then, when
//! `vm/rigtool/target/release/rigtool(.exe)` exists, prints `rigtool score --set …` over them.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use purge_engine::cli::output;
use purge_engine::pipeline::{self, Settings, Sources};
use purge_guard::prefix;
use purge_harvest::coproducts;
use purge_identity::kbdata::Kb;
use purge_index::baseline::Baseline;
use purge_index::local_baseline::LocalBaseline;
use purge_inventory::verify_gone::{self, VerifyTarget};
use purge_model::{Band, FileTime, InventoryEntry, ScanMode};
use purge_source::fixture::Fixture;
use purge_source::snapfixture::parse_iso8601;
use serde::Deserialize;

/// The frozen M0 runs `replay-all` replays (directory name = truth id).
pub const M0_RUNS: &[&str] = &["vscode", "git", "firefox", "npp"];

/// The plan file `replay-all` writes inside each run's `plans` directory.
pub const REPLAY_PLAN: &str = "purge-replay.json";

/// The environment variable naming the runs directory (also used by the ignored test).
pub const RUNS_DIR_VAR: &str = "PURGE_RUNS_DIR";

const REPLAY_USAGE: &str = "usage: cargo xtask replay --run <vm/runs/<id>> --app <truth id> -o <plan.json> \
                            [--overlay <dir>] [--baselines <dir>] [--fp <fp.json>] [--live] \
                            [--baseline-view exact|merged|local|none] [--local <file>] [--neighbour <file>]...";
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

/// Replays one rig run and writes its plan.
pub fn replay(opts: &ReplayOpts) -> Result<Replayed> {
    let run_json = opts.run_dir.join("run.json");
    let text = std::fs::read_to_string(&run_json)
        .with_context(|| format!("reading {}", run_json.display()))?;
    let info = parse_run_json(&text).with_context(|| format!("in {}", run_json.display()))?;
    let overlay = opts.overlay.as_deref();
    let settings = Settings {
        baseline_dir: opts.baselines.clone(),
        purge_dirs: Vec::new(),
        msi_table_dir: None,
    };
    let mut progress = |line: &str| eprintln!("replay: {line}");

    let before = load_phase(&opts.run_dir, &info.run, 1, overlay)?;
    let inv1 = pipeline::inventory(Sources::of(&before));
    let entry = entry_for(&inv1.doc.entries, &info.main_key)?;
    let program_id = entry.program_id.to_string();
    let harvested = pipeline::harvest(
        Sources::of(&before),
        &program_id,
        Kb::shipped(),
        &settings,
        &mut progress,
    )
    .map_err(|e| anyhow!("harvest at phase 1: {e}"))?;
    let mut warnings = harvested.warnings;
    let report = harvested.report;
    let mut fp = report.fingerprint;
    if let Some(path) = &opts.fp {
        fp = output::read_json(path).map_err(|e| anyhow!("fingerprint {e}"))?;
        fp.window.t_start = None;
        fp.window.t_end = None;
        fp.verify_gone = None;
        fp.co_removed.clear();
        progress(&format!("fingerprint from {}", path.display()));
    }

    if opts.live {
        progress("live: scanning phase 1 (the app is still installed), no uninstall step");
        let scanned = pipeline::scan(
            Sources::of(&before),
            &fp,
            ScanMode::External,
            Some(&opts.app),
            &settings,
            &mut progress,
        )
        .map_err(|e| anyhow!("scan at phase 1: {e}"))?;
        warnings.extend(scanned.warnings);
        write_plan(opts, &scanned.built.plan, &scanned.built.scan)?;
        return Ok(Replayed {
            plan: scanned.built.plan,
            warnings,
            limits: limits(&before, None, overlay),
            verify_passed: false,
            co_removed: 0,
            msi_roots: msi_roots(&fp),
        });
    }

    let after = load_phase(&opts.run_dir, &info.run, 2, overlay)?;
    let verify = verify_gone::check(
        &after,
        &after,
        &after,
        &VerifyTarget {
            arp_key: entry.key_path.clone(),
            product_code: entry.product_code.clone(),
            main_exes: fp.main_exes().map(|e| e.path.clone()).collect(),
        },
    )
    .result;
    let disappeared = verify_gone::disappeared(&after, &inv1.doc.entries, &entry.program_id);
    fp.window.t_start = Some(info.t_start);
    fp.window.t_end = Some(info.t_end);
    fp.verify_gone = Some(verify);
    fp.co_removed = coproducts::co_removed(&report.co_candidates, &disappeared);
    progress(&format!(
        "uninstall window from run.json; verify-gone at phase 2 {} (ARP key gone: {}, MSI unknown: {}, \
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
    ));

    let scanned = pipeline::scan(
        Sources::of(&after),
        &fp,
        ScanMode::Post,
        Some(&opts.app),
        &settings,
        &mut progress,
    )
    .map_err(|e| anyhow!("scan at phase 2: {e}"))?;
    warnings.extend(scanned.warnings);

    write_plan(opts, &scanned.built.plan, &scanned.built.scan)?;
    Ok(Replayed {
        plan: scanned.built.plan,
        warnings,
        limits: limits(&before, Some(&after), overlay),
        verify_passed: verify.is_passed(),
        co_removed: fp.co_removed.len(),
        msi_roots: msi_roots(&fp),
    })
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

impl ViewArgs {
    /// Checks the flags and their files, and returns the baseline directory the replay scans with: `baselines` for
    /// `exact`, none for `none`. `merged` and `local` end in an error after their inputs are checked, until the
    /// engine takes an injected view (BL-VIEW, BL-FRAMEWORK). `baselines_given`: `--baselines` was on the command
    /// line (it contradicts every mode but `exact`).
    pub fn baseline_dir(
        &self,
        baselines: Option<PathBuf>,
        baselines_given: bool,
    ) -> Result<Option<PathBuf>> {
        let mode = self.mode.name();
        if self.mode != ViewMode::Exact && baselines_given {
            bail!(
                "--baseline-view {mode} hides the exact baseline; --baselines does not go with it"
            );
        }
        match self.mode {
            ViewMode::Exact | ViewMode::None => {
                if self.local.is_some() || !self.neighbours.is_empty() {
                    bail!(
                        "--baseline-view {mode} takes no --local or --neighbour{}",
                        if self.mode == ViewMode::None {
                            " yet (presence from neighbours at trust None comes with BL-FRAMEWORK)"
                        } else {
                            ""
                        }
                    );
                }
                return Ok(if self.mode == ViewMode::Exact {
                    baselines
                } else {
                    None
                });
            }
            ViewMode::Local if !self.neighbours.is_empty() => {
                bail!("--baseline-view local takes no --neighbour (that is merged)")
            }
            ViewMode::Merged if self.neighbours.is_empty() => {
                bail!("--baseline-view merged needs at least one --neighbour <shipped baseline>")
            }
            ViewMode::Merged if self.neighbours.len() > MAX_NEIGHBOURS => {
                bail!("--baseline-view merged takes at most {MAX_NEIGHBOURS} --neighbour files")
            }
            ViewMode::Local | ViewMode::Merged => {}
        }
        let path = self.local.as_ref().with_context(|| {
            format!("--baseline-view {mode} needs --local <local baseline file>")
        })?;
        let local =
            LocalBaseline::load(path).map_err(|e| anyhow!("--local {}: {e}", path.display()))?;
        if !local.complete() {
            bail!(
                "--local {}: the local baseline is incomplete ({}); an incomplete local baseline gives trust None \
                 (design L2): use --baseline-view none",
                path.display(),
                local.incomplete_reasons().join("; ")
            );
        }
        let h = local.header();
        let mut names = Vec::new();
        for n in &self.neighbours {
            let b = Baseline::load(n).map_err(|e| anyhow!("--neighbour {}: {e}", n.display()))?;
            if b.is_for(&h.edition, h.build, h.ubr) {
                bail!(
                    "--neighbour {}: it is the exact baseline of the local file's Windows ({} {}.{}); a merged view \
                     leaves it out",
                    n.display(),
                    h.edition,
                    h.build,
                    h.ubr
                );
            }
            names.push(format!("{}-{}.{}", b.edition(), b.build(), b.ubr()));
        }
        bail!(
            "--baseline-view {mode}: inputs checked (local {} {}.{}, complete; neighbours [{}]), but the engine \
             cannot scan with an injected baseline view yet: BL-VIEW and BL-FRAMEWORK (wave 5) complete this flag",
            h.edition,
            h.build,
            h.ubr,
            names.join(", ")
        )
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
    let baselines = view.baseline_dir(
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
        baselines,
        fp: f.get(&["--fp"]).map(PathBuf::from),
        sidecar: true,
        live: f.has("--live"),
    };
    let r = replay(&opts)?;
    report(app, &opts.out, &r);
    Ok(true)
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

    #[test]
    fn baseline_view_flags() {
        let dir = std::env::temp_dir().join(format!("purge-xtask-view-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let kb = Some(PathBuf::from("kb/baselines"));
        let err = |v: &ViewArgs, given: bool| {
            format!("{:#}", v.baseline_dir(kb.clone(), given).unwrap_err())
        };
        assert_eq!(ViewMode::parse("merged").unwrap(), ViewMode::Merged);
        assert!(ViewMode::parse("exactly").is_err());
        // exact: today's directory; none: no baseline.
        let exact = view(ViewMode::Exact, None, &[]);
        assert_eq!(exact.baseline_dir(kb.clone(), true).unwrap(), kb);
        let none = view(ViewMode::None, None, &[]);
        assert_eq!(none.baseline_dir(kb.clone(), false).unwrap(), None);
        assert!(err(&none, true).contains("--baselines does not go"));
        let full = local_file(&dir, true);
        let part = local_file(&dir, false);
        let nb = shipped_file(&dir, "EnterpriseSEval", "26100.1742");
        let same = shipped_file(&dir, "Professional", "26340.9882");
        let e = |m, l: Option<&Path>, n: &[&Path]| err(&view(m, l, n), false);
        assert!(e(ViewMode::Exact, Some(&full), &[]).contains("takes no --local"));
        assert!(e(ViewMode::None, None, &[&nb]).contains("BL-FRAMEWORK"));
        assert!(e(ViewMode::Merged, Some(&full), &[]).contains("at least one --neighbour"));
        assert!(e(ViewMode::Merged, None, &[&nb]).contains("needs --local"));
        assert!(e(ViewMode::Local, Some(&full), &[&nb]).contains("takes no --neighbour"));
        assert!(e(ViewMode::Merged, Some(&full), &[&nb, &nb, &nb, &nb]).contains("at most 3"));
        assert!(e(ViewMode::Local, Some(&part), &[]).contains("incomplete"));
        assert!(e(ViewMode::Merged, Some(&full), &[&same]).contains("leaves it out"));
        // A shipped file is no local baseline (L6).
        assert!(e(ViewMode::Local, Some(&nb), &[]).starts_with("--local"));
        let m = e(ViewMode::Merged, Some(&full), &[&nb]);
        assert!(
            m.contains("inputs checked")
                && m.contains("EnterpriseSEval-26100.1742")
                && m.contains("BL-FRAMEWORK"),
            "{m}"
        );
        assert!(e(ViewMode::Local, Some(&full), &[]).contains("inputs checked"));
        let _ = std::fs::remove_dir_all(&dir);
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
}
