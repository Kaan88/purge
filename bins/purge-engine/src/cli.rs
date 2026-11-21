//! The CLI of ENGINE_PLAN.md §3.4: argument parsing ([`args`]), the M1a verbs over the
//! [`pipeline`](crate::pipeline), output files ([`output`]), `plan show` ([`show`]) and the local
//! baseline verbs ([`baseline`]).
//!
//! # Streams
//!
//! Documents go to the `-o` file, or to stdout when a verb allows that (`inventory --json`, `harvest`
//! and `uninstall` without `-o`). Everything else goes to stderr: progress lines, each prefixed with the
//! seconds since the start (the first one is written before any work), `warning:` lines, and short
//! summaries. `plan show` prints its table to stdout.
//!
//! # Exit codes
//!
//! | Code | [`Exit`] | When |
//! |---|---|---|
//! | 0 | `Ok` | success |
//! | 1 | `NotImplemented` | `kb lint`, `--stdio`, `--broker` (later milestones) |
//! | 2 | `Usage` | a usage error or a broken precondition (unknown program id, unreadable input file, `--mode post` without an uninstall window, no quiet uninstall command; an unknown session, a store that is not installed, a malformed fault or clock variable) |
//! | 3 | `Runtime` | a runtime error (an output file cannot be written) |
//! | 4 | `UninstallFailed` | the uninstaller failed, was cancelled or timed out (`run.json` is still written) |
//! | 5 | `NeedsConsent` | an executor verb (`exec`, `undo`, `journal`, `quarantine`, `plan from-targets`) in a build without `rig-exec`: it needs the consent dialog of a later version |
//! | 6 | `PlanRefused` | the plan was refused before a session existed: plan hash, sidecar, selection, order or confirmation; an undo of items the session does not hold or under another plan hash |
//! | 7 | `NeedsElevation` | `exec`, `undo`, `journal resume` / `rollback` / `retry-held`, `quarantine purge` run unelevated |
//! | 8 | `NeedsRecovery` | an interrupted session must be resumed or rolled back first |
//! | 9 | `StoreIntegrity` | the store or a journal failed its integrity check |
//! | 10 | `Partial` | the run did not commit, or an item did not end done; a purge item was not deleted (the document is written) |
//! | 11 | `UndoConflicts` | an undo (or a rollback) ended with conflicts or failures (the document is written) |
//! | 12 | `Unrecorded` | the session was not closed (a later recovery finishes it), or its report or index entry could not be written; a purge whose index entry was not updated (the document is written) |
//!
//! When several apply, the higher code is returned: 12 takes precedence over 10 and 11. The document
//! still states the outcome (the run's state and item outcomes, the undo's counts, each purge result),
//! and a `warning:` line on stderr names the code 12 hides.
//!
//! Being unelevated is never an error for the M1a verbs: `harvest` and `scan` warn and go on with what
//! they can read.
//!
//! # Executor verbs
//!
//! They are parsed in every build ([`args::ExecVerb`]). Only a `rig-exec` build compiles `cli::exec`, the one
//! module that links `purge-exec`; any other build answers [`Exit::NeedsConsent`] and touches nothing.

pub mod args;
pub mod baseline;
#[cfg(feature = "rig-exec")]
pub mod exec;
pub mod output;
pub mod show;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use purge_identity::kbdata::Kb;
use purge_inventory::runner::{ProcessHost, RunOptions};
use purge_model::{Fingerprint, InventoryDoc, Plan};
use purge_plan::emit::ScanDoc;
use purge_source::metered::{Meter, MeterSnapshot};

use crate::pipeline::{self, PipelineError, Scanned, Settings, Sources};
use args::{
    ExecVerb, HarvestArgs, InventoryArgs, Invocation, PlanShowArgs, ScanArgs, ScanFrom, USAGE,
    UninstallArgs,
};

/// The process exit code of a CLI run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// 0: success.
    Ok,
    /// 1: the command belongs to a later milestone.
    NotImplemented,
    /// 2: a usage error or a broken precondition.
    Usage,
    /// 3: a runtime error.
    Runtime,
    /// 4: the uninstaller failed, was cancelled or timed out.
    UninstallFailed,
    /// 5: an executor verb in a build without `rig-exec`; it needs the consent dialog.
    NeedsConsent,
    /// 6: the plan was refused before a session existed.
    PlanRefused,
    /// 7: the verb needs an elevated process.
    NeedsElevation,
    /// 8: an interrupted session must be recovered first.
    NeedsRecovery,
    /// 9: the store or a journal failed its integrity check.
    StoreIntegrity,
    /// 10: the run, recovery or purge did not end every item done.
    Partial,
    /// 11: the undo ended with conflicts or failures.
    UndoConflicts,
    /// 12: the session was not closed, or its report or index entry was not written.
    Unrecorded,
}

impl Exit {
    /// Every exit code, in numeric order.
    pub const ALL: [Exit; 13] = [
        Exit::Ok,
        Exit::NotImplemented,
        Exit::Usage,
        Exit::Runtime,
        Exit::UninstallFailed,
        Exit::NeedsConsent,
        Exit::PlanRefused,
        Exit::NeedsElevation,
        Exit::NeedsRecovery,
        Exit::StoreIntegrity,
        Exit::Partial,
        Exit::UndoConflicts,
        Exit::Unrecorded,
    ];

    /// The numeric exit code.
    pub fn code(self) -> u8 {
        match self {
            Exit::Ok => 0,
            Exit::NotImplemented => 1,
            Exit::Usage => 2,
            Exit::Runtime => 3,
            Exit::UninstallFailed => 4,
            Exit::NeedsConsent => 5,
            Exit::PlanRefused => 6,
            Exit::NeedsElevation => 7,
            Exit::NeedsRecovery => 8,
            Exit::StoreIntegrity => 9,
            Exit::Partial => 10,
            Exit::UndoConflicts => 11,
            Exit::Unrecorded => 12,
        }
    }

    /// What the code means, as the exit-code table of `--help` words it.
    pub fn meaning(self) -> &'static str {
        match self {
            Exit::Ok => "ok",
            Exit::NotImplemented => "not implemented yet",
            Exit::Usage => "usage error or broken precondition",
            Exit::Runtime => "runtime error",
            Exit::UninstallFailed => "uninstall failed, cancelled or timed out",
            Exit::NeedsConsent => "needs the consent dialog (executor verbs of a normal build)",
            Exit::PlanRefused => {
                "plan refused: hash, selection, order or confirmation; nothing was done"
            }
            Exit::NeedsElevation => "needs elevation",
            Exit::NeedsRecovery => {
                "needs recovery first: an interrupted session is pending (journal recover)"
            }
            Exit::StoreIntegrity => "store or journal integrity failure",
            Exit::Partial => "partial: not every item ended done (the document is still written)",
            Exit::UndoConflicts => {
                "undo ended with conflicts or failures (the document is still written)"
            }
            Exit::Unrecorded => {
                "session not closed, or its report or index entry not written (the document is still written; takes precedence over 10 and 11, which stderr then names)"
            }
        }
    }
}

impl From<&PipelineError> for Exit {
    fn from(e: &PipelineError) -> Self {
        match e {
            PipelineError::Precondition(_) => Exit::Usage,
            PipelineError::Runtime(_) => Exit::Runtime,
        }
    }
}

/// Everything a CLI run touches: the machine (sources and process host), the engine's settings, and
/// the two output streams.
pub struct Env<'a> {
    /// The machine the verbs read.
    pub sources: Sources<'a>,
    /// Starts and watches the uninstaller.
    pub host: &'a mut dyn ProcessHost,
    /// Baseline directory and Purge's own directories.
    pub settings: Settings,
    /// How long and how often `uninstall` waits.
    pub run_options: RunOptions,
    /// Documents and `plan show` tables.
    pub stdout: &'a mut dyn Write,
    /// Progress, warnings and errors.
    pub stderr: &'a mut dyn Write,
}

impl Env<'_> {
    fn error(&mut self, message: &str) {
        let _ = writeln!(self.stderr, "purge-engine: error: {message}");
    }

    fn warnings(&mut self, warnings: &[String]) {
        for w in warnings {
            let _ = writeln!(self.stderr, "warning: {w}");
        }
    }

    fn note(&mut self, line: &str) {
        let _ = writeln!(self.stderr, "{line}");
    }

    /// Writes a document to `out`, or to stdout when there is none.
    fn emit(&mut self, out: Option<&Path>, text: &str, what: &str) -> Exit {
        match out {
            None => match self.stdout.write_all(text.as_bytes()) {
                Ok(()) => Exit::Ok,
                Err(e) => {
                    self.error(&format!("cannot write the {what} to stdout: {e}"));
                    Exit::Runtime
                }
            },
            Some(path) => self.write_file(path, text, what),
        }
    }

    fn write_file(&mut self, path: &Path, text: &str, what: &str) -> Exit {
        match output::write_atomic(path, text) {
            Ok(()) => {
                self.note(&format!("wrote the {what} to {}", path.display()));
                Exit::Ok
            }
            Err(e) => {
                self.error(&format!(
                    "cannot write the {what} to {}: {e}",
                    path.display()
                ));
                Exit::Runtime
            }
        }
    }

    fn pipeline_error(&mut self, e: &PipelineError) -> Exit {
        self.error(&e.to_string());
        Exit::from(e)
    }
}

/// Writes progress lines to a stream, each with the seconds since `started`. When a source meter is
/// installed (`PURGE_TIMING`, see `main.rs`), each line is followed by a `timing:` line with the source
/// calls made since the line before.
fn progress_line(stderr: &mut dyn Write, started: Instant, line: &str) {
    let _ = writeln!(stderr, "[{:7.3}s] {line}", started.elapsed().as_secs_f64());
    if let Some(meter) = purge_source::metered::installed() {
        timing_line(stderr, meter);
    }
}

/// The meter's counters at the last [`timing_line`].
static LAST_TIMING: Mutex<Option<MeterSnapshot>> = Mutex::new(None);

/// Writes the source calls made since the previous call (nothing when there were none).
fn timing_line(stderr: &mut dyn Write, meter: &Meter) {
    let now = meter.snapshot();
    let mut last = LAST_TIMING.lock().unwrap_or_else(PoisonError::into_inner);
    let delta = match last.as_ref() {
        Some(before) => now.since(before),
        None => now.clone(),
    };
    *last = Some(now);
    let summary = delta.summary();
    if !summary.is_empty() {
        let _ = writeln!(stderr, "timing:   {summary}");
    }
}

/// Runs one command line (without the program name) and returns its exit code. In a `rig-exec` build
/// the executor verbs run against the installed store and the live machine (`exec::run_live`).
pub fn run(args: &[String], env: &mut Env<'_>) -> Exit {
    run_inner(args, env, &mut executor)
}

/// Runs one command line like [`run`], with the executor verbs working through `host` (the store, the
/// elevation answer and the system backends), so tests can drive them with a relaxed store and fakes.
#[cfg(feature = "rig-exec")]
pub fn run_with_exec<R>(
    args: &[String],
    env: &mut Env<'_>,
    host: &mut exec::ExecHost<'_, R>,
) -> Exit
where
    R: purge_exec::prepare::RestorePointBackend + Clone,
{
    run_inner(args, env, &mut |verb, env| exec::run(verb, env, host))
}

/// An executor verb in a build without `rig-exec`: refused, nothing read or written.
#[cfg(not(feature = "rig-exec"))]
fn executor(verb: ExecVerb, env: &mut Env<'_>) -> Exit {
    let cmd = verb.command();
    let why = if cmd.is_rig_tool() {
        "is a test tool of the VM rig and exists only in rig-exec builds"
    } else {
        "needs the consent dialog, which comes with a later version; only rig-exec builds of the VM rig \
         run it headless"
    };
    let _ = writeln!(
        env.stderr,
        "purge-engine {}: {why}. Nothing was done.",
        cmd.name()
    );
    Exit::NeedsConsent
}

/// An executor verb in a `rig-exec` build: run against the live machine.
#[cfg(feature = "rig-exec")]
fn executor(verb: ExecVerb, env: &mut Env<'_>) -> Exit {
    exec::run_live(verb, env)
}

/// Runs a pipeline verb as one engine start (BASELINE_LOCAL_DESIGN.md §5, W4): when the settings
/// name a local baseline cache (the live engine), the background build of this machine's local
/// baseline is started first ([`pipeline::start_local_build`]; nothing on a Windows with an exact
/// shipped baseline, nothing unelevated), the verb runs without waiting for it, and the process then
/// stays until the build it started has ended, at normal priority, so that the next run finds the
/// cache. The build reads the live machine: a cache directory belongs in the settings of the live
/// engine only.
fn with_local_build(env: &mut Env<'_>, verb: impl FnOnce(&mut Env<'_>) -> Exit) -> Exit {
    if env.settings.local_baseline_dir.is_none() {
        return verb(env);
    }
    let local = purge_source::live::LiveLocal::new();
    let sources = env.sources;
    std::thread::scope(|scope| {
        let build = pipeline::start_local_build(scope, sources, &env.settings, &local, || {
            purge_win::sxs::find_base().map_err(|e| e.to_string())
        });
        env.settings.local_build = build.clone();
        let exit = verb(env);
        if let Some(build) = build {
            finish_local_build(env, &build);
        }
        exit
    })
}

/// Waits for the background build this process started and says how it ended.
fn finish_local_build(env: &mut Env<'_>, build: &pipeline::LocalBuild) {
    use purge_rpc::BaselineBuild;
    if build.in_progress() {
        env.note(
            "baseline: finishing the local baseline build this run started (later runs use it)",
        );
        build.raise_priority();
    }
    match build.wait() {
        BaselineBuild::Done { rescan: true } => {
            env.note("baseline: this PC's local baseline is built; scan again to use it");
        }
        BaselineBuild::Done { rescan: false } => {
            env.note("baseline: this PC's local baseline is built");
        }
        BaselineBuild::Failed { reason } => {
            env.warnings(&[format!(
                "baseline: the local baseline build failed: {reason}"
            )]);
        }
        BaselineBuild::None { .. } | BaselineBuild::Checking | BaselineBuild::Building { .. } => {}
    }
}

fn run_inner(
    args: &[String],
    env: &mut Env<'_>,
    executor: &mut dyn FnMut(ExecVerb, &mut Env<'_>) -> Exit,
) -> Exit {
    let invocation = match args::parse(args) {
        Ok(i) => i,
        Err(e) => {
            let _ = writeln!(env.stderr, "purge-engine: {e}\n\n{USAGE}");
            return Exit::Usage;
        }
    };
    let started = Instant::now();
    match invocation {
        Invocation::Version => {
            let _ = writeln!(env.stdout, "purge-engine {}", env!("CARGO_PKG_VERSION"));
            #[cfg(feature = "rig-exec")]
            let _ = writeln!(env.stdout, "{}", exec::BUILD_MARKER);
            Exit::Ok
        }
        Invocation::Help => {
            let _ = write!(env.stdout, "{USAGE}");
            Exit::Ok
        }
        Invocation::NotImplemented(cmd, _) => {
            let _ = writeln!(
                env.stderr,
                "purge-engine {}: not implemented yet (milestone {})",
                cmd.name(),
                cmd.milestone()
            );
            Exit::NotImplemented
        }
        Invocation::Inventory(a) => inventory(&a, env, started),
        Invocation::Harvest(a) => with_local_build(env, |env| harvest(&a, env, started)),
        Invocation::Uninstall(a) => with_local_build(env, |env| uninstall(&a, env, started)),
        Invocation::Scan(a) => with_local_build(env, |env| scan(&a, env, started)),
        Invocation::PlanShow(a) => plan_show(&a, env),
        Invocation::BaselineBuild(a) => baseline::build_verb(
            &a,
            env,
            &purge_source::live::LiveLocal::new(),
            purge_win::sxs::find_base().map_err(|e| e.to_string()),
            started,
        ),
        Invocation::BaselineInfo(a) => baseline::info_verb(&a, env),
        Invocation::Executor(verb) => executor(verb, env),
    }
}

fn inventory(a: &InventoryArgs, env: &mut Env<'_>, started: Instant) -> Exit {
    progress_line(
        env.stderr,
        started,
        "inventory: reading the Uninstall keys and MSI",
    );
    let inv = pipeline::inventory(env.sources);
    let warnings: Vec<String> = inv
        .warnings
        .iter()
        .map(|w| format!("inventory: {w}"))
        .collect();
    env.warnings(&warnings);
    progress_line(
        env.stderr,
        started,
        &format!(
            "inventory: {} entries, {} MSI-only products",
            inv.doc.entries.len(),
            inv.doc.msi_only.len()
        ),
    );
    if a.json || a.out.is_some() {
        env.emit(a.out.as_deref(), &output::json_text(&inv.doc), "inventory")
    } else {
        let table = inventory_table(&inv.doc);
        env.emit(None, &table, "inventory")
    }
}

/// The inventory as a tab-separated table: program id, name, version, installer kind.
fn inventory_table(doc: &InventoryDoc) -> String {
    let mut out = String::from("program_id\tdisplay_name\tversion\tkind\n");
    for e in &doc.entries {
        out.push_str(&format!(
            "{}\t{}\t{}\t{:?}\n",
            e.program_id,
            e.display_name,
            e.version.as_deref().unwrap_or(""),
            e.installer_kind
        ));
    }
    out
}

fn harvest(a: &HarvestArgs, env: &mut Env<'_>, started: Instant) -> Exit {
    progress_line(
        env.stderr,
        started,
        &format!("harvest {}: starting", a.program_id),
    );
    let sources = env.sources;
    let settings = env.settings.clone();
    let result = {
        let stderr = &mut *env.stderr;
        let mut progress = |line: &str| progress_line(stderr, started, line);
        pipeline::harvest(
            sources,
            &a.program_id,
            Kb::shipped(),
            &settings,
            &mut progress,
        )
    };
    let harvested = match result {
        Ok(h) => h,
        Err(e) => return env.pipeline_error(&e),
    };
    env.warnings(&harvested.warnings);
    let report = &harvested.report;
    let fp = &report.fingerprint;
    let fp_warnings: Vec<String> = fp.warnings.iter().map(|w| format!("fp: {w}")).collect();
    env.warnings(&fp_warnings);
    let inno = match &report.inno.log_path {
        Some(log) if report.inno.parsed => format!(
            "Inno log {log}: {} of {} records kept",
            report.inno.records, report.inno.raw_records
        ),
        Some(log) => format!("Inno log {log}: not parsed"),
        None => "no Inno log".to_owned(),
    };
    let summary = format!(
        "harvest: {} ({}); {} root(s), {} rejected; {inno}; {} co-product candidate(s){}; reference \
         snapshot {}",
        fp.app.display_name,
        fp.app.program_id,
        fp.roots.len(),
        report.rejected_roots.len(),
        report.co_candidates.len(),
        if report.co_candidates.is_empty() {
            String::new()
        } else {
            format!(
                " ({})",
                report
                    .co_candidates
                    .iter()
                    .map(|c| c.app.display_name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
        if report.refsnap_complete {
            "complete"
        } else {
            "incomplete"
        }
    );
    env.note(&summary);
    env.emit(
        a.out.as_deref(),
        &purge_harvest::harvest::to_json(fp),
        "fingerprint",
    )
}

fn uninstall(a: &UninstallArgs, env: &mut Env<'_>, started: Instant) -> Exit {
    progress_line(
        env.stderr,
        started,
        &format!("uninstall {}: starting", a.program_id),
    );
    let mut fp: Option<Fingerprint> = match &a.fp {
        None => None,
        Some(path) => match output::read_json::<Fingerprint>(path) {
            Ok(fp) => Some(fp),
            Err(e) => {
                env.error(&format!("cannot read the fingerprint: {e}"));
                return Exit::Usage;
            }
        },
    };
    let sources = env.sources;
    let run_options = env.run_options;
    let result = {
        let stderr = &mut *env.stderr;
        let mut progress = |line: &str| progress_line(stderr, started, line);
        pipeline::uninstall(
            sources,
            &mut *env.host,
            &a.program_id,
            fp.as_mut(),
            &run_options,
            &mut progress,
        )
    };
    let done = match result {
        Ok(d) => d,
        Err(e) => return env.pipeline_error(&e),
    };
    env.warnings(&done.warnings);
    let routing = done.report.routing;
    env.note(&format!(
        "uninstall: ran as {:?}; should run at medium integrity: {}; wait ended {:?}; command {}",
        routing.ran_as, routing.should_run_medium, done.report.wait_end, done.report.doc.cmd
    ));
    let mut exit = env.emit(
        a.out.as_deref(),
        &output::json_text(&done.report.doc),
        "run record",
    );
    if let (Some(path), Some(fp)) = (&a.fp, &fp) {
        let wrote = env.write_file(path, &purge_harvest::harvest::to_json(fp), "fingerprint");
        if exit == Exit::Ok {
            exit = wrote;
        }
    }
    if exit != Exit::Ok {
        return exit;
    }
    if done.failed() {
        env.error(&format!(
            "the uninstaller did not succeed: {:?}",
            done.report.doc.outcome
        ));
        return Exit::UninstallFailed;
    }
    Exit::Ok
}

fn scan(a: &ScanArgs, env: &mut Env<'_>, started: Instant) -> Exit {
    progress_line(env.stderr, started, "scan: starting");
    let sources = env.sources;
    let settings = env.settings.clone();
    let result = match &a.from {
        ScanFrom::Fingerprint { fp, mode } => {
            let fp: Fingerprint = match output::read_json(fp) {
                Ok(fp) => fp,
                Err(e) => {
                    env.error(&format!("cannot read the fingerprint: {e}"));
                    return Exit::Usage;
                }
            };
            let stderr = &mut *env.stderr;
            let mut progress = |line: &str| progress_line(stderr, started, line);
            pipeline::scan(
                sources,
                &fp,
                *mode,
                a.app.as_deref(),
                &settings,
                &mut progress,
            )
        }
        ScanFrom::Path(dir) => {
            let stderr = &mut *env.stderr;
            let mut progress = |line: &str| progress_line(stderr, started, line);
            pipeline::scan_path(
                sources,
                dir,
                a.app.as_deref(),
                Kb::shipped(),
                &settings,
                &mut progress,
            )
        }
    };
    let scanned = match result {
        Ok(s) => s,
        Err(e) => return env.pipeline_error(&e),
    };
    env.warnings(&scanned.warnings);
    env.note(&scan_summary(&scanned));
    let exit = env.write_file(&a.out, &output::json_text(&scanned.built.plan), "plan");
    if exit != Exit::Ok {
        return exit;
    }
    let sidecar: PathBuf = output::sidecar_path(&a.out);
    env.write_file(
        &sidecar,
        &output::json_text(&scanned.built.scan),
        "scan sidecar",
    )
}

/// One line: items per band and the plan hash.
fn scan_summary(scanned: &Scanned) -> String {
    let plan = &scanned.built.plan;
    let count = |band| plan.items.iter().filter(|i| i.band == band).count();
    use purge_model::Band;
    format!(
        "scan: {} candidate(s) from the scanners; plan {} item(s): {} Safe ({} preselected), {} Likely, \
         {} Weak, {} Blocked; {} absorbed; hash {}",
        scanned.candidates.len(),
        plan.items.len(),
        count(Band::Safe),
        plan.items.iter().filter(|i| i.preselected).count(),
        count(Band::Likely),
        count(Band::Weak),
        count(Band::Blocked),
        scanned.built.scan.absorbed.len(),
        scanned.built.scan.plan_hash
    )
}

fn plan_show(a: &PlanShowArgs, env: &mut Env<'_>) -> Exit {
    let plan: Plan = match output::read_json(&a.plan) {
        Ok(p) => p,
        Err(e) => {
            env.error(&format!("cannot read the plan: {e}"));
            return Exit::Usage;
        }
    };
    let sidecar_path = output::sidecar_path(&a.plan);
    let sidecar: Result<ScanDoc, String> = if sidecar_path.exists() {
        output::read_json(&sidecar_path)
    } else {
        Err(format!("no sidecar {}", sidecar_path.display()))
    };
    let text = show::render(&plan, sidecar.as_ref().map_err(Clone::clone));
    env.emit(None, &text, "plan table")
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_source::fixture::Fixture;

    /// A host that must never be used.
    struct NoHost;

    impl ProcessHost for NoHost {
        fn spawn_in_job(&mut self, _: &str) -> std::io::Result<purge_inventory::runner::JobId> {
            panic!("no process may be started")
        }
        fn job_active_pids(
            &mut self,
            _: purge_inventory::runner::JobId,
        ) -> std::io::Result<Vec<u32>> {
            unreachable!()
        }
        fn job_exit_code(
            &mut self,
            _: purge_inventory::runner::JobId,
        ) -> std::io::Result<Option<u32>> {
            unreachable!()
        }
        fn process_info(&mut self, _: u32) -> Option<purge_model::ProcessSeen> {
            unreachable!()
        }
        fn running_processes(&mut self) -> std::io::Result<Vec<purge_model::ProcessSeen>> {
            Ok(Vec::new())
        }
        fn mutex_exists(&mut self, _: &str) -> std::io::Result<bool> {
            unreachable!()
        }
        fn now(&self) -> purge_model::FileTime {
            purge_model::FileTime(0)
        }
        fn sleep(&mut self, _: std::time::Duration) {}
    }

    fn run_line(line: &str) -> (Exit, String, String) {
        let fixture = Fixture::new();
        let mut host = NoHost;
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let args: Vec<String> = line.split_whitespace().map(String::from).collect();
        let exit = run(
            &args,
            &mut Env {
                sources: Sources::of(&fixture),
                host: &mut host,
                settings: Settings::default(),
                run_options: RunOptions::default(),
                stdout: &mut out,
                stderr: &mut err,
            },
        );
        (
            exit,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn exit_codes_are_the_documented_numbers() {
        let codes: Vec<u8> = Exit::ALL.iter().map(|e| e.code()).collect();
        assert_eq!(codes, (0..=12).collect::<Vec<u8>>());
        // The help prints the same table, one code per line.
        for exit in Exit::ALL {
            let line = format!("{:>4}  {}\n", exit.code(), exit.meaning());
            assert!(USAGE.contains(&line), "{line:?} is not in the help");
        }
        assert_eq!(
            Exit::from(&PipelineError::Precondition(String::new())),
            Exit::Usage
        );
        assert_eq!(
            Exit::from(&PipelineError::Runtime(String::new())),
            Exit::Runtime
        );
    }

    #[test]
    fn later_milestones_report_not_implemented() {
        for line in [
            "--stdio",
            "--broker --pipe p --parent 1 --parent-ctime 2",
            "kb lint a.json",
        ] {
            let (exit, out, err) = run_line(line);
            assert_eq!(exit, Exit::NotImplemented, "{line}");
            assert!(out.is_empty(), "{line}");
            assert!(err.contains("not implemented yet"), "{line}: {err}");
        }
    }

    /// Without `rig-exec`, every executor verb is refused with its own code before anything is read.
    #[cfg(not(feature = "rig-exec"))]
    #[test]
    fn executor_verbs_need_the_consent_dialog() {
        for line in [
            "exec --plan p.json --confirm abc",
            "undo --session s1",
            "journal recover",
            "journal resume",
            "journal rollback --session s1",
            "journal show --session s1",
            "journal retry-held --session s1",
            "quarantine expiring",
            "quarantine purge --ids s/1 --yes-irreversible",
        ] {
            let (exit, out, err) = run_line(line);
            assert_eq!(exit, Exit::NeedsConsent, "{line}");
            assert!(out.is_empty(), "{line}");
            assert!(err.contains("needs the consent dialog"), "{line}: {err}");
        }
        for line in ["plan from-targets t.json -o p.json", "journal fault-points"] {
            let (exit, _, err) = run_line(line);
            assert_eq!(exit, Exit::NeedsConsent, "{line}");
            assert!(err.contains("test tool of the VM rig"), "{line}: {err}");
        }
        // A usage error is still a usage error.
        assert_eq!(run_line("exec --plan p.json").0, Exit::Usage);
    }

    #[test]
    fn version_help_and_usage_errors() {
        let (exit, out, _) = run_line("--version");
        assert_eq!(exit, Exit::Ok);
        assert!(out.starts_with("purge-engine "));
        let (exit, out, _) = run_line("--help");
        assert_eq!(exit, Exit::Ok);
        assert!(out.contains("plan show <plan.json>"));
        let (exit, out, err) = run_line("harvest");
        assert_eq!(exit, Exit::Usage);
        assert!(out.is_empty());
        assert!(
            err.contains("missing <program_id>") && err.contains("usage:"),
            "{err}"
        );
    }

    #[test]
    fn inventory_of_an_empty_machine() {
        let (exit, out, err) = run_line("inventory --json");
        assert_eq!(exit, Exit::Ok);
        let doc: InventoryDoc = serde_json::from_str(&out).unwrap();
        assert!(doc.entries.is_empty());
        // The first progress line comes before any work.
        assert!(
            err.starts_with("[") && err.contains("inventory: reading"),
            "{err}"
        );
        let (exit, out, _) = run_line("inventory");
        assert_eq!(exit, Exit::Ok);
        assert_eq!(out, "program_id\tdisplay_name\tversion\tkind\n");
    }

    #[test]
    fn unknown_program_ids_and_missing_files_are_preconditions() {
        let (exit, _, err) = run_line("harvest HKLM|64|Nothing");
        assert_eq!(exit, Exit::Usage);
        assert!(err.contains("no inventory entry"), "{err}");
        let (exit, _, err) = run_line("uninstall Nothing --quiet");
        assert_eq!(exit, Exit::Usage, "{err}");
        let missing = std::env::temp_dir().join("purge-engine-no-such-file.json");
        let (exit, _, err) = run_line(&format!("scan --fp {} -o x.json", missing.display()));
        assert_eq!(exit, Exit::Usage);
        assert!(err.contains("cannot read the fingerprint"), "{err}");
        let (exit, _, err) = run_line(&format!("plan show {}", missing.display()));
        assert_eq!(exit, Exit::Usage);
        assert!(err.contains("cannot read the plan"), "{err}");
    }
}
