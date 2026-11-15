//! The executor verbs of a `rig-exec` build: `exec`, `undo`, `journal`, `quarantine` and the rig's
//! `plan from-targets` (docs/M2_DESIGN.json M2-CLI, vm/RIG.md §11.4, §11.7).
//!
//! This module is the only code of the engine that links `purge-exec`, and it is compiled only with the
//! `rig-exec` feature: a release build has no path into the executor (`cargo xtask check-deps`).
//!
//! # The store and elevation
//!
//! [`run_live`] works on the installed store (`%ProgramData%\Purge`, `StorageRoots::installed`, the strict
//! integrity policy) and the live backends. Nothing selects another store: there is no `--data-root`
//! and no variable for it. `exec`, `undo`, `journal resume` / `rollback` and `quarantine purge` refuse an
//! unelevated process with exit code 7 before they read anything. The tests drive the same verbs
//! through [`run`] with an [`ExecHost`] of their own (a relaxed store in a temp directory, which only the
//! `test-support` feature of `purge-exec` can create, and stand-in backends).
//!
//! A `sandbox-dev` build ([`super::sandbox`]) differs here only: [`run_live`] uses the relaxed store of
//! that module and needs no elevation, and [`run`] refuses the destructive verbs outside Sandboxie before
//! anything else.
//!
//! # Outputs
//!
//! Every document goes to stdout, and to the `-o` file when one is given, written with
//! [`output::write_atomic_no_follow`] (never through a link at the path). Progress and warnings go to
//! stderr. Documents of the model keep their schema: `exec` prints the `purge.exec/1` report, `undo` the
//! `purge.undo/1` report. The listings that have no model type are this CLI's own:
//!
//! | Verb | Schema | Content |
//! |---|---|---|
//! | `journal recover` | `purge.cli.recover/1` | the sessions that need recovery, with a probe of each open intent; nothing is changed |
//! | `journal resume` / `rollback` | `purge.cli.recovered/1` | per session what recovery settled, undid and reported |
//! | `journal show` | `purge.cli.journal/1` | the header, the state, the ops and every record of a journal |
//! | `quarantine expiring` | `purge.cli.expiring/1` | items and backup files due at the (offset) clock, `id` = `session/op` |
//! | `quarantine purge` | `purge.cli.purge/1` | one result per requested id |
//!
//! `journal fault-points` prints one line per fault point: `<name>` TAB `<description>`.
//!
//! # The rig's targets
//!
//! `plan from-targets` turns a `purge.rig.targets/0` document (`targets[]` of `{id, target, action}`,
//! optionally `category`) into a plan and its sidecar without a scan: every target becomes a candidate of
//! origin `ManualUser`, scanner `RIG-TARGETS`, band Safe, preselected (a package removal is not), with the
//! rig's id as candidate id, in the document's order. It is a test tool; the explanation of every item
//! says so.
//!
//! # Exit codes
//!
//! See [`crate::cli`]. `exec` and `journal resume` end with [`Exit::Partial`] when the run did not commit
//! or an item did not end done (`Done`, `Vanished`, or `Skipped(NoLongerEmpty)`: a remove-if-empty whose
//! directory or key holds something counts as carried out); `undo` and recovery that undid ops end with
//! [`Exit::UndoConflicts`] when an op ended in a conflict or failed. The document is written either way.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use purge_exec::act_typed::{PackageBackend, WinPackages};
use purge_exec::execute::{ExecEnv, ExecError, Progress, execute};
use purge_exec::expiry::{
    self, ExpiringBackup, ExpiringItem, ExpiryId, ExpiryListing, IndexUpdate, PurgeConsent,
    PurgeOutcome,
};
use purge_exec::fault;
use purge_exec::journal::{self, JournalError};
use purge_exec::locked::{PendingRenames, SystemPendingRenames};
use purge_exec::plan_in::{self, ExecRequest, ExecSettings, Selection};
use purge_exec::prepare::{
    LockerQuery, RestartManager, RestorePointBackend, RestorePointSetting, SystemRestore,
};
use purge_exec::recover::{
    self, PendingKind, PendingList, Probe, RecoverEnv, RecoverError, RecoverMode, RecoverOutput,
};
use purge_exec::storage::{StorageError, StorageRoots};
use purge_exec::undo::{self, UndoEnv, UndoError, UndoRequest, UndoSelection};
use purge_guard::canon::OtherAppRoot;
use purge_guard::deny::DenyList;
use purge_harvest::roots::guard_env;
use purge_model::exec::op::{ItemOutcome, OpId, Sha256Hex, SkipReason};
use purge_model::exec::session::{ExecReport, SessionId, SessionState, UndoCounts};
use purge_model::{
    Action, AppRef, Band, Candidate, CandidateId, Category, Decision, FileTime, Harm, Origin, Plan,
    ProgramId, Reversibility, ScanMode, Target, Tool,
};
use purge_plan::emit::{ScanDoc, ScanSchema, to_plan0};
use purge_plan::hash::plan_hash;
use purge_policy::band::POLICY_VERSION;
use purge_win::env::EnvMap;
use serde::Deserialize;
use serde_json::{Value, json};

use super::args::{ExecArgs, ExecVerb, FromTargetsArgs, PurgeArgs, RestorePointArg, UndoArgs};
use super::{Env, Exit, output};
use crate::pipeline;

/// Printed by `--version` of a `rig-exec` build, and found in no other build: the marker a strings check
/// of the release binary looks for.
pub const BUILD_MARKER: &str =
    "rig-exec build: executor verbs run headless, without the consent dialog (VM rig only)";

/// Shifts the clock of `quarantine expiring` / `purge` by whole days (the rig's expiry test). Read only
/// by [`run_live`] of a `rig-exec` build.
pub const NOW_OFFSET_VAR: &str = "PURGE_RIG_NOW_OFFSET_DAYS";

/// The largest clock offset [`NOW_OFFSET_VAR`] may give, either way.
pub const MAX_OFFSET_DAYS: i64 = 36_600;

/// The schema of the rig's target lists.
pub const TARGETS_SCHEMA: &str = "purge.rig.targets/0";

/// The scanner name of the candidates `plan from-targets` makes.
pub const RIG_SCANNER: &str = "RIG-TARGETS";

/// The owner of the candidates `plan from-targets` makes (no installed app has it).
pub const RIG_OWNER: &str = "HKLM|64|PurgeRigTargets";

/// The app id of a plan `plan from-targets` makes.
pub const RIG_APP: &str = "rig-targets";

/// FILETIME ticks (100 ns) per day.
const TICKS_PER_DAY: i64 = 864_000_000_000;

/// FILETIME of the Unix epoch.
const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;

/// Everything the executor verbs work with besides the machine's sources: the store, whether the process
/// is elevated, the system backends and the expiry clock offset.
pub struct ExecHost<'a, R> {
    /// The store, or why it could not be located.
    pub roots: Result<StorageRoots, StorageError>,
    /// Whether the process is elevated.
    pub elevated: bool,
    /// Package enumeration and removal.
    pub packages: &'a dyn PackageBackend,
    /// Restart Manager, query only.
    pub lockers: &'a dyn LockerQuery,
    /// The boot-time move list.
    pub pending_renames: &'a mut dyn PendingRenames,
    /// Creates restore points.
    pub restore_points: R,
    /// The clock offset of `quarantine` in days, or why the variable was refused.
    pub now_offset_days: Result<i64, String>,
}

/// Runs an executor verb against the installed store and the live machine.
pub fn run_live(verb: ExecVerb, env: &mut Env<'_>) -> Exit {
    let packages = WinPackages::new();
    let lockers = RestartManager;
    let mut pending_renames = SystemPendingRenames;
    #[cfg(not(feature = "sandbox-dev"))]
    let (roots, elevated) = (StorageRoots::installed(), env.sources.sys.elevated());
    // A sandbox-dev build: the relaxed store, created only by an `exec` that will run (inside Sandboxie),
    // and no elevation needed (`run` refuses the destructive verbs outside Sandboxie first).
    #[cfg(feature = "sandbox-dev")]
    let (roots, elevated) = (
        super::sandbox::live_store(
            matches!(verb, ExecVerb::Exec(_)) && super::sandbox::inside_sandboxie(),
        ),
        true,
    );
    let mut host = ExecHost {
        roots,
        elevated,
        packages: &packages,
        lockers: &lockers,
        pending_renames: &mut pending_renames,
        restore_points: SystemRestore,
        now_offset_days: offset_days(std::env::var_os(NOW_OFFSET_VAR).as_deref()),
    };
    run(verb, env, &mut host)
}

/// Reads the value of [`NOW_OFFSET_VAR`]: unset or empty is 0, otherwise a whole number of days within
/// ±[`MAX_OFFSET_DAYS`].
///
/// # Errors
///
/// A one-line message when the value is not such a number.
pub fn offset_days(value: Option<&OsStr>) -> Result<i64, String> {
    let Some(value) = value else {
        return Ok(0);
    };
    let text = value
        .to_str()
        .ok_or_else(|| format!("{NOW_OFFSET_VAR} is not valid Unicode"))?
        .trim();
    if text.is_empty() {
        return Ok(0);
    }
    let days: i64 = text
        .parse()
        .map_err(|_| format!("{NOW_OFFSET_VAR}={text:?} is not a whole number of days"))?;
    if days.abs() > MAX_OFFSET_DAYS {
        return Err(format!(
            "{NOW_OFFSET_VAR}={days} is beyond the {MAX_OFFSET_DAYS}-day limit"
        ));
    }
    Ok(days)
}

/// Whether a verb changes the system or the store and so needs an elevated process.
fn needs_elevation(verb: &ExecVerb) -> bool {
    matches!(
        verb,
        ExecVerb::Exec(_)
            | ExecVerb::Undo(_)
            | ExecVerb::JournalResume(_)
            | ExecVerb::JournalRollback(_)
            | ExecVerb::QuarantinePurge(_)
    )
}

/// Runs an executor verb with `host`.
pub fn run<R: RestorePointBackend + Clone>(
    verb: ExecVerb,
    env: &mut Env<'_>,
    host: &mut ExecHost<'_, R>,
) -> Exit {
    let name = verb.command().name();
    #[cfg(feature = "sandbox-dev")]
    if needs_elevation(&verb) && !super::sandbox::inside_sandboxie() {
        env.error(&format!("{name}: {}", super::sandbox::REFUSAL));
        return Exit::NotInSandbox;
    }
    if verb != ExecVerb::JournalFaultPoints
        && let Err(e) = fault::check_env()
    {
        env.error(&format!("{name}: {e}"));
        return Exit::Usage;
    }
    if needs_elevation(&verb) && !host.elevated {
        env.error(&format!(
            "{name} needs an elevated process (run it as administrator); nothing was done"
        ));
        return Exit::NeedsElevation;
    }
    match verb {
        ExecVerb::PlanFromTargets(a) => from_targets(&a, env),
        ExecVerb::Exec(a) => exec(&a, env, host),
        ExecVerb::Undo(a) => undo_verb(&a, env, host),
        ExecVerb::JournalRecover => journal_recover(env, host),
        ExecVerb::JournalResume(session) => {
            journal_recover_run(session.as_deref(), RecoverMode::Resume, env, host)
        }
        ExecVerb::JournalRollback(session) => {
            journal_recover_run(session.as_deref(), RecoverMode::Rollback, env, host)
        }
        ExecVerb::JournalShow(session) => journal_show(&session, env, host),
        ExecVerb::JournalFaultPoints => fault_points(env),
        ExecVerb::QuarantineExpiring => quarantine_expiring(env, host),
        ExecVerb::QuarantinePurge(a) => quarantine_purge(&a, env, host),
    }
}

// ---------------------------------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------------------------------

/// The exit code of a store error.
fn storage_exit(e: &StorageError) -> Exit {
    match e {
        StorageError::Integrity { .. }
        | StorageError::VolumeRoot { .. }
        | StorageError::VolumeMismatch { .. } => Exit::StoreIntegrity,
        StorageError::NotInstalled(_) | StorageError::SessionNotFound(_) => Exit::Usage,
        _ => Exit::Runtime,
    }
}

/// The exit code of a journal error.
fn journal_exit(e: &JournalError) -> Exit {
    match e {
        JournalError::Store(s) => storage_exit(s),
        JournalError::WrongSession { .. }
        | JournalError::TooLarge { .. }
        | JournalError::Empty { .. }
        | JournalError::Corrupt { .. }
        | JournalError::IndexMismatch { .. } => Exit::StoreIntegrity,
        _ => Exit::Runtime,
    }
}

/// The exit code of a run that did not start or stopped with an error.
fn exec_error_exit(e: &ExecError) -> Exit {
    match e {
        ExecError::Plan(_) => Exit::PlanRefused,
        ExecError::Store(s) => storage_exit(s),
        ExecError::Journal(j) => journal_exit(j),
        _ => Exit::Runtime,
    }
}

/// The exit code of a recovery that did not run or stopped.
fn recover_error_exit(e: &RecoverError) -> Exit {
    match e {
        RecoverError::Store(s) => storage_exit(s),
        RecoverError::Journal(j) => journal_exit(j),
        RecoverError::Exec(x) => exec_error_exit(x),
        _ => Exit::Runtime,
    }
}

/// Whether an item ended as asked: done, gone already, or a remove-if-empty whose object holds something.
fn complete(outcome: &ItemOutcome) -> bool {
    matches!(
        outcome,
        ItemOutcome::Done
            | ItemOutcome::Vanished
            | ItemOutcome::Skipped {
                reason: SkipReason::NoLongerEmpty
            }
    )
}

/// [`Exit::Ok`] for a committed run whose every item is complete, else [`Exit::Partial`].
fn report_exit(report: &ExecReport) -> Exit {
    if report.state == SessionState::Committed
        && report.items.iter().all(|item| complete(&item.outcome))
    {
        Exit::Ok
    } else {
        Exit::Partial
    }
}

/// The worse of two exit codes (the higher number; [`Exit::Ok`] is the best).
fn worse(a: Exit, b: Exit) -> Exit {
    if b.code() > a.code() { b } else { a }
}

/// The current time as a FILETIME, shifted by `offset_days`.
fn now_with_offset(offset_days: i64) -> FileTime {
    let since = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() / 100);
    let now = UNIX_EPOCH_TICKS.saturating_add(u64::try_from(since).unwrap_or(u64::MAX));
    let shift = offset_days.saturating_mul(TICKS_PER_DAY);
    FileTime(if shift >= 0 {
        now.saturating_add(shift.unsigned_abs())
    } else {
        now.saturating_sub(shift.unsigned_abs())
    })
}

/// The store of the host, or the exit code of why there is none.
fn roots_of<R>(
    env: &mut Env<'_>,
    host: &ExecHost<'_, R>,
    verb: &str,
) -> Result<StorageRoots, Exit> {
    host.roots.clone().map_err(|e| {
        env.error(&format!("{verb}: the store: {e}"));
        storage_exit(&e)
    })
}

/// A session id from the command line.
fn session_id(env: &mut Env<'_>, verb: &str, text: &str) -> Result<SessionId, Exit> {
    text.parse::<SessionId>().map_err(|_| {
        env.error(&format!("{verb}: {text:?} is not a session id"));
        Exit::Usage
    })
}

/// Prints a document to stdout and writes it to `out` when given, without following a link there.
fn emit_doc(env: &mut Env<'_>, out: Option<&Path>, text: &str, what: &str) -> Exit {
    let mut exit = Exit::Ok;
    if let Err(e) = env.stdout.write_all(text.as_bytes()) {
        env.error(&format!("cannot write the {what} to stdout: {e}"));
        exit = Exit::Runtime;
    }
    if let Some(path) = out {
        exit = worse(exit, write_doc(env, path, text, what));
    }
    exit
}

/// Writes a document to `path` without following a link there.
fn write_doc(env: &mut Env<'_>, path: &Path, text: &str, what: &str) -> Exit {
    match output::write_atomic_no_follow(path, text) {
        Ok(()) => {
            env.note(&format!("wrote the {what} to {}", path.display()));
            Exit::Ok
        }
        Err(e) => {
            env.error(&format!(
                "cannot write the {what} to {}: {e}",
                path.display()
            ));
            Exit::Runtime
        }
    }
}

/// A list of ids: a JSON array of strings, `{"ids": [...]}`, or one string.
#[derive(Deserialize)]
#[serde(untagged)]
enum IdList {
    Plain(Vec<String>),
    Doc { ids: Vec<String> },
    One(String),
}

/// Reads an id list file (`--select`, `--items`).
fn read_ids(env: &mut Env<'_>, path: &Path, what: &str) -> Result<Vec<CandidateId>, Exit> {
    let list: IdList = output::read_json(path).map_err(|e| {
        env.error(&format!("cannot read the {what}: {e}"));
        Exit::Usage
    })?;
    let ids = match list {
        IdList::Plain(ids) | IdList::Doc { ids } => ids,
        IdList::One(id) => vec![id],
    };
    Ok(ids
        .into_iter()
        .filter(|id| !id.is_empty())
        .map(CandidateId)
        .collect())
}

/// The deny-list of the live machine, as the scan builds it: the guard facts, Purge's own directories
/// with the store's data root, and the roots of every installed app except `exclude` (the owners of the
/// plan or session).
fn deny_list(
    env: &mut Env<'_>,
    roots: &StorageRoots,
    exclude: &[ProgramId],
) -> Result<DenyList, Exit> {
    let sources = env.sources;
    let mut warnings: Vec<String> = Vec::new();
    let vars = sources.sys.env().unwrap_or_else(|e| {
        warnings.push(format!("guard: the environment could not be read ({e})"));
        BTreeMap::new()
    });
    let env_map: EnvMap = vars.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let (mut guard, guard_warnings) = guard_env(sources.reg, sources.sys);
    warnings.extend(guard_warnings.into_iter().map(|w| format!("guard: {w}")));
    let data_root = roots.data_root().to_string_lossy().into_owned();
    let mut dirs = env.settings.purge_dirs.clone();
    dirs.push(data_root.clone());
    guard.purge_dirs = pipeline::canonical_dirs(&dirs, &guard, &mut warnings);
    let inventory = pipeline::inventory(sources);
    let excluded: Vec<&ProgramId> = exclude.iter().collect();
    let base = DenyList::compile(&guard);
    let others = pipeline::other_apps(&inventory.doc.entries, &excluded, &env_map, &guard, &base);
    guard.other_app_roots = others
        .iter()
        .flat_map(|app| {
            app.roots.iter().map(|root| OtherAppRoot {
                app: app.name.clone(),
                path: root.clone(),
            })
        })
        .collect();
    let deny = DenyList::compile(&guard);
    env.warnings(&warnings);
    if let Some(why) = deny.invalid() {
        env.error(&format!(
            "the deny-list could not be built ({why}); nothing was done"
        ));
        return Err(Exit::Runtime);
    }
    let canonical_root =
        pipeline::canonical_dirs(std::slice::from_ref(&data_root), &guard, &mut Vec::new());
    if canonical_root.is_empty() {
        env.error(&format!(
            "the store's data root {data_root} has no canonical path, so the guard could not protect it; \
             nothing was done"
        ));
        return Err(Exit::Runtime);
    }
    Ok(deny)
}

/// The owners the index records for `sessions` (left out of the other apps' roots).
fn session_owners(roots: &StorageRoots, sessions: &[SessionId]) -> Vec<ProgramId> {
    let Ok(index) = roots.read_index() else {
        return Vec::new();
    };
    sessions
        .iter()
        .filter_map(|id| index.get(id))
        .filter_map(|summary| summary.owner.as_ref())
        .map(|owner| owner.program_id.clone())
        .collect()
}

/// The JSON of a value that serialises (every model document does).
fn to_json<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}

// ---------------------------------------------------------------------------------------------------
// plan from-targets
// ---------------------------------------------------------------------------------------------------

/// A `purge.rig.targets/0` document.
#[derive(Deserialize)]
struct TargetsDoc {
    schema: String,
    #[serde(default)]
    origin: Option<String>,
    targets: Vec<RigTarget>,
}

/// One target of the rig.
#[derive(Deserialize)]
struct RigTarget {
    id: String,
    target: Target,
    action: Action,
    #[serde(default)]
    category: Option<Category>,
}

/// The category of a target the document does not categorise.
fn default_category(target: &Target) -> Category {
    match target {
        Target::Path { .. } => Category::AppFiles,
        Target::Service { .. } | Target::Task { .. } | Target::FirewallRule { .. } => {
            Category::System
        }
        Target::AppxPackage { .. } => Category::Package,
        _ => Category::Registration,
    }
}

/// The candidates of a targets document, in its order.
///
/// # Errors
///
/// A one-line message naming what is wrong with the document.
fn rig_candidates(doc: TargetsDoc) -> Result<Vec<Candidate>, String> {
    if doc.schema != TARGETS_SCHEMA {
        return Err(format!(
            "the document is {:?}, not {TARGETS_SCHEMA}",
            doc.schema
        ));
    }
    if let Some(origin) = doc.origin.as_deref()
        && origin != "ManualUser"
    {
        return Err(format!(
            "origin {origin:?}: plan from-targets plans ManualUser targets only"
        ));
    }
    if doc.targets.is_empty() {
        return Err("the document has no targets".into());
    }
    let owner = AppRef {
        program_id: RIG_OWNER
            .parse()
            .map_err(|e| format!("the rig owner id: {e}"))?,
        display_name: "Purge rig targets".into(),
    };
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(doc.targets.len());
    for t in doc.targets {
        let id = t.id.trim().to_owned();
        if id.is_empty() || id != t.id {
            return Err(format!(
                "target id {:?} is empty or has surrounding spaces",
                t.id
            ));
        }
        if !seen.insert(id.clone()) {
            return Err(format!("target id {id:?} appears more than once"));
        }
        if t.action == Action::ReportOnly || !t.action.pairs_with(&t.target) {
            return Err(format!(
                "target {id:?}: action {:?} does not act on this target",
                t.action
            ));
        }
        let package = t.action == Action::RemovePackage;
        out.push(Candidate {
            id: CandidateId(id),
            category: t.category.unwrap_or_else(|| default_category(&t.target)),
            target: t.target,
            action: t.action,
            owner: owner.clone(),
            origin: Origin::ManualUser,
            scanner: RIG_SCANNER.into(),
            evidence: Vec::new(),
            blockers: Vec::new(),
            harm: Harm::Low,
            reversibility: if package {
                Reversibility::None
            } else {
                Reversibility::Full
            },
            children: Vec::new(),
            size_bytes: None,
            child_count: None,
            item_fp: None,
            decision: Some(Decision {
                band: Band::Safe,
                preselected: !package,
                score: 9,
                explanation:
                    "rig target (plan from-targets, a test tool of the VM rig); not decided \
                              by the policy"
                        .into(),
            }),
        });
    }
    Ok(out)
}

fn from_targets(a: &FromTargetsArgs, env: &mut Env<'_>) -> Exit {
    env.note(
        "plan from-targets: a test tool of the VM rig; the items are not decided by the policy",
    );
    let doc: TargetsDoc = match output::read_json(&a.targets) {
        Ok(d) => d,
        Err(e) => {
            env.error(&format!("cannot read the targets: {e}"));
            return Exit::Usage;
        }
    };
    let items = match rig_candidates(doc) {
        Ok(items) => items,
        Err(e) => {
            env.error(&format!("{}: {e}", a.targets.display()));
            return Exit::Usage;
        }
    };
    let mode = ScanMode::Post;
    let scan = ScanDoc {
        schema: ScanSchema,
        app: RIG_APP.into(),
        tool: Tool::Purge,
        mode,
        policy_version: POLICY_VERSION.into(),
        plan_hash: plan_hash(&items, POLICY_VERSION, mode),
        items,
        absorbed: Vec::new(),
    };
    let plan = to_plan0(RIG_APP, mode, &scan.items);
    env.note(&format!(
        "plan from-targets: {} item(s), hash {}",
        scan.items.len(),
        scan.plan_hash
    ));
    let exit = write_doc(env, &a.out, &output::json_text(&plan), "plan");
    if exit != Exit::Ok {
        return exit;
    }
    let sidecar = output::sidecar_path(&a.out);
    write_doc(env, &sidecar, &output::json_text(&scan), "scan sidecar")
}

// ---------------------------------------------------------------------------------------------------
// exec
// ---------------------------------------------------------------------------------------------------

fn exec<R: RestorePointBackend + Clone>(
    a: &ExecArgs,
    env: &mut Env<'_>,
    host: &mut ExecHost<'_, R>,
) -> Exit {
    let plan: Plan = match output::read_json(&a.plan) {
        Ok(p) => p,
        Err(e) => {
            env.error(&format!("cannot read the plan: {e}"));
            return Exit::Usage;
        }
    };
    let sidecar_path = output::sidecar_path(&a.plan);
    let scan: ScanDoc = match output::read_json(&sidecar_path) {
        Ok(s) => s,
        Err(e) => {
            env.error(&format!("cannot read the scan sidecar: {e}"));
            return Exit::Usage;
        }
    };
    // The plan the user saw must be the one the sidecar holds.
    if to_plan0(&scan.app, scan.mode, &scan.items) != plan {
        env.error(&format!(
            "the plan {} does not match its sidecar {}; nothing was done",
            a.plan.display(),
            sidecar_path.display()
        ));
        return Exit::PlanRefused;
    }
    let selection = match &a.select {
        None => Selection::Preselected,
        Some(path) => match read_ids(env, path, "selection") {
            Ok(ids) => Selection::Ids(ids),
            Err(exit) => return exit,
        },
    };
    let owners: Vec<ProgramId> = scan
        .items
        .iter()
        .map(|c| c.owner.program_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let request = ExecRequest {
        scan,
        confirm: a.confirm.clone(),
        selection,
        allow_irreversible: a.allow_irreversible,
        settings: ExecSettings {
            restore_point: match a.restore_point {
                RestorePointArg::Off => RestorePointSetting::Off,
                RestorePointArg::HighRisk => RestorePointSetting::HighRiskOnly,
                RestorePointArg::Always => RestorePointSetting::Always,
            },
            user_sid: purge_win::sid::current_user_sid().ok(),
            // As the scan decided: candidates may spell 8.3 names, so the refusal stays on.
            long_names_resolved: false,
            ..ExecSettings::default()
        },
    };
    // Every refusal of the request comes before the store is touched.
    if let Err(refusal) = plan_in::bind(&request) {
        env.error(&format!(
            "the plan was refused: {refusal}; nothing was done"
        ));
        return Exit::PlanRefused;
    }
    let roots = match roots_of(env, host, "exec") {
        Ok(r) => r,
        Err(exit) => return exit,
    };
    if let Err(exit) = check_nothing_pending(env, &roots) {
        return exit;
    }
    let deny = match deny_list(env, &roots, &owners) {
        Ok(d) => d,
        Err(exit) => return exit,
    };
    let result = {
        let stderr = RefCell::new(&mut *env.stderr);
        let progress = |p: &Progress<'_>| {
            let line = match p {
                Progress::SessionCreated {
                    session,
                    path,
                    items,
                } => format!("session {session} {} ({items} item(s))", path.display()),
                Progress::ItemStarting { op, item } => format!("op {op} {}: starting", item.0),
                Progress::ItemFinished { op, outcome } => format!("op {op}: {outcome:?}"),
                Progress::Aborting { reason } => format!("aborting: {reason:?}"),
            };
            let _ = writeln!(stderr.borrow_mut(), "{line}");
        };
        let mut exec_env = ExecEnv::new(
            &roots,
            &deny,
            host.packages,
            host.lockers,
            &mut *host.pending_renames,
        );
        exec_env.progress = Some(&progress);
        execute(request, exec_env, host.restore_points.clone())
    };
    let out = match result {
        Ok(out) => out,
        Err(e) => {
            env.error(&format!("exec: {e}"));
            return exec_error_exit(&e);
        }
    };
    if !out.report_written {
        env.warnings(&["the session's report.json was not written".to_owned()]);
    }
    if !out.index_updated {
        env.warnings(&["the session index was not updated".to_owned()]);
    }
    let report = &out.report;
    env.note(&format!(
        "session {}: {:?}, {} item(s), pending reboot {}",
        out.session,
        report.state,
        report.items.len(),
        report.pending_reboot
    ));
    let written = emit_doc(env, a.out.as_deref(), &output::json_text(report), "report");
    worse(written, report_exit(report))
}

/// Refuses a new run while an interrupted session waits for recovery, or a journal is damaged.
fn check_nothing_pending(env: &mut Env<'_>, roots: &StorageRoots) -> Result<(), Exit> {
    let list = recover::pending(roots).map_err(|e| {
        env.error(&format!("listing the sessions: {e}"));
        storage_exit(&e)
    })?;
    for rejected in &list.rejected {
        env.warnings(&[format!("a session directory was rejected: {rejected}")]);
    }
    let damaged: Vec<String> = list
        .sessions
        .iter()
        .filter(|s| s.kind == PendingKind::Damaged)
        .map(|s| format!("{} ({})", s.session, s.detail))
        .collect();
    if !damaged.is_empty() {
        env.error(&format!(
            "the journal of session(s) {} is damaged; nothing was done",
            damaged.join(", ")
        ));
        return Err(Exit::StoreIntegrity);
    }
    let open: Vec<String> = list
        .sessions
        .iter()
        .filter(|s| {
            matches!(
                s.kind,
                PendingKind::Run | PendingKind::Undo | PendingKind::Retry
            )
        })
        .map(|s| format!("{} ({:?})", s.session, s.kind))
        .collect();
    if !open.is_empty() {
        env.error(&format!(
            "session(s) {} were interrupted; run journal resume or journal rollback first; nothing was done",
            open.join(", ")
        ));
        return Err(Exit::NeedsRecovery);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------
// undo
// ---------------------------------------------------------------------------------------------------

fn undo_verb<R>(a: &UndoArgs, env: &mut Env<'_>, host: &mut ExecHost<'_, R>) -> Exit {
    let session = match session_id(env, "undo", &a.session) {
        Ok(s) => s,
        Err(exit) => return exit,
    };
    let selection = match &a.items {
        None => UndoSelection::All,
        Some(path) => match read_ids(env, path, "item list") {
            Ok(ids) => UndoSelection::Items(ids),
            Err(exit) => return exit,
        },
    };
    let plan_hash: Option<Sha256Hex> = match &a.confirm {
        None => None,
        Some(text) => match text.parse() {
            Ok(h) => Some(h),
            Err(_) => {
                env.error("undo: --confirm takes the plan hash, 64 lower-case hex digits");
                return Exit::Usage;
            }
        },
    };
    let roots = match roots_of(env, host, "undo") {
        Ok(r) => r,
        Err(exit) => return exit,
    };
    let owners = session_owners(&roots, std::slice::from_ref(&session));
    let deny = match deny_list(env, &roots, &owners) {
        Ok(d) => d,
        Err(exit) => return exit,
    };
    let request = UndoRequest {
        session,
        selection,
        plan_hash,
    };
    let result = undo::undo(
        &request,
        UndoEnv::new(&roots, &deny, &mut *host.pending_renames),
    );
    let out = match result {
        Ok(out) => out,
        Err(e) => {
            env.error(&format!("undo: {e}"));
            return match &e {
                UndoError::Store(s) => storage_exit(s),
                UndoError::Journal(j) => journal_exit(j),
                UndoError::PlanMismatch { .. } | UndoError::UnknownItem(_) => Exit::PlanRefused,
                UndoError::NeedsRecovery(_) => Exit::NeedsRecovery,
                _ => Exit::Runtime,
            };
        }
    };
    let report = &out.report;
    let counts = report.counts;
    env.note(&format!(
        "undo {}: {:?}; restored {}, already restored {}, nothing to undo {}, conflicts {}, failed {}",
        report.session,
        report.state,
        counts.restored,
        counts.already_restored,
        counts.nothing_to_undo,
        counts.conflicts,
        counts.failed
    ));
    if !out.pulled_in.is_empty() {
        env.note(&format!(
            "undo: also undone because a selected restore depends on them: ops {}",
            op_list(&out.pulled_in)
        ));
    }
    if !out.already_undone.is_empty() {
        env.note(&format!(
            "undo: already undone before: ops {}",
            op_list(&out.already_undone)
        ));
    }
    if !out.index_updated {
        env.warnings(&["the session index was not updated".to_owned()]);
    }
    let mut exit = emit_doc(
        env,
        a.out.as_deref(),
        &output::json_text(report),
        "undo report",
    );
    if let Some(stopped) = &out.stopped {
        env.error(&format!("undo stopped early: {stopped}"));
        exit = worse(exit, Exit::Partial);
    }
    worse(exit, undo_exit(&counts))
}

/// [`Exit::UndoConflicts`] when an op ended in a conflict or failed.
fn undo_exit(counts: &UndoCounts) -> Exit {
    if counts.conflicts > 0 || counts.failed > 0 {
        Exit::UndoConflicts
    } else {
        Exit::Ok
    }
}

fn op_list(ops: &[OpId]) -> String {
    ops.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------------------------------
// journal
// ---------------------------------------------------------------------------------------------------

fn kind_name(kind: PendingKind) -> &'static str {
    match kind {
        PendingKind::Run => "Run",
        PendingKind::Undo => "Undo",
        PendingKind::Retry => "Retry",
        PendingKind::Unindexed => "Unindexed",
        PendingKind::Unstarted => "Unstarted",
        PendingKind::Damaged => "Damaged",
    }
}

fn probe_json(probe: &Probe) -> Value {
    match probe {
        Probe::NotDone => json!({ "probe": "NotDone" }),
        Probe::Done(outcome) => json!({ "probe": "Done", "outcome": to_json(outcome) }),
        Probe::Partial { missing_keys } => {
            json!({ "probe": "Partial", "missing_keys": missing_keys })
        }
        Probe::Attention { detail } => json!({ "probe": "Attention", "detail": detail }),
    }
}

/// The sessions that need recovery, with a probe of every open intent. Changes nothing.
fn journal_recover<R>(env: &mut Env<'_>, host: &mut ExecHost<'_, R>) -> Exit {
    let roots = match roots_of(env, host, "journal recover") {
        Ok(r) => r,
        Err(exit) => return exit,
    };
    let list: PendingList = match recover::pending(&roots) {
        Ok(l) => l,
        Err(e) => {
            env.error(&format!("journal recover: {e}"));
            return storage_exit(&e);
        }
    };
    let probing: Vec<SessionId> = list
        .sessions
        .iter()
        .filter(|s| !s.open_intents.is_empty())
        .map(|s| s.session.clone())
        .collect();
    let deny = if probing.is_empty() {
        None
    } else {
        let owners = session_owners(&roots, &probing);
        match deny_list(env, &roots, &owners) {
            Ok(d) => Some(d),
            Err(exit) => return exit,
        }
    };
    let mut sessions = Vec::new();
    let mut exit = Exit::Ok;
    for s in &list.sessions {
        let mut probes = Vec::new();
        if let Some(deny) = &deny {
            let probe_env = RecoverEnv::new(
                &roots,
                deny,
                host.packages,
                host.lockers,
                &mut *host.pending_renames,
            );
            for &op in &s.open_intents {
                probes.push(match recover::probe(&s.session, op, &probe_env) {
                    Ok(p) => json!({ "op": op, "result": probe_json(&p) }),
                    Err(e) => json!({ "op": op, "error": e.to_string() }),
                });
            }
        }
        if s.kind == PendingKind::Damaged {
            exit = Exit::StoreIntegrity;
        }
        env.note(&format!(
            "journal recover: session {} needs recovery ({}){}",
            s.session,
            kind_name(s.kind),
            if s.detail.is_empty() {
                String::new()
            } else {
                format!(": {}", s.detail)
            }
        ));
        sessions.push(json!({
            "session": s.session,
            "kind": kind_name(s.kind),
            "app": s.app,
            "started": s.started,
            "open_intents": s.open_intents,
            "undo_in_progress": s.undo_in_progress,
            "retries_in_flight": s.retries_in_flight,
            "detail": s.detail,
            "probes": probes,
        }));
    }
    if !list.rejected.is_empty() {
        env.warnings(
            &list
                .rejected
                .iter()
                .map(|r| format!("a session directory was rejected: {r}"))
                .collect::<Vec<_>>(),
        );
        exit = Exit::StoreIntegrity;
    }
    env.warnings(&list.warnings);
    if list.sessions.is_empty() {
        env.note("journal recover: no session needs recovery");
    }
    let doc = json!({
        "schema": "purge.cli.recover/1",
        "sessions": sessions,
        "rejected": list.rejected,
        "warnings": list.warnings,
    });
    worse(
        emit_doc(env, None, &output::json_text(&doc), "recovery list"),
        exit,
    )
}

/// The JSON of one recovery.
fn recovered_json(out: &RecoverOutput) -> Value {
    json!({
        "session": out.session,
        "mode": match out.mode {
            RecoverMode::Resume => "resume",
            RecoverMode::Rollback => "rollback",
        },
        "state": out.state.as_ref().map(to_json),
        "removed": out.removed,
        "settled": out.settled.iter().map(|s| json!({
            "op": s.op,
            "probe": probe_json(&s.probe),
            "outcome": to_json(&s.outcome),
        })).collect::<Vec<_>>(),
        "report": out.report.as_ref().map(to_json),
        "report_written": out.report_written,
        "undone": out.undone.iter().map(to_json).collect::<Vec<_>>(),
        "retries": out.retries.iter().map(|(op, outcome)| json!({
            "op": op,
            "outcome": to_json(outcome),
        })).collect::<Vec<_>>(),
        "index_updated": out.index_updated,
        "warnings": out.warnings,
    })
}

/// The exit code of one finished recovery.
fn recovered_exit(out: &RecoverOutput) -> Exit {
    let mut counts = UndoCounts::default();
    for item in &out.undone {
        counts.record(&item.result);
    }
    let mut exit = undo_exit(&counts);
    if out.mode == RecoverMode::Resume
        && let Some(report) = &out.report
    {
        exit = worse(exit, report_exit(report));
    }
    if out.retries.iter().any(|(_, outcome)| !complete(outcome)) {
        exit = worse(exit, Exit::Partial);
    }
    exit
}

/// `journal resume` / `journal rollback`: one session, or every session that needs recovery and can
/// have it (all but the damaged ones).
fn journal_recover_run<R>(
    session: Option<&str>,
    mode: RecoverMode,
    env: &mut Env<'_>,
    host: &mut ExecHost<'_, R>,
) -> Exit {
    let verb = match mode {
        RecoverMode::Resume => "journal resume",
        RecoverMode::Rollback => "journal rollback",
    };
    let roots = match roots_of(env, host, verb) {
        Ok(r) => r,
        Err(exit) => return exit,
    };
    let mut exit = Exit::Ok;
    let targets: Vec<SessionId> = match session {
        Some(text) => match session_id(env, verb, text) {
            Ok(id) => vec![id],
            Err(exit) => return exit,
        },
        None => {
            let list = match recover::pending(&roots) {
                Ok(l) => l,
                Err(e) => {
                    env.error(&format!("{verb}: {e}"));
                    return storage_exit(&e);
                }
            };
            for s in list
                .sessions
                .iter()
                .filter(|s| s.kind == PendingKind::Damaged)
            {
                env.error(&format!(
                    "{verb}: session {} is damaged and is left alone: {}",
                    s.session, s.detail
                ));
                exit = Exit::StoreIntegrity;
            }
            list.sessions
                .into_iter()
                .filter(|s| s.kind != PendingKind::Damaged)
                .map(|s| s.session)
                .collect()
        }
    };
    if targets.is_empty() {
        env.note(&format!("{verb}: no session needs recovery"));
    }
    let owners = session_owners(&roots, &targets);
    let deny = if targets.is_empty() {
        None
    } else {
        match deny_list(env, &roots, &owners) {
            Ok(d) => Some(d),
            Err(exit) => return exit,
        }
    };
    let mut results = Vec::new();
    for id in &targets {
        let Some(deny) = &deny else { break };
        let recover_env = RecoverEnv::new(
            &roots,
            deny,
            host.packages,
            host.lockers,
            &mut *host.pending_renames,
        );
        let result = match mode {
            RecoverMode::Resume => recover::resume(id, recover_env),
            RecoverMode::Rollback => recover::rollback(id, recover_env),
        };
        match result {
            Ok(out) => {
                env.note(&format!(
                    "{verb} {id}: {}; {} open intent(s) settled, {} op(s) undone",
                    out.state
                        .as_ref()
                        .map_or_else(|| "directory removed".to_owned(), |s| format!("{s:?}")),
                    out.settled.len(),
                    out.undone.len()
                ));
                env.warnings(&out.warnings);
                exit = worse(exit, recovered_exit(&out));
                results.push(recovered_json(&out));
            }
            Err(e) => {
                env.error(&format!("{verb} {id}: {e}"));
                let code = recover_error_exit(&e);
                exit = worse(exit, code);
                results.push(json!({
                    "session": id,
                    "error": e.to_string(),
                    "exit": code.code(),
                }));
            }
        }
    }
    let doc = json!({
        "schema": "purge.cli.recovered/1",
        "mode": match mode {
            RecoverMode::Resume => "resume",
            RecoverMode::Rollback => "rollback",
        },
        "sessions": results,
    });
    worse(
        emit_doc(env, None, &output::json_text(&doc), "recovery result"),
        exit,
    )
}

/// `journal show`: the journal of one session as it reads.
fn journal_show<R>(session: &str, env: &mut Env<'_>, host: &mut ExecHost<'_, R>) -> Exit {
    let id = match session_id(env, "journal show", session) {
        Ok(id) => id,
        Err(exit) => return exit,
    };
    let roots = match roots_of(env, host, "journal show") {
        Ok(r) => r,
        Err(exit) => return exit,
    };
    let dir = match roots.open_session(&id) {
        Ok(d) => d,
        Err(e) => {
            env.error(&format!("journal show: {e}"));
            return storage_exit(&e);
        }
    };
    let read = match journal::read(&dir) {
        Ok(r) => r,
        Err(e) => {
            env.error(&format!("journal show {id}: {e}"));
            return journal_exit(&e);
        }
    };
    let mut exit = Exit::Ok;
    let index_mark = match roots.read_index() {
        Err(e) => format!("the index cannot be read: {e}"),
        Ok(index) => match index.get(&id).and_then(|s| s.journal.as_ref()) {
            None => "the index has no mark for the session".to_owned(),
            Some(mark) => match journal::check_mark(&read, mark) {
                Ok(()) => "matches".to_owned(),
                Err(e) => {
                    env.error(&format!("journal show {id}: {e}"));
                    exit = journal_exit(&e);
                    format!("does not match: {e}")
                }
            },
        },
    };
    let state = &read.state;
    let ops_of = |ops: Vec<OpId>| ops.into_iter().map(|op| op.0).collect::<Vec<u32>>();
    let doc = json!({
        "schema": "purge.cli.journal/1",
        "session": id,
        "header": to_json(state.header()),
        "finished": state.is_finished(),
        "commit": state.commit().map(to_json),
        "aborted": state.aborted().map(to_json),
        "counts": to_json(&state.counts()),
        "records": read.records.len(),
        "valid_len": read.valid_len,
        "torn_tail": read.torn_tail,
        "head": read.head.to_string(),
        "index_mark": index_mark,
        "open_intents": ops_of(state.open_intents().map(|o| o.op).collect()),
        "pending_reboot": ops_of(state.pending_reboot().map(|o| o.op).collect()),
        "held_retry": ops_of(state.held_retry().map(|o| o.op).collect()),
        "retries_in_flight": ops_of(state.retries_in_flight().map(|o| o.op).collect()),
        "needs_attention": ops_of(state.needs_attention().map(|o| o.op).collect()),
        "undo_in_progress": ops_of(state.undo_in_progress().map(|o| o.op).collect()),
        "ops": state.ops().map(|o| json!({
            "op": o.op,
            "item": o.item,
            "target": to_json(&o.target),
            "outcome": o.outcome.as_ref().map(to_json),
        })).collect::<Vec<_>>(),
        "journal": read.records.iter().map(to_json).collect::<Vec<_>>(),
    });
    if read.torn_tail > 0 {
        env.warnings(&[format!(
            "the journal ends in an unfinished line of {} byte(s), which was ignored",
            read.torn_tail
        )]);
    }
    worse(
        emit_doc(env, None, &output::json_text(&doc), "journal"),
        exit,
    )
}

/// `journal fault-points`: one line per point, `<name>` TAB `<description>`.
fn fault_points(env: &mut Env<'_>) -> Exit {
    let mut text = String::new();
    for name in fault::FAULT_POINTS {
        text.push_str(name);
        text.push('\t');
        text.push_str(fault::describe(name).unwrap_or(""));
        text.push('\n');
    }
    emit_doc(env, None, &text, "fault points")
}

// ---------------------------------------------------------------------------------------------------
// quarantine
// ---------------------------------------------------------------------------------------------------

fn item_json(item: &ExpiringItem) -> Value {
    json!({
        "id": item.id.to_string(),
        "item": item.item,
        "original_path": item.original_path,
        "quarantine_path": item.quarantine_path,
        "expires": item.expires,
        "bytes": item.bytes,
        "is_dir": item.is_dir,
        "user_data": item.user_data,
        "unfinished": item.unfinished,
    })
}

fn backup_json(backup: &ExpiringBackup) -> Value {
    json!({
        "id": backup.id.to_string(),
        "item": backup.item,
        "files": backup.files,
        "expires": backup.expires,
        "bytes": backup.bytes,
        "user_data": backup.user_data,
        "unfinished": backup.unfinished,
    })
}

fn listing_json(listing: &ExpiryListing, now: FileTime, offset: i64) -> Value {
    json!({
        "schema": "purge.cli.expiring/1",
        "now": now,
        "offset_days": offset,
        "items": listing.items.iter().map(item_json).collect::<Vec<_>>(),
        "backups": listing.backups.iter().map(backup_json).collect::<Vec<_>>(),
        "held": listing.held.iter().map(|(id, reason)| json!({
            "id": id.to_string(),
            "reason": format!("{reason:?}"),
            "detail": reason.to_string(),
        })).collect::<Vec<_>>(),
        "due": listing.due.iter().map(|d| json!({
            "session": d.session,
            "class": to_json(&d.class),
            "expires": d.expires,
        })).collect::<Vec<_>>(),
        "problems": listing.problems.iter().map(|p| json!({
            "session": p.session,
            "detail": p.detail,
        })).collect::<Vec<_>>(),
    })
}

/// The clock of the quarantine verbs, or the exit code of a refused offset.
fn quarantine_now<R>(env: &mut Env<'_>, host: &ExecHost<'_, R>) -> Result<(FileTime, i64), Exit> {
    match &host.now_offset_days {
        Ok(days) => {
            if *days != 0 {
                env.note(&format!(
                    "quarantine: the clock is shifted by {days} day(s) ({NOW_OFFSET_VAR})"
                ));
            }
            Ok((now_with_offset(*days), *days))
        }
        Err(e) => {
            env.error(e);
            Err(Exit::Usage)
        }
    }
}

fn quarantine_expiring<R>(env: &mut Env<'_>, host: &mut ExecHost<'_, R>) -> Exit {
    let (now, offset) = match quarantine_now(env, host) {
        Ok(n) => n,
        Err(exit) => return exit,
    };
    let roots = match roots_of(env, host, "quarantine expiring") {
        Ok(r) => r,
        Err(exit) => return exit,
    };
    let listing = match expiry::expiring(&roots, now) {
        Ok(l) => l,
        Err(e) => {
            env.error(&format!("quarantine expiring: {e}"));
            return storage_exit(&e);
        }
    };
    for p in &listing.problems {
        env.warnings(&[format!(
            "session {}: {}",
            p.session
                .as_ref()
                .map_or_else(|| "?".to_owned(), ToString::to_string),
            p.detail
        )]);
    }
    env.note(&format!(
        "quarantine expiring: {} item(s) and {} backup set(s) may be purged, {} held",
        listing.items.len(),
        listing.backups.len(),
        listing.held.len()
    ));
    let doc = listing_json(&listing, now, offset);
    emit_doc(env, None, &output::json_text(&doc), "expiry listing")
}

fn quarantine_purge<R>(a: &PurgeArgs, env: &mut Env<'_>, host: &mut ExecHost<'_, R>) -> Exit {
    let mut ids: Vec<ExpiryId> = Vec::new();
    for text in &a.ids {
        match text.parse::<ExpiryId>() {
            Ok(id) => {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            Err(e) => {
                env.error(&format!("quarantine purge: {text:?}: {e}"));
                return Exit::Usage;
            }
        }
    }
    let mut user_data: Vec<ExpiryId> = Vec::new();
    for text in &a.confirm_user_data {
        match text.parse::<ExpiryId>() {
            Ok(id) => user_data.push(id),
            Err(e) => {
                env.error(&format!("quarantine purge: {text:?}: {e}"));
                return Exit::Usage;
            }
        }
    }
    let (now, _) = match quarantine_now(env, host) {
        Ok(n) => n,
        Err(exit) => return exit,
    };
    let roots = match roots_of(env, host, "quarantine purge") {
        Ok(r) => r,
        Err(exit) => return exit,
    };
    let listing = match expiry::expiring(&roots, now) {
        Ok(l) => l,
        Err(e) => {
            env.error(&format!("quarantine purge: {e}"));
            return storage_exit(&e);
        }
    };
    // The consent names every requested id and every backup file of it, and confirms the user-data
    // items --confirm-user-data lists; stderr names each one.
    let mut consent = PurgeConsent::naming(ids.iter().cloned());
    for id in &ids {
        let confirmed = user_data.contains(id);
        if confirmed {
            consent.confirm_user_data(id.clone());
        }
        let user = if confirmed {
            ", user data confirmed"
        } else {
            ""
        };
        if let Some(item) = listing.items.iter().find(|i| &i.id == id) {
            env.note(&format!(
                "quarantine purge: deleting {id} for good: {} ({} bytes{user})",
                item.original_path, item.bytes
            ));
        } else if let Some(backup) = listing.backups.iter().find(|b| &b.id == id) {
            for file in &backup.files {
                env.note(&format!(
                    "quarantine purge: deleting {id} backup file {file} for good{user}"
                ));
            }
            consent.name_files(id.clone(), backup.files.iter().cloned());
        } else {
            env.note(&format!(
                "quarantine purge: {id} is not listed as due; it is passed on and will be reported"
            ));
        }
    }
    let report = match expiry::purge(&roots, &ids, &consent, now) {
        Ok(r) => r,
        Err(e) => {
            env.error(&format!("quarantine purge: {e}"));
            return Exit::Runtime;
        }
    };
    let mut exit = Exit::Ok;
    let items: Vec<Value> = report
        .items
        .iter()
        .map(|r| {
            let (outcome, detail) = match &r.outcome {
                PurgeOutcome::Purged => ("Purged", String::new()),
                PurgeOutcome::AlreadyGone => ("AlreadyGone", String::new()),
                PurgeOutcome::Excluded(x) => ("Excluded", format!("{x:?}")),
                PurgeOutcome::Refused(x) => ("Refused", format!("{x:?}")),
                PurgeOutcome::Failed(x) => ("Failed", format!("{x:?}")),
            };
            if !matches!(r.outcome, PurgeOutcome::Purged | PurgeOutcome::AlreadyGone) {
                exit = Exit::Partial;
            }
            json!({
                "id": r.id.to_string(),
                "outcome": outcome,
                "detail": detail,
                "expire_recorded": r.expire_recorded,
                "entries_deleted": r.entries_deleted,
                "bytes_deleted": r.bytes_deleted,
                "op_dir_removed": r.op_dir_removed,
            })
        })
        .collect();
    for alert in &report.alerts {
        env.error(&format!(
            "quarantine purge {}: {}: {}",
            alert.id, alert.path, alert.detail
        ));
    }
    let index = match &report.index {
        IndexUpdate::NotNeeded => "NotNeeded".to_owned(),
        IndexUpdate::Updated => "Updated".to_owned(),
        IndexUpdate::Unavailable(e) => {
            env.warnings(&[format!("the session index was not updated: {e}")]);
            format!("Unavailable: {e}")
        }
        IndexUpdate::Failed(e) => {
            env.warnings(&[format!("the session index was not updated: {e}")]);
            format!("Failed: {e}")
        }
    };
    let doc = json!({
        "schema": "purge.cli.purge/1",
        "now": now,
        "items": items,
        "alerts": report.alerts.iter().map(|al| json!({
            "id": al.id.to_string(),
            "path": al.path,
            "detail": al.detail,
        })).collect::<Vec<_>>(),
        "index": index,
    });
    worse(
        emit_doc(env, None, &output::json_text(&doc), "purge result"),
        exit,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_clock_offset_is_a_bounded_whole_number_of_days() {
        assert_eq!(offset_days(None), Ok(0));
        assert_eq!(offset_days(Some(OsStr::new(""))), Ok(0));
        assert_eq!(offset_days(Some(OsStr::new("400"))), Ok(400));
        assert_eq!(offset_days(Some(OsStr::new(" -3 "))), Ok(-3));
        assert!(offset_days(Some(OsStr::new("1.5"))).is_err());
        assert!(offset_days(Some(OsStr::new("forever"))).is_err());
        assert!(offset_days(Some(OsStr::new("99999999"))).is_err());
        let base = now_with_offset(0).0;
        let later = now_with_offset(400).0;
        let diff = later - base;
        assert!((400 * 864_000_000_000..401 * 864_000_000_000).contains(&diff));
        assert!(now_with_offset(-1).0 < base);
    }

    #[test]
    fn complete_outcomes_and_the_worse_exit() {
        assert!(complete(&ItemOutcome::Done));
        assert!(complete(&ItemOutcome::Vanished));
        assert!(complete(&ItemOutcome::Skipped {
            reason: SkipReason::NoLongerEmpty
        }));
        assert!(!complete(&ItemOutcome::Skipped {
            reason: SkipReason::ChangedSinceScan
        }));
        assert!(!complete(&ItemOutcome::HeldRetry));
        assert_eq!(worse(Exit::Ok, Exit::Partial), Exit::Partial);
        assert_eq!(
            worse(Exit::UndoConflicts, Exit::Partial),
            Exit::UndoConflicts
        );
    }

    #[test]
    fn targets_documents_are_checked() {
        let doc = |v: Value| serde_json::from_value::<TargetsDoc>(v).unwrap();
        let path = json!({ "type": "Path", "path": r"C:\x\y" });
        let ok = rig_candidates(doc(json!({
            "schema": TARGETS_SCHEMA, "origin": "ManualUser",
            "targets": [
                { "id": "a", "trap": "t", "group": "main", "target": path, "action": "Quarantine" },
                { "id": "b", "target": { "type": "RegKey", "path": r"HKLM\SOFTWARE\X" },
                  "action": "DeleteKey", "category": "UserData" },
            ]
        })))
        .unwrap();
        assert_eq!(ok.len(), 2);
        assert_eq!(ok[0].id.0, "a");
        assert_eq!(ok[0].category, Category::AppFiles);
        assert_eq!(ok[0].origin, Origin::ManualUser);
        assert_eq!(ok[1].category, Category::UserData);
        assert!(ok.iter().all(|c| c.decision.as_ref().unwrap().preselected));
        for (bad, why) in [
            (
                json!({ "schema": "x", "targets": [] }),
                "not purge.rig.targets/0",
            ),
            (
                json!({ "schema": TARGETS_SCHEMA, "origin": "Scanner", "targets": [] }),
                "ManualUser",
            ),
            (
                json!({ "schema": TARGETS_SCHEMA, "targets": [] }),
                "no targets",
            ),
            (
                json!({ "schema": TARGETS_SCHEMA, "targets": [
                    { "id": "a", "target": path, "action": "Quarantine" },
                    { "id": "a", "target": path, "action": "Quarantine" }] }),
                "more than once",
            ),
            (
                json!({ "schema": TARGETS_SCHEMA, "targets": [
                    { "id": "a", "target": path, "action": "DeleteValue" }] }),
                "does not act",
            ),
            (
                json!({ "schema": TARGETS_SCHEMA, "targets": [
                    { "id": "a", "target": path, "action": "ReportOnly" }] }),
                "does not act",
            ),
            (
                json!({ "schema": TARGETS_SCHEMA, "targets": [
                    { "id": " a", "target": path, "action": "Quarantine" }] }),
                "surrounding spaces",
            ),
        ] {
            let e = rig_candidates(doc(bad)).unwrap_err();
            assert!(e.contains(why), "{e}");
        }
    }
}
