//! Executor action: delete and recreate a scheduled task (M1b, M1B-X-TASK; C-ACT for
//! [`ExecOp::DeleteTask`]).
//!
//! A task is deleted only after its registration XML and security descriptor are kept in a verified
//! definition file (`purge.taskdef/1`, [`TaskDef`]), and undo registers it again from that XML alone.
//! The M1b spike (`vm/spikes/m1b/README.md`, `RESULT.json` `task`) measured the procedure and wins over
//! the first contract text: `RegisterTask(name, xml, TASK_CREATE, ...)` with **no** SDDL argument brings
//! XML and SDDL back byte for byte; Task Scheduler regenerates the TaskCache `Tree\Id`, `Tree\SD`,
//! `DynamicInfo`, `Hash` and `Triggers` values, which belong to no check here; a task whose principal
//! holds a stored password cannot be registered again without it ([`UndoConflict::PasswordNeeded`]).
//!
//! # Entry points (the executor journals; this module never writes the journal)
//!
//! 1. [`validate_task`]: the validate pass for one item. Absent is `Vanished`; the identity digest of the
//!    live task (path and actions, [`TaskIdentity::fp`]) must equal the candidate's `object_fp`
//!    ([`gate::check_plan_fp`]); the guard's object rules must pass ([`guard_refusal`]); a running task
//!    is `GateBlocked{InUse}` (nothing is ever ended); a definition that cannot be read is
//!    `GateBlocked{CannotBackUp}`. A pass gives the [`Stamp::Object`] and the [`ItemFacts::Object`] of
//!    the journal's `validated` record.
//! 2. [`prepare_task`]: re-reads the task against the journalled stamp, reads XML and SDDL, re-reads the
//!    identity (it must be the same task, field for field), checks that the XML is the one of the
//!    identity's actions ([`xml_binds_actions`]), refuses what could not be registered again, and writes
//!    the definition ([`objdef::write_def`]). The [`TaskDelete::intent`] it returns names
//!    [`Inverse::RecreateTask`].
//!    A task with an exec program outside the journal header's `program_roots` is refused before
//!    anything is read further (`CannotBackUp`): undo would refuse to register it again. With no roots
//!    at all every task is refused there, one of COM handlers only too (review R3b S2).
//! 3. [`act_task`]: with the token of the durable intent: the act-time gate (the identity read now must
//!    have the validated digest, the guard must still pass, the task must not run, its programs must be
//!    inside the roots, and its XML, SDDL and Enabled setting must be exactly those of the definition
//!    the intent names, read hash-checked: review R2b B1, S4), then
//!    `ITaskFolder::DeleteTask`, fault point `objdelete.after`, the flush of `HKLM\SOFTWARE` (TaskCache)
//!    and of the task file's directory, fault point `act.after`.
//! 4. [`complete_task`]: the outcome for the `done` record: the task gone is `Done`, still there is
//!    `Failed{ObjectApi}`, or `Failed{VerifyFailed}` after a delete call that reported success. The
//!    now empty task folder is left alone. [`delete_task`] runs 3 and 4.
//! 5. [`probe_task`]: recovery's probe of an intent without `done`: absent `Done`, present with the
//!    recorded digest `NotDone`, anything else `Attention`. Changes nothing.
//! 6. [`prepare_undo_task`] and [`run_undo_task`]: the undo (see below).
//!
//! # Undo
//!
//! The definition is read only through the journal's reference ([`objdef::read_def_detailed`]: size,
//! SHA-256, schema, digest of its own fields). A task present at the path whose XML and SDDL equal the
//! backup (after the [`TASK_NORMALISE`] list, empty per the spike) is `AlreadyRestored`; any other task
//! there is [`UndoConflict::ObjectExists`]: nothing is ever overwritten, and the registration itself is
//! create-only ([`Register::CreateOnly`]). An absent task is registered again only when every exec action
//! of the definition runs a file inside a root recorded in the journal header
//! ([`UndoConflict::ProgramOutsideRoot`] otherwise, also when no root is given) and when its principal
//! holds no stored password ([`UndoConflict::PasswordNeeded`]: the XML stays in the definition file for
//! a manual import; the detail names the file). After the registration (fault point `undo.act.after`) the
//! hive and the directory are flushed and the task is read back: XML, SDDL, the Enabled setting and the
//! identity digest must equal the backup, else [`UndoConflict::ValueDiffers`]. The restored task keeps
//! its backed-up Enabled setting and is never run.
//!
//! # Fail-closed choices beyond the contract text
//!
//! - The guard's task rule is checked once for the path and once for every exec action's program
//!   (canonicalised with the deny-list's `GuardEnv`; a path that cannot be canonicalised is handed to the
//!   guard as written, which treats it as under `%SystemRoot%`). So one action under `%SystemRoot%`
//!   blocks the task, where the scan's rule needs every action there.
//! - `stored_password` of the definition is true when the backend says so, when the logon type may hold
//!   a password (`Password`, `InteractiveTokenOrPassword`, unknown), or when the XML names such a logon
//!   type; undo refuses on any of the three again.
//! - A task whose XML holds a `RegistrationTrigger` (it would start on registration), a NUL, or more than
//!   [`MAX_TASK_XML_BYTES`] is not deleted (`GateBlocked{CannotBackUp}`): it could not be put back.
//! - The XML must name exactly the identity's actions ([`xml_binds_actions`]); otherwise the read is
//!   taken as a task that changed between two reads (`ChangedSinceScan`), and a definition whose XML does
//!   not bind its actions is `BackupTampered` at undo.

use std::cell::Cell;

use purge_guard::canon::{GuardEnv, canon_path};
use purge_guard::deny::ObjectGuardFacts;
use purge_model::exec::journal::{Intent, ItemFacts, UndoConflict, UndoOutcome};
use purge_model::exec::op::{BackupRef, ExecOp, FailCode, Inverse, ItemOutcome, OpId, SkipReason};
use purge_model::object::fold;
use purge_model::{Blocker, Candidate, ObjectKind, Reversibility, TaskAction, TaskIdentity};
use purge_win::taskschd;

use crate::act_typed::{TypedResult, TypedUndo};
use crate::fault;
use crate::gate::{self, GateCtx, Stamp};
use crate::journal::{IntentToken, UndoToken};
use crate::objdef::{self, DefWriteError, TASKDEF_SCHEMA, TaskDef};
use crate::recover::Probe;
use crate::storage::SessionDir;

/// The largest task XML backed up: 1 MiB (C-ACT). A larger task is not deleted.
pub const MAX_TASK_XML_BYTES: usize = 1 << 20;

/// The XML elements the exact-restore comparison ignores, from `vm/spikes/m1b/RESULT.json`
/// (`task.normalise`). Empty: the spike found XML and SDDL byte-equal after re-registration, so
/// everything is compared byte for byte. A unit test keeps it equal to the spike result.
pub const TASK_NORMALISE: &[&str] = &[];

/// `logon_type` of a definition whose principal's logon type could not be read.
pub const LOGON_TYPE_UNKNOWN: u32 = u32::MAX;

/// `E_ACCESSDENIED`.
const HR_ACCESS_DENIED: u32 = 0x8007_0005;

/// The `reason` codes of the journal's `ItemFacts::Refused` for a task refused at validation (besides
/// the guard's rule names and the `gate.*` reasons of [`gate::reason`]).
pub mod reason {
    /// The op is not a task delete, or the plan item does not fit it.
    pub const NOT_TASK: &str = "task.not-a-task-op";
    /// The task runs now: nothing is ended.
    pub const RUNNING: &str = "task.running";
    /// The task's definition cannot be read.
    pub const UNREADABLE: &str = "task.unreadable";
    /// A Task Scheduler call failed.
    pub const API: &str = "task.api";
    /// The task's XML is larger than [`super::MAX_TASK_XML_BYTES`].
    pub const XML_TOO_LARGE: &str = "task.xml-too-large";
    /// The task's XML could not be registered again (a `RegistrationTrigger`, a NUL, empty).
    pub const NOT_RESTORABLE: &str = "task.not-restorable";
    /// The task's XML does not name the actions of its identity.
    pub const XML_ACTIONS: &str = "task.xml-actions";
    /// Two reads of the task differ.
    pub const CHANGED: &str = "task.changed-between-reads";
    /// The task holds a stored password and the plan states a full undo.
    pub const STORED_PASSWORD: &str = "task.stored-password";
    /// The task is gone.
    pub const GONE: &str = "task.gone";
    /// An exec action runs a program outside the run's roots: undo would never register it again.
    pub const OUTSIDE_ROOTS: &str = "task.program-outside-roots";
    /// The definition the intent names is missing, unusable, or not the task as it is now.
    pub const NO_DEFINITION: &str = "task.no-verified-definition";
}

// ---------------------------------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------------------------------

/// A Task Scheduler call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObjErr {
    /// The task exists but its definition cannot be read in full (access denied, text that is not
    /// UTF-16, a corrupt registration).
    #[error("the task's definition cannot be read: {0}")]
    Unreadable(String),
    /// A create-only registration found a task at the path; it was not changed.
    #[error("a task exists at the path")]
    AlreadyExists,
    /// The task cannot be registered without its stored password.
    #[error("the task needs its stored password to be registered")]
    PasswordNeeded,
    /// Refused before any call (a path or XML the wrapper does not accept).
    #[error("refused before any call: {0}")]
    Refused(String),
    /// Any other failure.
    #[error("{detail}")]
    Api {
        /// The HRESULT or Win32 code, when there is one.
        code: Option<u32>,
        /// What failed.
        detail: String,
    },
}

impl ObjErr {
    /// The code for the journal's `os_error`.
    pub fn code(&self) -> Option<u32> {
        match self {
            ObjErr::Api { code, .. } => *code,
            _ => None,
        }
    }

    fn fail_code(&self) -> FailCode {
        if self.code() == Some(HR_ACCESS_DENIED) || self.code() == Some(5) {
            FailCode::AccessDenied
        } else {
            FailCode::ObjectApi
        }
    }
}

/// One task as the backend reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskLive {
    /// Path (as Task Scheduler returns it) and actions.
    pub identity: TaskIdentity,
    /// An instance runs now. A state that cannot be read counts as running.
    pub running: bool,
    /// The principal may hold a stored password.
    pub stored_password: bool,
    /// The task is enabled.
    pub enabled: bool,
    /// The principal's `TASK_LOGON_TYPE`, [`LOGON_TYPE_UNKNOWN`] when it cannot be read.
    pub logon_type: u32,
}

/// A task's registration XML and security descriptor, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskXml {
    /// `IRegisteredTask::get_Xml`, unchanged.
    pub xml: String,
    /// `GetSecurityDescriptor(OWNER | GROUP | DACL)`.
    pub sddl: String,
}

/// How a task is registered on undo. There is one way: create only; a task at the path is never
/// replaced (`TASK_CREATE`, never `TASK_CREATE_OR_UPDATE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Register {
    /// Fail with [`ObjErr::AlreadyExists`] when a task exists at the path.
    CreateOnly,
}

/// The Task Scheduler calls the task action needs. [`WinTasks`] is the real one.
pub trait TaskBackend {
    /// The task at `path`; `None` when it or its folder does not exist. A task whose definition cannot
    /// be read is [`ObjErr::Unreadable`].
    fn read(&self, path: &str) -> Result<Option<TaskLive>, ObjErr>;
    /// The task's XML and SDDL; `None` when it does not exist.
    fn definition(&self, path: &str) -> Result<Option<TaskXml>, ObjErr>;
    /// Deletes the task (never its folder). A missing task is `Ok`.
    fn delete(&self, path: &str) -> Result<(), ObjErr>;
    /// Registers `def.xml` at `def.path` from the XML alone (no SDDL argument, spike), never replacing a
    /// task.
    fn register(&self, def: &TaskDef, mode: Register) -> Result<(), ObjErr>;
    /// Makes a delete or registration at `path` durable: flushes `HKLM\SOFTWARE` (TaskCache) and the
    /// directory of the task file.
    fn flush(&self, path: &str) -> Result<(), ObjErr>;
}

/// The real backend over `purge_win::taskschd`, `crate::durable` and `purge_win::fs_write::flush_dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WinTasks {
    /// The Windows directory; task files live in `<windir>\System32\Tasks`.
    windir: String,
}

impl WinTasks {
    /// The backend for a Windows directory (`GuardEnv::windir`).
    pub fn new(windir: &str) -> WinTasks {
        WinTasks {
            windir: windir.trim_end_matches('\\').to_owned(),
        }
    }

    /// The backend for the Windows directory of the deny-list's `GuardEnv`.
    pub fn from_env(env: &GuardEnv) -> WinTasks {
        WinTasks::new(&env.windir)
    }

    /// The directory holding the task file of `path`: `<windir>\System32\Tasks\<folders>`.
    fn task_dir(&self, path: &str) -> String {
        let mut segments: Vec<&str> = path.split('\\').filter(|s| !s.is_empty()).collect();
        segments.pop();
        let mut dir = format!(r"{}\System32\Tasks", self.windir);
        for segment in segments {
            dir.push('\\');
            dir.push_str(segment);
        }
        dir
    }
}

fn win_err(e: taskschd::WinError) -> ObjErr {
    match e {
        taskschd::WinError::InvalidPath(_) | taskschd::WinError::InvalidXml(_) => {
            ObjErr::Refused(e.to_string())
        }
        taskschd::WinError::AlreadyExists(_) => ObjErr::AlreadyExists,
        taskschd::WinError::PasswordNeeded(_) => ObjErr::PasswordNeeded,
        taskschd::WinError::InvalidUtf16 { .. } => ObjErr::Unreadable(e.to_string()),
        other => ObjErr::Api {
            code: other.hresult(),
            detail: other.to_string(),
        },
    }
}

fn logon_raw(t: taskschd::LogonType) -> u32 {
    use taskschd::LogonType as L;
    match t {
        L::None => 0,
        L::Password => 1,
        L::S4u => 2,
        L::InteractiveToken => 3,
        L::Group => 4,
        L::ServiceAccount => 5,
        L::InteractiveTokenOrPassword => 6,
        L::Other(n) => u32::try_from(n).unwrap_or(LOGON_TYPE_UNKNOWN),
    }
}

impl TaskBackend for WinTasks {
    fn read(&self, path: &str) -> Result<Option<TaskLive>, ObjErr> {
        let Some(raw) = taskschd::read_task(path).map_err(win_err)? else {
            return Ok(None);
        };
        if raw.unreadable {
            return Err(ObjErr::Unreadable(format!(
                "Task Scheduler cannot read the definition of {}",
                raw.path
            )));
        }
        let actions = raw
            .actions
            .into_iter()
            .map(|a| match a {
                taskschd::RawAction::Exec {
                    path,
                    arguments,
                    working_dir,
                } => TaskAction::Exec {
                    path,
                    arguments,
                    working_dir,
                },
                taskschd::RawAction::ComHandler { clsid, data } => {
                    TaskAction::ComHandler { clsid, data }
                }
                taskschd::RawAction::Other { kind } => TaskAction::Other { kind },
            })
            .collect();
        Ok(Some(TaskLive {
            identity: TaskIdentity {
                path: raw.path,
                actions,
            },
            running: raw.running.unwrap_or(true),
            stored_password: raw
                .logon_type
                .is_none_or(taskschd::LogonType::may_store_password),
            enabled: raw.enabled,
            logon_type: raw.logon_type.map_or(LOGON_TYPE_UNKNOWN, logon_raw),
        }))
    }

    fn definition(&self, path: &str) -> Result<Option<TaskXml>, ObjErr> {
        Ok(taskschd::read_xml(path)
            .map_err(win_err)?
            .map(|(xml, sddl)| TaskXml { xml, sddl }))
    }

    fn delete(&self, path: &str) -> Result<(), ObjErr> {
        taskschd::delete(path).map_err(win_err)
    }

    fn register(&self, def: &TaskDef, mode: Register) -> Result<(), ObjErr> {
        match mode {
            // `register_xml` is TASK_CREATE only.
            Register::CreateOnly => {
                taskschd::register_xml(&def.path, &def.xml, &def.sddl).map_err(win_err)
            }
        }
    }

    fn flush(&self, path: &str) -> Result<(), ObjErr> {
        crate::durable::flush_op_hive(&ExecOp::DeleteTask {
            path: path.to_owned(),
        })
        .map_err(|e| ObjErr::Api {
            code: Some(e.error.code()),
            detail: e.to_string(),
        })?;
        let dir = self.task_dir(path);
        match purge_win::fs_write::flush_dir(std::path::Path::new(&dir)) {
            // A folder whose directory is gone holds no task file to make durable.
            Ok(()) | Err(purge_win::fs_write::FsError::NotFound) => Ok(()),
            Err(e) => Err(ObjErr::Api {
                code: Some(e.code()),
                detail: format!("flushing the task directory {dir} failed: {e}"),
            }),
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Fault points (and their test observer)
// ---------------------------------------------------------------------------------------------------

thread_local! {
    static FAULT_OBSERVER: Cell<Option<fn(&'static str)>> = const { Cell::new(None) };
}

/// Hits fault point `name` ([`fault::point`]) and tells this thread's observer, if one is set.
fn hit(name: &'static str) {
    fault::point(name);
    if let Some(observer) = FAULT_OBSERVER.with(Cell::get) {
        observer(name);
    }
}

/// Test seam: `observer` is called on this thread with the name of every fault point this module hits
/// (`objdelete.after`, `act.after`, `undo.act.after`); `None` removes it. Without an observer nothing
/// changes; the points behave as [`fault::point`] says.
pub fn set_fault_observer(observer: Option<fn(&'static str)>) {
    FAULT_OBSERVER.with(|cell| cell.set(observer));
}

// ---------------------------------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------------------------------

fn result(outcome: ItemOutcome, detail: impl Into<String>) -> TypedResult {
    TypedResult {
        outcome,
        detail: detail.into(),
    }
}

fn skipped(detail: impl Into<String>) -> TypedResult {
    result(
        ItemOutcome::Skipped {
            reason: SkipReason::ChangedSinceScan,
        },
        detail,
    )
}

fn blocked(blocker: Blocker, detail: impl Into<String>) -> TypedResult {
    result(
        ItemOutcome::Skipped {
            reason: SkipReason::GateBlocked { blocker },
        },
        detail,
    )
}

fn failed(code: FailCode, os_error: Option<u32>, detail: impl Into<String>) -> TypedResult {
    let detail = detail.into();
    result(
        ItemOutcome::Failed {
            code,
            os_error,
            detail: detail.clone(),
        },
        detail,
    )
}

/// A decision taken before anything changed, with the `reason` code for the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The outcome and its detail.
    pub result: TypedResult,
    /// The code for an `ItemFacts::Refused` record (a guard rule name, a `gate.*` or a `task.*` reason).
    pub reason: String,
}

impl Decision {
    fn new(result: TypedResult, reason: &str) -> Decision {
        Decision {
            result,
            reason: reason.to_owned(),
        }
    }
}

/// The journal facts of a decided item: [`ItemFacts::Absent`] for `Vanished`, else
/// [`ItemFacts::Refused`] with the blocker of a gate refusal, the reason code and the error code.
fn decided_facts(decision: &Decision) -> ItemFacts {
    match &decision.result.outcome {
        ItemOutcome::Vanished => ItemFacts::Absent,
        ItemOutcome::Skipped {
            reason: SkipReason::GateBlocked { blocker },
        } => ItemFacts::Refused {
            blocker: Some(blocker.clone()),
            reason: decision.reason.clone(),
            os_error: None,
        },
        ItemOutcome::Skipped {
            reason: SkipReason::ChangedSinceScan,
        } => ItemFacts::Refused {
            blocker: Some(Blocker::ChangedSinceScan),
            reason: decision.reason.clone(),
            os_error: None,
        },
        ItemOutcome::Failed { os_error, .. } => ItemFacts::Refused {
            blocker: None,
            reason: decision.reason.clone(),
            os_error: *os_error,
        },
        _ => ItemFacts::Refused {
            blocker: None,
            reason: decision.reason.clone(),
            os_error: None,
        },
    }
}

// ---------------------------------------------------------------------------------------------------
// Checks shared by validate, prepare and act
// ---------------------------------------------------------------------------------------------------

/// `path` without one pair of surrounding double quotes and outer blanks.
fn unquote(path: &str) -> &str {
    let t = path.trim();
    t.strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(t)
        .trim()
}

/// The program an exec action runs, as the guard judges it: the canonical path when the action's path
/// canonicalises with `env`, else the path as written (which the guard treats as under `%SystemRoot%`).
fn guard_program(path: &str, env: &GuardEnv) -> String {
    let plain = unquote(path);
    match canon_path(plain, env, None) {
        Ok(canon) => canon.path,
        Err(_) => plain.to_owned(),
    }
}

/// The guard's refusal of a task: the object rules for the task path, then for every exec action's
/// program ([`guard_program`]). Every action is checked: one program under `%SystemRoot%` blocks.
pub fn guard_refusal(ctx: &GateCtx, identity: &TaskIdentity) -> Option<Blocker> {
    let deny = ctx.deny();
    let base = ObjectGuardFacts {
        name_or_path_or_id: &identity.path,
        ..ObjectGuardFacts::default()
    };
    if let Some(blocker) = deny.check_object(ObjectKind::Task, &base) {
        return Some(blocker);
    }
    for action in &identity.actions {
        if let TaskAction::Exec { path, .. } = action {
            let program = guard_program(path, deny.env());
            let facts = ObjectGuardFacts {
                program: Some(&program),
                ..base
            };
            if let Some(blocker) = deny.check_object(ObjectKind::Task, &facts) {
                return Some(blocker);
            }
        }
    }
    None
}

fn blocker_reason(blocker: &Blocker) -> String {
    match blocker {
        Blocker::DenyListed { rule } => rule.clone(),
        other => format!("guard.{}", other.name()),
    }
}

/// Reads the task at `path` and runs the gate on it against the stamp `stamp`: present, readable, the
/// stamp's digest, the guard, not running. `what` names the step for messages.
fn read_gated(
    backend: &dyn TaskBackend,
    ctx: &GateCtx,
    path: &str,
    stamp: &Stamp,
    what: &str,
) -> Result<TaskLive, Decision> {
    let live = match backend.read(path) {
        Ok(Some(live)) => live,
        Ok(None) => {
            return Err(Decision::new(
                result(
                    ItemOutcome::Vanished,
                    format!("scheduled task {path} is gone ({what})"),
                ),
                reason::GONE,
            ));
        }
        Err(ObjErr::Unreadable(why)) => {
            return Err(Decision::new(
                blocked(
                    Blocker::CannotBackUp,
                    format!("scheduled task {path}: {why} ({what}); left untouched"),
                ),
                reason::UNREADABLE,
            ));
        }
        Err(e) => {
            return Err(Decision::new(
                failed(
                    e.fail_code(),
                    e.code(),
                    format!("reading scheduled task {path} failed ({what}): {e}; left untouched"),
                ),
                reason::API,
            ));
        }
    };
    let fp = live.identity.fp();
    if let Err((reason, code)) = gate::check_object_stamp_detailed(stamp, Some(&fp)) {
        let _ = reason;
        return Err(Decision::new(
            skipped(format!(
                "scheduled task {path} is not the one validated ({code}, {what}); left untouched"
            )),
            code,
        ));
    }
    if fold(&live.identity.path) != fold(path) {
        return Err(Decision::new(
            skipped(format!(
                "Task Scheduler returned the path {:?} for {path} ({what}); left untouched",
                live.identity.path
            )),
            reason::CHANGED,
        ));
    }
    if let Some(blocker) = guard_refusal(ctx, &live.identity) {
        let code = blocker_reason(&blocker);
        return Err(Decision::new(
            blocked(
                blocker,
                format!("scheduled task {path} is refused by the guard ({code}); left untouched"),
            ),
            &code,
        ));
    }
    if live.running {
        return Err(Decision::new(
            blocked(
                Blocker::InUse,
                format!(
                    "scheduled task {path} is running (or its state cannot be read); nothing is \
                     ended, left untouched"
                ),
            ),
            reason::RUNNING,
        ));
    }
    Ok(live)
}

/// Why `xml` could not be registered again, if it could not: empty, a NUL, a `RegistrationTrigger` (it
/// starts the task at registration; `purge_win::taskschd::register_xml` refuses it), or larger than
/// [`MAX_TASK_XML_BYTES`].
fn not_restorable(xml: &str) -> Option<(&'static str, &'static str)> {
    if xml.len() > MAX_TASK_XML_BYTES {
        return Some((reason::XML_TOO_LARGE, "its XML is larger than 1 MiB"));
    }
    if xml.trim().is_empty() {
        return Some((reason::NOT_RESTORABLE, "its XML is empty"));
    }
    if xml.contains('\0') {
        return Some((reason::NOT_RESTORABLE, "its XML contains a NUL character"));
    }
    if xml.contains("RegistrationTrigger") {
        return Some((
            reason::NOT_RESTORABLE,
            "its XML has a RegistrationTrigger, so registering it again would start it",
        ));
    }
    None
}

/// Whether a `TASK_LOGON_TYPE` may hold a stored password: anything but `None` (0), `S4U` (2),
/// `InteractiveToken` (3), `Group` (4) and `ServiceAccount` (5).
pub fn logon_may_store_password(logon_type: u32) -> bool {
    !matches!(logon_type, 0 | 2..=5)
}

/// Whether the XML names a logon type that stores a password.
fn xml_names_password_logon(xml: &str) -> bool {
    xml.contains("<LogonType>Password</LogonType>")
        || xml.contains("<LogonType>InteractiveTokenOrPassword</LogonType>")
}

/// Whether a definition's task needs a password to be registered again: its own flag, its logon type
/// or its XML says so.
fn def_needs_password(def: &TaskDef) -> bool {
    def.stored_password
        || logon_may_store_password(def.logon_type)
        || xml_names_password_logon(&def.xml)
}

/// The number of elements named `name` in `xml` (`<name>`, `<name ...>`, `<name/>`).
fn count_elements(xml: &str, name: &str) -> usize {
    let open = format!("<{name}");
    let mut count = 0;
    let mut rest = xml;
    while let Some(at) = rest.find(&open) {
        let after = &rest[at + open.len()..];
        if matches!(
            after.chars().next(),
            Some('>' | '/' | ' ' | '\t' | '\r' | '\n')
        ) {
            count += 1;
        }
        rest = after;
    }
    count
}

/// The spellings a text node may have in Task Scheduler's XML: as is, with `&`, `<`, `>` escaped, and
/// with the quotes escaped too.
fn text_forms(text: &str) -> Vec<String> {
    let minimal = text
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let full = minimal.replace('"', "&quot;").replace('\'', "&apos;");
    vec![text.to_owned(), minimal, full]
}

/// Whether `xml` names exactly `actions`: as many `Exec`, `ComHandler`, `SendEmail` and `ShowMessage`
/// elements as there are actions of each kind, and every exec action's path as the text of a `Command`
/// element. This binds the XML that undo registers to the actions the identity digest, the guard and
/// the root check judged.
pub fn xml_binds_actions(xml: &str, actions: &[TaskAction]) -> bool {
    let exec = actions
        .iter()
        .filter(|a| matches!(a, TaskAction::Exec { .. }))
        .count();
    let com = actions
        .iter()
        .filter(|a| matches!(a, TaskAction::ComHandler { .. }))
        .count();
    let other = actions.len() - exec - com;
    if count_elements(xml, "Exec") != exec
        || count_elements(xml, "ComHandler") != com
        || count_elements(xml, "SendEmail") + count_elements(xml, "ShowMessage") != other
    {
        return false;
    }
    actions.iter().all(|action| match action {
        TaskAction::Exec { path, .. } => text_forms(path)
            .iter()
            .any(|form| xml.contains(&format!("<Command>{form}</Command>"))),
        _ => true,
    })
}

/// `xml` without the elements of `normalise` (each `<name>...</name>` and `<name/>`, by element name).
fn normalised(xml: &str, normalise: &[&str]) -> String {
    let mut out = xml.to_owned();
    for name in normalise {
        let empty = format!("<{name}/>");
        out = out.replace(&empty, "");
        let open = format!("<{name}>");
        let close = format!("</{name}>");
        while let Some(start) = out.find(&open) {
            let Some(len) = out[start..].find(&close) else {
                break;
            };
            out.replace_range(start..start + len + close.len(), "");
        }
    }
    out
}

/// Whether a task's XML and SDDL read now equal the backup: the XML after [`TASK_NORMALISE`] (every other
/// element byte for byte), the SDDL byte for byte.
fn same_definition(now: &TaskXml, def: &TaskDef) -> bool {
    same_definition_with(now, def, TASK_NORMALISE)
}

fn same_definition_with(now: &TaskXml, def: &TaskDef, normalise: &[&str]) -> bool {
    now.sddl == def.sddl && normalised(&now.xml, normalise) == normalised(&def.xml, normalise)
}

/// Whether the exec path `path` names a file strictly inside one of `roots`, all canonicalised with
/// `env` (per-user tokens with `user_sid`). A path that steps back, is relative, names an unknown token,
/// or looks like an 8.3 short name is outside every root, and so is everything when `roots` is empty.
pub fn program_in_roots(
    path: &str,
    env: &GuardEnv,
    user_sid: Option<&str>,
    roots: &[String],
) -> bool {
    gate::file_in_roots(unquote(path), roots, env, user_sid)
}

/// The first exec action of `actions` whose program is not inside `roots` ([`program_in_roots`]): undo
/// would refuse to register such a task again (`ProgramOutsideRoot`), so prepare and the act refuse to
/// delete it (M1b review R2b B1).
fn program_outside_roots<'a>(
    actions: &'a [TaskAction],
    env: &GuardEnv,
    user_sid: Option<&str>,
    roots: &[String],
) -> Option<&'a str> {
    actions.iter().find_map(|action| match action {
        TaskAction::Exec { path, .. } if !program_in_roots(path, env, user_sid, roots) => {
            Some(path.as_str())
        }
        _ => None,
    })
}

/// The refusal of every delete of a run whose journal header records no program roots (review R3b
/// S2): also a task without an exec action, which [`program_outside_roots`] lets through.
fn no_roots(path: &str) -> TypedResult {
    blocked(
        Blocker::CannotBackUp,
        format!(
            "scheduled task {path}: the run recorded no program roots ({}); left untouched",
            gate::reason::NO_ROOTS
        ),
    )
}

fn task_path(exec_op: &ExecOp) -> Option<&str> {
    match exec_op {
        ExecOp::DeleteTask { path } => Some(path),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------------------------------

/// What [`validate_task`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskValidate {
    /// The task may be acted on: journal `facts` in the `validated` record and hand that record to
    /// `GateCtx::record`.
    Validated {
        /// [`Stamp::Object`] of kind task with the live digest.
        stamp: Stamp,
        /// [`ItemFacts::Object`] of kind task, not running.
        facts: ItemFacts,
    },
    /// Decided without changing anything: journal [`TaskValidate::journal_facts`] in the `validated`
    /// record, then the outcome with `done_without_intent`.
    Decided(Decision),
}

impl TaskValidate {
    /// The facts for the journal's `validated` record.
    pub fn journal_facts(&self) -> ItemFacts {
        match self {
            TaskValidate::Validated { facts, .. } => facts.clone(),
            TaskValidate::Decided(decision) => decided_facts(decision),
        }
    }
}

/// The validate pass for the task delete `exec_op` of plan item `cand`. Read-only.
///
/// Decided: an op that is not [`ExecOp::DeleteTask`], an item whose target is not the op's, or a path
/// the wrapper refuses (`Failed{Internal}`); absent (`Vanished`); a definition that cannot be read
/// (`GateBlocked{CannotBackUp}`); a failed read (`Failed{ObjectApi}`); a digest other than the
/// candidate's `object_fp`, or no `object_fp` (`ChangedSinceScan`); a guard refusal
/// (`GateBlocked{..}`); a running task (`GateBlocked{InUse}`).
pub fn validate_task(
    backend: &dyn TaskBackend,
    ctx: &GateCtx,
    exec_op: &ExecOp,
    cand: &Candidate,
) -> TaskValidate {
    let decided =
        |result: TypedResult, reason: &str| TaskValidate::Decided(Decision::new(result, reason));
    let Some(path) = task_path(exec_op) else {
        return decided(
            failed(
                FailCode::Internal,
                None,
                format!("{} is not a task delete; nothing done", exec_op.name()),
            ),
            reason::NOT_TASK,
        );
    };
    if cand.target != exec_op.target() {
        return decided(
            failed(
                FailCode::Internal,
                None,
                format!("the plan item does not target scheduled task {path}; nothing done"),
            ),
            reason::NOT_TASK,
        );
    }
    if let Err(e) = taskschd::validate_path(path) {
        return decided(
            failed(FailCode::Internal, None, format!("{e}; nothing done")),
            reason::NOT_TASK,
        );
    }
    let live = match backend.read(path) {
        Ok(Some(live)) => live,
        Ok(None) => {
            return decided(
                result(
                    ItemOutcome::Vanished,
                    format!("scheduled task {path} does not exist"),
                ),
                reason::GONE,
            );
        }
        Err(ObjErr::Unreadable(why)) => {
            return decided(
                blocked(
                    Blocker::CannotBackUp,
                    format!("scheduled task {path}: {why}; left untouched"),
                ),
                reason::UNREADABLE,
            );
        }
        Err(e) => {
            return decided(
                failed(
                    e.fail_code(),
                    e.code(),
                    format!("reading scheduled task {path} failed: {e}; left untouched"),
                ),
                reason::API,
            );
        }
    };
    let fp = live.identity.fp();
    if let Err((_, code)) = gate::check_plan_fp_detailed(cand, &fp) {
        return decided(
            skipped(format!(
                "scheduled task {path} is not the one the scan saw ({code}); left untouched"
            )),
            code,
        );
    }
    if let Some(blocker) = guard_refusal(ctx, &live.identity) {
        let code = blocker_reason(&blocker);
        return decided(
            blocked(
                blocker,
                format!("scheduled task {path} is refused by the guard ({code}); left untouched"),
            ),
            &code,
        );
    }
    if live.running {
        return decided(
            blocked(
                Blocker::InUse,
                format!(
                    "scheduled task {path} is running (or its state cannot be read); nothing is \
                     ended, left untouched"
                ),
            ),
            reason::RUNNING,
        );
    }
    TaskValidate::Validated {
        stamp: Stamp::Object {
            kind: ObjectKind::Task,
            sha256: fp.sha256.clone(),
        },
        facts: ItemFacts::Object {
            kind: ObjectKind::Task,
            sha256: fp.sha256,
            running: false,
        },
    }
}

// ---------------------------------------------------------------------------------------------------
// Prepare
// ---------------------------------------------------------------------------------------------------

/// What [`prepare_task`] decided.
#[derive(Debug)]
pub enum TaskPrepared {
    /// Decided without changing anything: journal the outcome with `done_without_intent`.
    Decided(Decision),
    /// The definition is written and verified: journal [`TaskDelete::intent`], then call [`act_task`]
    /// (or [`delete_task`]) with its token.
    Ready(Box<TaskDelete>),
}

/// A task delete whose definition is on disk. Only [`prepare_task`] makes one.
#[derive(Debug)]
pub struct TaskDelete {
    intent: Intent,
    definition: TaskDef,
}

impl TaskDelete {
    /// The intent to journal before the delete: the op, [`Inverse::RecreateTask`] naming the verified
    /// definition file, and the journalled [`ItemFacts::Object`]. It passes `Intent::is_consistent`.
    pub fn intent(&self) -> &Intent {
        &self.intent
    }

    /// The definition written.
    pub fn definition(&self) -> &TaskDef {
        &self.definition
    }
}

/// Prepares the delete of op `op`, which must have an accepted `validated` record in `ctx`
/// (`GateCtx::record`): the plan item, the op and the stamp are taken from there. `planned` is the
/// plan item's `reversibility`.
///
/// In order: the task is read and gated against the stamp ([`read_gated`]: gone `Vanished`, unreadable
/// `CannotBackUp`, other digest `ChangedSinceScan`, guard, running `InUse`); its XML and SDDL are read
/// (unreadable `CannotBackUp`); an XML that could not be registered again is `CannotBackUp`
/// ([`MAX_TASK_XML_BYTES`], `RegistrationTrigger`, NUL); the task is read and gated again and must equal
/// the first read in every field (`ChangedSinceScan`); the XML must bind the identity's actions
/// ([`xml_binds_actions`], `ChangedSinceScan`); a task that needs a stored password while the plan states
/// [`Reversibility::Full`] is `GateBlocked{ReversibilityPartial}`. Then the definition is written
/// ([`objdef::write_def`]); its errors are returned as they are (journal [`DefWriteError::outcome`]
/// without an intent, or abort on [`DefWriteError::is_storage_integrity`]).
///
/// Right after the first read, an exec action whose program is not inside `program_roots` (the journal
/// header's; per-user tokens resolved for `GateCtx::user_sid`) is `GateBlocked{CannotBackUp}`: undo
/// would refuse to register the task again (`ProgramOutsideRoot`), so it is not deleted (review R2b
/// B1).
pub fn prepare_task(
    backend: &dyn TaskBackend,
    ctx: &GateCtx,
    session: &SessionDir,
    op: OpId,
    planned: Reversibility,
    program_roots: &[String],
) -> Result<TaskPrepared, DefWriteError> {
    let decided = |result: TypedResult, reason: &str| {
        Ok(TaskPrepared::Decided(Decision::new(result, reason)))
    };
    let Some((exec_op, record)) = ctx.journalled(op) else {
        return decided(
            failed(
                FailCode::Internal,
                None,
                format!("op {op} has no journalled validated record in this run; nothing done"),
            ),
            gate::reason::OBJECT_NOT_VALIDATED,
        );
    };
    let (Some(path), Some(stamp)) = (task_path(exec_op), ctx.stamp(op)) else {
        return decided(
            failed(
                FailCode::Internal,
                None,
                format!(
                    "the validated record of op {op} is a {} record, not a task delete; nothing done",
                    exec_op.name()
                ),
            ),
            reason::NOT_TASK,
        );
    };
    let validated_sha = match stamp {
        Stamp::Object {
            kind: ObjectKind::Task,
            sha256,
        } if matches!(
            record.facts,
            ItemFacts::Object {
                kind: ObjectKind::Task,
                ..
            }
        ) =>
        {
            sha256.clone()
        }
        _ => String::new(),
    };
    if validated_sha.is_empty() {
        return decided(
            failed(
                FailCode::Internal,
                None,
                format!("the validated record of op {op} is not a task record; nothing done"),
            ),
            reason::NOT_TASK,
        );
    }
    let first = match read_gated(backend, ctx, path, stamp, "before the backup") {
        Ok(live) => live,
        Err(decision) => return Ok(TaskPrepared::Decided(decision)),
    };
    // No roots: refused with a program or without one (a task of COM handlers only), review R3b S2.
    if gate::no_program_roots(program_roots) {
        return decided(no_roots(path), gate::reason::NO_ROOTS);
    }
    if let Some(program) = program_outside_roots(
        &first.identity.actions,
        ctx.deny().env(),
        ctx.user_sid(),
        program_roots,
    ) {
        return decided(
            blocked(
                Blocker::CannotBackUp,
                format!(
                    "scheduled task {path} runs {program:?}, which is not inside a root recorded for \
                     the run; undo would never register it again, so it is left untouched"
                ),
            ),
            reason::OUTSIDE_ROOTS,
        );
    }
    let xml = match backend.definition(path) {
        Ok(Some(xml)) => xml,
        Ok(None) => {
            return decided(
                result(
                    ItemOutcome::Vanished,
                    format!("scheduled task {path} is gone (reading its XML)"),
                ),
                reason::GONE,
            );
        }
        Err(e) => {
            return decided(
                blocked(
                    Blocker::CannotBackUp,
                    format!("the XML of scheduled task {path} cannot be read: {e}; left untouched"),
                ),
                reason::UNREADABLE,
            );
        }
    };
    if let Some((code, why)) = not_restorable(&xml.xml) {
        return decided(
            blocked(
                Blocker::CannotBackUp,
                format!(
                    "scheduled task {path} could not be registered again: {why}; left untouched"
                ),
            ),
            code,
        );
    }
    let second = match read_gated(backend, ctx, path, stamp, "after reading its XML") {
        Ok(live) => live,
        Err(decision) => return Ok(TaskPrepared::Decided(decision)),
    };
    if second != first {
        return decided(
            skipped(format!(
                "scheduled task {path} changed while its definition was read; left untouched"
            )),
            reason::CHANGED,
        );
    }
    if !xml_binds_actions(&xml.xml, &second.identity.actions) {
        return decided(
            skipped(format!(
                "the XML of scheduled task {path} does not name the actions that were validated; \
                 left untouched"
            )),
            reason::XML_ACTIONS,
        );
    }
    let stored_password = second.stored_password
        || logon_may_store_password(second.logon_type)
        || xml_names_password_logon(&xml.xml);
    if stored_password && planned == Reversibility::Full {
        return decided(
            blocked(
                Blocker::ReversibilityPartial,
                format!(
                    "scheduled task {path} runs with a stored password, which Purge cannot register \
                     again, but the plan states a full undo; left untouched"
                ),
            ),
            reason::STORED_PASSWORD,
        );
    }
    let definition = TaskDef {
        schema: TASKDEF_SCHEMA.to_owned(),
        path: second.identity.path.clone(),
        identity_sha256: validated_sha,
        actions: second.identity.actions.clone(),
        xml: xml.xml,
        sddl: xml.sddl,
        enabled: second.enabled,
        logon_type: second.logon_type,
        stored_password,
    };
    if objdef::check_def_identity(&definition, stamp).is_err() {
        return decided(
            skipped(format!(
                "the definition read for scheduled task {path} is not of the validated task; left \
                 untouched"
            )),
            gate::reason::OBJECT_CHANGED,
        );
    }
    let reference = objdef::write_def(session, op, &definition)?;
    let intent = Intent {
        op,
        item: record.item.clone(),
        exec_op: exec_op.clone(),
        inverse: Inverse::RecreateTask {
            definition: reference,
        },
        definition: None,
        pre: record.facts.clone(),
    };
    Ok(TaskPrepared::Ready(Box::new(TaskDelete {
        intent,
        definition,
    })))
}

// ---------------------------------------------------------------------------------------------------
// Act and complete
// ---------------------------------------------------------------------------------------------------

/// What the delete call and the flush after it returned. [`complete_task`] reads the task to decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acted {
    /// The delete call's error, if it failed.
    pub delete_error: Option<ObjErr>,
    /// The flush's error, if it failed.
    pub flush_error: Option<ObjErr>,
}

/// The intent's task path and digest, when the intent is a task delete that hangs together (op, inverse,
/// `pre`).
fn intent_task(intent: &Intent) -> Option<(&str, &str)> {
    let path = task_path(&intent.exec_op)?;
    let ItemFacts::Object {
        kind: ObjectKind::Task,
        sha256,
        ..
    } = &intent.pre
    else {
        return None;
    };
    (matches!(intent.inverse, Inverse::RecreateTask { .. })
        && intent.inverse.undoes(&intent.exec_op))
    .then_some((path, sha256.as_str()))
}

/// Deletes the task of `intent`, whose durability `token` proves, after the act-time gate. The
/// executor hits `act.before` before the call; this hits `objdelete.after` after the delete call and
/// `act.after` after the flush, then [`complete_task`] decides the outcome.
///
/// `Err` is decided before anything changed: a token of another op or an intent that is not a task
/// delete (`Failed{Internal}`); no accepted stamp for the op, or a stamp other than the intent's `pre`
/// (`ChangedSinceScan`); and the act-time gate ([`read_gated`]): gone `Vanished`, other digest or an
/// unreadable definition `ChangedSinceScan` / `CannotBackUp`, guard refusal, running `InUse`; an exec
/// program outside `program_roots` (the journal header's) `CannotBackUp`; and the binding to the backup
/// ([`check_definition`], review R2b S4): the definition the intent names must read hash-checked
/// (`NoVerifiedBackup` otherwise) and the task read now must have exactly its XML, SDDL and Enabled
/// setting (`ChangedSinceScan` otherwise; a trigger or principal changed since prepare is not deleted
/// unbacked, also not by a resumed run). Nothing is ended or disabled.
pub fn act_task(
    backend: &dyn TaskBackend,
    ctx: &GateCtx,
    session: &SessionDir,
    intent: &Intent,
    token: &IntentToken,
    program_roots: &[String],
) -> Result<Acted, TypedResult> {
    if token.op() != intent.op || token.item() != &intent.item {
        return Err(failed(
            FailCode::Internal,
            None,
            format!(
                "the intent token is for op {}, not op {}; nothing done",
                token.op(),
                intent.op
            ),
        ));
    }
    let Some((path, sha256)) = intent_task(intent) else {
        return Err(failed(
            FailCode::Internal,
            None,
            format!(
                "the intent of op {} is not a task delete; nothing done",
                intent.op
            ),
        ));
    };
    let Some(stamp) = ctx.stamp(intent.op) else {
        return Err(skipped(format!(
            "op {} has no accepted validated record ({}); scheduled task {path} left untouched",
            intent.op,
            gate::reason::OBJECT_NOT_VALIDATED
        )));
    };
    let fits = matches!(stamp, Stamp::Object { kind: ObjectKind::Task, sha256: s } if s == sha256);
    if !fits {
        return Err(skipped(format!(
            "the intent of op {} is not bound to its validated stamp ({}); scheduled task {path} \
             left untouched",
            intent.op,
            gate::reason::OBJECT_CHANGED
        )));
    }
    let live = read_gated(backend, ctx, path, stamp, "at the act").map_err(|d| d.result)?;
    if gate::no_program_roots(program_roots) {
        return Err(no_roots(path));
    }
    if let Some(program) = program_outside_roots(
        &live.identity.actions,
        ctx.deny().env(),
        ctx.user_sid(),
        program_roots,
    ) {
        return Err(blocked(
            Blocker::CannotBackUp,
            format!(
                "scheduled task {path} runs {program:?}, which is not inside a root recorded for the \
                 run ({}); left untouched",
                reason::OUTSIDE_ROOTS
            ),
        ));
    }
    check_definition(backend, session, intent, path, sha256, &live)?;
    let delete_error = backend.delete(path).err();
    hit(fault::OBJDELETE_AFTER);
    let flush_error = backend.flush(path).err();
    hit(fault::ACT_AFTER);
    Ok(Acted {
        delete_error,
        flush_error,
    })
}

/// The outcome of the delete of `intent`'s task, from a read now: gone is `Done`, or
/// `Failed{VerifyFailed}` when the flush after the delete failed (the delete may not survive a power
/// loss); still there is `Failed{ObjectApi}` (or `AccessDenied`, with the delete call's code), and
/// `Failed{VerifyFailed}` when this process's delete call reported success (review R3b M4); a read
/// that fails is `Failed{VerifyFailed}`. `acted` is what [`act_task`] returned, `None` when the delete
/// ran in an earlier process (recovery). The task's folder is left alone, empty or not.
pub fn complete_task(
    backend: &dyn TaskBackend,
    intent: &Intent,
    acted: Option<&Acted>,
) -> TypedResult {
    let Some((path, _)) = intent_task(intent) else {
        return failed(
            FailCode::Internal,
            None,
            format!("the intent of op {} is not a task delete", intent.op),
        );
    };
    let delete_error = acted.and_then(|a| a.delete_error.as_ref());
    let flush_error = acted.and_then(|a| a.flush_error.as_ref());
    match backend.read(path) {
        Ok(None) => match flush_error {
            Some(e) => failed(
                FailCode::VerifyFailed,
                e.code(),
                format!(
                    "scheduled task {path} is deleted, but the registry and its directory could not \
                     be flushed: {e}"
                ),
            ),
            None => match delete_error {
                Some(e) => result(
                    ItemOutcome::Done,
                    format!("the delete call reported {e}, but scheduled task {path} is gone"),
                ),
                None => result(ItemOutcome::Done, ""),
            },
        },
        Ok(Some(_)) | Err(ObjErr::Unreadable(_)) => match delete_error {
            Some(e) => failed(
                e.fail_code(),
                e.code(),
                format!("deleting scheduled task {path} failed: {e}; it is still there"),
            ),
            // The delete call of this process reported success: what it did is not known, so the
            // `done` must not read as "nothing changed" (review R3b M4). Without a call of this
            // process (recovery) the task is simply there.
            None if acted.is_some() => failed(
                FailCode::VerifyFailed,
                None,
                format!(
                    "Task Scheduler reported scheduled task {path} deleted, but it is still there"
                ),
            ),
            None => failed(
                FailCode::ObjectApi,
                None,
                format!("scheduled task {path} is still there"),
            ),
        },
        Err(e) => failed(
            FailCode::VerifyFailed,
            e.code(),
            format!("whether scheduled task {path} is gone cannot be read: {e}"),
        ),
    }
}

/// The binding of the act to the op's backup: the definition `intent` names, read hash-checked, is the
/// op's (path, digest `sha256`, an XML that binds its actions) and the task read now (`live`, and its
/// XML and SDDL read once more) is exactly it: XML ([`TASK_NORMALISE`]) and SDDL byte for byte, the
/// Enabled setting equal.
fn check_definition(
    backend: &dyn TaskBackend,
    session: &SessionDir,
    intent: &Intent,
    path: &str,
    sha256: &str,
    live: &TaskLive,
) -> Result<(), TypedResult> {
    let no_backup = |why: String| {
        result(
            ItemOutcome::Skipped {
                reason: SkipReason::NoVerifiedBackup,
            },
            format!(
                "scheduled task {path}: {why} ({}); left untouched",
                reason::NO_DEFINITION
            ),
        )
    };
    let Inverse::RecreateTask { definition } = &intent.inverse else {
        return Err(no_backup("the intent names no task definition".to_owned()));
    };
    let def: TaskDef = objdef::read_def_detailed(session, definition)
        .map_err(|e| no_backup(format!("its definition cannot be used: {}", e.detail)))?;
    if fold(&def.path) != fold(path)
        || def.identity_sha256 != sha256
        || !xml_binds_actions(&def.xml, &def.actions)
    {
        return Err(no_backup(
            "the definition is not the one of this op".to_owned(),
        ));
    }
    match backend.definition(path) {
        Ok(Some(now)) if same_definition(&now, &def) && live.enabled == def.enabled => Ok(()),
        Ok(None) => Err(result(
            ItemOutcome::Vanished,
            format!("scheduled task {path} is gone (comparing it with its backup)"),
        )),
        Ok(Some(_)) => Err(skipped(format!(
            "scheduled task {path} changed since its backup was taken ({}); left untouched",
            reason::CHANGED
        ))),
        Err(e) => Err(blocked(
            Blocker::CannotBackUp,
            format!(
                "the XML of scheduled task {path} cannot be read to compare it with its backup: {e}; \
                 left untouched"
            ),
        )),
    }
}

/// [`act_task`] then [`complete_task`]: the result for `JournalWriter::done` with `token`.
pub fn delete_task(
    backend: &dyn TaskBackend,
    ctx: &GateCtx,
    session: &SessionDir,
    intent: &Intent,
    token: &IntentToken,
    program_roots: &[String],
) -> TypedResult {
    match act_task(backend, ctx, session, intent, token, program_roots) {
        Ok(acted) => complete_task(backend, intent, Some(&acted)),
        Err(decided) => decided,
    }
}

// ---------------------------------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------------------------------

/// What became of the delete of `intent`, an intent with no `done`: absent is `Done(Done)`, present with
/// the intent's digest is `NotDone`, present with another digest, unreadable, or a failed read is
/// `Attention`. Changes nothing.
pub fn probe_task(backend: &dyn TaskBackend, intent: &Intent) -> Probe {
    let Some((path, sha256)) = intent_task(intent) else {
        return Probe::Attention {
            detail: "the intent is not a task delete".to_owned(),
        };
    };
    match backend.read(path) {
        Ok(None) => Probe::Done(ItemOutcome::Done),
        Ok(Some(live)) if live.identity.fp().sha256 == sha256 => Probe::NotDone,
        Ok(Some(_)) => Probe::Attention {
            detail: format!("another task than the recorded one is at {path}"),
        },
        Err(e) => Probe::Attention {
            detail: format!("scheduled task {path} cannot be read: {e}"),
        },
    }
}

// ---------------------------------------------------------------------------------------------------
// Undo
// ---------------------------------------------------------------------------------------------------

/// What [`prepare_undo_task`] decided.
#[derive(Debug)]
pub enum TaskUndoPrepared {
    /// No registration runs: journal [`TypedUndo::Done`] with `undo_done` (without an intent for
    /// `NothingToUndo` and `AlreadyRestored`) or [`TypedUndo::Conflict`] with `undo_conflict`.
    Decided(TypedUndo),
    /// The task may be registered: write `undo_intent`, then call [`run_undo_task`] with the unboxed value and its token.
    Ready(Box<TaskRecreate>),
}

/// A checked re-registration. Only [`prepare_undo_task`] makes one.
#[derive(Debug)]
pub struct TaskRecreate {
    op: OpId,
    definition: TaskDef,
}

impl TaskRecreate {
    /// The definition that will be registered.
    pub fn definition(&self) -> &TaskDef {
        &self.definition
    }
}

fn conflict(conflict: UndoConflict, detail: impl Into<String>) -> TypedUndo {
    TypedUndo::Conflict {
        conflict,
        detail: detail.into(),
    }
}

fn undo_failed(code: FailCode, os_error: Option<u32>, detail: impl Into<String>) -> TypedUndo {
    TypedUndo::Done(UndoOutcome::Failed {
        code,
        os_error,
        detail: detail.into(),
    })
}

/// Prepares the undo of the task delete `intent`. `done` is the op's `done` outcome (`None`: intent
/// only). `roots` are the roots recorded in the journal header; `user_sid` the user whose profile
/// tokens (`%LOCALAPPDATA%` ...) the paths may use. `None` for an op that is not a task delete.
///
/// In order: an inverse that is not [`Inverse::RecreateTask`] for the op is `BackupTampered`; an op that
/// changed nothing (`Vanished`, `Skipped`, `Failed` with a code other than `VerifyFailed`) is
/// `NothingToUndo`; the definition is read through the journal's reference
/// ([`objdef::read_def_detailed`]: `BackupMissing` / `BackupTampered`) and must be the op's (path, the
/// intent's digest, an XML that binds its actions; else `BackupTampered`). A task at the path whose XML
/// and SDDL equal the backup is `AlreadyRestored`, any other task there is `ObjectExists`, a failed read
/// is `Failed{ObjectApi}`. For an absent task every exec action must run a file inside `roots`
/// ([`program_in_roots`], else `ProgramOutsideRoot`) and the task must need no password
/// ([`UndoConflict::PasswordNeeded`], whose detail names the definition file holding the XML).
pub fn prepare_undo_task(
    backend: &dyn TaskBackend,
    ctx: &GateCtx,
    session: &SessionDir,
    intent: &Intent,
    done: Option<&ItemOutcome>,
    roots: &[String],
    user_sid: Option<&str>,
) -> Option<TaskUndoPrepared> {
    let path = task_path(&intent.exec_op)?;
    let decided = |undo: TypedUndo| Some(TaskUndoPrepared::Decided(undo));
    let Inverse::RecreateTask { definition } = &intent.inverse else {
        return decided(conflict(
            UndoConflict::BackupTampered,
            format!(
                "the journal's inverse {} does not undo the delete of scheduled task {path}",
                intent.inverse.name()
            ),
        ));
    };
    if !intent.inverse.undoes(&intent.exec_op) {
        return decided(conflict(
            UndoConflict::BackupTampered,
            format!("the journal's inverse does not undo the delete of scheduled task {path}"),
        ));
    }
    let unchanged = match done {
        Some(ItemOutcome::Failed { code, .. }) => *code != FailCode::VerifyFailed,
        Some(outcome) => !outcome.changed_system(),
        None => false,
    };
    if unchanged {
        return decided(TypedUndo::Done(UndoOutcome::NothingToUndo));
    }
    let def: TaskDef = match objdef::read_def_detailed(session, definition) {
        Ok(def) => def,
        Err(e) => return decided(conflict(e.conflict, e.detail)),
    };
    let pre_digest = match &intent.pre {
        ItemFacts::Object {
            kind: ObjectKind::Task,
            sha256,
            ..
        } => Some(sha256.as_str()),
        _ => None,
    };
    let own = fold(&def.path) == fold(path)
        && pre_digest == Some(def.identity_sha256.as_str())
        && xml_binds_actions(&def.xml, &def.actions);
    if !own {
        return decided(conflict(
            UndoConflict::BackupTampered,
            format!(
                "the definition {} is not the one of the delete of scheduled task {path}",
                definition.path
            ),
        ));
    }
    let present = match backend.read(&def.path) {
        Ok(Some(_)) | Err(ObjErr::Unreadable(_)) => true,
        Ok(None) => false,
        Err(e) => {
            return decided(undo_failed(
                e.fail_code(),
                e.code(),
                format!("reading scheduled task {path} failed: {e}; nothing registered"),
            ));
        }
    };
    if present {
        return decided(match backend.definition(&def.path) {
            Ok(Some(now)) if same_definition(&now, &def) => {
                TypedUndo::Done(UndoOutcome::AlreadyRestored)
            }
            Ok(None) => conflict(
                UndoConflict::ObjectExists,
                format!(
                    "scheduled task {path} came and went while it was compared with its backup; \
                     nothing registered (run undo again)"
                ),
            ),
            Ok(Some(_)) => conflict(
                UndoConflict::ObjectExists,
                format!(
                    "a scheduled task other than the backed-up one exists at {path}; it is never \
                     overwritten"
                ),
            ),
            Err(e) => conflict(
                UndoConflict::ObjectExists,
                format!(
                    "a scheduled task exists at {path} and cannot be compared with the backup ({e}); \
                     it is never overwritten"
                ),
            ),
        });
    }
    let env = ctx.deny().env();
    for action in &def.actions {
        if let TaskAction::Exec { path: program, .. } = action
            && !program_in_roots(program, env, user_sid, roots)
        {
            return decided(conflict(
                UndoConflict::ProgramOutsideRoot,
                format!(
                    "scheduled task {path} runs {program:?}, which is not inside a root recorded for \
                     the session; nothing registered"
                ),
            ));
        }
    }
    if def_needs_password(&def) {
        let file = session.path().join(&definition.path);
        return decided(conflict(
            UndoConflict::PasswordNeeded,
            format!(
                "scheduled task {path} ran with a stored password and cannot be registered again \
                 without it; its XML is kept in {} (member \"xml\") for a manual import",
                file.display()
            ),
        ));
    }
    Some(TaskUndoPrepared::Ready(Box::new(TaskRecreate {
        op: intent.op,
        definition: def,
    })))
}

/// Registers the task of `recreate` again under the undo intent `token`: create only (an existing task
/// is `ObjectExists`, a refused password `PasswordNeeded`, another failure `Failed{ObjectApi}`); fault
/// point `undo.act.after`; flush of the hive and the task directory; then the exact-restore check: XML
/// and SDDL read back equal to the backup ([`TASK_NORMALISE`]), the Enabled setting and the identity
/// digest equal, else `ValueDiffers` (the task is left as registered). A task that cannot be read back is
/// `Failed{VerifyFailed}`; one restored whose flush failed is `Failed{Os}`. A token of another op is
/// `Failed{Internal}` and nothing is called. The task is never run.
pub fn run_undo_task(
    backend: &dyn TaskBackend,
    recreate: TaskRecreate,
    token: &UndoToken,
) -> TypedUndo {
    let TaskRecreate { op, definition } = recreate;
    let path = definition.path.as_str();
    if token.op() != op {
        return undo_failed(
            FailCode::Internal,
            None,
            format!(
                "the undo token is for op {}, not op {op}; scheduled task {path} not registered",
                token.op()
            ),
        );
    }
    match backend.register(&definition, Register::CreateOnly) {
        Ok(()) => {}
        Err(ObjErr::AlreadyExists) => {
            return conflict(
                UndoConflict::ObjectExists,
                format!("a scheduled task appeared at {path}; it is never overwritten"),
            );
        }
        Err(ObjErr::PasswordNeeded) => {
            return conflict(
                UndoConflict::PasswordNeeded,
                format!("Task Scheduler needs the stored password of scheduled task {path}"),
            );
        }
        Err(e) => {
            return undo_failed(
                e.fail_code(),
                e.code(),
                format!("registering scheduled task {path} failed: {e}"),
            );
        }
    }
    hit(fault::UNDO_ACT_AFTER);
    let flush_error = backend.flush(path).err();
    let xml = backend.definition(path);
    let live = backend.read(path);
    match (xml, live) {
        (Ok(Some(xml)), Ok(Some(live))) => {
            let exact = same_definition(&xml, &definition)
                && live.enabled == definition.enabled
                && live.identity.fp().sha256 == definition.identity_sha256;
            if !exact {
                return conflict(
                    UndoConflict::ValueDiffers,
                    format!(
                        "scheduled task {path} was registered again, but it does not read back \
                         exactly as backed up"
                    ),
                );
            }
            match flush_error {
                Some(e) => undo_failed(
                    FailCode::Os,
                    e.code(),
                    format!(
                        "scheduled task {path} is registered again, but the registry and its \
                         directory could not be flushed: {e}"
                    ),
                ),
                None => TypedUndo::Done(UndoOutcome::Restored),
            }
        }
        (Ok(None), _) | (_, Ok(None)) => undo_failed(
            FailCode::VerifyFailed,
            None,
            format!("scheduled task {path} was registered, but it is not there"),
        ),
        (Err(e), _) | (_, Err(e)) => undo_failed(
            FailCode::VerifyFailed,
            e.code(),
            format!("scheduled task {path} was registered, but it cannot be read back: {e}"),
        ),
    }
}

/// The definition file of a task delete's inverse, for messages and reports.
pub fn definition_ref(intent: &Intent) -> Option<&BackupRef> {
    match &intent.inverse {
        Inverse::RecreateTask { definition } => Some(definition),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exec(path: &str) -> TaskAction {
        TaskAction::Exec {
            path: path.into(),
            arguments: None,
            working_dir: None,
        }
    }

    /// The constant is the spike's `task.normalise`.
    #[test]
    fn normalise_list_is_the_spike_result() {
        let text = include_str!("../../../vm/spikes/m1b/RESULT.json");
        let doc: serde_json::Value =
            serde_json::from_str(text.trim_start_matches('\u{feff}')).expect("RESULT.json parses");
        let list: Vec<&str> = doc["task"]["normalise"]
            .as_array()
            .expect("task.normalise is a list")
            .iter()
            .map(|v| v.as_str().expect("a string"))
            .collect();
        assert_eq!(list, TASK_NORMALISE);
        assert_eq!(doc["task"]["register_mode"], "xml_only");
    }

    #[test]
    fn normalisation_removes_only_listed_elements() {
        let a = "<Task><Date>1</Date><Uri>\\x</Uri><Empty/></Task>";
        let b = "<Task><Date>2</Date><Uri>\\x</Uri></Task>";
        assert_eq!(
            normalised(a, &["Date", "Empty"]),
            "<Task><Uri>\\x</Uri></Task>"
        );
        assert_eq!(
            normalised(a, &["Date", "Empty"]),
            normalised(b, &["Date", "Empty"])
        );
        assert_ne!(normalised(a, &["Date"]), normalised(b, &["Date"]));
        assert_eq!(normalised(a, &[]), a);
    }

    #[test]
    fn xml_must_name_the_actions() {
        let xml = "<Actions><Exec><Command>\"C:\\Program Files\\V &amp; Co\\u.exe\"</Command></Exec>\
                   <ComHandler><ClassId>{X}</ClassId></ComHandler></Actions>\
                   <Settings><ExecutionTimeLimit>PT1H</ExecutionTimeLimit></Settings>";
        let com = TaskAction::ComHandler {
            clsid: "{X}".into(),
            data: None,
        };
        let good = [exec("\"C:\\Program Files\\V & Co\\u.exe\""), com.clone()];
        assert!(xml_binds_actions(xml, &good));
        assert!(!xml_binds_actions(
            xml,
            &[exec("C:\\Other\\u.exe"), com.clone()]
        ));
        assert!(!xml_binds_actions(xml, &good[..1]));
        assert!(!xml_binds_actions(
            xml,
            &[good[0].clone(), com.clone(), exec("C:\\x.exe")]
        ));
        assert_eq!(count_elements("<Exec id=\"a\"><Exec/><Exec>", "Exec"), 3);
        assert_eq!(count_elements("<ExecutionTimeLimit>", "Exec"), 0);
    }

    #[test]
    fn password_logon_types() {
        for (t, stored) in [
            (0, false),
            (1, true),
            (2, false),
            (3, false),
            (4, false),
            (5, false),
        ] {
            assert_eq!(logon_may_store_password(t), stored, "{t}");
        }
        assert!(logon_may_store_password(6));
        assert!(logon_may_store_password(LOGON_TYPE_UNKNOWN));
        assert!(xml_names_password_logon("<LogonType>Password</LogonType>"));
        assert!(!xml_names_password_logon(
            "<LogonType>InteractiveToken</LogonType>"
        ));
    }

    #[test]
    fn roots_are_checked_canonically() {
        let env = GuardEnv::sample();
        let roots = vec![r"C:\Program Files\Vendor".to_owned()];
        let sid = Some(GuardEnv::SAMPLE_SID);
        for (path, inside) in [
            (r"C:\Program Files\Vendor\u.exe", true),
            (r#""C:\Program Files\Vendor\bin\u.exe""#, true),
            (r"%ProgramFiles%\Vendor\u.exe", true),
            (r"c:/program files/vendor/u.exe", true),
            (r"C:\Program Files\Vendor", false),
            (r"C:\Program Files\VendorX\u.exe", false),
            (r"C:\Program Files\Vendor\..\Evil\u.exe", false),
            (r"C:\PROGRA~1\Vendor\u.exe", false),
            (r"u.exe", false),
            (r"%TEMP%\u.exe", false),
            (r"\\server\share\Vendor\u.exe", false),
            ("", false),
        ] {
            assert_eq!(program_in_roots(path, &env, sid, &roots), inside, "{path}");
        }
        assert!(!program_in_roots(
            r"C:\Program Files\Vendor\u.exe",
            &env,
            sid,
            &[]
        ));
    }
}
