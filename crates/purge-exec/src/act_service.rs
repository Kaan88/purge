//! Executor action: delete and recreate a Windows service (M1B-X-SERVICE; ENGINE_PLAN.md §5.7.2, §7).
//!
//! The six entry points of C-ACT for [`ExecOp::DeleteService`], over a [`ServiceBackend`] so that every
//! path is tested without Windows: [`validate`], [`prepare`] (or [`prepare_recorded`]), [`act`],
//! [`complete`], [`probe`], and undo as [`prepare_undo`] plus [`run_undo`]. [`LiveServices`] is the real
//! backend over `purge_win::scm` and the registry; [`fake::FakeServices`] (tests and `test-support`) is
//! an in-memory one.
//!
//! # What the spike changed (vm/spikes/m1b/RESULT.json, section `service`)
//!
//! The spike overrides the first design text:
//!
//! - A delete closes its own SCM handle before it looks again (`scm::delete`). A service another handle
//!   keeps open is only marked for delete (`DeleteFlag = 1`, a create fails with 1072): that is
//!   [`ItemOutcome::PendingDelete`], not `PendingReboot` (DECISIONS.md, M1b).
//! - Undo creates the service from the **raw** `ImagePath` of the key backup (`QueryServiceConfigW`
//!   expands it), applies a config2 item only where the key backup holds its value
//!   (`Config2Kind::registry_entries`), sets the DACL only (never owner and group) and only when the key
//!   backup has a `Security` subkey, then writes back every backed-up value or key that is absent or
//!   different. The SCM owns no value the restore cannot reproduce ([`SCM_OWNED_VALUES`] is empty).
//! - A service account's stored password is lost on delete and invisible to any comparison: the item is
//!   `Reversibility::Partial` from the definition alone ([`SvcDef::account_builtin`]). A plan that says
//!   `Full` for such a service is refused at prepare (`GateBlocked{ReversibilityPartial}`). Undo re-creates
//!   the service under its account without a password and says so; `UndoConflict::PasswordNeeded` is for
//!   tasks only (DECISIONS.md, M1b).
//!
//! # One item
//!
//! 1. [`validate`]: the service is read fresh; absent is `Vanished`. Its identity digest
//!    ([`ServiceIdentity::fp`], built from the registry key exactly as the scanner builds it) must be the
//!    plan's `object_fp` (else `Skipped{ChangedSinceScan}`); then the gate ([`gate_blocker`]): the
//!    guard's `check_object` with facts read now (drivers, per-user services, a set `DeleteFlag`, a
//!    program under `%SystemRoot%`), a type that is not a plain Win32 service, dependents, a state other
//!    than `SERVICE_STOPPED`. It hands back [`Stamp::Object`] and [`ItemFacts::Object`].
//! 2. [`prepare`]: the whole `Services\<name>` tree is captured and its identity compared with the stamp;
//!    a program outside the journal header's `program_roots` is `GateBlocked{CannotBackUp}` before any
//!    backup (undo would refuse it with `ProgramOutsideRoot`), and with no roots at all every service
//!    is, by the same rule as tasks and rules (review R3b S2); the SCM definition is read and the
//!    identity once more (another digest: `Skipped{ChangedSinceScan}`); what undo is certain to refuse
//!    ([`restore_refusal`]: `CreateServiceW` arguments the SCM wrapper refuses, config2 items that cannot
//!    be applied) is `CannotBackUp`; then the tree is written as the op's verified registry backup
//!    (`reg\<op>.regbackup.json`) and `purge.svcdef/1` naming it. The intent carries
//!    [`Inverse::RecreateService`] (the definition) and names the key backup in its `definition` slot,
//!    so that expiry and the report see both files (review R2b S5).
//! 3. The executor journals the intent and hits `act.before`.
//! 4. [`act`]: the act-time gate reads everything again (digest equal to the validated stamp, the guard,
//!    no dependents, stopped), then binds the act to the backups (review R2b S4): both files are read
//!    hash-checked through the intent, the live tree must be exactly the key backup and the SCM's
//!    definition exactly the stored one (else `ChangedSinceScan`; a missing or unusable backup is
//!    `NoVerifiedBackup`), and the undo checks of step 2 run again. Then the delete, fault point
//!    `objdelete.after`, a flush of `SYSTEM`, fault point `act.after`, and [`complete`]'s verdict from a
//!    fresh read: gone is `Done`, present with `DeleteFlag` is `PendingDelete`, present without is
//!    `Failed{ObjectApi}`. The executor then journals `done` (`done.before`). A resumed run's act
//!    ([`SvcRemoval::from_intent`]) runs the same gate, so a backup older than the service is never
//!    the only copy.
//!
//! [`probe`] says what became of an intent without a `done` (recovery): absent is done, marked is done
//! as `PendingDelete`, present with the stamp's digest is not done, anything else needs attention.
//! [`SvcRemoval::from_intent`] rebuilds the removal for a resumed run.
//!
//! # Undo
//!
//! [`prepare_undo`] decides everything that needs no `undo_intent`: an op that changed nothing, a
//! definition or key backup that is missing or does not match the journal (the key backup must be the
//! file the intent names, with its hash, and the one the definition names), a key backup whose identity
//! is not the definition's, a service that exists marked for delete (`PendingDelete`), one that exists
//! and is exactly the backup (`AlreadyRestored`), one that exists and differs (`ObjectExists`), and a
//! program outside the roots recorded for the run (`ProgramOutsideRoot`: a tampered store must not plant
//! a service for an arbitrary binary; the definition hash check is the first lock, this the second).
//!
//! [`run_undo`] runs under the token of the flushed `undo_intent`: create, fault point
//! `svcrestore.mid`, config2, DACL, write-back, flush of `SYSTEM`, fault point `undo.act.after`, then the
//! exact-restore check (capture the tree again and compare it with the key backup): equal is
//! `Restored` (with the note that a stored password must be set again, for a service whose account is
//! not built in: the caller journals it with `undo_done_noted`, review R2b S6), anything else the
//! conflict `ValueDiffers` with the first difference named. A failure before or at the create is
//! `Failed{ObjectApi}` or a conflict; every failure after it is `Failed{VerifyFailed}`.
//!
//! A crash at `svcrestore.mid`, or a failure after the create, leaves a half-configured service that was
//! never started. Undo is then run again with [`SvcUndoArgs::own_attempt`] (the op's last undo attempt
//! ended open or `Failed{VerifyFailed}`: it created the service); the service exists and differs, and
//! this module recognises its own partial restore (same name, raw `ImagePath`, type, start type and
//! account as the backup, `ServiceDll` equal or not yet written, stopped, and nothing in the key that the
//! backup lacks) and continues from config2 instead of failing with `ObjectExists`. Without
//! `own_attempt` (no attempt, or one that ended before its create did anything) it is `ObjectExists`: a
//! service another install created is never adopted.
//!
//! Nothing here starts, stops or controls a service: the backend has no such entry, and the restored
//! service keeps the start type its backup records.
//!
//! # Names
//!
//! The name validated is the name acted on: every backend call takes the op's name, and every SCM call
//! opens the service by that name. A name that is empty, longer than 256 units, or holds `\`, `/` or a
//! NUL is refused before anything is read.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use purge_guard::canon::{GuardEnv, canon_path};
use purge_guard::deny::{DenyList, ObjectGuardFacts, ids};
use purge_guard::prefix::{self, eq_ci, expand_env};
use purge_model::exec::journal::{Intent, ItemFacts, UndoConflict, UndoOutcome};
use purge_model::exec::op::{ExecOp, FailCode, Inverse, ItemOutcome, OpId, SkipReason};
use purge_model::exec::regbackup::{RegBackup, RegBackupBody, RegBackupSchema, RegTree};
use purge_model::{Blocker, Candidate, CandidateId, FileTime, ObjectKind, Reversibility};
use purge_model::{ServiceIdentity, Target};
use purge_win::os::Win32Error;
use purge_win::reg::{REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_SZ, RegRoot, RegValue, RegView};
use purge_win::reg_write::{KeyAccess, WKey};
use purge_win::scm::{
    self, Config2Item, Config2Kind, FailureAction, FailureActions, ScmCreate, ScmDelete, ScmGuid,
    ScmService, ScmTrigger, TriggerDataItem, WinError, is_plain_win32_service,
};

use crate::act_reg::already_exists;
use crate::act_typed::TypedResult;
use crate::durable;
use crate::fault;
use crate::gate::{self, GateCtx, Stamp, check_object_stamp_detailed, check_plan_fp_detailed};
use crate::journal::{IntentToken, UndoToken, sha256_bytes};
use crate::objdef::{
    DefWriteError, SVCDEF_SCHEMA, SvcConfig, SvcConfig2, SvcDef, SvcFailureAction,
    SvcFailureActions, SvcTrigger, SvcTriggerData, account_builtin, read_def_detailed, write_def,
};
use crate::recover::Probe;
use crate::regbackup::{self, BackupFileError, CaptureError, VerifiedBackup};
use crate::storage::{BackupKind, SessionDir, StorageError, backup_rel};

/// The key holding one subkey per service, as the scanner spells it and as backups record it.
pub const SERVICES_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services";

/// `SERVICE_STOPPED`: the only state in which a service is deleted.
pub const SERVICE_STOPPED: u32 = 1;

/// Values of `Services\<name>` that the SCM owns and a restore cannot reproduce, which the exact-restore
/// check ignores (`scm_owned_values` of vm/spikes/m1b/RESULT.json). The spike found none.
pub const SCM_OWNED_VALUES: &[&str] = &[];

/// The longest service name the SCM accepts, in UTF-16 units.
const MAX_NAME_UNITS: usize = 256;

/// `ERROR_INVALID_OWNER`.
const INVALID_OWNER: Win32Error = Win32Error(1307);

// ---------------------------------------------------------------------------------------------------
// Fault points (with a trace for tests)
// ---------------------------------------------------------------------------------------------------

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    static TRACE: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
}

/// Hits fault point `point`; under `cfg(test)` and `test-support` it is also noted in this thread's
/// trace ([`take_fault_trace`]).
fn hit(point: &'static str) {
    fault::point(point);
    #[cfg(any(test, feature = "test-support"))]
    TRACE.with(|trace| trace.borrow_mut().push(point));
}

/// Test seam (`test-support`): the fault points this module hit on this thread since the last call, in
/// order, and forgets them. Points the executor and the journal hit (`act.before`, `done.before`,
/// `undo.intent`) are not in it.
#[cfg(any(test, feature = "test-support"))]
pub fn take_fault_trace() -> Vec<&'static str> {
    TRACE.with(|trace| std::mem::take(&mut *trace.borrow_mut()))
}

// ---------------------------------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------------------------------

/// What kind of failure an [`ObjErr`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjErrKind {
    /// The service does not exist.
    NotFound,
    /// The service is not stopped.
    InUse,
    /// A service with the name exists.
    Exists,
    /// The service is marked for delete and still held open (1072).
    MarkedForDelete,
    /// The SCM wrapper refused the service or the definition (a driver, a per-user service, a start type
    /// it does not create).
    Refused,
    /// A config2 value the SCM refuses and that is a new service's default anyway.
    NotSettable,
    /// Access was denied.
    AccessDenied,
    /// Anything else.
    Other,
}

/// A failed backend call: its kind, the Win32 code when there is one, and a line for the report.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{detail}")]
pub struct ObjErr {
    /// The kind.
    pub kind: ObjErrKind,
    /// The Win32 error code, when there is one.
    pub os_error: Option<u32>,
    /// What failed.
    pub detail: String,
}

impl ObjErr {
    /// An error of `kind`.
    pub fn new(kind: ObjErrKind, os_error: Option<u32>, detail: impl Into<String>) -> ObjErr {
        ObjErr {
            kind,
            os_error,
            detail: detail.into(),
        }
    }

    fn other(detail: impl Into<String>) -> ObjErr {
        ObjErr::new(ObjErrKind::Other, None, detail)
    }

    fn os(what: &str, error: Win32Error) -> ObjErr {
        let kind = if error.is_access_denied() {
            ObjErrKind::AccessDenied
        } else {
            ObjErrKind::Other
        };
        ObjErr::new(kind, Some(error.code()), format!("{what}: {error}"))
    }

    fn scm(what: &str, error: WinError) -> ObjErr {
        let kind = match &error {
            WinError::NotFound => ObjErrKind::NotFound,
            WinError::InUse { .. } => ObjErrKind::InUse,
            WinError::Exists | WinError::DuplicateName => ObjErrKind::Exists,
            WinError::MarkedForDelete => ObjErrKind::MarkedForDelete,
            WinError::Refused(_) | WinError::InvalidName(_) | WinError::InvalidArgument(_) => {
                ObjErrKind::Refused
            }
            WinError::NotSettable { .. } => ObjErrKind::NotSettable,
            _ if error.is_access_denied() => ObjErrKind::AccessDenied,
            _ => ObjErrKind::Other,
        };
        let os_error = match &error {
            WinError::MarkedForDelete => Some(1072),
            WinError::Exists => Some(1073),
            other => other.win32().map(Win32Error::code),
        };
        ObjErr::new(kind, os_error, format!("{what}: {error}"))
    }
}

/// One service as [`ServiceBackend::read`] sees it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceLive {
    /// The identity, from the registry key ([`identity_from_tree`] rules).
    pub identity: ServiceIdentity,
    /// `dwCurrentState` (`SERVICE_STOPPED` = 1).
    pub state: u32,
    /// `DeleteFlag` is set: the service is marked for delete.
    pub delete_flag: bool,
    /// Other services that list this one in `DependOnService` (or its group in `DependOnGroup` or as
    /// `+group`).
    pub dependents: Vec<String>,
    /// The name is `<stem>_<hex>` and a service `<stem>` exists: a per-user service instance.
    pub per_user_instance: bool,
}

/// What [`ServiceBackend::delete`] achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteResult {
    /// The service is gone.
    Deleted,
    /// The service is marked for delete; it goes when the last handle closes.
    Marked,
}

/// The SCM's definition of a service: what `purge.svcdef/1` records besides the key backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScmDefinition {
    /// `QueryServiceConfigW`.
    pub config: SvcConfig,
    /// `QueryServiceConfig2W`.
    pub config2: SvcConfig2,
    /// Owner, group and DACL of the service object as SDDL.
    pub sddl: String,
}

/// One write of the registry write-back after a re-create: a key or a value the key backup holds and
/// the live key does not, or holds otherwise. Paths are the key names below `Services\<name>` (empty for
/// the service's own key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteBack {
    /// Create the key `path` (its parent exists) with its recorded class, descriptor and volatility.
    CreateKey {
        /// Key names below the service key; never empty.
        path: Vec<String>,
        /// The class; empty for none.
        class: String,
        /// Owner, group and DACL as recorded.
        sddl: String,
        /// Whether the key is volatile.
        volatile: bool,
    },
    /// Set value `name` of key `path` to exactly this type and data.
    SetValue {
        /// Key names below the service key.
        path: Vec<String>,
        /// The value name; empty for the default value.
        name: String,
        /// The raw type.
        value_type: u32,
        /// The raw data.
        data: Vec<u8>,
    },
}

/// The service calls this module needs. [`LiveServices`] is the real one. Nothing in it starts, stops
/// or controls a service.
pub trait ServiceBackend {
    /// The service `name` as it is now; `None` when its key does not exist.
    fn read(&self, name: &str) -> Result<Option<ServiceLive>, ObjErr>;
    /// The SCM's definition of `name`.
    fn definition(&self, name: &str) -> Result<ScmDefinition, ObjErr>;
    /// The whole `Services\<name>` tree as a `purge.regbackup/1` document (`key` = `SERVICES_KEY\<name>`),
    /// refused beyond `limit` keys; `None` when the key does not exist.
    fn capture_key(&self, name: &str, limit: usize) -> Result<Option<RegBackup>, CaptureError>;
    /// Deletes the stopped service `name` (`DeleteService`, own handle closed before the re-open check).
    fn delete(&self, name: &str) -> Result<DeleteResult, ObjErr>;
    /// Creates a service; never starts it.
    fn create(&self, args: &ScmCreate) -> Result<(), ObjErr>;
    /// Sets one config2 item of `name`.
    fn apply_config2(&self, name: &str, item: &Config2Item) -> Result<(), ObjErr>;
    /// Sets the DACL of the service object `name` from `sddl` (owner and group are not set).
    fn apply_security(&self, name: &str, sddl: &str) -> Result<(), ObjErr>;
    /// Applies `writes`, in order, below the key of `name`.
    fn write_back(&self, name: &str, writes: &[WriteBack]) -> Result<(), ObjErr>;
    /// Flushes the `SYSTEM` hive.
    fn flush_system(&self) -> Result<(), ObjErr>;
}

/// Whether `name` can be a service name: 1 to 256 UTF-16 units, no `\`, `/` or NUL. Anything else could
/// address another key than `Services\<name>`.
fn valid_name(name: &str) -> bool {
    let units = name.encode_utf16().count();
    (1..=MAX_NAME_UNITS).contains(&units) && !name.contains(['\\', '/', '\0'])
}

// ---------------------------------------------------------------------------------------------------
// Identity: the scanner's reading of the key
// ---------------------------------------------------------------------------------------------------

/// One raw value.
#[derive(Debug, Clone, Copy)]
struct Raw<'a> {
    name: &'a str,
    ty: u32,
    data: &'a [u8],
}

/// The value named `name` (case-insensitive, as the scanner looks it up).
fn find<'a>(values: &'a [Raw<'a>], name: &str) -> Option<&'a Raw<'a>> {
    values.iter().find(|v| eq_ci(v.name, name))
}

/// The bytes as UTF-16 text up to the first NUL (an odd trailing byte dropped), as `purge-source` reads
/// strings.
fn text_of(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
    String::from_utf16_lossy(&units[..end])
}

/// A string that goes into the digest: `None` when absent, `Err` when not `REG_SZ` / `REG_EXPAND_SZ`.
fn exact_string(value: Option<&Raw<'_>>, what: &str) -> Result<Option<String>, String> {
    match value {
        None => Ok(None),
        Some(v) if matches!(v.ty, REG_SZ | REG_EXPAND_SZ) => Ok(Some(text_of(v.data))),
        Some(v) => Err(format!("{what} is not a string (type {})", v.ty)),
    }
}

/// `REG_DWORD_BIG_ENDIAN`.
const REG_DWORD_BIG_ENDIAN: u32 = 5;

/// A DWORD that goes into the digest: 0 when absent, `Err` when not a four-byte DWORD.
fn exact_dword(value: Option<&Raw<'_>>, what: &str) -> Result<u32, String> {
    let Some(v) = value else {
        return Ok(0);
    };
    let bytes: Option<[u8; 4]> = v.data.try_into().ok();
    match (v.ty, bytes) {
        (REG_DWORD, Some(b)) => Ok(u32::from_le_bytes(b)),
        (REG_DWORD_BIG_ENDIAN, Some(b)) => Ok(u32::from_be_bytes(b)),
        _ => Err(format!("{what} is not a DWORD (type {})", v.ty)),
    }
}

/// The identity of service `name` from its key's values and `Parameters\ServiceDll`, by the rules of
/// the scanner (`purge_index::sysobj`): `ImagePath` as stored, `Parameters\ServiceDll` else the
/// top-level `ServiceDll`, `Type` and `Start` (0 when absent), `ObjectName`. A field of the wrong type
/// is an error (the scanner leaves such a service out).
fn identity_from_values(
    name: &str,
    root: &[Raw<'_>],
    params_dll: Option<&Raw<'_>>,
) -> Result<ServiceIdentity, String> {
    let image_path = exact_string(find(root, "ImagePath"), "ImagePath")?;
    let service_dll = match exact_string(params_dll, r"Parameters\ServiceDll")? {
        Some(dll) => Some(dll),
        None => exact_string(find(root, "ServiceDll"), "ServiceDll")?,
    };
    Ok(ServiceIdentity {
        name: name.to_owned(),
        image_path,
        service_dll,
        service_type: exact_dword(find(root, "Type"), "Type")?,
        start: exact_dword(find(root, "Start"), "Start")?,
        object_name: exact_string(find(root, "ObjectName"), "ObjectName")?,
    })
}

/// `DeleteFlag` is a non-zero DWORD.
fn delete_flag_of(root: &[Raw<'_>]) -> bool {
    find(root, "DeleteFlag").is_some_and(|v| exact_dword(Some(v), "").is_ok_and(|n| n != 0))
}

/// The values of key `index` of `tree` as raw values; `None` when a name is not representable.
fn tree_values(tree: &RegTree, index: usize) -> Option<Vec<(String, u32, &[u8])>> {
    tree.keys[index]
        .values
        .iter()
        .map(|v| {
            String::from_utf16(&v.name_b64.0)
                .ok()
                .map(|name| (name, v.value_type, v.data_b64.0.as_slice()))
        })
        .collect()
}

fn as_raw<'a>(values: &'a [(String, u32, &'a [u8])]) -> Vec<Raw<'a>> {
    values
        .iter()
        .map(|(name, ty, data)| Raw {
            name,
            ty: *ty,
            data,
        })
        .collect()
}

/// The index of the direct child of key `parent` named `name` (case-insensitive).
fn child_named(tree: &RegTree, parent: usize, name: &str) -> Option<usize> {
    let want = regbackup::fold_str(name);
    tree.keys.iter().enumerate().find_map(|(i, key)| {
        (key.parent == Some(parent as u32) && regbackup::fold_units(&key.name_b64.0) == want)
            .then_some(i)
    })
}

/// The identity of service `name` from a captured `Services\<name>` tree, by the same rules as a live
/// read ([`ServiceBackend::read`]).
pub fn identity_from_tree(name: &str, tree: &RegTree) -> Result<ServiceIdentity, String> {
    if tree.keys.is_empty() {
        return Err("the key tree is empty".to_owned());
    }
    let root = tree_values(tree, 0).ok_or("a value name is not representable")?;
    let params = match child_named(tree, 0, "Parameters") {
        Some(i) => Some(tree_values(tree, i).ok_or("a value name is not representable")?),
        None => None,
    };
    let params_raw = params.as_deref().map(as_raw);
    let dll = params_raw
        .as_deref()
        .and_then(|values| find(values, "ServiceDll"));
    identity_from_values(name, &as_raw(&root), dll)
}

/// Whether the root of `tree` has `DeleteFlag` set.
fn tree_delete_flag(tree: &RegTree) -> bool {
    tree_values(tree, 0).is_some_and(|values| delete_flag_of(&as_raw(&values)))
}

// ---------------------------------------------------------------------------------------------------
// Program resolution
// ---------------------------------------------------------------------------------------------------

/// The machine environment a service's paths are expanded with, from the run's [`GuardEnv`] (the
/// SCM expands `ImagePath` with the system environment, not a user's): `SystemRoot`, `windir`,
/// `SystemDrive`, `ProgramFiles`, `ProgramW6432`, `ProgramFiles(x86)`, the `CommonProgramFiles` forms,
/// `ProgramData` and `ALLUSERSPROFILE`. A reference to anything else stays unexpanded, and the path is
/// then unresolved.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgramEnv {
    vars: BTreeMap<String, String>,
    windir: Option<String>,
}

impl ProgramEnv {
    /// The environment of `env`.
    pub fn from_guard(env: &GuardEnv) -> ProgramEnv {
        let mut vars = BTreeMap::new();
        let mut put = |name: &str, value: &str| {
            let value = value.trim().trim_end_matches(['\\', '/']);
            if !value.is_empty() {
                vars.insert(name.to_owned(), value.to_owned());
            }
        };
        put("SYSTEMROOT", &env.windir);
        put("WINDIR", &env.windir);
        put("SYSTEMDRIVE", &env.system_drive);
        put("PROGRAMFILES", &env.program_files);
        put("PROGRAMW6432", &env.program_files);
        put(
            "COMMONPROGRAMFILES",
            &format!(r"{}\Common Files", env.program_files.trim_end_matches('\\')),
        );
        put(
            "COMMONPROGRAMW6432",
            &format!(r"{}\Common Files", env.program_files.trim_end_matches('\\')),
        );
        if let Some(x86) = env.program_files_x86.as_deref().filter(|x| !x.is_empty()) {
            put("PROGRAMFILES(X86)", x86);
            put(
                "COMMONPROGRAMFILES(X86)",
                &format!(r"{}\Common Files", x86.trim_end_matches('\\')),
            );
        }
        put("PROGRAMDATA", &env.program_data);
        put("ALLUSERSPROFILE", &env.program_data);
        let windir = vars.get("SYSTEMROOT").cloned();
        ProgramEnv { vars, windir }
    }
}

/// The program a service runs, as far as it can be told without the file system (the scanner's rules,
/// `purge_index::sysobj`): the `ServiceDll` of a service run by the Windows `svchost.exe`, else what
/// `ImagePath` runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceProgram {
    /// One file, as a canonical path.
    File(String),
    /// A program is named but cannot be told to be one file; the raw text.
    Unresolved(String),
}

impl ServiceProgram {
    /// The text the guard judges: the file, or the raw text (judged lexically, which counts anything
    /// that is not a local path as under `%SystemRoot%`).
    fn guard_text(&self) -> &str {
        match self {
            ServiceProgram::File(path) | ServiceProgram::Unresolved(path) => path,
        }
    }
}

/// `text` without `head`, compared ignoring ASCII case.
fn strip_prefix_ci<'a>(text: &'a str, head: &str) -> Option<&'a str> {
    let start = text.get(..head.len())?;
    start
        .eq_ignore_ascii_case(head)
        .then(|| &text[head.len()..])
}

/// The canonical form of an expanded program path: `\SystemRoot\` and a leading `System32\` mapped to
/// the Windows directory; `None` for anything that is not one absolute local file path.
fn canonical_program(path: &str, env: &ProgramEnv) -> Option<String> {
    let path = path.trim();
    if path.contains('%') {
        return None;
    }
    let windir = || env.windir.as_deref().filter(|w| !w.contains('%'));
    let mapped = if let Some(rest) = strip_prefix_ci(path, r"\SystemRoot\") {
        format!("{}\\{rest}", windir()?)
    } else if strip_prefix_ci(path, r"System32\").is_some() {
        format!("{}\\{path}", windir()?)
    } else {
        path.to_owned()
    };
    let canon = canon_path(&mapped, &GuardEnv::default(), None).ok()?;
    (!canon.needs_long_name && prefix::depth(&canon.path) >= 2).then_some(canon.path)
}

/// The one program of a command line, expanded; `None` when it cannot be told (the scanner's
/// `command_exe`).
fn command_exe(raw: &str, env: &ProgramEnv) -> Option<String> {
    let expanded = expand_env(raw.trim(), &env.vars);
    let command = expanded.trim();
    if command.is_empty() {
        return None;
    }
    if command.starts_with('"') {
        return purge_win::cmdline::split(command).ok().map(|s| s.exe);
    }
    let candidates = RefCell::new(Vec::<usize>::new());
    purge_win::cmdline::split_with(command, |prefix| {
        candidates.borrow_mut().push(prefix.len());
        false
    })
    .ok()?;
    let mut candidates = candidates.into_inner();
    let lower = command.to_ascii_lowercase();
    if !command.contains('"') && (lower.ends_with(".sys") || lower.ends_with(".dll")) {
        candidates.push(command.len());
    }
    candidates.sort_unstable();
    candidates.dedup();
    match candidates.as_slice() {
        [] if !command.contains(char::is_whitespace) => Some(command.to_owned()),
        [end] => Some(command[..*end].trim().to_owned()),
        _ => None,
    }
}

/// The file a plain path names (`ServiceDll`): one pair of quotes dropped, references expanded.
fn resolve_file(raw: &str, env: &ProgramEnv) -> Option<String> {
    let text = raw.trim();
    let inner = match text.strip_prefix('"') {
        Some(rest) => rest.strip_suffix('"')?.trim(),
        None => text,
    };
    let path = expand_env(inner, &env.vars);
    if path.trim().is_empty() {
        return None;
    }
    canonical_program(&path, env)
}

/// Whether a program path names a file called `svchost.exe` (the index's `ServiceFacts::svchost`).
fn is_svchost_exe(exe: &str) -> bool {
    exe.rsplit(['\\', '/'])
        .next()
        .is_some_and(|leaf| leaf.trim().eq_ignore_ascii_case("svchost.exe"))
}

/// The text the guard's object rules judge for a service (the index's `ServiceFacts::guard_program`):
/// the `ImagePath` command itself when it runs a file called `svchost.exe`, so that a service hosted
/// by svchost is judged by its host (`sys.service.windows`), never by its `ServiceDll`; else the
/// program ([`ServiceProgram::guard_text`]).
fn guard_program_text<'a>(
    identity: &'a ServiceIdentity,
    program: &'a ServiceProgram,
    env: &ProgramEnv,
) -> &'a str {
    let raw = identity.image_path.as_deref().unwrap_or("");
    if command_exe(raw, env).is_some_and(|exe| is_svchost_exe(&exe)) {
        raw
    } else {
        program.guard_text()
    }
}

/// The program of a service identity (see [`ServiceProgram`]).
pub fn service_program(identity: &ServiceIdentity, env: &ProgramEnv) -> ServiceProgram {
    let raw = identity.image_path.as_deref().unwrap_or("");
    let unresolved = || ServiceProgram::Unresolved(raw.to_owned());
    let Some(exe) = command_exe(raw, env) else {
        return unresolved();
    };
    if is_svchost_exe(&exe) {
        let system = canonical_program(&exe, env).is_some_and(|exe| {
            env.windir.as_deref().is_some_and(|windir| {
                ["System32", "SysWOW64"].iter().any(|dir| {
                    canonical_program(&format!(r"{windir}\{dir}\svchost.exe"), env)
                        .is_some_and(|s| prefix::is_same(&exe, &s))
                })
            })
        });
        return match identity.service_dll.as_deref() {
            Some(dll) if system => {
                resolve_file(dll, env).map_or_else(unresolved, ServiceProgram::File)
            }
            _ => unresolved(),
        };
    }
    canonical_program(&exe, env).map_or_else(unresolved, ServiceProgram::File)
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

fn skipped(reason: SkipReason, detail: impl Into<String>) -> TypedResult {
    result(ItemOutcome::Skipped { reason }, detail)
}

fn blocked(blocker: Blocker, detail: impl Into<String>) -> TypedResult {
    skipped(SkipReason::GateBlocked { blocker }, detail)
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

fn api_failed(name: &str, e: &ObjErr) -> TypedResult {
    failed(
        FailCode::ObjectApi,
        e.os_error,
        format!("service {name}: {}; left untouched", e.detail),
    )
}

// ---------------------------------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------------------------------

/// Why `live` must not be deleted, judged on facts read now, in this order: the guard's `check_object`
/// (`sys.driver` for a driver or unknown type, `sys.service.peruser`, `sys.service.marked`, the
/// baseline, `sys.service.windows` for a program under `%SystemRoot%`, which a service hosted by
/// svchost always is: it is judged by its host, not its `ServiceDll`), a type that is not a plain Win32
/// service (`sys.driver`), dependents (`HasDependents`), a state other than stopped (`InUse`).
///
/// The baseline fact is not known to the executor and is passed as false: the scan applied it, and the
/// digest binds the act to what the scan saw.
pub fn gate_blocker(deny: &DenyList, live: &ServiceLive) -> Option<(Blocker, String)> {
    let name = &live.identity.name;
    let env = ProgramEnv::from_guard(deny.env());
    let program = service_program(&live.identity, &env);
    let facts = ObjectGuardFacts {
        name_or_path_or_id: name,
        program: Some(guard_program_text(&live.identity, &program, &env)),
        service_type: Some(live.identity.service_type),
        delete_flag: live.delete_flag,
        per_user_template: live.per_user_instance,
        package_bound: false,
        resource_name: false,
        in_baseline: false,
    };
    if let Some(blocker) = deny.check_object(ObjectKind::Service, &facts) {
        return Some((blocker, format!("service {name} is protected by the guard")));
    }
    if !is_plain_win32_service(live.identity.service_type) {
        return Some((
            Blocker::DenyListed {
                rule: ids::SYS_DRIVER.to_owned(),
            },
            format!(
                "service {name} has type {:#x}, not a plain Win32 service",
                live.identity.service_type
            ),
        ));
    }
    if !live.dependents.is_empty() {
        return Some((
            Blocker::HasDependents {
                names: live.dependents.clone(),
            },
            format!(
                "services depend on {name}: {}; they must go first",
                live.dependents.join(", ")
            ),
        ));
    }
    if live.state != SERVICE_STOPPED {
        return Some((
            Blocker::InUse,
            format!(
                "service {name} is not stopped (state {}); nothing is stopped",
                live.state
            ),
        ));
    }
    None
}

// ---------------------------------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------------------------------

/// What [`validate`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SvcValidated {
    /// The item passed: journal `facts` in its `validated` record; the act is bound to `stamp`.
    Validated {
        /// [`Stamp::Object`] of the service's digest.
        stamp: Stamp,
        /// [`ItemFacts::Object`] of the service, not running.
        facts: ItemFacts,
    },
    /// Decided without changing anything.
    Decided(TypedResult),
}

/// The name of a `DeleteService` op, when it is one with a usable name.
fn op_name(exec_op: &ExecOp) -> Result<&str, TypedResult> {
    match exec_op {
        ExecOp::DeleteService { name } if valid_name(name) => Ok(name),
        ExecOp::DeleteService { name } => Err(failed(
            FailCode::Internal,
            None,
            format!("{name:?} is not a service name; nothing done"),
        )),
        other => Err(failed(
            FailCode::Internal,
            None,
            format!("{} is not a service delete; nothing done", other.name()),
        )),
    }
}

/// The validate pass for a service delete: read-only. See the module docs, step 1.
pub fn validate(
    backend: &dyn ServiceBackend,
    deny: &DenyList,
    exec_op: &ExecOp,
    cand: &Candidate,
) -> SvcValidated {
    let decided = SvcValidated::Decided;
    let name = match op_name(exec_op) {
        Ok(name) => name,
        Err(r) => return decided(r),
    };
    if exec_op.target() != cand.target || !matches!(cand.target, Target::Service { .. }) {
        return decided(failed(
            FailCode::Internal,
            None,
            format!("the op for service {name} does not act on its plan item's target"),
        ));
    }
    let live = match backend.read(name) {
        Ok(Some(live)) => live,
        Ok(None) => {
            return decided(result(
                ItemOutcome::Vanished,
                format!("service {name} no longer exists"),
            ));
        }
        Err(e) => return decided(api_failed(name, &e)),
    };
    let fp = live.identity.fp();
    if let Err((reason, why)) = check_plan_fp_detailed(cand, &fp) {
        return decided(skipped(
            reason,
            format!("service {name}: {why}; it is not the service the scan saw"),
        ));
    }
    if let Some((blocker, why)) = gate_blocker(deny, &live) {
        return decided(blocked(blocker, format!("{why}; left untouched")));
    }
    SvcValidated::Validated {
        stamp: Stamp::Object {
            kind: ObjectKind::Service,
            sha256: fp.sha256.clone(),
        },
        facts: ItemFacts::Object {
            kind: ObjectKind::Service,
            sha256: fp.sha256,
            running: false,
        },
    }
}

// ---------------------------------------------------------------------------------------------------
// Prepare
// ---------------------------------------------------------------------------------------------------

/// The key backup or the definition could not be written as verified. Nothing was deleted and no intent
/// is needed: journal [`SvcPrepareError::outcome`] without an intent, or abort the run when
/// [`SvcPrepareError::is_storage_integrity`].
#[derive(Debug, thiserror::Error)]
pub enum SvcPrepareError {
    /// The store refused the key backup.
    #[error("key backup: {0}")]
    Storage(#[from] StorageError),
    /// The key backup could not be written or read back.
    #[error("key backup {path}: {detail}")]
    KeyBackup {
        /// The session-relative file.
        path: String,
        /// What went wrong.
        detail: String,
    },
    /// The definition file could not be written as verified.
    #[error(transparent)]
    Definition(#[from] DefWriteError),
}

impl SvcPrepareError {
    /// The outcome to journal for the item: `Skipped{NoVerifiedBackup}`.
    pub fn outcome(&self) -> ItemOutcome {
        ItemOutcome::Skipped {
            reason: SkipReason::NoVerifiedBackup,
        }
    }

    /// Whether a storage directory failed its integrity check (the whole run is concerned).
    pub fn is_storage_integrity(&self) -> bool {
        match self {
            SvcPrepareError::Storage(e) => matches!(e, StorageError::Integrity { .. }),
            SvcPrepareError::Definition(e) => e.is_storage_integrity(),
            SvcPrepareError::KeyBackup { .. } => false,
        }
    }
}

/// What [`prepare`] decided.
#[derive(Debug)]
pub enum SvcPrepared {
    /// Decided without changing anything: journal with `done_without_intent`.
    Decided(TypedResult),
    /// Both backups are written and verified: journal [`SvcRemoval::intent`], hit `act.before`, call
    /// [`act`] with the token.
    Ready(Box<SvcRemoval>),
}

/// A service delete that passed prepare (or an intent a resumed run completes). Consumed by [`act`].
#[derive(Debug, Clone)]
pub struct SvcRemoval {
    intent: Intent,
    name: String,
    stamp: Stamp,
}

impl SvcRemoval {
    /// The intent to journal: the op, [`Inverse::RecreateService`] naming the definition, and
    /// [`ItemFacts::Object`] of the validated digest. It passes `Intent::is_consistent`.
    pub fn intent(&self) -> &Intent {
        &self.intent
    }

    /// The removal of a journalled intent, for a resumed run whose probe found it not done
    /// ([`probe`] `NotDone`): `None` when the intent is not a service delete with object facts of a
    /// service that is not running.
    pub fn from_intent(intent: &Intent) -> Option<SvcRemoval> {
        let name = op_name(&intent.exec_op).ok()?.to_owned();
        let stamp = Stamp::from_item_facts(&intent.pre)?;
        matches!(
            stamp,
            Stamp::Object {
                kind: ObjectKind::Service,
                ..
            }
        )
        .then(|| SvcRemoval {
            intent: intent.clone(),
            name,
            stamp,
        })
    }
}

/// What [`prepare`] takes about the item, all from its journal `validated` record and the plan.
#[derive(Debug, Clone, Copy)]
pub struct SvcPrepareArgs<'a> {
    /// The op.
    pub op: OpId,
    /// The plan item.
    pub item: &'a CandidateId,
    /// The op ([`ExecOp::DeleteService`]).
    pub exec_op: &'a ExecOp,
    /// The stamp of the op's `validated` record.
    pub validated: &'a Stamp,
    /// The plan item's reversibility.
    pub planned: Reversibility,
    /// The most keys the service's tree may hold (the run's key limit).
    pub key_limit: usize,
    /// The program roots of the journal header (`Header::program_roots`): a service whose program is
    /// not inside one is not deleted, since its undo would refuse to create it again.
    pub program_roots: &'a [String],
    /// The run's environment (the deny-list's), which the program is resolved with.
    pub env: &'a GuardEnv,
}

/// [`prepare`] for op `op` as journalled: item, op and stamp come from the record `GateCtx::record`
/// accepted, the environment from the context's deny-list. An op without one is `Failed{Internal}`
/// before any call. `program_roots` are the journal header's.
pub fn prepare_recorded(
    backend: &dyn ServiceBackend,
    ctx: &GateCtx,
    session: &SessionDir,
    op: OpId,
    planned: Reversibility,
    key_limit: usize,
    program_roots: &[String],
) -> Result<SvcPrepared, SvcPrepareError> {
    let (Some((exec_op, record)), Some(stamp)) = (ctx.journalled(op), ctx.stamp(op)) else {
        return Ok(SvcPrepared::Decided(failed(
            FailCode::Internal,
            None,
            format!("op {op} has no journalled validated record in this run; nothing done"),
        )));
    };
    prepare(
        backend,
        session,
        &SvcPrepareArgs {
            op,
            item: &record.item,
            exec_op,
            validated: stamp,
            planned,
            key_limit,
            program_roots,
            env: ctx.deny().env(),
        },
    )
}

/// The digest of a [`Stamp::Object`] of a service.
fn service_stamp(stamp: &Stamp) -> Option<&str> {
    match stamp {
        Stamp::Object {
            kind: ObjectKind::Service,
            sha256,
        } => Some(sha256),
        _ => None,
    }
}

/// Writes `doc` as op `op`'s registry backup with [`regbackup::write_verified`]. A file of that name a
/// crash left before the intent is adopted when it verifies and holds `doc` (capture time aside);
/// otherwise it is deleted through the store and written anew.
fn write_key_backup(
    session: &SessionDir,
    op: OpId,
    doc: &RegBackup,
) -> Result<VerifiedBackup, SvcPrepareError> {
    let rel = backup_rel(BackupKind::Registry, op);
    let failure = |e: BackupFileError| match e {
        BackupFileError::Store(e) => SvcPrepareError::Storage(*e),
        other => SvcPrepareError::KeyBackup {
            path: rel.clone(),
            detail: other.to_string(),
        },
    };
    match regbackup::write_verified(session, &rel, doc) {
        Err(BackupFileError::Store(e)) if already_exists(&e) => {
            if let Some(adopted) = adopt_key_backup(session, &rel, doc) {
                return Ok(adopted);
            }
            session.delete_backup_file(&rel)?;
            regbackup::write_verified(session, &rel, doc).map_err(failure)
        }
        written => written.map_err(failure),
    }
}

fn adopt_key_backup(session: &SessionDir, rel: &str, doc: &RegBackup) -> Option<VerifiedBackup> {
    let mut file = session.open_file(rel).ok()?;
    let bytes = file.read_all(regbackup::MAX_BACKUP_FILE_BYTES).ok()?;
    drop(file);
    let reference = purge_model::exec::op::BackupRef {
        path: rel.to_owned(),
        sha256: sha256_bytes(&bytes),
        bytes: u64::try_from(bytes.len()).ok()?,
    };
    let found = regbackup::verify_bytes(&reference, &bytes).ok()?;
    let fresh = RegBackup {
        captured: found.doc().captured,
        ..doc.clone()
    };
    (found.doc() == &fresh).then_some(found)
}

/// The refusal of every delete of a run whose journal header records no program roots (review R3b
/// S2). [`program_outside_roots`] refuses such a service anyway; this says why in one form for the
/// three kinds.
fn no_roots(name: &str) -> TypedResult {
    blocked(
        Blocker::CannotBackUp,
        format!(
            "service {name}: the run recorded no program roots ({}); left untouched",
            gate::reason::NO_ROOTS
        ),
    )
}

/// The `Reversibility::Full` plan of a service whose account holds a stored password: refused.
fn partial_refusal(name: &str, account: Option<&str>) -> TypedResult {
    blocked(
        Blocker::ReversibilityPartial,
        format!(
            "service {name} runs as {}, whose stored password a delete loses, but the plan says the \
             delete is fully reversible; left untouched",
            account.unwrap_or("?")
        ),
    )
}

/// Takes the backups of a service delete: see the module docs, step 2. Never deletes anything.
pub fn prepare(
    backend: &dyn ServiceBackend,
    session: &SessionDir,
    args: &SvcPrepareArgs<'_>,
) -> Result<SvcPrepared, SvcPrepareError> {
    let decided = |r| Ok(SvcPrepared::Decided(r));
    let name = match op_name(args.exec_op) {
        Ok(name) => name,
        Err(r) => return decided(r),
    };
    let Some(digest) = service_stamp(args.validated) else {
        return decided(failed(
            FailCode::Internal,
            None,
            format!("service {name} was not validated as a service; nothing done"),
        ));
    };

    // 1. The whole key tree, bound to the validated digest.
    let doc = match backend.capture_key(name, args.key_limit) {
        Ok(Some(doc)) => doc,
        Ok(None) | Err(CaptureError::Vanished) => {
            return decided(result(
                ItemOutcome::Vanished,
                format!("service {name} no longer exists"),
            ));
        }
        Err(e) => {
            return decided(match e.blocker() {
                Some(blocker) => blocked(
                    blocker,
                    format!("the key of service {name} cannot be backed up: {e}; left untouched"),
                ),
                None => failed(
                    FailCode::Os,
                    None,
                    format!("the key of service {name} cannot be read: {e}; left untouched"),
                ),
            });
        }
    };
    let changed = |why: String| {
        Ok(SvcPrepared::Decided(skipped(
            SkipReason::ChangedSinceScan,
            format!("service {name}: {why}; left untouched"),
        )))
    };
    let Some(tree) = doc.tree() else {
        return changed("the key capture holds no tree".to_owned());
    };
    let identity = match identity_from_tree(name, tree) {
        Ok(identity) => identity,
        Err(why) => return changed(format!("its key cannot be read as a service: {why}")),
    };
    if identity.fp().sha256 != digest {
        return changed("its key is not the one validated".to_owned());
    }
    if identity.image_path.is_none() {
        return decided(blocked(
            Blocker::CannotBackUp,
            format!("service {name} has no ImagePath to create it again from; left untouched"),
        ));
    }
    if !identity.account_builtin() && args.planned == Reversibility::Full {
        return decided(partial_refusal(name, identity.object_name.as_deref()));
    }
    // The second lock, before any backup: a program outside the run's roots is never created again,
    // and a run without roots deletes no service at all (review R3b S2).
    if gate::no_program_roots(args.program_roots) {
        return decided(no_roots(name));
    }
    if let Some(program) = program_outside_roots(&identity, args.env, args.program_roots) {
        return decided(blocked(
            Blocker::CannotBackUp,
            format!(
                "service {name} runs {program}, which is not inside a root recorded for the run; \
                 undo would never create it again, so it is left untouched"
            ),
        ));
    }

    // 2. The SCM's definition, then the identity once more, then what undo would refuse, then the key
    //    backup.
    let scm = match backend.definition(name) {
        Ok(scm) => scm,
        Err(e) => return decided(api_failed(name, &e)),
    };
    match backend.read(name) {
        Ok(Some(live)) if live.identity.fp().sha256 == digest => {}
        Ok(Some(_)) => {
            return changed("it changed while its definition was read".to_owned());
        }
        Ok(None) => {
            return decided(result(
                ItemOutcome::Vanished,
                format!("service {name} disappeared while its definition was read"),
            ));
        }
        Err(e) => return decided(api_failed(name, &e)),
    }
    let builtin = account_builtin(scm.config.service_start_name.as_deref());
    if builtin != identity.account_builtin() {
        return changed("the SCM and the registry name different accounts".to_owned());
    }
    if !builtin && args.planned == Reversibility::Full {
        return decided(partial_refusal(
            name,
            scm.config.service_start_name.as_deref(),
        ));
    }
    if let Some(why) = restore_refusal(name, &identity, tree, &scm, args.env, args.program_roots) {
        return decided(blocked(
            Blocker::CannotBackUp,
            format!("service {name}: {why}; left untouched"),
        ));
    }
    let key_backup = write_key_backup(session, args.op, &doc)?;

    // 3. The definition. The intent names both files: the definition as the inverse's, the key backup
    //    in `definition`, so that expiry, the byte count and the report see it (review R2b S5).
    let def = SvcDef {
        schema: SVCDEF_SCHEMA.to_owned(),
        name: name.to_owned(),
        identity_sha256: digest.to_owned(),
        config: scm.config,
        config2: scm.config2,
        sddl: scm.sddl,
        key_backup: key_backup.reference().clone(),
        account_builtin: builtin,
    };
    let definition = match write_def(session, args.op, &def) {
        Ok(definition) => definition,
        Err(e) => {
            // The item is skipped without an intent, so no record would name the key backup: it is
            // removed again through the store (review R3b M6). Not on a storage integrity failure,
            // which aborts the run with the store left as it is.
            if !e.is_storage_integrity() {
                let _ = session.delete_backup_file(&key_backup.reference().path);
            }
            return Err(e.into());
        }
    };
    let intent = Intent {
        op: args.op,
        item: args.item.clone(),
        exec_op: args.exec_op.clone(),
        inverse: Inverse::RecreateService { definition },
        definition: Some(key_backup.reference().clone()),
        pre: ItemFacts::Object {
            kind: ObjectKind::Service,
            sha256: digest.to_owned(),
            running: false,
        },
    };
    Ok(SvcPrepared::Ready(Box::new(SvcRemoval {
        intent,
        name: name.to_owned(),
        stamp: args.validated.clone(),
    })))
}

// ---------------------------------------------------------------------------------------------------
// Act, complete, probe
// ---------------------------------------------------------------------------------------------------

/// The backups `intent` names, bound to the service read now (M1b review R2b S4): the definition and the
/// key backup are read hash-checked through the journal's references (the key backup must be the one
/// both the intent and the definition name), the live `Services\<name>` tree must be exactly the key
/// backup ([`tree_difference`]) and the SCM's definition exactly the stored one. Then the checks undo
/// will make ([`restore_refusal`]). In a straight run this closes the window of the intent flush; in a
/// resumed run, hours later, it is what keeps a backup older than the service from being the only copy.
fn check_backup_binding(
    backend: &dyn ServiceBackend,
    session: &SessionDir,
    intent: &Intent,
    name: &str,
    env: &GuardEnv,
    roots: &[String],
) -> Result<(), TypedResult> {
    let no_backup = |why: String| {
        skipped(
            SkipReason::NoVerifiedBackup,
            format!("service {name}: {why}; left untouched"),
        )
    };
    let changed = |why: &str| {
        skipped(
            SkipReason::ChangedSinceScan,
            format!("service {name}: {why} since its backup was taken; left untouched"),
        )
    };
    let Inverse::RecreateService { definition } = &intent.inverse else {
        return Err(failed(
            FailCode::Internal,
            None,
            format!("the intent of service {name} is not a service delete; left untouched"),
        ));
    };
    let def: SvcDef = read_def_detailed(session, definition)
        .map_err(|e| no_backup(format!("its definition cannot be used: {}", e.detail)))?;
    let digest = match &intent.pre {
        ItemFacts::Object { sha256, .. } => sha256.as_str(),
        _ => "",
    };
    if !eq_ci(&def.name, name) || def.identity_sha256 != digest {
        return Err(no_backup(
            "the definition is not the one of this op".to_owned(),
        ));
    }
    if intent.definition.as_ref() != Some(&def.key_backup) {
        return Err(no_backup(
            "the intent and the definition do not name the same key backup".to_owned(),
        ));
    }
    let (tree, identity) = match read_key_backup(session, intent.op, name, &def) {
        Ok(found) => found,
        Err(SvcUndoResult::Done { detail, .. } | SvcUndoResult::Conflict { detail, .. }) => {
            return Err(no_backup(detail));
        }
    };
    let live_tree = match backend.capture_key(name, tree.keys.len().max(1) * 4) {
        Ok(Some(doc)) => doc.tree().cloned(),
        Ok(None) | Err(CaptureError::Vanished) => {
            return Err(result(
                ItemOutcome::Vanished,
                format!("service {name} was deleted before Purge deleted it"),
            ));
        }
        Err(_) => None,
    };
    match live_tree {
        Some(live) if tree_difference(&tree, &live).is_none() => {}
        Some(_) => return Err(changed("its key changed")),
        None => return Err(changed("its key cannot be read as it was")),
    }
    let scm = match backend.definition(name) {
        Ok(scm) => scm,
        Err(e) => return Err(api_failed(name, &e)),
    };
    let stored = ScmDefinition {
        config: def.config.clone(),
        config2: def.config2.clone(),
        sddl: def.sddl.clone(),
    };
    if scm != stored {
        return Err(changed("its SCM definition changed"));
    }
    if let Some(why) = restore_refusal(name, &identity, &tree, &stored, env, roots) {
        return Err(blocked(
            Blocker::CannotBackUp,
            format!("service {name}: {why}; left untouched"),
        ));
    }
    Ok(())
}

/// Deletes the service of `removal`, whose intent `token` proves durable: the act-time gate (the
/// service read again, its digest, [`gate_blocker`], then the binding to the op's backups,
/// [`check_backup_binding`], with the journal header's `program_roots`), the delete, `objdelete.after`,
/// the flush of `SYSTEM`, `act.after`, and [`complete`]'s verdict. A token of another op is
/// `Failed{Internal}` and nothing is called.
pub fn act(
    backend: &dyn ServiceBackend,
    deny: &DenyList,
    session: &SessionDir,
    removal: Box<SvcRemoval>,
    token: &IntentToken,
    program_roots: &[String],
) -> TypedResult {
    let SvcRemoval {
        intent,
        name,
        stamp,
    } = *removal;
    if token.op() != intent.op || token.item() != &intent.item {
        return failed(
            FailCode::Internal,
            None,
            format!(
                "the intent token is for op {}, not op {}; service {name} left untouched",
                token.op(),
                intent.op
            ),
        );
    }
    // The act-time gate: everything read again now.
    let live = match backend.read(&name) {
        Ok(Some(live)) => live,
        Ok(None) => {
            return result(
                ItemOutcome::Vanished,
                format!("service {name} was deleted before Purge deleted it"),
            );
        }
        Err(e) => return api_failed(&name, &e),
    };
    if let Err((reason, why)) = check_object_stamp_detailed(&stamp, Some(&live.identity.fp())) {
        return skipped(reason, format!("service {name}: {why}; left untouched"));
    }
    if let Some((blocker, why)) = gate_blocker(deny, &live) {
        return blocked(blocker, format!("{why}; left untouched"));
    }
    if gate::no_program_roots(program_roots) {
        return no_roots(&name);
    }
    if let Err(r) =
        check_backup_binding(backend, session, &intent, &name, deny.env(), program_roots)
    {
        return r;
    }

    let deleted = backend.delete(&name);
    if let Err(e) = &deleted {
        return match e.kind {
            ObjErrKind::NotFound => result(
                ItemOutcome::Vanished,
                format!("service {name} was deleted before Purge deleted it"),
            ),
            ObjErrKind::InUse => blocked(
                Blocker::InUse,
                format!("service {name} was started; nothing is stopped; left untouched"),
            ),
            ObjErrKind::Refused => blocked(
                Blocker::DenyListed {
                    rule: ids::SYS_DRIVER.to_owned(),
                },
                format!("service {name}: {}; left untouched", e.detail),
            ),
            ObjErrKind::AccessDenied => failed(
                FailCode::AccessDenied,
                e.os_error,
                format!("service {name}: {}", e.detail),
            ),
            _ => api_failed(&name, e),
        };
    }
    hit(fault::OBJDELETE_AFTER);
    if let Err(e) = backend.flush_system() {
        return failed(
            FailCode::VerifyFailed,
            e.os_error,
            format!(
                "service {name} was deleted, but the SYSTEM hive could not be flushed ({}); whether \
                 the delete survives a restart is not known",
                e.detail
            ),
        );
    }
    hit(fault::ACT_AFTER);
    complete(backend, &name)
}

/// The verdict on a delete of `name` from a fresh read: gone is `Done`, present with `DeleteFlag` is
/// `PendingDelete` (another handle keeps it; it goes when that closes, at the latest at restart),
/// present without is `Failed{VerifyFailed}` (the delete call reported success, so the `done` must not
/// say "nothing changed"; review R3b M4), a failed read is `Failed{VerifyFailed}`.
pub fn complete(backend: &dyn ServiceBackend, name: &str) -> TypedResult {
    match backend.read(name) {
        Ok(None) => result(ItemOutcome::Done, ""),
        Ok(Some(live)) if live.delete_flag => result(
            ItemOutcome::PendingDelete,
            format!(
                "service {name} is marked for delete; another program holds it open, and it goes \
                 when that handle closes (at the latest at restart)"
            ),
        ),
        // The delete call returned success: what it did is not known, so the `done` must not read as
        // "nothing changed" (`ObjectApi` settles undo as `NothingToUndo`; review R3b M4).
        Ok(Some(_)) => failed(
            FailCode::VerifyFailed,
            None,
            format!(
                "service {name} is still there after a delete the SCM reported done, and is not \
                 marked for delete"
            ),
        ),
        Err(e) => failed(
            FailCode::VerifyFailed,
            e.os_error,
            format!(
                "whether service {name} is gone cannot be read: {}",
                e.detail
            ),
        ),
    }
}

/// What became of the delete of `intent`, an intent without its `done` (recovery). Changes nothing.
pub fn probe(backend: &dyn ServiceBackend, intent: &Intent) -> Probe {
    let attention = |detail: String| Probe::Attention { detail };
    let Ok(name) = op_name(&intent.exec_op) else {
        return attention("the intent is not a service delete".to_owned());
    };
    let ItemFacts::Object {
        kind: ObjectKind::Service,
        sha256,
        ..
    } = &intent.pre
    else {
        return attention(format!(
            "the intent of service {name} holds no service facts"
        ));
    };
    match backend.read(name) {
        Ok(None) => Probe::Done(ItemOutcome::Done),
        Ok(Some(live)) if live.delete_flag => Probe::Done(ItemOutcome::PendingDelete),
        Ok(Some(live)) if live.identity.fp().sha256 == *sha256 => Probe::NotDone,
        Ok(Some(_)) => attention(format!(
            "service {name} exists and is not the one the intent recorded"
        )),
        Err(e) => attention(format!("service {name} cannot be read: {}", e.detail)),
    }
}

// ---------------------------------------------------------------------------------------------------
// Tree comparison and write-back
// ---------------------------------------------------------------------------------------------------

/// The folded path (names below the root, joined by `\`) of every key of `tree`; the root's is empty.
fn folded_paths(tree: &RegTree) -> Vec<Vec<u16>> {
    let mut paths: Vec<Vec<u16>> = Vec::with_capacity(tree.keys.len());
    for (i, key) in tree.keys.iter().enumerate() {
        let path = match key.parent {
            None => Vec::new(),
            Some(p) => {
                let mut path = paths.get(p as usize).cloned().unwrap_or_default();
                if !path.is_empty() || i == 0 {
                    path.push(u16::from(b'\\'));
                }
                path.extend(regbackup::fold_units(&key.name_b64.0));
                path
            }
        };
        paths.push(path);
    }
    paths
}

/// The names below the root of key `index` of `tree`, as stored.
fn name_path(tree: &RegTree, index: usize) -> Vec<String> {
    let mut names = Vec::new();
    let mut at = index;
    while let Some(parent) = tree.keys.get(at).and_then(|k| k.parent) {
        names.push(tree.keys[at].name_b64.to_string_lossy());
        at = parent as usize;
    }
    names.reverse();
    names
}

/// `path\name` for messages.
fn display(tree: &RegTree, index: usize, value: Option<&str>) -> String {
    let path = name_path(tree, index).join("\\");
    match value {
        Some(v) => format!("{path}|{v}"),
        None => format!("{path}\\"),
    }
}

/// An SDDL string without its owner part.
fn sddl_without_owner(sddl: &str) -> &str {
    let Some(rest) = sddl.strip_prefix("O:") else {
        return sddl;
    };
    match rest.find(':') {
        Some(colon) if colon >= 2 && rest.is_char_boundary(colon - 1) => &rest[colon - 1..],
        Some(_) => sddl,
        None => "",
    }
}

/// The values of key `index` by folded name.
fn values_by_name(tree: &RegTree, index: usize) -> HashMap<Vec<u16>, (u32, &[u8])> {
    tree.keys[index]
        .values
        .iter()
        .map(|v| {
            (
                regbackup::fold_units(&v.name_b64.0),
                (v.value_type, v.data_b64.0.as_slice()),
            )
        })
        .collect()
}

/// The first difference between the live tree and the key backup, or `None` when the live tree is the
/// backup: the same keys (names compared without case), each with the backup's class, volatility,
/// descriptor (owner aside; not compared on the service's own key, which the SCM creates) and exactly the
/// backup's values (type and data), apart from [`SCM_OWNED_VALUES`] on the service's own key. Last write
/// times are not compared.
pub fn tree_difference(backup: &RegTree, live: &RegTree) -> Option<String> {
    let backup_paths = folded_paths(backup);
    let live_paths = folded_paths(live);
    let live_index: HashMap<&Vec<u16>, usize> =
        live_paths.iter().enumerate().map(|(i, p)| (p, i)).collect();
    let owned: Vec<Vec<u16>> = SCM_OWNED_VALUES
        .iter()
        .map(|v| regbackup::fold_str(v))
        .collect();
    for (i, path) in backup_paths.iter().enumerate() {
        let Some(&j) = live_index.get(path) else {
            return Some(format!("key {} is missing", display(backup, i, None)));
        };
        let (b, l) = (&backup.keys[i], &live.keys[j]);
        let class = |c: &Option<purge_model::exec::regbackup::WideB64>| {
            c.as_ref().map(|c| c.0.clone()).unwrap_or_default()
        };
        if class(&b.class_b64) != class(&l.class_b64) {
            return Some(format!(
                "key {} has another class",
                display(backup, i, None)
            ));
        }
        if b.volatile != l.volatile {
            return Some(format!(
                "key {} has another volatility",
                display(backup, i, None)
            ));
        }
        if i != 0 && sddl_without_owner(&b.sddl) != sddl_without_owner(&l.sddl) {
            return Some(format!(
                "key {} has another security descriptor",
                display(backup, i, None)
            ));
        }
        let live_values = values_by_name(live, j);
        for value in &b.values {
            let shown = value.name_b64.to_string_lossy();
            match live_values.get(&regbackup::fold_units(&value.name_b64.0)) {
                None => {
                    return Some(format!(
                        "value {} is missing",
                        display(backup, i, Some(&shown))
                    ));
                }
                Some((ty, _)) if *ty != value.value_type => {
                    return Some(format!(
                        "value {} has type {ty}, not {}",
                        display(backup, i, Some(&shown)),
                        value.value_type
                    ));
                }
                Some((_, data)) if *data != value.data_b64.0.as_slice() => {
                    return Some(format!(
                        "value {} holds other data",
                        display(backup, i, Some(&shown))
                    ));
                }
                Some(_) => {}
            }
        }
        let backup_values = values_by_name(backup, i);
        for value in &l.values {
            let folded = regbackup::fold_units(&value.name_b64.0);
            let owned_here = j == 0 && owned.contains(&folded);
            if !backup_values.contains_key(&folded) && !owned_here {
                return Some(format!(
                    "value {} is not in the backup",
                    display(live, j, Some(&value.name_b64.to_string_lossy()))
                ));
            }
        }
    }
    let backup_set: std::collections::HashSet<&Vec<u16>> = backup_paths.iter().collect();
    for (j, path) in live_paths.iter().enumerate() {
        if !backup_set.contains(path) {
            return Some(format!(
                "key {} is not in the backup",
                display(live, j, None)
            ));
        }
    }
    None
}

/// Whether every key and value of `live` is in `backup` (names compared without case): nothing in the
/// live key comes from anywhere but a restore of this backup.
fn live_within_backup(backup: &RegTree, live: &RegTree) -> bool {
    let backup_paths = folded_paths(backup);
    let index: HashMap<&Vec<u16>, usize> = backup_paths
        .iter()
        .enumerate()
        .map(|(i, p)| (p, i))
        .collect();
    folded_paths(live).iter().enumerate().all(|(j, path)| {
        index.get(path).is_some_and(|&i| {
            let names = values_by_name(backup, i);
            live.keys[j]
                .values
                .iter()
                .all(|v| names.contains_key(&regbackup::fold_units(&v.name_b64.0)))
        })
    })
}

/// The writes that make `live` hold every key and value of `backup`: each backup key that is missing
/// (created with its class, descriptor and volatility, parent first) and each backup value that is
/// missing or has another type or data. Nothing is ever deleted.
pub fn write_back_ops(backup: &RegTree, live: &RegTree) -> Vec<WriteBack> {
    let backup_paths = folded_paths(backup);
    let live_index: HashMap<Vec<u16>, usize> = folded_paths(live)
        .into_iter()
        .enumerate()
        .map(|(i, p)| (p, i))
        .collect();
    let mut writes = Vec::new();
    for (i, path) in backup_paths.iter().enumerate() {
        let node = &backup.keys[i];
        let names = name_path(backup, i);
        let live_values = match live_index.get(path) {
            Some(&j) => values_by_name(live, j),
            None => {
                writes.push(WriteBack::CreateKey {
                    path: names.clone(),
                    class: node
                        .class_b64
                        .as_ref()
                        .map(|c| c.to_string_lossy())
                        .unwrap_or_default(),
                    sddl: node.sddl.clone(),
                    volatile: node.volatile,
                });
                HashMap::new()
            }
        };
        for value in &node.values {
            let same = live_values
                .get(&regbackup::fold_units(&value.name_b64.0))
                .is_some_and(|(ty, data)| {
                    *ty == value.value_type && *data == value.data_b64.0.as_slice()
                });
            if !same {
                writes.push(WriteBack::SetValue {
                    path: names.clone(),
                    name: value.name_b64.to_string_lossy(),
                    value_type: value.value_type,
                    data: value.data_b64.0.clone(),
                });
            }
        }
    }
    writes
}

// ---------------------------------------------------------------------------------------------------
// Definition <-> SCM
// ---------------------------------------------------------------------------------------------------

/// The config2 items of a definition whose value the key backup holds (`Config2Kind::registry_entries`:
/// a value of the service key, or the `TriggerInfo` subkey), in the spike's order. Applying the others
/// would write values the service never had.
fn config2_to_apply(config2: &SvcConfig2, tree: &RegTree) -> Result<Vec<Config2Item>, String> {
    let root = tree_values(tree, 0).ok_or("a value name is not representable")?;
    let holds = |kind: Config2Kind| {
        kind.registry_entries()
            .iter()
            .any(|entry| match entry.strip_suffix('\\') {
                Some(subkey) => child_named(tree, 0, subkey).is_some(),
                None => root.iter().any(|(name, _, _)| eq_ci(name, entry)),
            })
    };
    let mut items = Vec::new();
    let mut push = |item: Config2Item| {
        if holds(item.kind()) {
            items.push(item);
        }
    };
    if let Some(v) = &config2.description {
        push(Config2Item::Description(v.clone()));
    }
    if let Some(v) = &config2.failure_actions {
        push(Config2Item::FailureActions(FailureActions {
            reset_period: v.reset_period,
            reboot_msg: v.reboot_msg.clone(),
            command: v.command.clone(),
            actions: v
                .actions
                .iter()
                .map(|a| FailureAction {
                    action_type: a.action_type,
                    delay_ms: a.delay_ms,
                })
                .collect(),
        }));
    }
    if let Some(v) = config2.failure_actions_flag {
        push(Config2Item::FailureActionsFlag(v));
    }
    if let Some(v) = config2.delayed_auto_start {
        push(Config2Item::DelayedAutoStart(v));
    }
    if let Some(v) = config2.service_sid_type {
        push(Config2Item::ServiceSidType(v));
    }
    if let Some(v) = &config2.required_privileges {
        push(Config2Item::RequiredPrivileges(v.clone()));
    }
    if let Some(v) = config2.preshutdown_timeout_ms {
        push(Config2Item::PreshutdownTimeout(v));
    }
    if let Some(triggers) = &config2.triggers {
        let mut out = Vec::with_capacity(triggers.len());
        for t in triggers {
            let subtype = if t.subtype.is_empty() {
                None
            } else {
                Some(
                    ScmGuid::parse(&t.subtype)
                        .ok_or_else(|| format!("trigger subtype {:?} is not a GUID", t.subtype))?,
                )
            };
            let mut data = Vec::with_capacity(t.data.len());
            for d in &t.data {
                data.push(TriggerDataItem {
                    data_type: d.data_type,
                    bytes: b64_decode(&d.base64)
                        .ok_or_else(|| "trigger data is not base64".to_owned())?,
                });
            }
            out.push(ScmTrigger {
                trigger_type: t.trigger_type,
                action: t.action,
                subtype,
                data,
            });
        }
        push(Config2Item::Triggers(out));
    }
    if let Some(v) = config2.launch_protected {
        push(Config2Item::LaunchProtected(v));
    }
    Ok(items)
}

/// The `CreateServiceW` arguments of a definition: the raw `ImagePath`, type, start type and error
/// control of the key backup (the registry is what the exact-restore check compares), the display name
/// as stored (`None` when the backup has none), and the SCM's load order group, dependencies and
/// account. No password.
fn create_args(
    name: &str,
    config: &SvcConfig,
    identity: &ServiceIdentity,
    tree: &RegTree,
) -> Result<ScmCreate, String> {
    let root_values = tree_values(tree, 0).ok_or("a value name is not representable")?;
    let root = as_raw(&root_values);
    let binary_path = identity
        .image_path
        .clone()
        .ok_or("the key backup has no ImagePath")?;
    let error_control = match find(&root, "ErrorControl") {
        Some(v) => exact_dword(Some(v), "ErrorControl")?,
        None => config.error_control,
    };
    Ok(ScmCreate {
        name: name.to_owned(),
        display_name: exact_string(find(&root, "DisplayName"), "DisplayName")?
            .filter(|d| !d.is_empty()),
        service_type: identity.service_type,
        start_type: identity.start,
        error_control,
        binary_path,
        load_order_group: config.load_order_group.clone(),
        dependencies: config.dependencies.clone(),
        service_start_name: config.service_start_name.clone(),
    })
}

/// The program of `identity` when it is a file outside every root of `roots` (or cannot be told to be
/// one file): the text for the message. `None` when it lies inside one ([`gate::file_in_roots`], the one
/// root check of the object ops). The same check refuses the delete (prepare, act) and the re-create
/// (undo, `ProgramOutsideRoot`).
fn program_outside_roots(
    identity: &ServiceIdentity,
    env: &GuardEnv,
    roots: &[String],
) -> Option<String> {
    match service_program(identity, &ProgramEnv::from_guard(env)) {
        ServiceProgram::File(file) if gate::file_in_roots(&file, roots, env, None) => None,
        program => Some(program.guard_text().to_owned()),
    }
}

/// Why the undo of a delete of this service would be refused for certain, judged before the delete
/// (M1b review R2b B1): a program outside the run's roots ([`program_outside_roots`]), `CreateServiceW`
/// arguments the SCM wrapper refuses (`scm::check_create`: a start type other than auto, demand or
/// disabled, an error control above 3, ...), or config2 items that cannot be applied. Undo makes the
/// same three checks on the same data.
fn restore_refusal(
    name: &str,
    identity: &ServiceIdentity,
    tree: &RegTree,
    scm: &ScmDefinition,
    env: &GuardEnv,
    roots: &[String],
) -> Option<String> {
    if let Some(program) = program_outside_roots(identity, env, roots) {
        return Some(format!(
            "its program {program} is not inside a root recorded for the run, so undo would never \
             create it again"
        ));
    }
    let create = match create_args(name, &scm.config, identity, tree) {
        Ok(create) => create,
        Err(why) => return Some(format!("it could not be created again: {why}")),
    };
    if let Err(e) = scm::check_create(&create) {
        return Some(format!("it could not be created again: {e}"));
    }
    if let Err(why) = config2_to_apply(&scm.config2, tree) {
        return Some(format!("its settings could not be applied again: {why}"));
    }
    None
}

/// The SCM's view of a service as a definition (`purge.svcdef/1` without the key backup).
fn scm_definition(service: &ScmService) -> ScmDefinition {
    let c = &service.config;
    let c2 = &service.config2;
    ScmDefinition {
        config: SvcConfig {
            service_type: c.service_type,
            start_type: c.start_type,
            error_control: c.error_control,
            binary_path: c.binary_path.clone(),
            load_order_group: c.load_order_group.clone().filter(|g| !g.is_empty()),
            tag_id: c.tag_id,
            dependencies: c.dependencies.clone(),
            service_start_name: c.service_start_name.clone().filter(|a| !a.is_empty()),
            display_name: c.display_name.clone().filter(|d| !d.is_empty()),
        },
        config2: SvcConfig2 {
            description: c2.description.clone(),
            delayed_auto_start: c2.delayed_auto_start,
            failure_actions: c2.failure_actions.as_ref().map(|f| SvcFailureActions {
                reset_period: f.reset_period,
                reboot_msg: f.reboot_msg.clone(),
                command: f.command.clone(),
                actions: f
                    .actions
                    .iter()
                    .map(|a| SvcFailureAction {
                        action_type: a.action_type,
                        delay_ms: a.delay_ms,
                    })
                    .collect(),
            }),
            failure_actions_flag: c2.failure_actions_flag,
            service_sid_type: c2.service_sid_type,
            required_privileges: c2.required_privileges.clone(),
            preshutdown_timeout_ms: c2.preshutdown_timeout_ms,
            triggers: c2.triggers.as_ref().map(|triggers| {
                triggers
                    .iter()
                    .map(|t| SvcTrigger {
                        trigger_type: t.trigger_type,
                        action: t.action,
                        subtype: t.subtype.map(|g| g.to_string()).unwrap_or_default(),
                        data: t
                            .data
                            .iter()
                            .map(|d| SvcTriggerData {
                                data_type: d.data_type,
                                base64: b64_encode(&d.bytes),
                            })
                            .collect(),
                    })
                    .collect()
            }),
            launch_protected: c2.launch_protected,
        },
        sddl: service.sddl.clone(),
    }
}

// ---------------------------------------------------------------------------------------------------
// Undo
// ---------------------------------------------------------------------------------------------------

/// How the undo of a service delete ends, as the journal takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SvcUndoResult {
    /// `undo_done` (with the token when an inverse ran, else without an intent: only `NothingToUndo`,
    /// `AlreadyRestored`, and a `Failed` found before anything ran).
    Done {
        /// The outcome.
        outcome: UndoOutcome,
        /// Text for the report.
        detail: String,
    },
    /// `undo_conflict` (with the token when an inverse ran, else without an intent).
    Conflict {
        /// The conflict.
        conflict: UndoConflict,
        /// Text for the report.
        detail: String,
    },
}

impl SvcUndoResult {
    fn done(outcome: UndoOutcome, detail: impl Into<String>) -> SvcUndoResult {
        SvcUndoResult::Done {
            outcome,
            detail: detail.into(),
        }
    }

    fn conflict(conflict: UndoConflict, detail: impl Into<String>) -> SvcUndoResult {
        SvcUndoResult::Conflict {
            conflict,
            detail: detail.into(),
        }
    }

    fn failed(code: FailCode, os_error: Option<u32>, detail: impl Into<String>) -> SvcUndoResult {
        let detail = detail.into();
        SvcUndoResult::Done {
            outcome: UndoOutcome::Failed {
                code,
                os_error,
                detail: detail.clone(),
            },
            detail,
        }
    }
}

/// What [`prepare_undo`] decided.
#[derive(Debug)]
pub enum SvcUndoPrepared {
    /// Decided without an inverse: journal it without an `undo_intent` (or with the open one).
    Decided(SvcUndoResult),
    /// The inverse runs: write the `undo_intent` and call [`run_undo`] with its token.
    Ready(Box<SvcUndoJob>),
}

/// A re-create that passed every check of [`prepare_undo`].
#[derive(Debug, Clone)]
pub struct SvcUndoJob {
    op: OpId,
    name: String,
    tree: RegTree,
    /// `None` when an earlier attempt of this undo created the service already.
    create: Option<ScmCreate>,
    config2: Vec<Config2Item>,
    sddl: Option<String>,
    note: String,
}

impl SvcUndoJob {
    /// Whether the job creates the service (`false`: it continues an earlier attempt's restore).
    pub fn creates(&self) -> bool {
        self.create.is_some()
    }
}

/// What [`prepare_undo`] takes about the op, all from its journal records.
#[derive(Debug, Clone, Copy)]
pub struct SvcUndoArgs<'a> {
    /// The op's intent.
    pub intent: &'a Intent,
    /// The op's `done` outcome; `None` when the journal holds only its intent.
    pub done: Option<&'a ItemOutcome>,
    /// Whether this op's last undo attempt created the service (review R2b S3), as the caller reads it
    /// from the journal's undo records of the op:
    ///
    /// - true when the op's last undo record is an `undo_intent` with nothing after it (the process
    ///   ended inside [`run_undo`], for example at `svcrestore.mid`);
    /// - true when that attempt ended with `undo_done` `Failed{VerifyFailed}`: [`run_undo`] ends every
    ///   failure after a successful create (or after continuing an earlier attempt's) with that code;
    /// - false otherwise: no attempt, an attempt that ended before or at the create (`Failed` with any
    ///   other code, or a conflict such as `ObjectExists`, `PendingDelete`), or one that ended with
    ///   `ValueDiffers`.
    ///
    /// Only then is a present service that matches the backup's identity taken for this undo's own
    /// half-made one and configured further; otherwise it is `ObjectExists` (another install may have
    /// created it). Its `done` outcome aside, an op with `own_attempt` is never `NothingToUndo`.
    pub own_attempt: bool,
    /// The roots recorded for the run (the journal header's `program_roots`): the service's program must
    /// lie inside one.
    pub program_roots: &'a [String],
}

/// The key backup of a definition, read hash-checked, as a tree whose identity is the definition's.
fn read_key_backup(
    session: &SessionDir,
    op: OpId,
    name: &str,
    def: &SvcDef,
) -> Result<(RegTree, ServiceIdentity), SvcUndoResult> {
    let tampered = |why: String| {
        SvcUndoResult::conflict(
            UndoConflict::BackupTampered,
            format!("service {name}: {why}"),
        )
    };
    let Some(reference) = def.key_backup_for(op) else {
        return Err(tampered(
            "the definition names another file than the op's key backup".to_owned(),
        ));
    };
    let backup = match regbackup::read_verified(session, reference) {
        Ok(backup) => backup,
        Err(BackupFileError::Missing) => {
            return Err(SvcUndoResult::conflict(
                UndoConflict::BackupMissing,
                format!(
                    "service {name}: the key backup {} is missing",
                    reference.path
                ),
            ));
        }
        Err(e) => return Err(tampered(format!("the key backup cannot be used: {e}"))),
    };
    let Some(tree) = backup.tree() else {
        return Err(tampered("the key backup holds no tree".to_owned()));
    };
    if !eq_ci(&tree.keys[0].name_b64.to_string_lossy(), name) {
        return Err(tampered("the key backup is of another key".to_owned()));
    }
    let identity = identity_from_tree(name, tree)
        .map_err(|why| tampered(format!("the key backup is not a service key: {why}")))?;
    if identity.fp().sha256 != def.identity_sha256 {
        return Err(tampered(
            "the key backup is not the key the definition was taken from".to_owned(),
        ));
    }
    Ok((tree.clone(), identity))
}

/// Whether `live` is what an earlier attempt of this undo left: the backup's name, raw `ImagePath`,
/// type, start type and account, its `ServiceDll` equal or not yet written back, not marked, stopped,
/// and nothing in its key that the backup lacks.
fn own_partial_restore(
    backup: &ServiceIdentity,
    backup_tree: &RegTree,
    live: &ServiceLive,
    live_tree: &RegTree,
) -> bool {
    let l = &live.identity;
    eq_ci(&l.name, &backup.name)
        && l.image_path == backup.image_path
        && l.service_type == backup.service_type
        && l.start == backup.start
        && l.object_name == backup.object_name
        && (l.service_dll.is_none() || l.service_dll == backup.service_dll)
        && !live.delete_flag
        && live.state == SERVICE_STOPPED
        && live_within_backup(backup_tree, live_tree)
}

/// Decides the undo of a service delete before any `undo_intent`; see the module docs.
pub fn prepare_undo(
    backend: &dyn ServiceBackend,
    session: &SessionDir,
    env: &GuardEnv,
    args: &SvcUndoArgs<'_>,
) -> SvcUndoPrepared {
    let decided = SvcUndoPrepared::Decided;
    let intent = args.intent;
    let internal = |why: String| decided(SvcUndoResult::failed(FailCode::Internal, None, why));
    let name = match op_name(&intent.exec_op) {
        Ok(name) => name.to_owned(),
        Err(r) => return internal(r.detail),
    };
    let Inverse::RecreateService { definition } = &intent.inverse else {
        return internal(format!(
            "the intent of service {name} names the inverse {}",
            intent.inverse.name()
        ));
    };
    let ItemFacts::Object {
        kind: ObjectKind::Service,
        sha256: pre,
        ..
    } = &intent.pre
    else {
        return internal(format!(
            "the intent of service {name} holds no service facts"
        ));
    };
    let unchanged = match args.done {
        Some(ItemOutcome::Failed { code, .. }) => *code != FailCode::VerifyFailed,
        Some(outcome) => !outcome.changed_system(),
        None => false,
    };
    if unchanged && !args.own_attempt {
        return decided(SvcUndoResult::done(
            UndoOutcome::NothingToUndo,
            format!("the delete of service {name} changed nothing"),
        ));
    }

    let def: SvcDef = match read_def_detailed(session, definition) {
        Ok(def) => def,
        Err(e) => return decided(SvcUndoResult::conflict(e.conflict, e.detail)),
    };
    if !eq_ci(&def.name, &name) || def.identity_sha256 != *pre {
        return decided(SvcUndoResult::conflict(
            UndoConflict::BackupTampered,
            format!("service {name}: the definition is not the one of this op"),
        ));
    }
    // The key backup is taken from the journal's own record, and the definition must name the same
    // file with the same hash (review R2b S5).
    if intent.definition.as_ref() != Some(&def.key_backup) {
        return decided(SvcUndoResult::conflict(
            UndoConflict::BackupTampered,
            format!(
                "service {name}: the journal and the definition do not name the same key backup"
            ),
        ));
    }
    let (tree, identity) = match read_key_backup(session, intent.op, &name, &def) {
        Ok(found) => found,
        Err(r) => return decided(r),
    };
    let tampered = |why: String| {
        decided(SvcUndoResult::conflict(
            UndoConflict::BackupTampered,
            format!("service {name}: {why}"),
        ))
    };
    let config2 = match config2_to_apply(&def.config2, &tree) {
        Ok(items) => items,
        Err(why) => return tampered(format!("the definition cannot be applied: {why}")),
    };
    let create = match create_args(&name, &def.config, &identity, &tree) {
        Ok(create) => create,
        Err(why) => return tampered(format!("the key backup cannot be applied: {why}")),
    };
    let sddl = child_named(&tree, 0, "Security").map(|_| def.sddl.clone());
    let note = if def.account_builtin {
        String::new()
    } else {
        format!(
            "service {name} runs as {}; its stored password was lost with the delete and must be set \
             again in Services",
            def.config.service_start_name.as_deref().unwrap_or("?")
        )
    };

    // The second lock: the program must be one of the run's roots (the check prepare and the act made).
    if let Some(program) = program_outside_roots(&identity, env, args.program_roots) {
        return decided(SvcUndoResult::conflict(
            UndoConflict::ProgramOutsideRoot,
            format!(
                "service {name}: its program {program} is not inside a root recorded for the run; \
                 nothing is created"
            ),
        ));
    }

    let mut job = SvcUndoJob {
        op: intent.op,
        name: name.clone(),
        tree,
        create: Some(create),
        config2,
        sddl,
        note,
    };
    let live = match backend.read(&name) {
        Ok(live) => live,
        Err(e) => {
            return decided(SvcUndoResult::failed(
                FailCode::ObjectApi,
                e.os_error,
                format!("service {name} cannot be read: {}", e.detail),
            ));
        }
    };
    let Some(live) = live else {
        return SvcUndoPrepared::Ready(Box::new(job));
    };
    if live.delete_flag {
        return decided(SvcUndoResult::conflict(
            UndoConflict::PendingDelete,
            format!(
                "service {name} is still marked for delete because a handle to it is open; undo can \
                 run again once it is gone (at the latest after a restart)"
            ),
        ));
    }
    let live_tree = match backend.capture_key(&name, job.tree.keys.len().max(1) * 4) {
        Ok(Some(doc)) => doc.tree().cloned(),
        Ok(None) | Err(_) => None,
    };
    let Some(live_tree) = live_tree else {
        return decided(SvcUndoResult::conflict(
            UndoConflict::ObjectExists,
            format!("a service named {name} exists and its key cannot be compared with the backup"),
        ));
    };
    if live.identity.fp().sha256 == def.identity_sha256
        && tree_difference(&job.tree, &live_tree).is_none()
    {
        return decided(SvcUndoResult::done(
            UndoOutcome::AlreadyRestored,
            format!("service {name} is already as backed up"),
        ));
    }
    if args.own_attempt && own_partial_restore(&identity, &job.tree, &live, &live_tree) {
        job.create = None;
        return SvcUndoPrepared::Ready(Box::new(job));
    }
    decided(SvcUndoResult::conflict(
        UndoConflict::ObjectExists,
        format!("a service named {name} exists and is not the one backed up; nothing is changed"),
    ))
}

/// Runs the re-create of `job` under the token of its flushed `undo_intent`; see the module docs.
/// Never starts the service.
pub fn run_undo(
    backend: &dyn ServiceBackend,
    job: Box<SvcUndoJob>,
    token: &UndoToken,
) -> SvcUndoResult {
    let SvcUndoJob {
        op,
        name,
        tree,
        create,
        config2,
        sddl,
        note,
    } = *job;
    if token.op() != op {
        return SvcUndoResult::failed(
            FailCode::Internal,
            None,
            format!(
                "the undo token is for op {}, not op {op}; nothing created",
                token.op()
            ),
        );
    }
    // Before or at the create nothing of this attempt exists: `ObjectApi` and the conflicts. After it,
    // every failure is `VerifyFailed`, which tells the next attempt that the service present is this
    // undo's own (`SvcUndoArgs::own_attempt`, review R2b S3).
    let api = |what: &str, e: &ObjErr| {
        SvcUndoResult::failed(
            FailCode::VerifyFailed,
            e.os_error,
            format!(
                "service {name} was created again, but {what} failed: {}; it was not started",
                e.detail
            ),
        )
    };
    if let Some(args) = &create {
        if let Err(e) = backend.create(args) {
            return match e.kind {
                ObjErrKind::Exists => SvcUndoResult::conflict(
                    UndoConflict::ObjectExists,
                    format!("a service named {name} was created meanwhile; nothing is changed"),
                ),
                ObjErrKind::MarkedForDelete => SvcUndoResult::conflict(
                    UndoConflict::PendingDelete,
                    format!("service {name} is still marked for delete; undo can run again later"),
                ),
                _ => SvcUndoResult::failed(
                    FailCode::ObjectApi,
                    e.os_error,
                    format!("service {name}: create: {}; nothing created", e.detail),
                ),
            };
        }
        hit(fault::SVCRESTORE_MID);
    }
    for item in &config2 {
        match backend.apply_config2(&name, item) {
            Ok(()) => {}
            // A value the SCM refuses to set is a new service's default; the write-back writes the
            // backed-up value, and the exact-restore check compares it.
            Err(e) if e.kind == ObjErrKind::NotSettable => {}
            Err(e) => return api(&format!("config2 {}", item.kind().name()), &e),
        }
    }
    if let Some(sddl) = &sddl
        && let Err(e) = backend.apply_security(&name, sddl)
    {
        return api("set the DACL", &e);
    }
    let capture = |when: &str| match backend.capture_key(&name, tree.keys.len().max(1) * 4) {
        Ok(Some(doc)) => doc.tree().cloned().ok_or_else(|| {
            SvcUndoResult::failed(
                FailCode::VerifyFailed,
                None,
                format!("service {name}: the key capture {when} holds no tree"),
            )
        }),
        Ok(None) => Err(SvcUndoResult::failed(
            FailCode::VerifyFailed,
            None,
            format!("service {name}: its key is gone {when}"),
        )),
        Err(e) => Err(SvcUndoResult::failed(
            FailCode::VerifyFailed,
            None,
            format!("service {name}: its key cannot be read {when}: {e}"),
        )),
    };
    let live = match capture("before the write-back") {
        Ok(live) => live,
        Err(r) => return r,
    };
    let writes = write_back_ops(&tree, &live);
    if !writes.is_empty()
        && let Err(e) = backend.write_back(&name, &writes)
    {
        return api("write back the backed-up values", &e);
    }
    if let Err(e) = backend.flush_system() {
        return SvcUndoResult::failed(
            FailCode::VerifyFailed,
            e.os_error,
            format!(
                "service {name}: the SYSTEM hive could not be flushed: {}",
                e.detail
            ),
        );
    }
    hit(fault::UNDO_ACT_AFTER);
    let after = match capture("after the restore") {
        Ok(after) => after,
        Err(r) => return r,
    };
    match tree_difference(&tree, &after) {
        None => SvcUndoResult::done(UndoOutcome::Restored, note),
        Some(difference) => SvcUndoResult::conflict(
            UndoConflict::ValueDiffers,
            format!(
                "service {name} was created again, but its key is not the backup: {difference}; it \
                 was not started"
            ),
        ),
    }
}

// ---------------------------------------------------------------------------------------------------
// Base64 (standard alphabet, padded), for trigger data
// ---------------------------------------------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding.
pub fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes [`b64_encode`]'s form; `None` for anything else.
pub fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let value = |c: u8| B64.iter().position(|&b| b == c).map(|p| p as u32);
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let last = index == bytes.len() / 4 - 1;
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &chunk[..4 - pad] {
            n = (n << 6) | value(c)?;
        }
        n <<= 6 * pad as u32;
        let take = 3 - pad;
        for i in 0..take {
            out.push((n >> (16 - 8 * i)) as u8);
        }
        if b64_encode(&out[out.len() - take..]) != std::str::from_utf8(chunk).ok()? {
            return None;
        }
    }
    Some(out)
}

// ---------------------------------------------------------------------------------------------------
// The live backend
// ---------------------------------------------------------------------------------------------------

/// The real backend: the SCM through `purge_win::scm`, the `Services` key through `purge_win::reg_write`
/// (every open component-wise without following links, through `ControlSet00N`, since
/// `CurrentControlSet` is itself a link), the `SYSTEM` flush through `durable`.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveServices;

impl LiveServices {
    /// `SYSTEM\ControlSet00N\Services` of the current control set.
    fn services_path() -> Result<String, ObjErr> {
        let set = purge_win::reg::current_control_set()
            .map_err(|e| ObjErr::os("read the current control set", e))?;
        if set.contains(['\\', '/']) || set.is_empty() {
            return Err(ObjErr::other(format!(
                "the current control set {set:?} is not a key name"
            )));
        }
        Ok(format!(r"SYSTEM\{set}\Services"))
    }

    /// The key of service `name` with `access`; `None` when it does not exist. A link is refused.
    fn open(name: &str, access: KeyAccess) -> Result<Option<WKey>, ObjErr> {
        if !valid_name(name) {
            return Err(ObjErr::new(
                ObjErrKind::Refused,
                None,
                format!("{name:?} is not a service name"),
            ));
        }
        let path = format!(r"{}\{name}", Self::services_path()?);
        let key = match WKey::open(RegRoot::Hklm, &path, RegView::K64, access) {
            Ok(key) => key,
            Err(e) if e.is_not_found() => return Ok(None),
            Err(e) => return Err(ObjErr::os("open the service key", e)),
        };
        if key
            .is_link()
            .map_err(|e| ObjErr::os("read the service key", e))?
        {
            return Err(ObjErr::new(
                ObjErrKind::Refused,
                None,
                format!("the key of service {name} is a registry link"),
            ));
        }
        Ok(Some(key))
    }

    /// The other services that depend on `name` (or on its group `group`).
    fn dependents(name: &str, group: Option<&str>) -> Result<Vec<String>, ObjErr> {
        let services = WKey::open(
            RegRoot::Hklm,
            &Self::services_path()?,
            RegView::K64,
            KeyAccess::READ,
        )
        .map_err(|e| ObjErr::os("open the Services key", e))?;
        let names = services
            .subkey_names()
            .map_err(|e| ObjErr::os("list the services", e))?;
        let group = group.map(str::trim).filter(|g| !g.is_empty());
        let mut out = Vec::new();
        for other in names {
            if eq_ci(&other, name) {
                continue;
            }
            let key = match services.open_subkey(&other, KeyAccess::READ) {
                Ok(key) => key,
                Err(e) if e.is_not_found() => continue,
                Err(e) => {
                    return Err(ObjErr::os(
                        &format!("open service {other} to read its dependencies"),
                        e,
                    ));
                }
            };
            let read = |value: &str| -> Result<Vec<String>, ObjErr> {
                match key.value(value) {
                    Ok(Some(v)) => Ok(list_entries(&v)),
                    Ok(None) => Ok(Vec::new()),
                    Err(e) if e.is_not_found() => Ok(Vec::new()),
                    Err(e) => Err(ObjErr::os(&format!("read {value} of service {other}"), e)),
                }
            };
            let on_service = read("DependOnService")?;
            let on_group = read("DependOnGroup")?;
            let depends = on_service.iter().any(|entry| {
                eq_ci(entry, name)
                    || group.is_some_and(|g| entry.strip_prefix('+').is_some_and(|e| eq_ci(e, g)))
            }) || group.is_some_and(|g| on_group.iter().any(|entry| eq_ci(entry, g)));
            if depends {
                out.push(other);
            }
        }
        Ok(out)
    }
}

/// The entries of a `REG_MULTI_SZ` (or a `REG_SZ` as one entry), trimmed, empty ones dropped.
fn list_entries(value: &RegValue) -> Vec<String> {
    let entries = match value.ty {
        REG_MULTI_SZ => value.as_multi_sz().unwrap_or_default(),
        REG_SZ | REG_EXPAND_SZ => value.as_string().into_iter().collect(),
        _ => Vec::new(),
    };
    entries
        .into_iter()
        .map(|e| e.trim().to_owned())
        .filter(|e| !e.is_empty())
        .collect()
}

fn raw_of(value: &RegValue) -> Raw<'_> {
    Raw {
        name: &value.name,
        ty: value.ty,
        data: &value.data,
    }
}

impl ServiceBackend for LiveServices {
    fn read(&self, name: &str) -> Result<Option<ServiceLive>, ObjErr> {
        let Some(key) = Self::open(name, KeyAccess::READ)? else {
            return Ok(None);
        };
        let values = key
            .values()
            .map_err(|e| ObjErr::os("read the service key", e))?;
        let params_dll = match key.open_subkey("Parameters", KeyAccess::READ) {
            Ok(params) => params
                .value("ServiceDll")
                .map_err(|e| ObjErr::os(r"read Parameters\ServiceDll", e))?,
            Err(e) if e.is_not_found() => None,
            Err(e) => return Err(ObjErr::os(r"open Parameters", e)),
        };
        let raw: Vec<Raw<'_>> = values.iter().map(raw_of).collect();
        let identity = identity_from_values(name, &raw, params_dll.as_ref().map(raw_of).as_ref())
            .map_err(|why| ObjErr::other(format!("the key of service {name}: {why}")))?;
        let delete_flag = delete_flag_of(&raw);
        let group = exact_string(find(&raw, "Group"), "Group").ok().flatten();
        let status = match scm::query(name) {
            Ok(Some(service)) => service.status,
            Ok(None) => {
                return Err(ObjErr::other(format!(
                    "service {name} has a key but the SCM does not know it"
                )));
            }
            Err(e) => return Err(ObjErr::scm("query the SCM", e)),
        };
        let dependents = Self::dependents(name, group.as_deref())?;
        let per_user_instance = match name.rsplit_once('_') {
            Some((stem, suffix))
                if !stem.is_empty()
                    && (1..=16).contains(&suffix.len())
                    && suffix.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                Self::open(stem, KeyAccess::READ)?.is_some()
            }
            _ => false,
        };
        Ok(Some(ServiceLive {
            identity,
            state: status.current_state,
            delete_flag,
            dependents,
            per_user_instance,
        }))
    }

    fn definition(&self, name: &str) -> Result<ScmDefinition, ObjErr> {
        match scm::query(name) {
            Ok(Some(service)) => Ok(scm_definition(&service)),
            Ok(None) => Err(ObjErr::new(
                ObjErrKind::NotFound,
                None,
                format!("service {name} does not exist"),
            )),
            Err(e) => Err(ObjErr::scm("query the SCM", e)),
        }
    }

    fn capture_key(&self, name: &str, limit: usize) -> Result<Option<RegBackup>, CaptureError> {
        let key = match Self::open(name, KeyAccess::READ) {
            Ok(Some(key)) => key,
            Ok(None) => return Ok(None),
            Err(e) => {
                return Err(CaptureError::Os(regbackup::KeyOpError {
                    at: String::new(),
                    op: "open the service key",
                    error: Win32Error(e.os_error.unwrap_or(1)),
                }));
            }
        };
        regbackup::capture_tree(&key, &format!(r"{SERVICES_KEY}\{name}"), limit).map(Some)
    }

    fn delete(&self, name: &str) -> Result<DeleteResult, ObjErr> {
        match scm::delete(name) {
            Ok(ScmDelete::Deleted) => Ok(DeleteResult::Deleted),
            Ok(ScmDelete::Marked) => Ok(DeleteResult::Marked),
            Err(e) => Err(ObjErr::scm("DeleteService", e)),
        }
    }

    fn create(&self, args: &ScmCreate) -> Result<(), ObjErr> {
        scm::create(args).map_err(|e| ObjErr::scm("CreateServiceW", e))
    }

    fn apply_config2(&self, name: &str, item: &Config2Item) -> Result<(), ObjErr> {
        scm::set_config2(name, item.clone()).map_err(|e| ObjErr::scm("ChangeServiceConfig2W", e))
    }

    fn apply_security(&self, name: &str, sddl: &str) -> Result<(), ObjErr> {
        scm::set_security(name, sddl).map_err(|e| ObjErr::scm("SetServiceObjectSecurity", e))
    }

    fn write_back(&self, name: &str, writes: &[WriteBack]) -> Result<(), ObjErr> {
        let Some(root) = Self::open(name, KeyAccess::SET_VALUE | KeyAccess::CREATE_SUB_KEY)? else {
            return Err(ObjErr::new(
                ObjErrKind::NotFound,
                None,
                format!("the key of service {name} is gone"),
            ));
        };
        let below = |path: &[String], access: KeyAccess| -> Result<Option<WKey>, ObjErr> {
            if path.is_empty() {
                return Ok(None);
            }
            if path.iter().any(|p| p.is_empty() || p.contains('\\')) {
                return Err(ObjErr::other("a key name of the backup is not usable"));
            }
            root.open_subkey(&path.join("\\"), access)
                .map(Some)
                .map_err(|e| ObjErr::os(&format!(r"open {}", path.join("\\")), e))
        };
        for write in writes {
            match write {
                WriteBack::CreateKey {
                    path,
                    class,
                    sddl,
                    volatile,
                } => {
                    let Some((leaf, parent_path)) = path.split_last() else {
                        return Err(ObjErr::other("a key to create has no name"));
                    };
                    let parent = below(parent_path, KeyAccess::CREATE_SUB_KEY)?;
                    let parent = parent.as_ref().unwrap_or(&root);
                    let what = format!(r"create {}", path.join("\\"));
                    match parent.create_subkey(leaf, class, Some(sddl), *volatile) {
                        Ok(_) => {}
                        Err(e) if e == INVALID_OWNER => {
                            // The recorded owner (SYSTEM) needs SeRestorePrivilege, which only the
                            // created key's own security write enables.
                            let rest = sddl_without_owner(sddl);
                            let created = parent
                                .create_subkey(
                                    leaf,
                                    class,
                                    (!rest.is_empty()).then_some(rest),
                                    *volatile,
                                )
                                .map_err(|e| ObjErr::os(&what, e))?;
                            let _ = created.set_security(sddl);
                        }
                        Err(e) => return Err(ObjErr::os(&what, e)),
                    }
                }
                WriteBack::SetValue {
                    path,
                    name: value,
                    value_type,
                    data,
                } => {
                    let key = below(path, KeyAccess::SET_VALUE)?;
                    key.as_ref()
                        .unwrap_or(&root)
                        .set_value_raw(value, *value_type, data)
                        .map_err(|e| ObjErr::os(&format!("set value {value}"), e))?;
                }
            }
        }
        Ok(())
    }

    fn flush_system(&self) -> Result<(), ObjErr> {
        durable::flush_op_hive(&ExecOp::DeleteService {
            name: "flush".to_owned(),
        })
        .map_err(|e| ObjErr::new(ObjErrKind::Other, Some(e.error.code()), e.to_string()))
    }
}

// ---------------------------------------------------------------------------------------------------
// The fake backend (tests and test-support)
// ---------------------------------------------------------------------------------------------------

/// An in-memory [`ServiceBackend`] for tests: services as `Services\<name>` key trees, a call log, failure
/// injection and one-shot hooks. It has no start, stop or control entry, like the trait.
#[cfg(any(test, feature = "test-support"))]
pub mod fake {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use purge_model::exec::regbackup::{BytesB64, KeyNode, ValueBackup, WideB64};

    use super::*;

    /// A test SDDL for keys.
    pub const KEY_SDDL: &str = "O:BAG:SYD:(A;CI;KA;;;BA)(A;CI;KA;;;SY)";
    /// A test SDDL for service objects.
    pub const SVC_SDDL: &str =
        "O:SYG:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)";

    /// One service of the fake.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct FakeService {
        /// Its `Services\<name>` key tree.
        pub tree: RegTree,
        /// `dwCurrentState`.
        pub state: u32,
        /// Services that depend on it.
        pub dependents: Vec<String>,
        /// A per-user instance.
        pub per_user_instance: bool,
        /// The SCM's definition.
        pub scm: ScmDefinition,
    }

    /// A REG_SZ / REG_EXPAND_SZ payload with its terminator.
    pub fn sz(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// A REG_DWORD payload.
    pub fn dword(n: u32) -> Vec<u8> {
        n.to_le_bytes().to_vec()
    }

    fn node(parent: Option<u32>, name: &str, values: Vec<ValueBackup>) -> KeyNode {
        KeyNode {
            parent,
            name_b64: WideB64::from(name),
            class_b64: None,
            sddl: KEY_SDDL.to_owned(),
            last_write_time: FileTime(0),
            link: false,
            volatile: false,
            values,
        }
    }

    fn value(name: &str, ty: u32, data: Vec<u8>) -> ValueBackup {
        ValueBackup {
            name_b64: WideB64::from(name),
            value_type: ty,
            data_b64: BytesB64(data),
        }
    }

    impl FakeService {
        /// A stopped own-process service of `name` running `image_path` (raw, `REG_EXPAND_SZ`) as
        /// `account` (`None`: LocalSystem), demand start, with a display name and no dependents.
        pub fn new(name: &str, image_path: &str, account: Option<&str>) -> FakeService {
            let account_value = account.unwrap_or("LocalSystem");
            let root = node(
                None,
                name,
                vec![
                    value("Type", REG_DWORD, dword(0x10)),
                    value("Start", REG_DWORD, dword(3)),
                    value("ErrorControl", REG_DWORD, dword(1)),
                    value("ImagePath", REG_EXPAND_SZ, sz(image_path)),
                    value("DisplayName", REG_SZ, sz(&format!("{name} display"))),
                    value("ObjectName", REG_SZ, sz(account_value)),
                ],
            );
            FakeService {
                tree: RegTree { keys: vec![root] },
                state: SERVICE_STOPPED,
                dependents: Vec::new(),
                per_user_instance: false,
                scm: ScmDefinition {
                    config: SvcConfig {
                        service_type: 0x10,
                        start_type: 3,
                        error_control: 1,
                        binary_path: image_path.replace("%ProgramFiles%", r"C:\Program Files"),
                        load_order_group: None,
                        tag_id: 0,
                        dependencies: Vec::new(),
                        service_start_name: Some(account_value.to_owned()),
                        display_name: Some(format!("{name} display")),
                    },
                    config2: SvcConfig2 {
                        description: None,
                        delayed_auto_start: None,
                        failure_actions: None,
                        failure_actions_flag: None,
                        service_sid_type: None,
                        required_privileges: None,
                        preshutdown_timeout_ms: None,
                        triggers: None,
                        launch_protected: None,
                    },
                    sddl: SVC_SDDL.to_owned(),
                },
            }
        }

        /// Sets value `name` of the service key (replacing one of the same name).
        pub fn set_value(&mut self, name: &str, ty: u32, data: Vec<u8>) {
            set_in(&mut self.tree, 0, name, ty, data);
        }

        /// Adds subkey `name` below key `parent` with `values`; returns its index.
        pub fn add_key(
            &mut self,
            parent: usize,
            name: &str,
            values: Vec<(&str, u32, Vec<u8>)>,
        ) -> usize {
            let values = values.into_iter().map(|(n, t, d)| value(n, t, d)).collect();
            self.tree.keys.push(node(Some(parent as u32), name, values));
            self.tree.keys.len() - 1
        }

        /// The identity the fake reads for it.
        pub fn identity(&self) -> ServiceIdentity {
            let name = self.tree.keys[0].name_b64.to_string_lossy();
            identity_from_tree(&name, &self.tree).expect("a readable fake service")
        }
    }

    fn set_in(tree: &mut RegTree, index: usize, name: &str, ty: u32, data: Vec<u8>) {
        let values = &mut tree.keys[index].values;
        let folded = regbackup::fold_str(name);
        match values
            .iter_mut()
            .find(|v| regbackup::fold_units(&v.name_b64.0) == folded)
        {
            Some(v) => {
                v.value_type = ty;
                v.data_b64 = BytesB64(data);
            }
            None => values.push(value(name, ty, data)),
        }
    }

    fn find_key(tree: &RegTree, path: &[String]) -> Option<usize> {
        let mut at = 0;
        for name in path {
            at = child_named(tree, at, name)?;
        }
        Some(at)
    }

    /// The fake's state.
    #[derive(Debug, Default)]
    pub struct FakeWorld {
        /// The services by folded name.
        pub services: BTreeMap<String, FakeService>,
        /// Every call, in order: `read X`, `definition X`, `capture X`, `delete X`, `create X`,
        /// `config2 X <item>`, `security X`, `write_back X <n>`, `flush`.
        pub log: Vec<String>,
        /// The next call of each named kind (`read`, `definition`, `capture`, `delete`, `create`,
        /// `config2`, `security`, `write_back`, `flush`) fails with this error.
        pub fail_next: BTreeMap<&'static str, ObjErr>,
        /// A delete only marks the service (another handle is open): `DeleteFlag = 1`, key kept.
        pub mark_on_delete: bool,
        /// Value names the write-back silently skips (a write the registry did not take).
        pub skip_writes: Vec<String>,
        /// What the fake SCM writes on a `create` besides the main values: none by default.
        pub create_extra: Vec<(String, u32, Vec<u8>)>,
    }

    type Hook = Box<dyn FnOnce(&mut FakeWorld)>;

    /// The fake backend.
    #[derive(Default)]
    pub struct FakeServices {
        world: RefCell<FakeWorld>,
        hooks: RefCell<Vec<(&'static str, Hook)>>,
    }

    impl std::fmt::Debug for FakeServices {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FakeServices")
                .field("world", &self.world)
                .finish_non_exhaustive()
        }
    }

    fn key_of(name: &str) -> String {
        name.to_lowercase()
    }

    impl FakeServices {
        /// A fake with `services`.
        pub fn with(services: impl IntoIterator<Item = FakeService>) -> FakeServices {
            let fake = FakeServices::default();
            for service in services {
                fake.insert(service);
            }
            fake
        }

        /// Adds or replaces a service.
        pub fn insert(&self, service: FakeService) {
            let name = service.tree.keys[0].name_b64.to_string_lossy();
            self.world
                .borrow_mut()
                .services
                .insert(key_of(&name), service);
        }

        /// The state, to look at or change.
        pub fn world(&self) -> std::cell::RefMut<'_, FakeWorld> {
            self.world.borrow_mut()
        }

        /// The service `name`, when it exists.
        pub fn service(&self, name: &str) -> Option<FakeService> {
            self.world.borrow().services.get(&key_of(name)).cloned()
        }

        /// The call log so far.
        pub fn log(&self) -> Vec<String> {
            self.world.borrow().log.clone()
        }

        /// Runs `hook` on the state once, right after the next call of kind `call`.
        pub fn after(&self, call: &'static str, hook: impl FnOnce(&mut FakeWorld) + 'static) {
            self.hooks.borrow_mut().push((call, Box::new(hook)));
        }

        /// Logs a call, fails it when asked; the hooks run when the call returns ([`Self::done`]).
        fn begin(&self, call: &'static str, line: String) -> Result<(), ObjErr> {
            let mut world = self.world.borrow_mut();
            world.log.push(line);
            match world.fail_next.remove(call) {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }

        fn done<T>(&self, call: &'static str, value: T) -> T {
            let mut hooks = self.hooks.borrow_mut();
            let due: Vec<Hook> = {
                let mut keep = Vec::new();
                let mut due = Vec::new();
                for (c, h) in hooks.drain(..) {
                    if c == call {
                        due.push(h);
                    } else {
                        keep.push((c, h));
                    }
                }
                *hooks = keep;
                due
            };
            drop(hooks);
            for hook in due {
                hook(&mut self.world.borrow_mut());
            }
            value
        }
    }

    impl ServiceBackend for FakeServices {
        fn read(&self, name: &str) -> Result<Option<ServiceLive>, ObjErr> {
            self.begin("read", format!("read {name}"))?;
            let found = self.world.borrow().services.get(&key_of(name)).cloned();
            let live = match found {
                None => None,
                Some(s) => Some(ServiceLive {
                    identity: identity_from_tree(name, &s.tree).map_err(ObjErr::other)?,
                    state: s.state,
                    delete_flag: tree_delete_flag(&s.tree),
                    dependents: s.dependents.clone(),
                    per_user_instance: s.per_user_instance,
                }),
            };
            Ok(self.done("read", live))
        }

        fn definition(&self, name: &str) -> Result<ScmDefinition, ObjErr> {
            self.begin("definition", format!("definition {name}"))?;
            let found = self.world.borrow().services.get(&key_of(name)).cloned();
            let def = found
                .map(|s| s.scm)
                .ok_or_else(|| ObjErr::new(ObjErrKind::NotFound, Some(1060), "no such service"))?;
            Ok(self.done("definition", def))
        }

        fn capture_key(&self, name: &str, limit: usize) -> Result<Option<RegBackup>, CaptureError> {
            self.begin("capture", format!("capture {name}"))
                .map_err(|e| {
                    CaptureError::Os(regbackup::KeyOpError {
                        at: String::new(),
                        op: "capture",
                        error: Win32Error(e.os_error.unwrap_or(5)),
                    })
                })?;
            let found = self.world.borrow().services.get(&key_of(name)).cloned();
            let doc = match found {
                None => None,
                Some(s) if s.tree.keys.len() > limit => {
                    return Err(CaptureError::TooLarge { limit });
                }
                Some(s) => Some(RegBackup {
                    schema: RegBackupSchema,
                    key: format!(r"{SERVICES_KEY}\{name}"),
                    captured: FileTime(1),
                    body: RegBackupBody::Tree(s.tree),
                }),
            };
            Ok(self.done("capture", doc))
        }

        fn delete(&self, name: &str) -> Result<DeleteResult, ObjErr> {
            self.begin("delete", format!("delete {name}"))?;
            let outcome = {
                let mut world = self.world.borrow_mut();
                let mark = world.mark_on_delete;
                let Some(service) = world.services.get_mut(&key_of(name)) else {
                    return Err(ObjErr::new(
                        ObjErrKind::NotFound,
                        Some(1060),
                        "no such service",
                    ));
                };
                if service.state != SERVICE_STOPPED {
                    return Err(ObjErr::new(ObjErrKind::InUse, None, "not stopped"));
                }
                if mark {
                    set_in(&mut service.tree, 0, "DeleteFlag", REG_DWORD, dword(1));
                    DeleteResult::Marked
                } else {
                    world.services.remove(&key_of(name));
                    DeleteResult::Deleted
                }
            };
            Ok(self.done("delete", outcome))
        }

        fn create(&self, args: &ScmCreate) -> Result<(), ObjErr> {
            self.begin("create", format!("create {}", args.name))?;
            {
                let mut world = self.world.borrow_mut();
                if let Some(existing) = world.services.get(&key_of(&args.name)) {
                    return Err(if tree_delete_flag(&existing.tree) {
                        ObjErr::new(ObjErrKind::MarkedForDelete, Some(1072), "marked")
                    } else {
                        ObjErr::new(ObjErrKind::Exists, Some(1073), "exists")
                    });
                }
                let mut values = vec![
                    value("Type", REG_DWORD, dword(args.service_type)),
                    value("Start", REG_DWORD, dword(args.start_type)),
                    value("ErrorControl", REG_DWORD, dword(args.error_control)),
                    value("ImagePath", REG_EXPAND_SZ, sz(&args.binary_path)),
                ];
                if let Some(d) = &args.display_name {
                    values.push(value("DisplayName", REG_SZ, sz(d)));
                }
                values.push(value(
                    "ObjectName",
                    REG_SZ,
                    sz(args.service_start_name.as_deref().unwrap_or("LocalSystem")),
                ));
                for (n, t, d) in world.create_extra.clone() {
                    values.push(value(&n, t, d));
                }
                let mut service = FakeService::new(&args.name, &args.binary_path, None);
                service.tree = RegTree {
                    keys: vec![node(None, &args.name, values)],
                };
                world.services.insert(key_of(&args.name), service);
            }
            self.done("create", ());
            Ok(())
        }

        fn apply_config2(&self, name: &str, item: &Config2Item) -> Result<(), ObjErr> {
            self.begin("config2", format!("config2 {name} {}", item.kind().name()))?;
            {
                let mut world = self.world.borrow_mut();
                let Some(service) = world.services.get_mut(&key_of(name)) else {
                    return Err(ObjErr::new(
                        ObjErrKind::NotFound,
                        Some(1060),
                        "no such service",
                    ));
                };
                if let Config2Item::Description(text) = item {
                    set_in(&mut service.tree, 0, "Description", REG_SZ, sz(text));
                }
            }
            self.done("config2", ());
            Ok(())
        }

        fn apply_security(&self, name: &str, _sddl: &str) -> Result<(), ObjErr> {
            self.begin("security", format!("security {name}"))?;
            {
                let mut world = self.world.borrow_mut();
                let Some(service) = world.services.get_mut(&key_of(name)) else {
                    return Err(ObjErr::new(
                        ObjErrKind::NotFound,
                        Some(1060),
                        "no such service",
                    ));
                };
                // The SCM stores the descriptor in Security\Security, in its own binary form.
                let index = match child_named(&service.tree, 0, "Security") {
                    Some(i) => i,
                    None => {
                        service
                            .tree
                            .keys
                            .push(node(Some(0), "Security", Vec::new()));
                        service.tree.keys.len() - 1
                    }
                };
                set_in(&mut service.tree, index, "Security", 3, vec![1, 0, 4, 0x80]);
            }
            self.done("security", ());
            Ok(())
        }

        fn write_back(&self, name: &str, writes: &[WriteBack]) -> Result<(), ObjErr> {
            self.begin("write_back", format!("write_back {name} {}", writes.len()))?;
            {
                let mut world = self.world.borrow_mut();
                let skip = world.skip_writes.clone();
                let Some(service) = world.services.get_mut(&key_of(name)) else {
                    return Err(ObjErr::new(
                        ObjErrKind::NotFound,
                        Some(1060),
                        "no such service",
                    ));
                };
                for write in writes {
                    match write {
                        WriteBack::CreateKey {
                            path,
                            class,
                            sddl,
                            volatile,
                        } => {
                            let (leaf, parent) = path
                                .split_last()
                                .ok_or_else(|| ObjErr::other("a key to create has no name"))?;
                            let parent = find_key(&service.tree, parent)
                                .ok_or_else(|| ObjErr::other("parent missing"))?;
                            let mut key = node(Some(parent as u32), leaf, Vec::new());
                            key.class_b64 =
                                (!class.is_empty()).then(|| WideB64::from(class.as_str()));
                            key.sddl = sddl.clone();
                            key.volatile = *volatile;
                            service.tree.keys.push(key);
                        }
                        WriteBack::SetValue {
                            path,
                            name: value_name,
                            value_type,
                            data,
                        } => {
                            if skip.iter().any(|s| eq_ci(s, value_name)) {
                                continue;
                            }
                            let index = find_key(&service.tree, path)
                                .ok_or_else(|| ObjErr::other("key missing"))?;
                            set_in(
                                &mut service.tree,
                                index,
                                value_name,
                                *value_type,
                                data.clone(),
                            );
                        }
                    }
                }
            }
            self.done("write_back", ());
            Ok(())
        }

        fn flush_system(&self) -> Result<(), ObjErr> {
            self.begin("flush", "flush".to_owned())?;
            self.done("flush", ());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        for len in 0..10u8 {
            let bytes: Vec<u8> = (0..len).map(|b| b.wrapping_mul(37)).collect();
            assert_eq!(b64_decode(&b64_encode(&bytes)), Some(bytes));
        }
        assert_eq!(b64_encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64_decode("Zg=="), Some(b"f".to_vec()));
        assert_eq!(b64_decode("Zh=="), None);
        assert_eq!(b64_decode("Zg="), None);
        assert_eq!(b64_decode("Z==="), None);
    }

    #[test]
    fn names_that_address_another_key_are_refused() {
        assert!(valid_name("VendorUpdate"));
        assert!(!valid_name(""));
        assert!(!valid_name(r"..\Tcpip"));
        assert!(!valid_name("a/b"));
        assert!(!valid_name("a\0b"));
        assert!(!valid_name(&"x".repeat(257)));
    }

    #[test]
    fn sddl_owner_is_dropped() {
        assert_eq!(
            sddl_without_owner("O:SYG:SYD:(A;;KA;;;SY)"),
            "G:SYD:(A;;KA;;;SY)"
        );
        assert_eq!(
            sddl_without_owner("O:S-1-5-18G:SYD:(A;;KA;;;SY)"),
            "G:SYD:(A;;KA;;;SY)"
        );
        assert_eq!(sddl_without_owner("D:(A;;KA;;;SY)"), "D:(A;;KA;;;SY)");
    }
}
