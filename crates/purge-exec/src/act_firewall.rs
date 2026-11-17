//! Executor action: delete and recreate a firewall rule (M1B-X-FIREWALL; ENGINE_PLAN.md §5.7.2, §7).
//!
//! The six entry points of C-ACT for [`ExecOp::DeleteFirewallRule`], over a [`FirewallBackend`] so that
//! every path is tested without Windows: [`validate`], [`prepare`] (or [`prepare_recorded`]), [`act`],
//! [`complete`], [`probe`], and undo as [`prepare_undo`] plus [`run_undo`]. [`LiveFirewall`] is the real
//! backend (the rule's registry value through `purge_win::reg_write`, delete and create through
//! `purge_win::firewall`); [`fake::FakeFirewall`] (tests and `test-support`) is an in-memory one.
//!
//! # Identity
//!
//! A rule is its value under `...\FirewallPolicy\FirewallRules` ([`FIREWALL_RULES_KEY`]): the value
//! name is the rule's id (the WMI `InstanceID`), the data the raw rule string. Identity is always read
//! from there ([`FirewallBackend::read`]); this module never writes that key. The rule's display name
//! is used for nothing but report text. A rule of the same id in the group-policy store is another
//! store and is never read or touched.
//!
//! What the spike settled (vm/spikes/m1b/RESULT.json, section `firewall`, `exact: true`): the delete is
//! a WQL query on `InstanceID` with exactly one match and an exact-id check after WMI's case-blind
//! match; the re-create is a create-only `PutInstance` under the rule's own id, with the filters passed
//! as context values. [`purge_model::FIREWALL_RESTORE_EXACT`] is true and no re-create-under-a-new-id
//! path exists (DECISIONS.md, M1b); this module does not compile if the constant turns false.
//!
//! # One item
//!
//! 1. [`validate`]: the rule is read fresh; absent is `Vanished`. The digest of (id, raw string) must be
//!    the plan's `object_fp` (else `Skipped{ChangedSinceScan}`). Then [`rule_blocker`]: the string must
//!    parse (else `GateBlocked{CannotBackUp}`), the guard's `check_object` with the rule's facts
//!    (`fw.package-bound`, `fw.resource-name`), and every field must have an exact re-create mapping
//!    (`purge_win::firewall::map_rule`; else `GateBlocked{CannotBackUp}`: a rule that cannot come back
//!    is never deleted), none of a form whose mapping no VM round trip has proven yet
//!    ([`FirewallShape::unproven_in`], `purge_model::FIREWALL_UNPROVEN_SHAPES`, review R2b S2), and no
//!    `Svc` (a service's rule runs the service host, outside every root of an app: undo could never
//!    bring it back, review R2b B1). All `CannotBackUp`.
//! 2. [`prepare`]: one read, bound to the validated stamp and judged again by [`rule_blocker`]; an
//!    `App` outside the journal header's `program_roots` is `CannotBackUp` (the check undo makes), and
//!    with no roots at all every rule is, a rule without `App` too (review R3b S2);
//!    `purge.fwdef/1` is written from that same read. The intent carries
//!    [`Inverse::RecreateFirewallRule`].
//! 3. The executor journals the intent and hits `act.before`.
//! 4. [`act`]: the act-time gate (read again, digest equal to the stamp, [`rule_blocker`], the root
//!    check, and the definition the intent names read hash-checked and equal to the rule now, else
//!    `NoVerifiedBackup`), then
//!    `delete_by_instance_id(id)`. One deleted: fault point `objdelete.after`, flush of `SYSTEM`, fault
//!    point `act.after`, and [`complete`]'s verdict from a fresh read. None deleted: a fresh read tells
//!    `Vanished` (absent) from `Failed{ObjectApi}` (still there). A failed delete call is followed by a
//!    fresh read as well: a rule that is gone anyway goes the deleted way, so its `done` never claims
//!    "nothing changed" for a rule that is gone (undo would then refuse to bring it back).
//!
//! [`probe`]: absent is done, present with the stamp's digest is not done, anything else needs
//! attention. [`FwRemoval::from_intent`] rebuilds the removal for a resumed run.
//!
//! # Undo
//!
//! [`prepare_undo`] decides everything that needs no `undo_intent`: an op that changed nothing; a
//! definition that is missing, does not match the journal, is not this op's, or whose `fields` are not
//! exactly the parse of its own raw string (`BackupTampered`; the create is fed from `fields`, the
//! identity digest covers only the raw string); a rule present with this exact id and the backup's
//! fields (`AlreadyRestored`); a rule present otherwise (`ObjectExists`); and, when absent, a backed-up
//! `App` that is not a file under a root recorded for the run (`ProgramOutsideRoot`: a tampered store
//! must not be usable to open the firewall for an arbitrary program).
//!
//! [`run_undo`] runs under the token of the flushed `undo_intent`: create under the same id, fault point
//! `fwrestore.mid`, flush of `SYSTEM`, fault point `undo.act.after`, then the exact-restore check: the
//! value is read again and must carry exactly the id and the backup's fields (`same_rule`; version and
//! order aside) for `Restored`. Anything else deletes the half-made rule by its id, flushes `SYSTEM`,
//! and is the conflict `ValueDiffers`, whose detail names the definition file that keeps the rule
//! string.
//!
//! A crash at `fwrestore.mid` leaves the re-created rule unchecked; the undo run again finds it present
//! and checks it as [`prepare_undo`] checks any present rule: the backup's fields are
//! `AlreadyRestored` (after a flush of `SYSTEM`), anything else `ObjectExists`.

#[cfg(any(test, feature = "test-support"))]
use std::cell::RefCell;
use std::collections::BTreeMap;

use purge_guard::canon::{GuardEnv, canon_path};
use purge_guard::deny::{DenyList, ObjectGuardFacts};
use purge_guard::prefix::{self, eq_ci, expand_env};
use purge_model::exec::journal::{Intent, ItemFacts, UndoConflict, UndoOutcome};
use purge_model::exec::op::{ExecOp, FailCode, Inverse, ItemOutcome, OpId, SkipReason};
use purge_model::{
    Blocker, Candidate, CandidateId, FIREWALL_RESTORE_EXACT, FirewallIdentity, FirewallRuleFields,
    FirewallShape, ObjectKind, Target, parse_firewall_rule,
};
use purge_win::firewall::{self as fw, WinError};
use purge_win::reg::{REG_EXPAND_SZ, REG_SZ, RegRoot, RegView};
use purge_win::reg_write::{KeyAccess, WKey};

use crate::act_service::{ObjErr, ObjErrKind};
use crate::act_typed::TypedResult;
use crate::durable;
use crate::fault;
use crate::gate::{self, GateCtx, Stamp, check_object_stamp_detailed, check_plan_fp_detailed};
use crate::journal::{IntentToken, UndoToken};
use crate::objdef::{DefWriteError, FWDEF_SCHEMA, FwDef, read_def_detailed, write_def};
use crate::recover::Probe;
use crate::storage::SessionDir;

/// The key holding one value per rule of the local (persistent) store, as the scanner spells it.
pub const FIREWALL_RULES_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

/// The key below `ControlSet00N`, opened by [`LiveFirewall`].
const RULES_BELOW_CONTROL_SET: &str =
    r"Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules";

/// Fields that bind a rule to an AppX package or AppContainer (the scanner's `PACKAGE_FIELDS`).
const PACKAGE_FIELDS: [&str; 3] = ["AppPkgId", "PFN", "LUOwn"];

/// The prefix of AppContainer and capability SIDs (`S-1-15-2-...`, `S-1-15-3-...`).
const APP_CONTAINER_SID: &str = "S-1-15-";

// Undo re-creates under the rule's own id only. Should the spike ever say otherwise, the fallback of
// C-OBJECT (a new id, `Reversibility::Partial`) must be written before this module builds again.
const _: () = assert!(
    FIREWALL_RESTORE_EXACT,
    "FIREWALL_RESTORE_EXACT is false: act_firewall has no new-id fallback"
);

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
/// order, and forgets them. Points the executor, the journal and the definition writer hit are not in it.
#[cfg(any(test, feature = "test-support"))]
pub fn take_fault_trace() -> Vec<&'static str> {
    TRACE.with(|trace| std::mem::take(&mut *trace.borrow_mut()))
}

// ---------------------------------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------------------------------

/// The firewall calls this module needs. [`LiveFirewall`] is the real one. Nothing in it writes the
/// rules key, selects a rule by anything but its id, or edits a rule in place.
pub trait FirewallBackend {
    /// The rule whose value name equals `id` (ignoring case, as the registry compares names), from its
    /// registry value: the stored name and the raw string. `None` when there is no such value. A value
    /// that is not exactly one string is an error of kind [`ObjErrKind::Refused`].
    fn read(&self, id: &str) -> Result<Option<FirewallIdentity>, ObjErr>;
    /// Deletes the persistent-store rule whose `InstanceID` is exactly `id`; the number deleted (0 or 1).
    fn delete_by_instance_id(&self, id: &str) -> Result<u32, ObjErr>;
    /// Creates a persistent-store rule with `InstanceID` `id` from a stored rule's fields; never over an
    /// existing one ([`ObjErrKind::Exists`]).
    fn create_with_instance_id(&self, id: &str, fields: &[(String, String)]) -> Result<(), ObjErr>;
    /// Flushes the `SYSTEM` hive.
    fn flush_system(&self) -> Result<(), ObjErr>;
    /// Waits a moment before the registry value is read again, while a delete or create may still be
    /// reaching it ([`SETTLE_TRIES`]). The live backend sleeps [`SETTLE_PAUSE_MS`]; the default does
    /// not wait.
    fn pause(&self) {}
}

/// How often a verdict read after a delete or a create is repeated while the value is not yet as the
/// call left it (the spike waited up to 5 s for the registry value to follow a WMI call).
pub const SETTLE_TRIES: u32 = 50;

/// The live backend's pause between two such reads, in milliseconds.
pub const SETTLE_PAUSE_MS: u64 = 100;

/// Reads rule `id` until it is present (`want_present`) or absent, a read fails, or [`SETTLE_TRIES`]
/// more reads were made; the last read.
fn read_settled(
    backend: &dyn FirewallBackend,
    id: &str,
    want_present: bool,
) -> Result<Option<FirewallIdentity>, ObjErr> {
    let mut last = backend.read(id);
    for _ in 0..SETTLE_TRIES {
        match &last {
            Ok(found) if found.is_some() != want_present => {}
            _ => break,
        }
        backend.pause();
        last = backend.read(id);
    }
    last
}

/// The error of a `purge_win::firewall` call as an [`ObjErr`].
fn win_err(what: &str, error: &WinError) -> ObjErr {
    let (kind, os_error) = match error {
        WinError::InvalidId(_)
        | WinError::Unmapped(_)
        | WinError::Ambiguous { .. }
        | WinError::IdMismatch { .. } => (ObjErrKind::Refused, None),
        WinError::ObjectExists => (ObjErrKind::Exists, Some(0x8004_1019)),
        // E_ACCESSDENIED and WBEM_E_ACCESS_DENIED.
        WinError::Com { hresult, .. } if matches!(*hresult, 0x8007_0005 | 0x8004_1003) => {
            (ObjErrKind::AccessDenied, Some(*hresult))
        }
        WinError::Com { hresult, .. } => (ObjErrKind::Other, Some(*hresult)),
    };
    ObjErr::new(kind, os_error, format!("{what}: {error}"))
}

/// The id of a `DeleteFirewallRule` op, when it is one with a usable id (the wrapper's own check: not
/// empty, at most 260 units, no control character).
fn op_id(exec_op: &ExecOp) -> Result<&str, TypedResult> {
    match exec_op {
        ExecOp::DeleteFirewallRule { id } if fw::check_instance_id(id).is_ok() => Ok(id),
        ExecOp::DeleteFirewallRule { id } => Err(failed(
            FailCode::Internal,
            None,
            format!("{id:?} is not a firewall rule id; nothing done"),
        )),
        other => Err(failed(
            FailCode::Internal,
            None,
            format!(
                "{} is not a firewall rule delete; nothing done",
                other.name()
            ),
        )),
    }
}

// ---------------------------------------------------------------------------------------------------
// The rule's facts
// ---------------------------------------------------------------------------------------------------

/// Whether the rule is bound to an AppX package or AppContainer: an `AppPkgId`, `PFN` or `LUOwn` field,
/// or any value that is an AppContainer SID (the scanner's rule).
pub fn package_bound(fields: &FirewallRuleFields) -> bool {
    fields.fields.iter().any(|(key, value)| {
        PACKAGE_FIELDS.iter().any(|f| key.eq_ignore_ascii_case(f))
            || value
                .trim()
                .get(..APP_CONTAINER_SID.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(APP_CONTAINER_SID))
    })
}

/// Whether the rule's `Name` or `EmbedCtxt` is a resource reference (`@...`): Windows' own rule groups
/// (C-GUARD `fw.resource-name`; the scanner looks at `Name` only, this gate at both).
pub fn resource_name(fields: &FirewallRuleFields) -> bool {
    ["Name", "EmbedCtxt"].iter().any(|key| {
        fields
            .get_all(key)
            .iter()
            .any(|v| v.trim_start().starts_with('@'))
    })
}

/// Why the rule with raw string `rule` must not be deleted, judged on the string read now: it does not
/// parse (`CannotBackUp`), the guard's `check_object` (`fw.package-bound`, `fw.resource-name`), or a
/// field has no exact re-create mapping (`CannotBackUp`). On success, the parsed fields.
pub fn rule_blocker(
    deny: &DenyList,
    identity: &FirewallIdentity,
) -> Result<FirewallRuleFields, (Blocker, String)> {
    let id = &identity.id;
    let fields = parse_firewall_rule(&identity.rule).map_err(|e| {
        (
            Blocker::CannotBackUp,
            format!("firewall rule {id}: its string cannot be read ({e})"),
        )
    })?;
    let facts = ObjectGuardFacts {
        name_or_path_or_id: id,
        program: None,
        service_type: None,
        delete_flag: false,
        per_user_template: false,
        package_bound: package_bound(&fields),
        resource_name: resource_name(&fields),
        in_baseline: false,
    };
    if let Some(blocker) = deny.check_object(ObjectKind::FirewallRule, &facts) {
        return Err((
            blocker,
            format!("firewall rule {id} is protected by the guard"),
        ));
    }
    if let Err(unmapped) = fw::map_rule(&fields.fields) {
        return Err((
            Blocker::CannotBackUp,
            format!(
                "firewall rule {id} could not be re-created exactly ({}); it is not deleted",
                unmapped.join("; ")
            ),
        ));
    }
    // Mapped by inference only: a wrong mapping is found at undo, when the half-made rule is deleted
    // again and the original is lost. Refused until a VM round trip proves the form (review R2b S2).
    let unproven = FirewallShape::unproven_in(&fields.fields);
    if !unproven.is_empty() {
        let names: Vec<&str> = unproven.iter().map(|s| s.name()).collect();
        return Err((
            Blocker::CannotBackUp,
            format!(
                "firewall rule {id} uses fields whose re-creation is not yet proven ({}); it is not \
                 deleted",
                names.join(", ")
            ),
        ));
    }
    // A service's rule runs the service host: its program is never inside the app's roots, so undo
    // would never bring it back (review R2b B1).
    if fields.get("Svc").is_some() {
        return Err((
            Blocker::CannotBackUp,
            format!(
                "firewall rule {id} is a service's rule (Svc), which undo could not create again; it \
                 is not deleted"
            ),
        ));
    }
    Ok(fields)
}

/// Why undo would refuse to create the rule of `fields` again, judged before the delete (review R2b
/// B1): a backed-up `App` that is not a file inside the journal header's `program_roots`
/// ([`gate::file_in_roots`], the one root check of the object ops). A rule without a program (`App`
/// absent or `System`) passes; prepare and the act refuse it anyway when the run has no roots at all
/// ([`gate::no_program_roots`]). Undo applies exactly this ([`UndoConflict::ProgramOutsideRoot`]).
fn program_refusal(
    fields: &FirewallRuleFields,
    env: &GuardEnv,
    roots: &[String],
) -> Option<String> {
    match rule_program(fields, env) {
        RuleProgram::None => None,
        RuleProgram::File(file) if gate::file_in_roots(&file, roots, env, None) => None,
        RuleProgram::File(text) | RuleProgram::Unresolved(text) => Some(text),
    }
}

/// The refusal of every delete of a run whose journal header records no program roots (review R3b
/// S2): also a rule without a program, which [`program_refusal`] lets through.
fn no_roots(id: &str) -> TypedResult {
    blocked(
        Blocker::CannotBackUp,
        format!(
            "firewall rule {id}: the run recorded no program roots ({}); left untouched",
            gate::reason::NO_ROOTS
        ),
    )
}

// ---------------------------------------------------------------------------------------------------
// Program of a rule (undo's root check)
// ---------------------------------------------------------------------------------------------------

/// The machine environment a rule's `App` is expanded with (the firewall service expands it with the
/// system environment): `SystemRoot`, `windir`, `SystemDrive`, the Program Files forms, `ProgramData`,
/// `ALLUSERSPROFILE`. A reference to anything else stays unexpanded and the path is then unresolved.
fn machine_vars(env: &GuardEnv) -> BTreeMap<String, String> {
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
    if let Some(x86) = env.program_files_x86.as_deref() {
        put("PROGRAMFILES(X86)", x86);
    }
    put("PROGRAMDATA", &env.program_data);
    put("ALLUSERSPROFILE", &env.program_data);
    vars
}

/// The program of a rule, as far as undo's root check needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleProgram {
    /// No `App` field, or `App=System` (the kernel).
    None,
    /// One file, as a canonical path.
    File(String),
    /// `App` names something that cannot be told to be one file; the raw text.
    Unresolved(String),
}

/// The program of `fields` (`App`, expanded with the machine environment of `env`).
pub fn rule_program(fields: &FirewallRuleFields, env: &GuardEnv) -> RuleProgram {
    let apps = fields.get_all("App");
    let raw = match apps.as_slice() {
        [] => return RuleProgram::None,
        [app] if app.trim().eq_ignore_ascii_case("System") => return RuleProgram::None,
        [app] => *app,
        more => return RuleProgram::Unresolved(more.join("|")),
    };
    let unresolved = || RuleProgram::Unresolved(raw.to_owned());
    let expanded = expand_env(raw.trim(), &machine_vars(env));
    if expanded.contains('%') || expanded.trim().is_empty() {
        return unresolved();
    }
    match canon_path(expanded.trim(), &GuardEnv::default(), None) {
        Ok(canon) if !canon.needs_long_name && prefix::depth(&canon.path) >= 2 => {
            RuleProgram::File(canon.path)
        }
        _ => unresolved(),
    }
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

/// A failed read: a value that is not one exact string is `GateBlocked{CannotBackUp}` (nothing could
/// bring it back byte for byte), anything else `Failed{ObjectApi}`.
fn read_failed(id: &str, e: &ObjErr) -> TypedResult {
    if e.kind == ObjErrKind::Refused {
        blocked(
            Blocker::CannotBackUp,
            format!("firewall rule {id}: {}; left untouched", e.detail),
        )
    } else {
        failed(
            FailCode::ObjectApi,
            e.os_error,
            format!(
                "firewall rule {id} cannot be read: {}; left untouched",
                e.detail
            ),
        )
    }
}

/// `Skipped{ChangedSinceScan}` when the rule read for `id` is stored under another spelling of the id:
/// the delete selects exactly `id` and would refuse it, so it is not the rule the op names.
fn other_spelling(id: &str, live: &FirewallIdentity) -> Option<TypedResult> {
    (live.id != id).then(|| {
        skipped(
            SkipReason::ChangedSinceScan,
            format!(
                "firewall rule {id} is stored as {:?}, another spelling of its id; left untouched",
                live.id
            ),
        )
    })
}

// ---------------------------------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------------------------------

/// What [`validate`] decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FwValidated {
    /// The item passed: journal `facts` in its `validated` record; the act is bound to `stamp`.
    Validated {
        /// [`Stamp::Object`] of the rule's digest.
        stamp: Stamp,
        /// [`ItemFacts::Object`] of the rule (never running).
        facts: ItemFacts,
    },
    /// Decided without changing anything.
    Decided(TypedResult),
}

/// The validate pass for a firewall rule delete: read-only. See the module docs, step 1.
pub fn validate(
    backend: &dyn FirewallBackend,
    deny: &DenyList,
    exec_op: &ExecOp,
    cand: &Candidate,
) -> FwValidated {
    let decided = FwValidated::Decided;
    let id = match op_id(exec_op) {
        Ok(id) => id,
        Err(r) => return decided(r),
    };
    if exec_op.target() != cand.target || !matches!(cand.target, Target::FirewallRule { .. }) {
        return decided(failed(
            FailCode::Internal,
            None,
            format!("the op for firewall rule {id} does not act on its plan item's target"),
        ));
    }
    let live = match backend.read(id) {
        Ok(Some(live)) => live,
        Ok(None) => {
            return decided(result(
                ItemOutcome::Vanished,
                format!("firewall rule {id} no longer exists"),
            ));
        }
        Err(e) => return decided(read_failed(id, &e)),
    };
    if let Some(r) = other_spelling(id, &live) {
        return decided(r);
    }
    let fp = live.fp();
    if let Err((reason, why)) = check_plan_fp_detailed(cand, &fp) {
        return decided(skipped(
            reason,
            format!("firewall rule {id}: {why}; it is not the rule the scan saw"),
        ));
    }
    if let Err((blocker, why)) = rule_blocker(deny, &live) {
        return decided(blocked(blocker, format!("{why}; left untouched")));
    }
    FwValidated::Validated {
        stamp: Stamp::Object {
            kind: ObjectKind::FirewallRule,
            sha256: fp.sha256.clone(),
        },
        facts: ItemFacts::Object {
            kind: ObjectKind::FirewallRule,
            sha256: fp.sha256,
            running: false,
        },
    }
}

// ---------------------------------------------------------------------------------------------------
// Prepare
// ---------------------------------------------------------------------------------------------------

/// What [`prepare`] decided.
#[derive(Debug)]
pub enum FwPrepared {
    /// Decided without changing anything: journal with `done_without_intent`.
    Decided(TypedResult),
    /// The definition is written and verified: journal [`FwRemoval::intent`], hit `act.before`, call
    /// [`act`] with the token.
    Ready(Box<FwRemoval>),
}

/// A firewall rule delete that passed prepare (or an intent a resumed run completes). Consumed by
/// [`act`].
#[derive(Debug, Clone)]
pub struct FwRemoval {
    intent: Intent,
    id: String,
    stamp: Stamp,
}

impl FwRemoval {
    /// The intent to journal: the op, [`Inverse::RecreateFirewallRule`] naming the definition, and
    /// [`ItemFacts::Object`] of the validated digest. It passes `Intent::is_consistent`.
    pub fn intent(&self) -> &Intent {
        &self.intent
    }

    /// The removal of a journalled intent, for a resumed run whose probe found it not done ([`probe`]
    /// `NotDone`): `None` when the intent is not a firewall rule delete with object facts of a rule.
    pub fn from_intent(intent: &Intent) -> Option<FwRemoval> {
        let id = op_id(&intent.exec_op).ok()?.to_owned();
        let stamp = Stamp::from_item_facts(&intent.pre)?;
        matches!(
            stamp,
            Stamp::Object {
                kind: ObjectKind::FirewallRule,
                ..
            }
        )
        .then(|| FwRemoval {
            intent: intent.clone(),
            id,
            stamp,
        })
    }
}

/// What [`prepare`] takes about the item, all from its journal `validated` record and the plan.
#[derive(Debug, Clone, Copy)]
pub struct FwPrepareArgs<'a> {
    /// The op.
    pub op: OpId,
    /// The plan item.
    pub item: &'a CandidateId,
    /// The op ([`ExecOp::DeleteFirewallRule`]).
    pub exec_op: &'a ExecOp,
    /// The stamp of the op's `validated` record.
    pub validated: &'a Stamp,
    /// The program roots of the journal header (`Header::program_roots`): a rule whose `App` is not
    /// inside one is not deleted, since its undo would refuse to create it again.
    pub program_roots: &'a [String],
}

/// [`prepare`] for op `op` as journalled: item, op and stamp come from the record `GateCtx::record`
/// accepted. An op without one is `Failed{Internal}` before any call. `program_roots` are the journal
/// header's.
pub fn prepare_recorded(
    backend: &dyn FirewallBackend,
    deny: &DenyList,
    ctx: &GateCtx,
    session: &SessionDir,
    op: OpId,
    program_roots: &[String],
) -> Result<FwPrepared, DefWriteError> {
    let (Some((exec_op, record)), Some(stamp)) = (ctx.journalled(op), ctx.stamp(op)) else {
        return Ok(FwPrepared::Decided(failed(
            FailCode::Internal,
            None,
            format!("op {op} has no journalled validated record in this run; nothing done"),
        )));
    };
    prepare(
        backend,
        deny,
        session,
        &FwPrepareArgs {
            op,
            item: &record.item,
            exec_op,
            validated: stamp,
            program_roots,
        },
    )
}

/// The digest of a [`Stamp::Object`] of a firewall rule.
fn rule_stamp(stamp: &Stamp) -> Option<&str> {
    match stamp {
        Stamp::Object {
            kind: ObjectKind::FirewallRule,
            sha256,
        } => Some(sha256),
        _ => None,
    }
}

/// Writes the definition of a firewall rule delete from one read: see the module docs, step 2. Never
/// deletes anything. A definition that cannot be written as verified is the error (the item is then
/// `Skipped{NoVerifiedBackup}`, [`DefWriteError::outcome`], or the run aborts on a storage integrity
/// failure).
pub fn prepare(
    backend: &dyn FirewallBackend,
    deny: &DenyList,
    session: &SessionDir,
    args: &FwPrepareArgs<'_>,
) -> Result<FwPrepared, DefWriteError> {
    let decided = |r| Ok(FwPrepared::Decided(r));
    let id = match op_id(args.exec_op) {
        Ok(id) => id,
        Err(r) => return decided(r),
    };
    let Some(digest) = rule_stamp(args.validated) else {
        return decided(failed(
            FailCode::Internal,
            None,
            format!("firewall rule {id} was not validated as a firewall rule; nothing done"),
        ));
    };
    // The one read the definition is written from.
    let live = match backend.read(id) {
        Ok(Some(live)) => live,
        Ok(None) => {
            return decided(result(
                ItemOutcome::Vanished,
                format!("firewall rule {id} no longer exists"),
            ));
        }
        Err(e) => return decided(read_failed(id, &e)),
    };
    if let Some(r) = other_spelling(id, &live) {
        return decided(r);
    }
    if let Err((reason, why)) = check_object_stamp_detailed(args.validated, Some(&live.fp())) {
        return decided(skipped(
            reason,
            format!("firewall rule {id}: {why}; left untouched"),
        ));
    }
    let fields = match rule_blocker(deny, &live) {
        Ok(fields) => fields,
        Err((blocker, why)) => return decided(blocked(blocker, format!("{why}; left untouched"))),
    };
    if gate::no_program_roots(args.program_roots) {
        return decided(no_roots(id));
    }
    if let Some(program) = program_refusal(&fields, deny.env(), args.program_roots) {
        return decided(blocked(
            Blocker::CannotBackUp,
            format!(
                "firewall rule {id} opens the firewall for {program}, which is not inside a root \
                 recorded for the run; undo would never create it again, so it is left untouched"
            ),
        ));
    }
    let def = FwDef {
        schema: FWDEF_SCHEMA.to_owned(),
        id: live.id.clone(),
        identity_sha256: digest.to_owned(),
        rule: live.rule,
        fields: fields.fields,
    };
    let definition = write_def(session, args.op, &def)?;
    let intent = Intent {
        op: args.op,
        item: args.item.clone(),
        exec_op: args.exec_op.clone(),
        inverse: Inverse::RecreateFirewallRule { definition },
        definition: None,
        pre: ItemFacts::Object {
            kind: ObjectKind::FirewallRule,
            sha256: digest.to_owned(),
            running: false,
        },
    };
    Ok(FwPrepared::Ready(Box::new(FwRemoval {
        intent,
        id: id.to_owned(),
        stamp: args.validated.clone(),
    })))
}

// ---------------------------------------------------------------------------------------------------
// Act, complete, probe
// ---------------------------------------------------------------------------------------------------

/// Whether the definition `intent` names is readable, hash-checked, and holds exactly the rule `live`:
/// its id, its raw string, the parse of that string as its fields.
fn check_definition(
    session: &SessionDir,
    intent: &Intent,
    id: &str,
    live: &FirewallIdentity,
) -> Result<(), String> {
    let Inverse::RecreateFirewallRule { definition } = &intent.inverse else {
        return Err("the intent is not a firewall rule delete".to_owned());
    };
    let def: FwDef = read_def_detailed(session, definition)
        .map_err(|e| format!("its definition cannot be used: {}", e.detail))?;
    let fields_match = parse_firewall_rule(&def.rule).is_ok_and(|f| f.fields == def.fields);
    if def.id != id || def.rule != live.rule || !fields_match {
        return Err("the definition is not the rule as it is now".to_owned());
    }
    Ok(())
}

/// Deletes the rule of `removal`, whose intent `token` proves durable: see the module docs, step 4.
/// `program_roots` are the journal header's. A token of another op is `Failed{Internal}` and nothing is
/// called.
pub fn act(
    backend: &dyn FirewallBackend,
    deny: &DenyList,
    session: &SessionDir,
    removal: Box<FwRemoval>,
    token: &IntentToken,
    program_roots: &[String],
) -> TypedResult {
    let FwRemoval { intent, id, stamp } = *removal;
    if token.op() != intent.op || token.item() != &intent.item {
        return failed(
            FailCode::Internal,
            None,
            format!(
                "the intent token is for op {}, not op {}; firewall rule {id} left untouched",
                token.op(),
                intent.op
            ),
        );
    }
    // The act-time gate: everything read again now.
    let live = match backend.read(&id) {
        Ok(Some(live)) => live,
        Ok(None) => {
            return result(
                ItemOutcome::Vanished,
                format!("firewall rule {id} was deleted before Purge deleted it"),
            );
        }
        Err(e) => return read_failed(&id, &e),
    };
    if let Some(r) = other_spelling(&id, &live) {
        return r;
    }
    if let Err((reason, why)) = check_object_stamp_detailed(&stamp, Some(&live.fp())) {
        return skipped(reason, format!("firewall rule {id}: {why}; left untouched"));
    }
    match rule_blocker(deny, &live) {
        Err((blocker, why)) => return blocked(blocker, format!("{why}; left untouched")),
        Ok(fields) => {
            if gate::no_program_roots(program_roots) {
                return no_roots(&id);
            }
            if let Some(program) = program_refusal(&fields, deny.env(), program_roots) {
                return blocked(
                    Blocker::CannotBackUp,
                    format!(
                        "firewall rule {id} opens the firewall for {program}, which is not inside a \
                         root recorded for the run; left untouched"
                    ),
                );
            }
        }
    }
    // The backup the intent names must still be there and be this rule's (a resumed run acts long
    // after prepare wrote it).
    if let Err(why) = check_definition(session, &intent, &id, &live) {
        return skipped(
            SkipReason::NoVerifiedBackup,
            format!("firewall rule {id}: {why}; left untouched"),
        );
    }

    let mut note = String::new();
    match backend.delete_by_instance_id(&id) {
        Ok(1) => {}
        Ok(0) => {
            return match backend.read(&id) {
                Ok(None) => result(
                    ItemOutcome::Vanished,
                    format!("firewall rule {id} was deleted before Purge deleted it"),
                ),
                Ok(Some(_)) => failed(
                    FailCode::ObjectApi,
                    None,
                    format!(
                        "WMI found no firewall rule with id {id}, but its registry value is still \
                         there; left untouched"
                    ),
                ),
                Err(e) => failed(
                    FailCode::VerifyFailed,
                    e.os_error,
                    format!(
                        "WMI found no firewall rule with id {id}, and whether it is still there \
                         cannot be read: {}",
                        e.detail
                    ),
                ),
            };
        }
        Ok(n) => {
            // The wrapper never reports more than one. Whatever happened, a rule that is gone must
            // stay undoable: `VerifyFailed` (undo treats it as changed), never "nothing changed".
            let _ = backend.flush_system();
            return match backend.read(&id) {
                Ok(Some(_)) => failed(
                    FailCode::Internal,
                    None,
                    format!(
                        "the delete of firewall rule {id} reported {n} rules; it is still there"
                    ),
                ),
                _ => failed(
                    FailCode::VerifyFailed,
                    None,
                    format!(
                        "the delete of firewall rule {id} reported {n} rules deleted, which cannot \
                         happen; the rule is gone"
                    ),
                ),
            };
        }
        Err(e) => {
            // A failed call may still have deleted the rule: only a fresh read tells.
            match read_settled(backend, &id, false) {
                Ok(Some(_)) => {
                    let code = if e.kind == ObjErrKind::AccessDenied {
                        FailCode::AccessDenied
                    } else {
                        FailCode::ObjectApi
                    };
                    return failed(
                        code,
                        e.os_error,
                        format!("firewall rule {id}: {}; left untouched", e.detail),
                    );
                }
                Ok(None) => {
                    note = format!(
                        "the delete call failed ({}), but the rule is gone",
                        e.detail
                    );
                }
                Err(read) => {
                    return failed(
                        FailCode::VerifyFailed,
                        e.os_error,
                        format!(
                            "the delete of firewall rule {id} failed ({}) and whether it is still \
                             there cannot be read: {}",
                            e.detail, read.detail
                        ),
                    );
                }
            }
        }
    }
    hit(fault::OBJDELETE_AFTER);
    if let Err(e) = backend.flush_system() {
        return failed(
            FailCode::VerifyFailed,
            e.os_error,
            format!(
                "firewall rule {id} was deleted, but the SYSTEM hive could not be flushed ({}); \
                 whether the delete survives a restart is not known",
                e.detail
            ),
        );
    }
    hit(fault::ACT_AFTER);
    let mut verdict = complete(backend, &id);
    if !note.is_empty() && verdict.outcome == ItemOutcome::Done {
        verdict.detail = note;
    }
    verdict
}

/// The verdict on a delete of `id` from a fresh read of its registry value (repeated while the value
/// is still there, see [`SETTLE_TRIES`]): absent is `Done`, present is `Failed{VerifyFailed}`, a failed
/// read is `Failed{VerifyFailed}` too.
pub fn complete(backend: &dyn FirewallBackend, id: &str) -> TypedResult {
    match read_settled(backend, id, false) {
        Ok(None) => result(ItemOutcome::Done, ""),
        Ok(Some(_)) => failed(
            FailCode::VerifyFailed,
            None,
            format!("firewall rule {id} is still there after its delete"),
        ),
        Err(e) => failed(
            FailCode::VerifyFailed,
            e.os_error,
            format!(
                "whether firewall rule {id} is gone cannot be read: {}",
                e.detail
            ),
        ),
    }
}

/// What became of the delete of `intent`, an intent without its `done` (recovery). Changes nothing.
pub fn probe(backend: &dyn FirewallBackend, intent: &Intent) -> Probe {
    let attention = |detail: String| Probe::Attention { detail };
    let Ok(id) = op_id(&intent.exec_op) else {
        return attention("the intent is not a firewall rule delete".to_owned());
    };
    let ItemFacts::Object {
        kind: ObjectKind::FirewallRule,
        sha256,
        ..
    } = &intent.pre
    else {
        return attention(format!(
            "the intent of firewall rule {id} holds no firewall rule facts"
        ));
    };
    match backend.read(id) {
        Ok(None) => Probe::Done(ItemOutcome::Done),
        Ok(Some(live)) if live.fp().sha256 == *sha256 => Probe::NotDone,
        Ok(Some(_)) => attention(format!(
            "firewall rule {id} exists and is not the one the intent recorded"
        )),
        Err(e) => attention(format!("firewall rule {id} cannot be read: {}", e.detail)),
    }
}

// ---------------------------------------------------------------------------------------------------
// Undo
// ---------------------------------------------------------------------------------------------------

/// How the undo of a firewall rule delete ends, as the journal takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FwUndoResult {
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

impl FwUndoResult {
    fn done(outcome: UndoOutcome, detail: impl Into<String>) -> FwUndoResult {
        FwUndoResult::Done {
            outcome,
            detail: detail.into(),
        }
    }

    fn conflict(conflict: UndoConflict, detail: impl Into<String>) -> FwUndoResult {
        FwUndoResult::Conflict {
            conflict,
            detail: detail.into(),
        }
    }

    fn failed(code: FailCode, os_error: Option<u32>, detail: impl Into<String>) -> FwUndoResult {
        let detail = detail.into();
        FwUndoResult::Done {
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
pub enum FwUndoPrepared {
    /// Decided without an inverse: journal it without an `undo_intent` (or with the open one).
    Decided(FwUndoResult),
    /// The inverse runs: write the `undo_intent` and call [`run_undo`] with its token.
    Ready(FwUndoJob),
}

/// A re-create that passed every check of [`prepare_undo`].
#[derive(Debug, Clone)]
pub struct FwUndoJob {
    op: OpId,
    id: String,
    backup: FirewallRuleFields,
    rule: String,
    /// The definition file, as a path for the report (it keeps the raw rule string).
    definition_file: String,
}

impl FwUndoJob {
    /// The id the rule is re-created under (always the backed-up rule's own id).
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// What [`prepare_undo`] takes about the op, all from its journal records.
#[derive(Debug, Clone, Copy)]
pub struct FwUndoArgs<'a> {
    /// The op's intent.
    pub intent: &'a Intent,
    /// The op's `done` outcome; `None` when the journal holds only its intent.
    pub done: Option<&'a ItemOutcome>,
    /// Whether the journal holds an `undo_intent` of this op (an earlier undo attempt that may have
    /// created the rule and stopped part way).
    pub own_attempt: bool,
    /// The roots recorded for the run (the journal header's): a backed-up `App` must lie inside one.
    pub program_roots: &'a [String],
}

/// Whether `live` is the backed-up rule: exactly the id, and the backup's fields (`same_rule`).
fn is_backup(id: &str, backup: &FirewallRuleFields, live: &FirewallIdentity) -> bool {
    live.id == id && parse_firewall_rule(&live.rule).is_ok_and(|fields| fields.same_rule(backup))
}

/// Decides the undo of a firewall rule delete before any `undo_intent`; see the module docs.
pub fn prepare_undo(
    backend: &dyn FirewallBackend,
    session: &SessionDir,
    env: &GuardEnv,
    args: &FwUndoArgs<'_>,
) -> FwUndoPrepared {
    let decided = FwUndoPrepared::Decided;
    let intent = args.intent;
    let internal = |why: String| decided(FwUndoResult::failed(FailCode::Internal, None, why));
    let id = match op_id(&intent.exec_op) {
        Ok(id) => id.to_owned(),
        Err(r) => return internal(r.detail),
    };
    let Inverse::RecreateFirewallRule { definition } = &intent.inverse else {
        return internal(format!(
            "the intent of firewall rule {id} names the inverse {}",
            intent.inverse.name()
        ));
    };
    let ItemFacts::Object {
        kind: ObjectKind::FirewallRule,
        sha256: pre,
        ..
    } = &intent.pre
    else {
        return internal(format!(
            "the intent of firewall rule {id} holds no firewall rule facts"
        ));
    };
    let unchanged = match args.done {
        Some(ItemOutcome::Failed { code, .. }) => *code != FailCode::VerifyFailed,
        Some(outcome) => !outcome.changed_system(),
        None => false,
    };
    if unchanged && !args.own_attempt {
        return decided(FwUndoResult::done(
            UndoOutcome::NothingToUndo,
            format!("the delete of firewall rule {id} changed nothing"),
        ));
    }

    // The definition, bound to this op and to its own raw string.
    let def: FwDef = match read_def_detailed(session, definition) {
        Ok(def) => def,
        Err(e) => return decided(FwUndoResult::conflict(e.conflict, e.detail)),
    };
    let tampered = |why: &str| {
        decided(FwUndoResult::conflict(
            UndoConflict::BackupTampered,
            format!("firewall rule {id}: {why}"),
        ))
    };
    if def.id != id || def.identity_sha256 != *pre {
        return tampered("the definition is not the one of this op");
    }
    let backup = match parse_firewall_rule(&def.rule) {
        Ok(backup) => backup,
        Err(_) => return tampered("the definition's rule string does not parse"),
    };
    if backup.fields != def.fields {
        return tampered("the definition's fields are not the ones of its rule string");
    }
    if package_bound(&backup) || resource_name(&backup) {
        return tampered("the definition is of a rule Purge never deletes");
    }
    if let Err(unmapped) = fw::map_rule(&def.fields) {
        return internal(format!(
            "firewall rule {id} cannot be re-created exactly ({}); nothing is created",
            unmapped.join("; ")
        ));
    }

    match backend.read(&id) {
        Err(e) => decided(FwUndoResult::failed(
            FailCode::ObjectApi,
            e.os_error,
            format!("firewall rule {id} cannot be read: {}", e.detail),
        )),
        Ok(Some(live)) if is_backup(&id, &backup, &live) => {
            // An earlier attempt may have created it and stopped before its flush.
            if args.own_attempt
                && let Err(e) = backend.flush_system()
            {
                return decided(FwUndoResult::failed(
                    FailCode::VerifyFailed,
                    e.os_error,
                    format!(
                        "firewall rule {id} is as backed up, but the SYSTEM hive could not be \
                         flushed: {}",
                        e.detail
                    ),
                ));
            }
            decided(FwUndoResult::done(
                UndoOutcome::AlreadyRestored,
                format!("firewall rule {id} is already as backed up"),
            ))
        }
        Ok(Some(_)) => decided(FwUndoResult::conflict(
            UndoConflict::ObjectExists,
            format!(
                "a firewall rule with id {id} exists and is not the one backed up; nothing is changed"
            ),
        )),
        Ok(None) => {
            // The second lock: a program the rule opens the firewall for must be one of the run's
            // (the check prepare and the act made).
            if let Some(text) = program_refusal(&backup, env, args.program_roots) {
                return decided(FwUndoResult::conflict(
                    UndoConflict::ProgramOutsideRoot,
                    format!(
                        "firewall rule {id}: its program {text} is not inside a root recorded for \
                         the run; nothing is created"
                    ),
                ));
            }
            FwUndoPrepared::Ready(FwUndoJob {
                op: intent.op,
                id,
                backup,
                rule: def.rule,
                definition_file: session.path().join(&definition.path).display().to_string(),
            })
        }
    }
}

/// Runs the re-create of `job` under the token of its flushed `undo_intent`; see the module docs.
pub fn run_undo(backend: &dyn FirewallBackend, job: FwUndoJob, token: &UndoToken) -> FwUndoResult {
    let FwUndoJob {
        op,
        id,
        backup,
        rule,
        definition_file,
    } = job;
    if token.op() != op {
        return FwUndoResult::failed(
            FailCode::Internal,
            None,
            format!(
                "the undo token is for op {}, not op {op}; nothing created",
                token.op()
            ),
        );
    }
    if let Err(e) = backend.create_with_instance_id(&id, &backup.fields) {
        match e.kind {
            ObjErrKind::Exists => {
                return FwUndoResult::conflict(
                    UndoConflict::ObjectExists,
                    format!(
                        "a firewall rule with id {id} was created meanwhile; nothing is changed"
                    ),
                );
            }
            ObjErrKind::Refused => {
                return FwUndoResult::failed(
                    FailCode::Internal,
                    None,
                    format!("firewall rule {id}: {}; nothing created", e.detail),
                );
            }
            _ => {
                // A failed call may still have left a rule: only a fresh read tells, and a rule that
                // is there is checked like a created one.
                match read_settled(backend, &id, true) {
                    Ok(None) => {
                        let code = if e.kind == ObjErrKind::AccessDenied {
                            FailCode::AccessDenied
                        } else {
                            FailCode::ObjectApi
                        };
                        return FwUndoResult::failed(
                            code,
                            e.os_error,
                            format!("firewall rule {id}: {}; nothing created", e.detail),
                        );
                    }
                    Ok(Some(_)) => {}
                    Err(read) => {
                        return FwUndoResult::failed(
                            FailCode::VerifyFailed,
                            e.os_error,
                            format!(
                                "the create of firewall rule {id} failed ({}) and whether a rule \
                                 was left cannot be read: {}",
                                e.detail, read.detail
                            ),
                        );
                    }
                }
            }
        }
    }
    hit(fault::FWRESTORE_MID);
    if let Err(e) = backend.flush_system() {
        return FwUndoResult::failed(
            FailCode::VerifyFailed,
            e.os_error,
            format!(
                "firewall rule {id} was created again, but the SYSTEM hive could not be flushed: {}",
                e.detail
            ),
        );
    }
    hit(fault::UNDO_ACT_AFTER);

    // The exact-restore check.
    let live = match read_settled(backend, &id, true) {
        Ok(Some(live)) => live,
        Ok(None) => {
            return FwUndoResult::failed(
                FailCode::VerifyFailed,
                None,
                format!("firewall rule {id} is not there after its re-create"),
            );
        }
        Err(e) => {
            return FwUndoResult::failed(
                FailCode::VerifyFailed,
                e.os_error,
                format!(
                    "whether firewall rule {id} came back as backed up cannot be read: {}",
                    e.detail
                ),
            );
        }
    };
    if is_backup(&id, &backup, &live) {
        let detail = if live.rule == rule {
            String::new()
        } else {
            format!(
                "firewall rule {id} came back with the same fields; its stored string differs in \
                 version or field order"
            )
        };
        return FwUndoResult::done(UndoOutcome::Restored, detail);
    }
    // Not the backup: the half-made rule goes again, by its id only.
    let removal = match backend.delete_by_instance_id(&id) {
        Ok(1) => match backend.flush_system() {
            Ok(()) => "it was deleted again".to_owned(),
            Err(e) => format!(
                "it was deleted again, but the SYSTEM hive could not be flushed: {}",
                e.detail
            ),
        },
        Ok(n) => format!("deleting it again removed {n} rules"),
        Err(e) => format!("it could not be deleted again: {}", e.detail),
    };
    FwUndoResult::conflict(
        UndoConflict::ValueDiffers,
        format!(
            "firewall rule {id} was created again, but it is not the backed-up rule (stored as \
             {:?}); {removal}; the backed-up rule string is kept in {definition_file} (member \
             \"rule\")",
            live.rule
        ),
    )
}

// ---------------------------------------------------------------------------------------------------
// The live backend
// ---------------------------------------------------------------------------------------------------

/// The real backend: the rule's value under `ControlSet00N\...\FirewallRules` (opened component-wise
/// without following links, read only), delete and create through `purge_win::firewall` (WMI,
/// `PersistentStore` only), the `SYSTEM` flush through `durable`.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveFirewall;

impl LiveFirewall {
    /// `SYSTEM\ControlSet00N\...\FirewallRules` of the current control set.
    fn rules_path() -> Result<String, ObjErr> {
        let set = purge_win::reg::current_control_set().map_err(|e| {
            ObjErr::new(
                ObjErrKind::Other,
                Some(e.code()),
                format!("read the current control set: {e}"),
            )
        })?;
        if set.contains(['\\', '/']) || set.is_empty() {
            return Err(ObjErr::new(
                ObjErrKind::Other,
                None,
                format!("the current control set {set:?} is not a key name"),
            ));
        }
        Ok(format!(r"SYSTEM\{set}\{RULES_BELOW_CONTROL_SET}"))
    }
}

/// The raw rule string of a value, exactly: `REG_SZ` or `REG_EXPAND_SZ` (the scanner's types), an even
/// byte count, valid UTF-16 up to the first NUL and nothing but NULs after it. Anything else could
/// stand for more than one string and is refused.
pub fn exact_rule_string(ty: u32, data: &[u8]) -> Result<String, String> {
    if ty != REG_SZ && ty != REG_EXPAND_SZ {
        return Err(format!("its value has type {ty}, not a string"));
    }
    if data.len() % 2 != 0 {
        return Err("its value has an odd number of bytes".to_owned());
    }
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    if units[end..].iter().any(|&u| u != 0) {
        return Err("its value holds text after the terminating NUL".to_owned());
    }
    String::from_utf16(&units[..end]).map_err(|_| "its value is not valid UTF-16".to_owned())
}

impl FirewallBackend for LiveFirewall {
    fn read(&self, id: &str) -> Result<Option<FirewallIdentity>, ObjErr> {
        if let Err(e) = fw::check_instance_id(id) {
            return Err(ObjErr::new(
                ObjErrKind::Refused,
                None,
                format!("{id:?} is not a firewall rule id: {e}"),
            ));
        }
        let key = match WKey::open(
            RegRoot::Hklm,
            &Self::rules_path()?,
            RegView::K64,
            KeyAccess::READ,
        ) {
            Ok(key) => key,
            Err(e) if e.is_not_found() => return Ok(None),
            Err(e) => {
                return Err(ObjErr::new(
                    ObjErrKind::Other,
                    Some(e.code()),
                    format!("open the firewall rules key: {e}"),
                ));
            }
        };
        if key.is_link().map_err(|e| {
            ObjErr::new(
                ObjErrKind::Other,
                Some(e.code()),
                format!("read the firewall rules key: {e}"),
            )
        })? {
            return Err(ObjErr::new(
                ObjErrKind::Refused,
                None,
                "the firewall rules key is a registry link",
            ));
        }
        // Every value, so the stored spelling of the name is known (a lookup by name returns the
        // spelling asked for).
        let values = key.values().map_err(|e| {
            ObjErr::new(
                ObjErrKind::Other,
                Some(e.code()),
                format!("read the firewall rules: {e}"),
            )
        })?;
        let mut found = values.into_iter().filter(|v| eq_ci(&v.name, id));
        let Some(value) = found.next() else {
            return Ok(None);
        };
        if found.next().is_some() {
            return Err(ObjErr::new(
                ObjErrKind::Refused,
                None,
                format!("more than one firewall rule value is named {id}"),
            ));
        }
        let rule = exact_rule_string(value.ty, &value.data).map_err(|why| {
            ObjErr::new(
                ObjErrKind::Refused,
                None,
                format!("firewall rule {id}: {why}"),
            )
        })?;
        Ok(Some(FirewallIdentity {
            id: value.name,
            rule,
        }))
    }

    fn delete_by_instance_id(&self, id: &str) -> Result<u32, ObjErr> {
        fw::delete_by_instance_id(id).map_err(|e| win_err("delete the firewall rule", &e))
    }

    fn create_with_instance_id(&self, id: &str, fields: &[(String, String)]) -> Result<(), ObjErr> {
        fw::create_with_instance_id(id, fields).map_err(|e| win_err("create the firewall rule", &e))
    }

    fn pause(&self) {
        std::thread::sleep(std::time::Duration::from_millis(SETTLE_PAUSE_MS));
    }

    fn flush_system(&self) -> Result<(), ObjErr> {
        durable::flush_op_hive(&ExecOp::DeleteFirewallRule {
            id: "flush".to_owned(),
        })
        .map_err(|e| ObjErr::new(ObjErrKind::Other, Some(e.error.code()), e.to_string()))
    }
}

// ---------------------------------------------------------------------------------------------------
// The fake backend (tests and test-support)
// ---------------------------------------------------------------------------------------------------

/// An in-memory [`FirewallBackend`] for tests: rules as (stored id, raw string) pairs, a call log,
/// failure injection and one-shot hooks.
#[cfg(any(test, feature = "test-support"))]
pub mod fake {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use super::*;

    /// The fake's state.
    #[derive(Debug)]
    pub struct FakeWorld {
        /// The rules, in order: (stored id, raw string). Ids compare without regard to ASCII case, as
        /// both the registry and WQL do.
        pub rules: Vec<(String, String)>,
        /// Every call, in order: `read X`, `delete X`, `create X`, `flush`.
        pub log: Vec<String>,
        /// The next call of each named kind (`read`, `delete`, `create`, `flush`) fails with this
        /// error (after the hooks of a delete or create ran, when [`FakeWorld::fail_after_act`]).
        pub fail_next: BTreeMap<&'static str, ObjErr>,
        /// A failing delete or create (from `fail_next`) still does its work first.
        pub fail_after_act: bool,
        /// The delete reports this count instead of its real one and changes nothing.
        pub delete_reports: Option<u32>,
        /// The version prefix a create writes.
        pub create_version: String,
        /// Fields a create appends to what it was given (a provider that adds something).
        pub create_extra: Vec<(String, String)>,
        /// A create stores its id in this spelling instead.
        pub create_id_as: Option<String>,
    }

    impl Default for FakeWorld {
        fn default() -> Self {
            FakeWorld {
                rules: Vec::new(),
                log: Vec::new(),
                fail_next: BTreeMap::new(),
                fail_after_act: false,
                delete_reports: None,
                create_version: "v2.33".to_owned(),
                create_extra: Vec::new(),
                create_id_as: None,
            }
        }
    }

    type Hook = Box<dyn FnOnce(&mut FakeWorld)>;

    /// The fake backend.
    #[derive(Default)]
    pub struct FakeFirewall {
        world: RefCell<FakeWorld>,
        hooks: RefCell<Vec<(&'static str, Hook)>>,
    }

    impl std::fmt::Debug for FakeFirewall {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FakeFirewall")
                .field("world", &self.world)
                .finish_non_exhaustive()
        }
    }

    fn same_id(a: &str, b: &str) -> bool {
        a.eq_ignore_ascii_case(b)
    }

    impl FakeFirewall {
        /// A fake holding `rules` as (id, raw string).
        pub fn with<I, S, T>(rules: I) -> FakeFirewall
        where
            I: IntoIterator<Item = (S, T)>,
            S: Into<String>,
            T: Into<String>,
        {
            let fake = FakeFirewall::default();
            fake.world.borrow_mut().rules = rules
                .into_iter()
                .map(|(id, rule)| (id.into(), rule.into()))
                .collect();
            fake
        }

        /// The state, to look at or change.
        pub fn world(&self) -> std::cell::RefMut<'_, FakeWorld> {
            self.world.borrow_mut()
        }

        /// The raw string of the rule whose id is `id` (ignoring case).
        pub fn rule(&self, id: &str) -> Option<String> {
            self.world
                .borrow()
                .rules
                .iter()
                .find(|(i, _)| same_id(i, id))
                .map(|(_, r)| r.clone())
        }

        /// Every rule, in order.
        pub fn rules(&self) -> Vec<(String, String)> {
            self.world.borrow().rules.clone()
        }

        /// Sets the raw string of rule `id` (adding it when absent).
        pub fn set_rule(&self, id: &str, rule: &str) {
            let mut world = self.world.borrow_mut();
            match world.rules.iter_mut().find(|(i, _)| same_id(i, id)) {
                Some(entry) => entry.1 = rule.to_owned(),
                None => world.rules.push((id.to_owned(), rule.to_owned())),
            }
        }

        /// Removes rule `id`.
        pub fn remove_rule(&self, id: &str) {
            self.world
                .borrow_mut()
                .rules
                .retain(|(i, _)| !same_id(i, id));
        }

        /// The call log so far.
        pub fn log(&self) -> Vec<String> {
            self.world.borrow().log.clone()
        }

        /// Runs `hook` on the state once, right after the next call of kind `call`.
        pub fn after(&self, call: &'static str, hook: impl FnOnce(&mut FakeWorld) + 'static) {
            self.hooks.borrow_mut().push((call, Box::new(hook)));
        }

        /// Logs a call; the error to fail it with, when one is set.
        fn begin(&self, call: &'static str, line: String) -> Option<ObjErr> {
            let mut world = self.world.borrow_mut();
            world.log.push(line);
            world.fail_next.remove(call)
        }

        fn done<T>(&self, call: &'static str, value: T) -> T {
            let due: Vec<Hook> = {
                let mut hooks = self.hooks.borrow_mut();
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
            for hook in due {
                hook(&mut self.world.borrow_mut());
            }
            value
        }
    }

    impl FirewallBackend for FakeFirewall {
        fn read(&self, id: &str) -> Result<Option<FirewallIdentity>, ObjErr> {
            if let Some(e) = self.begin("read", format!("read {id}")) {
                return Err(e);
            }
            let found = self
                .world
                .borrow()
                .rules
                .iter()
                .find(|(i, _)| same_id(i, id))
                .map(|(i, r)| FirewallIdentity {
                    id: i.clone(),
                    rule: r.clone(),
                });
            Ok(self.done("read", found))
        }

        fn delete_by_instance_id(&self, id: &str) -> Result<u32, ObjErr> {
            let fail = match self.begin("delete", format!("delete {id}")) {
                Some(e) if !self.world.borrow().fail_after_act => return Err(e),
                fail => fail,
            };
            let outcome = {
                let mut world = self.world.borrow_mut();
                if let Some(n) = world.delete_reports {
                    Ok(n)
                } else {
                    let matched: Vec<usize> = world
                        .rules
                        .iter()
                        .enumerate()
                        .filter(|(_, (i, _))| same_id(i, id))
                        .map(|(n, _)| n)
                        .collect();
                    match matched.as_slice() {
                        [] => Ok(0),
                        [one] if world.rules[*one].0 == id => {
                            world.rules.remove(*one);
                            Ok(1)
                        }
                        [one] => Err(win_err(
                            "delete the firewall rule",
                            &WinError::IdMismatch {
                                found: world.rules[*one].0.clone(),
                            },
                        )),
                        more => Err(win_err(
                            "delete the firewall rule",
                            &WinError::Ambiguous {
                                matched: more.len() as u32,
                            },
                        )),
                    }
                }
            };
            let outcome = self.done("delete", outcome);
            match fail {
                Some(e) => Err(e),
                None => outcome,
            }
        }

        fn create_with_instance_id(
            &self,
            id: &str,
            fields: &[(String, String)],
        ) -> Result<(), ObjErr> {
            let fail = match self.begin("create", format!("create {id}")) {
                Some(e) if !self.world.borrow().fail_after_act => return Err(e),
                fail => fail,
            };
            let outcome = (|| {
                fw::check_instance_id(id)
                    .map_err(|e| win_err("create the firewall rule", &WinError::InvalidId(e)))?;
                fw::map_rule(fields)
                    .map_err(|e| win_err("create the firewall rule", &WinError::Unmapped(e)))?;
                let mut world = self.world.borrow_mut();
                if world.rules.iter().any(|(i, _)| same_id(i, id)) {
                    return Err(win_err("create the firewall rule", &WinError::ObjectExists));
                }
                let mut rule = world.create_version.clone();
                for (k, v) in fields.iter().chain(world.create_extra.iter()) {
                    rule.push('|');
                    rule.push_str(k);
                    rule.push('=');
                    rule.push_str(v);
                }
                rule.push('|');
                let stored = world.create_id_as.clone().unwrap_or_else(|| id.to_owned());
                world.rules.push((stored, rule));
                Ok(())
            })();
            let outcome = self.done("create", outcome);
            match fail {
                Some(e) => Err(e),
                None => outcome,
            }
        }

        fn flush_system(&self) -> Result<(), ObjErr> {
            if let Some(e) = self.begin("flush", "flush".to_owned()) {
                return Err(e);
            }
            self.done("flush", ());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(raw: &str) -> FirewallRuleFields {
        parse_firewall_rule(raw).unwrap()
    }

    /// `purge_win::firewall::map_rule` and `purge_model::FirewallShape` tell the same inferred forms
    /// apart, so the one list in purge-model decides for what map_rule maps.
    #[test]
    fn map_rule_shapes_agree_with_the_model() {
        let base = "v2.33|Action=Allow|Active=TRUE|Dir=In|Name=X|";
        for extra in [
            "",
            "Edge=TRUE|",
            "Edge=TRUE|Defer=App|",
            "Defer=User|",
            "LSM=TRUE|LOM=TRUE|",
            "Protocol=1|",
            "Protocol=58|",
            "Protocol=6|LPort=80|LPort2_10=81-82|",
            "Protocol=17|RPort=53|RPort2_10=1-9|",
            "LA4=10.0.0.1|LA6=fe80::1|",
            "RA4=LocalSubnet|RA6=LocalSubnet|",
            "Profile=Domain|Profile=Private|",
            "Profile=Public|IFType=Lan|IFType=Wireless|",
            "Protocol=47|",
            r"App=C:\x\a.exe|Svc=S|",
        ] {
            let raw = format!("{base}{extra}");
            let f = fields(&raw);
            let win: Vec<&str> = fw::map_rule(&f.fields)
                .unwrap_or_else(|e| panic!("{raw}: {e:?}"))
                .shapes
                .iter()
                .map(|s| s.name())
                .collect();
            let model: Vec<&str> = FirewallShape::of(&f.fields)
                .iter()
                .map(|s| s.name())
                .collect();
            assert_eq!(win, model, "{raw}");
        }
        // ICMP entries: map_rule itself refuses them (the VM re-create failed), and the model still
        // names the shape as unproven, so the refusal does not hang on one list line (review R3b).
        for extra in ["Protocol=1|ICMP4=8:*|", "Protocol=58|ICMP6=128:*|"] {
            let raw = format!("{base}{extra}");
            let f = fields(&raw);
            assert!(fw::map_rule(&f.fields).is_err(), "{raw}");
            assert!(
                FirewallShape::unproven_in(&f.fields).contains(&FirewallShape::IcmpTypes),
                "{raw}"
            );
        }
    }

    #[test]
    fn exact_rule_string_refuses_what_is_not_one_string() {
        let sz = |s: &str| -> Vec<u8> {
            s.encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect()
        };
        assert_eq!(
            exact_rule_string(REG_SZ, &sz("v2.33|A=B|")).unwrap(),
            "v2.33|A=B|"
        );
        assert_eq!(exact_rule_string(REG_EXPAND_SZ, &sz("x")).unwrap(), "x");
        // No terminator is still one string.
        assert_eq!(exact_rule_string(REG_SZ, &sz("x")[..2]).unwrap(), "x");
        assert!(exact_rule_string(3, &sz("x")).is_err());
        assert!(exact_rule_string(REG_SZ, &[b'x', 0, 0]).is_err());
        let mut hidden = sz("v2.33|A=B|");
        hidden.extend(sz("C=D"));
        assert!(exact_rule_string(REG_SZ, &hidden).is_err());
        // A lone surrogate.
        assert!(exact_rule_string(REG_SZ, &[0x00, 0xD8, 0, 0]).is_err());
    }

    #[test]
    fn package_and_resource_facts() {
        assert!(package_bound(&fields(
            "v2.33|Action=Allow|PFN=Vendor.App_x|Name=X|"
        )));
        assert!(!package_bound(&fields(
            "v2.33|Action=Allow|LUAuth=O:LSD:(A;;CC;;;S-1-15-2-1)|Name=X|"
        )));
        assert!(package_bound(&fields(
            "v2.33|Action=Allow|LUOwn=S-1-5-21-1|Name=X|"
        )));
        assert!(package_bound(&fields(
            "v2.33|Action=Allow|Desc= s-1-15-2-9|Name=X|"
        )));
        assert!(!package_bound(&fields("v2.33|Action=Allow|Name=X|")));
        assert!(resource_name(&fields(
            "v2.33|Action=Allow|Name=@FirewallAPI.dll,-1|"
        )));
        assert!(resource_name(&fields(
            "v2.33|Action=Allow|Name=X|EmbedCtxt=@FirewallAPI.dll,-2|"
        )));
        assert!(!resource_name(&fields("v2.33|Action=Allow|Name=X @ Y|")));
    }

    #[test]
    fn rule_program_expands_the_machine_environment() {
        let env = GuardEnv::sample();
        assert_eq!(
            rule_program(&fields("v2.33|Name=X|"), &env),
            RuleProgram::None
        );
        assert_eq!(
            rule_program(&fields("v2.33|App=System|Name=X|"), &env),
            RuleProgram::None
        );
        let RuleProgram::File(file) = rule_program(
            &fields(r"v2.33|App=%ProgramFiles%\Vendor\app.exe|Name=X|"),
            &env,
        ) else {
            panic!("not a file");
        };
        assert!(gate::file_in_roots(
            &file,
            &[r"C:\Program Files\Vendor".to_owned()],
            &env,
            None
        ));
        assert!(!gate::file_in_roots(
            &file,
            &[r"C:\Program Files\Other".to_owned()],
            &env,
            None
        ));
        assert!(!gate::file_in_roots(
            &file,
            &[r"C:\".to_owned()],
            &env,
            None
        ));
        assert!(matches!(
            rule_program(&fields(r"v2.33|App=%USERPROFILE%\a.exe|Name=X|"), &env),
            RuleProgram::Unresolved(_)
        ));
        assert!(matches!(
            rule_program(&fields(r"v2.33|App=a.exe|Name=X|"), &env),
            RuleProgram::Unresolved(_)
        ));
    }
}
