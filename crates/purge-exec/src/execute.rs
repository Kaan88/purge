//! Execute orchestration: the per-item pipeline (M2-X-EXEC; ENGINE_PLAN.md §7).
//!
//! [`execute`] turns a confirmed plan into deletions by driving the modules of this crate. Four rules
//! shape it:
//!
//! - **The confirmation is bound to the plan.** [`plan_in::bind`] runs first and reads nothing from the
//!   system; a refusal comes before a session exists.
//! - **Journal before acting.** Every action takes the [`IntentToken`] that
//!   [`JournalWriter::intent`] hands out after the intent is flushed.
//! - **Nothing is acted on that the journal does not record.** The gate context is filled only with the
//!   `validated` records as they were written ([`GateCtx::record`]); the actions take an op id and
//!   read op, plan item, stamp and exemptions from that record.
//! - **One item's failure never harms another.** Every per-item problem is that item's journalled
//!   outcome. The run stops early only when the journal or a backup cannot be written or the store
//!   fails its integrity check; it then writes `aborted` and leaves the remaining items untouched.
//!
//! # The run
//!
//! | # | Step | Journal record | Fault point | When it fails |
//! |---|---|---|---|---|
//! | 1 | bind request (hashes, selection, order, confirm) | | | [`ExecError::Plan`], nothing touched |
//! | 2 | expose cloud placeholders to the process | | | [`ExecError::Gate`] |
//! | 3 | check the store; read the index; size cap over the plan's sizes | | | [`ExecError::Store`]; an unavailable index is a warning and the cap is then not checked |
//! | 4 | create the session directory | | | [`ExecError::Store`] |
//! | 5 | write the scan copy `plan.scan.json`, flushed with its directory | | | [`ExecError::ScanCopy`]; no journal exists, the session directory is removed |
//! | 6 | journal header, then the run's settings and its selected ids | `header`, `settings` (flushed) | `journal.header` | [`ExecError::Journal`]; no item was looked at. Before the header the session directory is removed ([`SessionDir::remove_unstarted`]) |
//! | 7 | validate every selected item, read-only; a path item whose candidate carries a scan-time identity (`item_fp`) must still be that object | one `validated` per item (an item that did not pass: `Refused` or `Absent` facts), flushed after the last | | abort `JournalWriteFailed` |
//! | 8 | prepare: restore point (per setting), Restart Manager query | | | never: warnings |
//! | 9 | every item in plan order ([`Run::run_item`]) | see below | see below | see "Aborts" |
//! | 10 | commit | `group_end` (`group.end`), `commit` | `commit.before` | abort `JournalWriteFailed` |
//! | 11 | index entry, then `report.json` | | `index.write` (in the store) | warnings in the report |
//!
//! # One item
//!
//! [`Run::run_item`] is the whole contract for an item, in this order:
//!
//! 1. The journal already holds a `done` for the op: nothing to do. It holds an intent without a done:
//!    nothing is done here (recovery probes such an op).
//! 2. **Route.** A service, scheduled task or firewall rule without its scan-time digest
//!    (`Candidate::object_fp`) is `done` as `Skipped{ChangedSinceScan}` ("no object fingerprint")
//!    before any backup. An op without a recorded `validated` record (it was gone, refused or
//!    unreadable at validation) is `done` with what a fresh read-only look says and is never acted on.
//! 3. **Gate and backup** (`prepare_fs`, `prepare_reg`, `prepare_remove_package`, and for an object
//!    `act_service::prepare_recorded`, `act_task::prepare_task`, `act_firewall::prepare_recorded`): the
//!    act-time gate on the handle the action will use, the quarantine directory or the verified backup
//!    or definition file (`backup.written`, `backup.verified`). A decision here is a `done` without an
//!    intent.
//! 4. **Intent** (`intent`, flushed; `intent.flushed`), which yields the token. An object op's intent
//!    marks its hive (`SYSTEM` for a service or firewall rule, `SOFTWARE` for a task) for the flush
//!    before the next `group_end`, `commit` or `aborted`.
//! 5. **Act** (`act.before`, then `act_fs` / `act_reg` / `remove_package` / the object's `act`, which
//!    hit `act.after`, `regdelete.mid` or `objdelete.after`, flush the object's hive, and verify).
//! 6. **Done** (`done.before`, `done` with the token; `group_end` after 64 intents).
//!
//! Registry items of one run may depend on each other (a key deleted if empty after the values and
//! subkeys inside it, a key tree after separate items inside it). The gate context is told the run's
//! ops before the validate pass (`GateCtx::set_run_ops`) and every completed registry op right after
//! its `done` (`GateCtx::note_done`); a resumed run notes the journal's completed ops when it is made,
//! and again after recovery wrote through [`Run::journal_mut`] (`GateCtx::note_journal`). The act-time
//! gate then accepts exactly the changes those own ops explain; see `crate::gate`.
//!
//! # System objects
//!
//! A service, scheduled task or firewall rule (`ExecOp::DeleteService`, `DeleteTask`,
//! `DeleteFirewallRule`) runs through its action module over the backends of [`ExecEnv::objects`]: the
//! validate pass reads it (its digest against the candidate's `object_fp`), the item writes its
//! definition, journals the intent, re-reads and gates it at act time and deletes it. Only the roots of
//! the journal header (`Header::program_roots`, from [`ExecSettings::program_roots`]) count as the
//! app's: a service or task whose program, or a rule whose `App`, is outside them is not deleted, and
//! with no roots no object is deleted at all. A root the guard refuses as an app's root
//! (`gate::root_refusal`) is dropped with a warning before the header is written (review R3b S3). A
//! process without object backends (not elevated) cannot run a plan that selects one: the run is
//! refused before its session exists ([`ExecError::NeedsElevation`]). Nothing is stopped or ended: a
//! running service or task is `Skipped{GateBlocked{InUse}}`. A service another handle keeps open is
//! `PendingDelete`: it goes at the next restart at the latest.
//!
//! A file that stays locked goes to the ladder ([`crate::locked`]): Restart Manager names the holders
//! (nothing is closed), then the item is held for the next run (`HeldRetry`) or a boot-time move into
//! quarantine is registered (`PendingReboot`; `bootmove.registered` before its flushed `done`). A
//! boot-time delete is never chosen. A package is removed only when the request acknowledged
//! irreversible removals.
//!
//! # Aborts
//!
//! | Cause | `aborted` reason |
//! |---|---|
//! | a journal record cannot be written or flushed | `JournalWriteFailed` (the record is retried once through a fresh handle, because a failed writer takes no more records) |
//! | a backup or definition file cannot be written or does not read back; an op directory cannot be made | `BackupWriteFailed` |
//! | a store directory fails its integrity check | `StorageIntegrity` |
//!
//! A backup that cannot be *encoded* (too large) is not an abort: that item is `Skipped{NoVerifiedBackup}`.
//!
//! # What is not here
//!
//! No implicit pruning: only the `RemoveDirIfEmpty` items the plan carries are run. No shell change
//! notification is sent: `purge-win` offers none. Undo and crash recovery are the next package; it
//! resumes a run through [`Run::resume`] (which reads the run's settings from the journal and enforces
//! the size cap again) and [`Run::run_item`].

// The store's and the journal's errors carry paths and are over clippy's size threshold wherever
// they are returned in this crate; the run's own errors wrap them unboxed like every other module.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use purge_guard::deny::{DenyList, Exemptions};
use purge_model::Blocker;
use purge_model::exec::journal::{
    AbortReason, Header, Intent, ItemFacts, JournalSchema, Validated, VolumeRecord,
};
use purge_model::exec::op::{ExecOp, FailCode, ItemOutcome, OpId, SkipReason};
use purge_model::exec::session::{ExecReport, SessionId, SessionIndex, SessionState, VolumeUsage};
use purge_model::{Candidate, CandidateId, ObjectKind, Reversibility};
use purge_plan::emit::ScanDoc;

use crate::act_firewall::{self, FirewallBackend, FwPrepared, FwRemoval, FwValidated};
use crate::act_fs::{self, FsActed, FsCompletion, FsPrepared, Retry, act_fs, prepare_fs};
use crate::act_reg::{self, BackupWriteError, RegPrepared, act_reg, prepare_reg};
use crate::act_service::{self, ServiceBackend, SvcPrepared, SvcRemoval, SvcValidated};
use crate::act_task::{self, TaskBackend, TaskPrepared, TaskValidate};
use crate::act_typed::{
    self, DefinitionError, IrreversibleAck, PackageBackend, TypedResult,
    prepare_remove_package_recorded, remove_package,
};
use crate::fault;
use crate::gate::{self, GateCtx, GateItem, GateOutcome, GateSetupError};
use crate::journal::{IntentToken, JournalError, JournalState, JournalWriter, OpState, OpStatus};
use crate::locked::{
    self, ConsentAnswer, ConsentCallback, DenyAll, Ladder, LockPrepared, LockResult,
    PendingRenames, StoreLadder,
};
use crate::plan_in::{self, BoundItem, BoundPlan, ExecRequest, ExecSettings, PlanRefusal};
use crate::prepare::{
    self, LockerQuery, PrepareRequest, Prepared, RESTORE_POINT_FINISH_WAIT, RESTORE_POINT_WAIT,
    RestorePointBackend, RiskItem,
};
use crate::recover::{Probe, SettledOp};
use crate::report::{self, DataVolume, RunNotes};
use crate::storage::{
    QuarantineDir, SCAN_FILE, SessionDir, StorageError, StorageRoots, VOLUME_QUARANTINE_DIR,
    cap_bytes, now,
};

#[cfg(test)]
mod tests;

/// The largest scan copy [`read_scan_copy`] accepts.
pub const MAX_SCAN_BYTES: u64 = 256 << 20;

// ---------------------------------------------------------------------------------------------------
// What a run works with
// ---------------------------------------------------------------------------------------------------

/// What a run tells its caller while it works (`exec.progress`).
#[derive(Debug, Clone, Copy)]
pub enum Progress<'a> {
    /// The session exists; its journal does not yet.
    SessionCreated {
        /// The session id.
        session: &'a SessionId,
        /// The session directory.
        path: &'a Path,
        /// How many items are selected.
        items: u32,
    },
    /// An item is about to be gated.
    ItemStarting {
        /// Its op id.
        op: OpId,
        /// Its candidate id.
        item: &'a CandidateId,
    },
    /// An item's `done` record was written.
    ItemFinished {
        /// Its op id.
        op: OpId,
        /// How it ended.
        outcome: &'a ItemOutcome,
    },
    /// The run stops early; the `aborted` record is about to be written.
    Aborting {
        /// Why.
        reason: AbortReason,
    },
}

/// The backends of the system objects a run may delete: services, scheduled tasks, firewall rules. The
/// engine passes the live ones (`act_service::LiveServices`, `act_task::WinTasks`,
/// `act_firewall::LiveFirewall`) only to an elevated process; the tests pass scripted fakes.
#[derive(Clone, Copy)]
pub struct ObjectBackends<'a> {
    /// The Service Control Manager and the `Services` keys.
    pub services: &'a dyn ServiceBackend,
    /// The Task Scheduler.
    pub tasks: &'a dyn TaskBackend,
    /// The firewall rules (WMI and their registry values).
    pub firewall: &'a dyn FirewallBackend,
}

impl std::fmt::Debug for ObjectBackends<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectBackends").finish_non_exhaustive()
    }
}

/// Everything outside the request that a run works with. The backends are trait objects so that the rig
/// and the tests can script them.
pub struct ExecEnv<'a> {
    /// The store.
    pub roots: &'a StorageRoots,
    /// The deny-list compiled from the live `GuardEnv`, whose `purge_dirs` hold the store roots.
    pub deny: &'a DenyList,
    /// Package enumeration and removal.
    pub packages: &'a dyn PackageBackend,
    /// The backends of services, scheduled tasks and firewall rules; `None` (the default) in a process
    /// that may not change them (not elevated), which then refuses a plan that selects one.
    pub objects: Option<ObjectBackends<'a>>,
    /// Restart Manager, query only.
    pub lockers: &'a dyn LockerQuery,
    /// Who answers the "close these programs?" question. Nothing is closed whatever the answer.
    pub consent: &'a dyn ConsentCallback,
    /// The boot-time move list.
    pub pending_renames: &'a mut dyn PendingRenames,
    /// The retries on a locked item.
    pub retry: Retry,
    /// Told what the run does, when set.
    pub progress: Option<&'a dyn Fn(&Progress<'_>)>,
    /// The engine version for the journal header.
    pub engine_version: String,
    /// How long to wait for the restore point before the first item ([`RESTORE_POINT_WAIT`]).
    pub restore_point_wait: Duration,
    /// How long to wait for it again after the last item ([`RESTORE_POINT_FINISH_WAIT`]).
    pub restore_point_finish_wait: Duration,
}

impl<'a> ExecEnv<'a> {
    /// An environment with the standard retries, the default consent answer (deny) and no progress
    /// callback. The locked-file ladder always reads live facts and checks a boot move's destination
    /// against this session's store ([`StoreLadder`]).
    pub fn new(
        roots: &'a StorageRoots,
        deny: &'a DenyList,
        packages: &'a dyn PackageBackend,
        lockers: &'a dyn LockerQuery,
        pending_renames: &'a mut dyn PendingRenames,
    ) -> ExecEnv<'a> {
        ExecEnv {
            roots,
            deny,
            packages,
            objects: None,
            lockers,
            consent: &DenyAll,
            pending_renames,
            retry: Retry::standard(),
            progress: None,
            engine_version: env!("CARGO_PKG_VERSION").to_owned(),
            restore_point_wait: RESTORE_POINT_WAIT,
            restore_point_finish_wait: RESTORE_POINT_FINISH_WAIT,
        }
    }
}

impl std::fmt::Debug for ExecEnv<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecEnv")
            .field("roots", &self.roots)
            .field("retry", &self.retry)
            .field("engine_version", &self.engine_version)
            .finish_non_exhaustive()
    }
}

/// Why a run did not start. Nothing outside Purge's store was changed, and no journal record says
/// otherwise: every variant is raised before the journal's first `validated` record.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// The request was refused; nothing was read or changed.
    #[error(transparent)]
    Plan(#[from] PlanRefusal),
    /// The gate could not be set up.
    #[error(transparent)]
    Gate(#[from] GateSetupError),
    /// The store refused (integrity, size cap, I/O).
    #[error(transparent)]
    Store(#[from] StorageError),
    /// The session's copy of the scan document could not be written, flushed or read.
    #[error("the session's copy of the scan document: {0}")]
    ScanCopy(String),
    /// The journal could not be created or opened.
    #[error(transparent)]
    Journal(#[from] JournalError),
    /// The session cannot be resumed.
    #[error("the session cannot be resumed: {0}")]
    NotResumable(String),
    /// The plan selects this many service, scheduled task or firewall rule items and the process has no
    /// backends to change them ([`ExecEnv::objects`]: it is not elevated). Raised before the session
    /// exists (a resumed run: before anything is read or written).
    #[error(
        "the plan selects {0} service, scheduled task or firewall rule item(s), which only an elevated process can remove; nothing was done"
    )]
    NeedsElevation(usize),
}

/// Why a run stops early.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Abort {
    /// The reason for the `aborted` record.
    pub reason: AbortReason,
    /// What failed.
    pub detail: String,
}

impl Abort {
    fn journal(error: JournalError) -> Abort {
        Abort {
            reason: AbortReason::JournalWriteFailed,
            detail: error.to_string(),
        }
    }

    fn store(error: &StorageError) -> Abort {
        let reason = match error {
            StorageError::Integrity { .. } => AbortReason::StorageIntegrity,
            _ => AbortReason::BackupWriteFailed,
        };
        Abort {
            reason,
            detail: error.to_string(),
        }
    }

    fn backup(integrity: bool, detail: String) -> Abort {
        let reason = if integrity {
            AbortReason::StorageIntegrity
        } else {
            AbortReason::BackupWriteFailed
        };
        Abort { reason, detail }
    }
}

/// What [`Run::run_item`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ItemStep {
    /// The item ran to its `done` record in this call, with this outcome.
    Finished(ItemOutcome),
    /// The journal already held the op's `done`; nothing was done.
    AlreadyDone,
    /// The journal holds the op's intent and no `done`: the action may have run. Nothing was done here;
    /// recovery probes the op and ends it with the token of `JournalWriter::resume_intent`.
    OpenIntent,
    /// The journal holds no `validated` record for the op id; nothing was done.
    NotInRun,
}

/// How a run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOutput {
    /// The session.
    pub session: SessionId,
    /// The report, built from the journal.
    pub report: ExecReport,
    /// Whether the journal holds the run's end (`commit` or `aborted`); `false` when the `aborted`
    /// record could not be written, so the session still waits for recovery.
    pub closed: bool,
    /// Whether `report.json` was written into the session.
    pub report_written: bool,
    /// Whether the session's entry in the index was written.
    pub index_updated: bool,
}

// ---------------------------------------------------------------------------------------------------
// Volumes and the size cap
// ---------------------------------------------------------------------------------------------------

/// A volume the run may quarantine on.
#[derive(Debug, Clone)]
struct Volume {
    root: PathBuf,
    serial: u64,
    fs_name: String,
    total_bytes: u64,
}

/// Whether `root` is the root of a drive (`C:\`), the only place the store puts a `.purge-q`.
fn is_drive_root(root: &Path) -> bool {
    let text = root.to_string_lossy();
    let bytes = text.as_bytes();
    bytes.len() == 3 && bytes[0].is_ascii_alphabetic() && &bytes[1..] == br":\"
}

fn same_root(a: &Path, b: &Path) -> bool {
    a.to_string_lossy()
        .eq_ignore_ascii_case(&b.to_string_lossy())
}

/// The volume of `path`, when a quarantine can be on it and its serial can be read.
fn volume_of(roots: &StorageRoots, path: &str) -> Option<Volume> {
    let facts = roots.volume(Path::new(path)).ok()?;
    if facts.quarantine_capable().is_err() || !is_drive_root(&facts.root) {
        return None;
    }
    let serial = report::volume_serial(&facts.root).filter(|serial| *serial != 0)?;
    Some(Volume {
        root: facts.root,
        serial,
        fs_name: facts.fs_name,
        total_bytes: facts.total_bytes,
    })
}

/// The volumes the plan's quarantine moves are on, each once, with the bytes the plan says they hold
/// there. An item on a volume that cannot hold a quarantine is left out; the file action skips it.
fn plan_volumes(roots: &StorageRoots, plan: &BoundPlan) -> Vec<(Volume, u64)> {
    let mut volumes: Vec<(Volume, u64)> = Vec::new();
    for item in plan.items() {
        let Some(ExecOp::QuarantineMove { path }) = &item.exec_op else {
            continue;
        };
        let Some(volume) = volume_of(roots, path) else {
            continue;
        };
        let bytes = plan
            .candidate(item)
            .and_then(|candidate| candidate.size_bytes)
            .unwrap_or(0);
        match volumes
            .iter_mut()
            .find(|(seen, _)| seen.serial == volume.serial)
        {
            Some((_, planned)) => *planned = planned.saturating_add(bytes),
            None => volumes.push((volume, bytes)),
        }
    }
    volumes
}

/// The journal header's volume records: where this session quarantines on each volume.
fn volume_records(
    roots: &StorageRoots,
    session: &SessionId,
    volumes: &[(Volume, u64)],
) -> Vec<VolumeRecord> {
    let data_root = roots.volume(roots.data_root()).map(|facts| facts.root).ok();
    volumes
        .iter()
        .map(|(volume, _)| {
            let on_data_volume = data_root
                .as_deref()
                .is_some_and(|root| same_root(root, &volume.root));
            let quarantine = if on_data_volume {
                roots.quarantine_path()
            } else {
                volume.root.join(VOLUME_QUARANTINE_DIR)
            };
            VolumeRecord {
                root: volume.root.to_string_lossy().into_owned(),
                serial: volume.serial,
                file_system: volume.fs_name.clone(),
                quarantine: quarantine
                    .join(session.as_str())
                    .to_string_lossy()
                    .into_owned(),
            }
        })
        .collect()
}

/// What each volume may still take before its size cap; `None` when the index could not be read, in
/// which case the cap is not enforced (and the report says so).
#[derive(Debug, Clone, Default)]
struct Budget(Option<BTreeMap<u64, u64>>);

impl Budget {
    fn new(index: Option<&SessionIndex>, volumes: &[(Volume, u64)]) -> Budget {
        Budget(index.map(|index| {
            volumes
                .iter()
                .map(|(volume, _)| {
                    let held = index.bytes_on_volume(volume.serial);
                    (
                        volume.serial,
                        cap_bytes(volume.total_bytes).saturating_sub(held),
                    )
                })
                .collect()
        }))
    }

    /// Whether `bytes` more fit on volume `serial`. A volume the budget does not know is not limited
    /// here.
    fn allows(&self, serial: u64, bytes: u64) -> bool {
        self.0
            .as_ref()
            .and_then(|left| left.get(&serial))
            .is_none_or(|left| bytes <= *left)
    }

    fn spend(&mut self, serial: u64, bytes: u64) {
        if let Some(left) = self.0.as_mut().and_then(|left| left.get_mut(&serial)) {
            *left = left.saturating_sub(bytes);
        }
    }
}

/// The index, or `None` (with a warning) when it is unavailable; any other failure is the store's.
fn read_index_for_cap(
    roots: &StorageRoots,
    warnings: &mut Vec<String>,
) -> Result<Option<SessionIndex>, StorageError> {
    match roots.read_index() {
        Ok(index) => Ok(Some(index)),
        Err(e) if e.is_index_unavailable() => {
            warnings.push(format!(
                "the session index is unavailable ({e}); the quarantine size cap was not checked"
            ));
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// The budget of a resumed run: what each volume of the journal header may still take, counting what
/// the other sessions of the index hold there (this session's own entry, if a former close wrote one,
/// is left out) and what this session's journal says it already holds there (`spent`). A volume that
/// cannot be found now is not limited (nothing can be quarantined on it). `None` index: no cap.
fn resume_budget(
    roots: &StorageRoots,
    state: &JournalState,
    index: Option<SessionIndex>,
    spent: &[VolumeUsage],
) -> Budget {
    let Some(mut index) = index else {
        return Budget(None);
    };
    index.remove(&state.header().session);
    let volumes: Vec<(Volume, u64)> = state
        .header()
        .volumes
        .iter()
        .filter_map(|record| {
            volume_of(roots, &record.root)
                .filter(|volume| volume.serial == record.serial)
                .map(|volume| (volume, 0))
        })
        .collect();
    let mut budget = Budget::new(Some(&index), &volumes);
    for usage in spent {
        budget.spend(usage.serial, usage.bytes);
    }
    budget
}

/// Reads the index and checks the plan's sizes against the cap of each volume. An unavailable index is
/// not an error: the run goes on without the cap, and `warnings` says so.
fn preflight_cap(
    roots: &StorageRoots,
    volumes: &[(Volume, u64)],
    warnings: &mut Vec<String>,
) -> Result<Budget, StorageError> {
    let Some(index) = read_index_for_cap(roots, warnings)? else {
        return Ok(Budget(None));
    };
    let planned: Vec<VolumeUsage> = volumes
        .iter()
        .map(|(volume, bytes)| VolumeUsage {
            serial: volume.serial,
            root: volume.root.to_string_lossy().into_owned(),
            bytes: *bytes,
        })
        .collect();
    roots.check_cap(&index, &planned)?;
    Ok(Budget::new(Some(&index), volumes))
}

// ---------------------------------------------------------------------------------------------------
// The scan copy
// ---------------------------------------------------------------------------------------------------

/// Writes the session's copy of the scan document, `plan.scan.json`, through the store, and flushes
/// the file and its directory. Expiry and recovery read it; it must be durable before the journal
/// exists. A failure discards the file through its own handle.
fn write_scan_copy(session: &SessionDir, scan: &ScanDoc) -> Result<(), ExecError> {
    let text = serde_json::to_vec(scan).map_err(|e| ExecError::ScanCopy(e.to_string()))?;
    let mut file = session.create_file(SCAN_FILE)?;
    let written = file
        .write_all(&text)
        .map_err(|e| e.to_string())
        .and_then(|()| file.sync().map_err(|e| e.to_string()))
        .and_then(|()| file.sync_dir().map_err(|e| e.to_string()));
    if let Err(detail) = written {
        // The file is Purge's own, created a moment ago.
        let _ = file.discard();
        return Err(ExecError::ScanCopy(detail));
    }
    Ok(())
}

/// Reads the session's copy of the scan document through the store.
pub fn read_scan_copy(session: &SessionDir) -> Result<ScanDoc, ExecError> {
    let mut file = session.open_file(SCAN_FILE)?;
    let text = file.read_all(MAX_SCAN_BYTES)?;
    serde_json::from_slice(&text).map_err(|e| ExecError::ScanCopy(e.to_string()))
}

// ---------------------------------------------------------------------------------------------------
// The journal and the notes: what every step writes through
// ---------------------------------------------------------------------------------------------------

/// The most bytes of a skip's detail a `done` record carries. The detail is engine text with a path or
/// an SDDL string in it, both of which can be tens of kilobytes (F11 of the M2 fix-round review); the
/// report keeps it whole.
pub(crate) const MAX_DONE_DETAIL: usize = 2048;

/// What a cut detail ends with.
const DETAIL_CUT: &str = " [...]";

/// `detail` as a `done` record carries it: whole up to [`MAX_DONE_DETAIL`] bytes, else cut at a character
/// boundary so that, with [`DETAIL_CUT`] after it, it is at most that long.
pub(crate) fn journal_detail(detail: &str) -> String {
    if detail.len() <= MAX_DONE_DETAIL {
        return detail.to_owned();
    }
    let mut end = MAX_DONE_DETAIL - DETAIL_CUT.len();
    while end > 0 && !detail.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{DETAIL_CUT}", detail.get(..end).unwrap_or_default())
}

/// The journal writer and the notes the journal has no place for. Every journal write of the per-item
/// pipeline goes through here, and every failure of one becomes an [`Abort`].
#[derive(Debug)]
struct Ledger {
    journal: JournalWriter,
    notes: RunNotes,
}

impl Ledger {
    /// Keeps `detail` for the report, and returns what the `done` record carries: the detail of a
    /// skipped item (why it was left untouched, e.g. the step that could not make a backup location),
    /// empty for every other outcome.
    fn note(&mut self, op: OpId, outcome: &ItemOutcome, detail: String) -> String {
        let journalled = match outcome {
            ItemOutcome::Skipped { .. } => journal_detail(&detail),
            _ => String::new(),
        };
        if !detail.is_empty() && !outcome.is_success() {
            self.notes.details.insert(op, detail);
        }
        journalled
    }

    /// Writes and flushes an intent; the token proves it durable.
    fn intent(&mut self, intent: Intent) -> Result<IntentToken, Abort> {
        self.journal.intent(intent).map_err(Abort::journal)
    }

    /// Writes the `done` of an op that holds an intent.
    fn done(
        &mut self,
        token: IntentToken,
        outcome: ItemOutcome,
        detail: String,
    ) -> Result<ItemOutcome, Abort> {
        let detail = self.note(token.op(), &outcome, detail);
        self.journal
            .done_noted(token, outcome.clone(), detail)
            .map_err(Abort::journal)?;
        Ok(outcome)
    }

    /// Writes the `done` of an op decided before any intent. An outcome that needs an intent cannot be
    /// decided here; one that arrives anyway is journalled as an internal failure, never as success.
    fn decided(
        &mut self,
        op: OpId,
        outcome: ItemOutcome,
        detail: String,
    ) -> Result<ItemOutcome, Abort> {
        let outcome = if outcome.allowed_without_intent() {
            outcome
        } else {
            ItemOutcome::Failed {
                code: FailCode::Internal,
                os_error: None,
                detail: "an outcome that needs an intent was decided without one".into(),
            }
        };
        let detail = self.note(op, &outcome, detail);
        self.journal
            .done_without_intent_noted(op, outcome.clone(), detail)
            .map_err(Abort::journal)?;
        Ok(outcome)
    }

    /// Ends an op with or without the token it holds.
    fn end(
        &mut self,
        op: OpId,
        token: Option<IntentToken>,
        outcome: ItemOutcome,
        detail: String,
    ) -> Result<ItemOutcome, Abort> {
        match token {
            Some(token) => self.done(token, outcome, detail),
            None => self.decided(op, outcome, detail),
        }
    }
}

/// The rule of a `Refused` validated record for an item whose open failed at validation.
const OPEN_FAILED: &str = "gate.open-failed";
/// The rule of a `Refused` validated record for an item the validate pass found in use.
const LOCKED_AT_VALIDATION: &str = "gate.locked";
/// The rule of a `Refused` validated record for a service, task or firewall item without its scan-time
/// digest (`Candidate::object_fp`).
const NO_OBJECT_FP: &str = "exec.no-object-fp";
/// The rule of a `Refused` validated record for an object op in a process without object backends.
const NO_OBJECT_BACKENDS: &str = "exec.no-object-backends";
/// The rule of a `Refused` validated record for an object op its module refused at validation.
const OBJECT_REFUSED: &str = "exec.object-refused";

/// The facts of the `validated` record of an item that did not pass the validate pass: `Absent` when it
/// is gone, else [`ItemFacts::Refused`] with the blocker and rule of a refusal, the Win32 error of a
/// failed or locked open, or (`None`: an object item without its scan-time digest, which is not looked
/// at) [`Blocker::ChangedSinceScan`].
fn refused_facts(outcome: Option<&GateOutcome<gate::Validation>>) -> ItemFacts {
    let refused = |blocker, reason: &str, os_error| ItemFacts::Refused {
        blocker,
        reason: reason.to_owned(),
        os_error,
    };
    match outcome {
        Some(GateOutcome::Vanished) => ItemFacts::Absent,
        Some(GateOutcome::Refused(refusal)) => {
            refused(Some(refusal.blocker.clone()), refusal.reason, None)
        }
        Some(GateOutcome::Failed(error)) => refused(None, OPEN_FAILED, Some(error.0)),
        Some(GateOutcome::Locked(locked)) => {
            refused(None, LOCKED_AT_VALIDATION, Some(locked.error.0))
        }
        // A pass is journalled with its own facts; one arriving here binds nothing.
        Some(GateOutcome::Pass(_)) => refused(None, "exec.internal", None),
        None => refused(Some(Blocker::ChangedSinceScan), NO_OBJECT_FP, None),
    }
}

/// The facts of the `validated` record of an object op its module decided at validation: `Absent` for
/// `Vanished`, else [`ItemFacts::Refused`] with the blocker of a gate refusal
/// ([`Blocker::ChangedSinceScan`] for another digest) and the error code of a failed read.
fn object_decided_facts(result: &TypedResult) -> ItemFacts {
    let refused = |blocker, reason: &str, os_error| ItemFacts::Refused {
        blocker,
        reason: reason.to_owned(),
        os_error,
    };
    match &result.outcome {
        ItemOutcome::Vanished => ItemFacts::Absent,
        ItemOutcome::Skipped {
            reason: SkipReason::GateBlocked { blocker },
        } => refused(Some(blocker.clone()), OBJECT_REFUSED, None),
        ItemOutcome::Skipped {
            reason: SkipReason::ChangedSinceScan,
        } => refused(
            Some(Blocker::ChangedSinceScan),
            gate::reason::OBJECT_CHANGED,
            None,
        ),
        ItemOutcome::Failed { os_error, .. } => refused(None, OPEN_FAILED, *os_error),
        _ => refused(None, OBJECT_REFUSED, None),
    }
}

/// The validate pass for an object op (`exec_op` of plan item `cand`): its module's `validate`, read
/// only, over `objects`. `Ok` with the object facts that bind the act to its digest; `Err` with the
/// facts to journal ([`object_decided_facts`]) and the module's result, for an item that is never acted
/// on. Without backends nothing is read and the item is refused.
fn validate_object(
    objects: Option<ObjectBackends<'_>>,
    ctx: &GateCtx,
    exec_op: &ExecOp,
    cand: &Candidate,
) -> Result<ItemFacts, (ItemFacts, TypedResult)> {
    let Some(objects) = objects else {
        let facts = ItemFacts::Refused {
            blocker: None,
            reason: NO_OBJECT_BACKENDS.to_owned(),
            os_error: None,
        };
        return Err((facts, no_backends(exec_op)));
    };
    let decided = |result: TypedResult| (object_decided_facts(&result), result);
    match exec_op {
        ExecOp::DeleteService { .. } => {
            match act_service::validate(objects.services, ctx.deny(), exec_op, cand) {
                SvcValidated::Validated { facts, .. } => Ok(facts),
                SvcValidated::Decided(result) => Err(decided(result)),
            }
        }
        ExecOp::DeleteFirewallRule { .. } => {
            match act_firewall::validate(objects.firewall, ctx.deny(), exec_op, cand) {
                FwValidated::Validated { facts, .. } => Ok(facts),
                FwValidated::Decided(result) => Err(decided(result)),
            }
        }
        ExecOp::DeleteTask { .. } => {
            let validated = act_task::validate_task(objects.tasks, ctx, exec_op, cand);
            let facts = validated.journal_facts();
            match validated {
                TaskValidate::Validated { .. } => Ok(facts),
                TaskValidate::Decided(decision) => Err((facts, decision.result)),
            }
        }
        _ => {
            let (outcome, detail) = internal(format!("{} is not an object op", exec_op.name()));
            let facts = ItemFacts::Refused {
                blocker: None,
                reason: "exec.internal".to_owned(),
                os_error: None,
            };
            Err((facts, TypedResult { outcome, detail }))
        }
    }
}

/// The result for an object op in a process without object backends: nothing is read or changed.
fn no_backends(exec_op: &ExecOp) -> TypedResult {
    let (outcome, detail) = internal(format!(
        "{} on {:?}: this process has no backends for services, scheduled tasks and firewall rules \
         (it is not elevated); nothing was read or changed",
        exec_op.name(),
        exec_op.target()
    ));
    TypedResult { outcome, detail }
}

/// The program roots of a new run's journal header: `roots` (the caller's, from the app's fingerprint)
/// without every root that [`gate::root_refusal`] refuses (review R3b S3), each dropped with a warning
/// in the report. The executor does not take the fingerprint's word for its roots: a root such as
/// `C:\Program Files` itself would make every program below it "inside a root".
fn checked_roots(
    roots: &[String],
    deny: &DenyList,
    user_sid: Option<&str>,
    warnings: &mut Vec<String>,
) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    for root in roots {
        match gate::root_refusal(root, deny, user_sid) {
            Some(why) => warnings.push(format!(
                "program root {root:?} was not recorded for the run: {why}; no service, task or \
                 firewall rule counts as inside it"
            )),
            None if kept.contains(root) => {}
            None => kept.push(root.clone()),
        }
    }
    kept
}

/// The program roots of the journal header of `state` (`Header::program_roots`).
fn header_roots(state: &JournalState) -> Vec<String> {
    state.header().program_roots.clone()
}

/// The forward completion of an object op whose intent recovery found not done: the op's act again,
/// bound to the journalled intent and run under its resumed `token`, so the act-time gate (the object
/// read again, its digest against the intent's, the guard, the program roots, the definition binding)
/// runs again before anything is deleted. Without backends nothing is called: `Failed{VerifyFailed}`,
/// the item left as it is.
pub(crate) fn complete_object(
    objects: Option<ObjectBackends<'_>>,
    ctx: &GateCtx,
    session: &SessionDir,
    intent: &Intent,
    token: &IntentToken,
    program_roots: &[String],
) -> TypedResult {
    let Some(objects) = objects else {
        let detail = format!(
            "{} was interrupted and this process has no backends for services, scheduled tasks and \
             firewall rules (it is not elevated); the item was left as it is",
            intent.exec_op.name()
        );
        return TypedResult {
            outcome: ItemOutcome::Failed {
                code: FailCode::VerifyFailed,
                os_error: None,
                detail: detail.clone(),
            },
            detail,
        };
    };
    let not_bound = || {
        let (outcome, detail) = internal(format!(
            "the intent of op {} does not hang together; nothing done",
            intent.op
        ));
        TypedResult { outcome, detail }
    };
    match &intent.exec_op {
        ExecOp::DeleteService { .. } => match SvcRemoval::from_intent(intent) {
            Some(removal) => act_service::act(
                objects.services,
                ctx.deny(),
                session,
                Box::new(removal),
                token,
                program_roots,
            ),
            None => not_bound(),
        },
        ExecOp::DeleteFirewallRule { .. } => match FwRemoval::from_intent(intent) {
            Some(removal) => act_firewall::act(
                objects.firewall,
                ctx.deny(),
                session,
                Box::new(removal),
                token,
                program_roots,
            ),
            None => not_bound(),
        },
        ExecOp::DeleteTask { .. } => {
            act_task::delete_task(objects.tasks, ctx, session, intent, token, program_roots)
        }
        _ => not_bound(),
    }
}

/// What became of the object op of `intent`, an intent without its `done` (recovery), through its
/// module's probe. Without backends: `Attention` (nothing can be read).
pub(crate) fn probe_object(objects: Option<ObjectBackends<'_>>, intent: &Intent) -> Probe {
    let Some(objects) = objects else {
        return Probe::Attention {
            detail:
                "this process has no backends for services, scheduled tasks and firewall rules \
                     (it is not elevated); what became of the item cannot be read"
                    .to_owned(),
        };
    };
    match &intent.exec_op {
        ExecOp::DeleteService { .. } => act_service::probe(objects.services, intent),
        ExecOp::DeleteTask { .. } => act_task::probe_task(objects.tasks, intent),
        ExecOp::DeleteFirewallRule { .. } => act_firewall::probe(objects.firewall, intent),
        _ => Probe::Attention {
            detail: "the intent is not an object op".to_owned(),
        },
    }
}

/// How many selected items of `plan` are object ops.
fn object_ops(plan: &BoundPlan) -> usize {
    plan.items()
        .iter()
        .filter(|item| item.exec_op.as_ref().is_some_and(ExecOp::is_object))
        .count()
}

fn internal(detail: impl Into<String>) -> (ItemOutcome, String) {
    let detail = detail.into();
    (
        ItemOutcome::Failed {
            code: FailCode::Internal,
            os_error: None,
            detail: detail.clone(),
        },
        detail,
    )
}

// ---------------------------------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------------------------------

/// Which part of the pipeline an op goes through.
enum Route {
    /// A service, task or firewall item without its scan-time digest: journalled as skipped.
    NoObjectFp,
    /// No recorded `validated` record: never acted on.
    NotValidated,
    /// A quarantine move or a remove-dir-if-empty.
    File,
    /// A registry action.
    Registry,
    /// A package removal.
    Package,
    /// A service, scheduled task or firewall rule delete.
    Object,
}

/// A run in progress: the session, its journal, and the gate context filled from the journal.
///
/// [`execute`] makes one and drives it to the end. Crash recovery makes one with [`Run::resume`] and
/// drives the remaining items through [`Run::run_item`], then ends it with [`Run::finish`] or
/// [`Run::abort`].
#[derive(Debug)]
pub struct Run<'a> {
    env: ExecEnv<'a>,
    plan: BoundPlan,
    settings: ExecSettings,
    session: SessionDir,
    ctx: GateCtx,
    ledger: Ledger,
    budget: Budget,
    data_volume: Option<DataVolume>,
    prepared: Option<Prepared>,
    /// The journal was handed out ([`Run::journal_mut`]) and may hold `done` records the gate context
    /// has not noted: [`Run::run_item`] notes the journal's completed ops again before the next item.
    journal_lent: bool,
    /// Why the run must stop before any item runs (a resumed validation that could not be journalled);
    /// the next [`Run::run_item`] returns it.
    stopped: Option<Abort>,
}

/// The run's ops with their op ids, for [`GateCtx::set_run_ops`].
fn run_ops(plan: &BoundPlan) -> Vec<(OpId, ExecOp)> {
    plan.items()
        .iter()
        .filter_map(|item| Some((item.op, item.exec_op.clone()?)))
        .collect()
}

/// The risk view of the selected items and their absorbed children (`prepare::risk_reasons`). A key
/// item whose validation (`facts_of` its op) read the key counts its direct subkeys and itself
/// (`RiskItem::with_subtree_keys`; review M2 M24): a lower bound of its tree, since deeper levels are
/// not counted before the act. Without validated facts a key counts as one.
fn risk_items<'p>(
    plan: &'p BoundPlan,
    facts_of: impl Fn(OpId) -> Option<ItemFacts>,
) -> Vec<RiskItem<'p>> {
    let mut items = Vec::new();
    for item in plan.items() {
        if let Some(candidate) = plan.candidate(item) {
            let risk = RiskItem::from_candidate(candidate);
            items.push(match facts_of(item.op) {
                Some(ItemFacts::Key(key)) => risk.with_subtree_keys(u64::from(key.subkeys) + 1),
                _ => risk,
            });
            items.extend(plan.children(candidate).map(RiskItem::from_candidate));
        }
    }
    items
}

impl<'a> Run<'a> {
    /// Steps 2 to 6 of the run: the store, the session, the scan copy, the journal header and the
    /// run's settings. A failure before the header removes the session directory again
    /// ([`SessionDir::remove_unstarted`]: by handle, only when it holds nothing or only the scan copy);
    /// a failure of that cleanup leaves the directory, which holds no journal and so describes no run.
    fn start(request: ExecRequest, env: ExecEnv<'a>) -> Result<Run<'a>, ExecError> {
        let plan = plan_in::bind(&request)?;
        let objects = object_ops(&plan);
        if objects > 0 && env.objects.is_none() {
            return Err(ExecError::NeedsElevation(objects));
        }
        gate::expose_placeholders()?;
        env.roots.check()?;
        let volumes = plan_volumes(env.roots, &plan);
        let mut notes = RunNotes::default();
        let budget = preflight_cap(env.roots, &volumes, &mut notes.warnings)?;
        // Recorded only for a run that selects an object op, so that every other run's header stays as
        // M2 wrote it; a root the guard refuses as an app's root is dropped first (review R3b S3).
        let program_roots = if objects > 0 {
            checked_roots(
                &request.settings.program_roots,
                env.deny,
                request.settings.user_sid.as_deref(),
                &mut notes.warnings,
            )
        } else {
            Vec::new()
        };

        let session = env.roots.create_session()?;
        let items = u32::try_from(plan.items().len()).unwrap_or(u32::MAX);
        if let Some(progress) = env.progress {
            progress(&Progress::SessionCreated {
                session: session.id(),
                path: session.path(),
                items,
            });
        }
        let opened = (|| -> Result<(GateCtx, JournalWriter), ExecError> {
            write_scan_copy(&session, plan.scan())?;
            let volume_roots: Vec<&Path> = volumes.iter().map(|(v, _)| v.root.as_path()).collect();
            let scope = env.roots.store_scope(session.id(), &volume_roots)?;
            let mut ctx = GateCtx::new(env.deny.clone(), &plan.exec_ops(), scope)?;
            ctx.set_run_ops(run_ops(&plan));
            ctx.bind_user(request.settings.user_sid.as_deref());
            ctx.set_gone(&request.settings.gone);
            let header = Header {
                schema: JournalSchema,
                session: session.id().clone(),
                created: now(),
                engine_version: env.engine_version.clone(),
                app: plan.scan().app.clone(),
                plan_hash: plan.plan_hash(),
                selection_hash: plan.selection_hash(),
                policy_version: plan.scan().policy_version.clone(),
                mode: plan.scan().mode,
                items,
                allow_irreversible: plan.allow_irreversible(),
                volumes: volume_records(env.roots, session.id(), &volumes),
                program_roots,
            };
            // The selected ids in op order go into the settings record, so that a run stopped in its
            // validation is bound to its selection again without a search (`rebind_interrupted`).
            let mut settings = request.settings.to_journal();
            settings.selected = plan
                .items()
                .iter()
                .filter_map(|item| plan.candidate(item))
                .map(|candidate| candidate.id.clone())
                .collect();
            let journal = JournalWriter::create_with_settings(&session, header, settings)?;
            Ok((ctx, journal))
        })();
        let (ctx, journal) = match opened {
            Ok(opened) => opened,
            Err(e) => {
                // A journal created before the failure (an unfinished header) makes this refuse, and
                // the directory then stays as it is.
                let _ = session.remove_unstarted();
                return Err(e);
            }
        };
        Ok(Run {
            data_volume: report::data_volume(env.roots),
            env,
            plan,
            settings: request.settings,
            session,
            ctx,
            ledger: Ledger { journal, notes },
            budget,
            prepared: None,
            journal_lent: false,
            stopped: None,
        })
    }

    /// Takes up the unfinished run of `session`, whose copy of the scan document is `scan`
    /// ([`read_scan_copy`]): the journal is opened to append, the plan is bound to it again
    /// ([`plan_in::rebind`]), and every `validated` record of the journal ([`OpState::validated`]) is
    /// handed to the gate context, exactly as a fresh run hands over the ones it wrote. Nothing is
    /// acted on here.
    ///
    /// Refused when the journal already ended and when the journal holds no `settings` record (written
    /// before the record existed): the run's settings are read from the journal
    /// ([`ExecSettings::from_journal`]), never taken from the caller.
    ///
    /// A run that stopped before every item was validated (a crash at the header or in the validate
    /// pass) acted on nothing; it is continued as if it had not stopped. The plan is bound again with
    /// the selection the settings record holds (in an older journal: the rest of it found from the
    /// header; [`plan_in::rebind_interrupted`]), the items
    /// without a `validated` record are validated now (step 7, for those items only: a journalled
    /// record is never written or validated again) and their records journalled and handed to the gate
    /// context. Step 8 is not repeated: no restore point is asked for (the report says so when the
    /// run's setting would have asked), and the Restart Manager is asked by the locked-file ladder per
    /// item. A journal write that fails in that validation stops the run: the next
    /// [`Run::run_item`] returns the [`Abort`].
    ///
    /// The size cap is enforced for the remaining items as for a fresh run: each volume of the header
    /// may take what its cap leaves after the other sessions of the index and what this session's
    /// journal already holds there. An unavailable index lifts the cap, with a warning.
    pub fn resume(
        env: ExecEnv<'a>,
        session: SessionDir,
        scan: &ScanDoc,
    ) -> Result<Run<'a>, ExecError> {
        gate::expose_placeholders()?;
        let journal = JournalWriter::open_append(&session)?;
        let state = journal.state();
        if state.is_finished() {
            return Err(ExecError::NotResumable("its journal already ended".into()));
        }
        let Some(journalled) = state.settings() else {
            return Err(ExecError::NotResumable(
                "its journal records no run settings (it was written before they were journalled)"
                    .into(),
            ));
        };
        let mut settings = ExecSettings::from_journal(journalled);
        settings.program_roots = header_roots(state);
        let validated: Vec<Validated> = state.ops().map(OpState::validated).collect();
        let plan = plan_in::rebind_interrupted(scan, state)?;
        // An object op that may still run needs the backends; nothing is written before this.
        let open_objects = plan
            .items()
            .iter()
            .filter(|item| item.exec_op.as_ref().is_some_and(ExecOp::is_object))
            .filter(|item| {
                state
                    .op(item.op)
                    .is_none_or(|op| !matches!(op.status(), OpStatus::Done(_)))
            })
            .count();
        if open_objects > 0 && env.objects.is_none() {
            return Err(ExecError::NeedsElevation(open_objects));
        }
        let volume_roots: Vec<&str> = state
            .header()
            .volumes
            .iter()
            .map(|volume| volume.root.as_str())
            .collect();
        let scope = env.roots.store_scope(session.id(), &volume_roots)?;
        let mut ctx = GateCtx::new(env.deny.clone(), &plan.exec_ops(), scope)?;
        ctx.set_run_ops(run_ops(&plan));
        ctx.bind_user(settings.user_sid.as_deref());
        ctx.set_gone(&settings.gone);
        let mut notes = RunNotes::default();
        let data_volume = report::data_volume(env.roots);
        let index = read_index_for_cap(env.roots, &mut notes.warnings)?;
        let spent = report::usage(state, data_volume.as_ref());
        let budget = resume_budget(env.roots, state, index, &spent);
        for record in &validated {
            let exec_op = plan.item(record.op).and_then(|item| item.exec_op.as_ref());
            if let Some(exec_op) = exec_op {
                let max_files = GateItem::new(exec_op, Exemptions::default()).max_files;
                if let Err(refusal) = ctx.record(exec_op, record, max_files) {
                    notes.details.insert(
                        record.op,
                        format!("its validated record was not accepted: {refusal}"),
                    );
                }
            }
        }
        // What the run's completed registry ops did to the keys later ops are bound to, from their
        // journalled intent and done records (`GateCtx::note_done`).
        ctx.note_journal(state);
        let unvalidated = state.validated_count() < state.header().items;
        let mut run = Run {
            data_volume,
            env,
            plan,
            settings,
            session,
            ctx,
            ledger: Ledger { journal, notes },
            budget,
            prepared: None,
            journal_lent: false,
            stopped: None,
        };
        if unvalidated {
            // The gone lists were judged on the day the run started; an item validated now must not
            // lean on them (the product may have been installed again since): the resumed run works
            // without them, and what needs them is refused (review R3b M2).
            let empty = crate::plan_in::GoneLists::default();
            if run.settings.gone != empty {
                run.ctx.set_gone(&empty);
                run.ledger.notes.warnings.push(
                    "the run's M1b exemption lists (gone MSI products, Package Cache folders, Burn \
                     records) were not used: the run stopped before its items were validated and \
                     was resumed"
                        .to_owned(),
                );
            }
            if let Err(abort) = run.validate() {
                run.stopped = Some(abort);
            } else if run.settings.restore_point.requests(&run.risk_reasons()) {
                run.ledger.notes.warnings.push(
                    "no restore point was asked for: the run stopped before its items were \
                     validated and was resumed"
                        .to_owned(),
                );
            }
        }
        Ok(run)
    }

    /// The settings the run works with: the request's for a fresh run, the journal's for a resumed one.
    pub fn settings(&self) -> &ExecSettings {
        &self.settings
    }

    /// The session directory.
    pub fn session(&self) -> &SessionDir {
        &self.session
    }

    /// The bound plan.
    pub fn plan(&self) -> &BoundPlan {
        &self.plan
    }

    /// The gate context, holding the journalled `validated` records.
    pub fn ctx(&self) -> &GateCtx {
        &self.ctx
    }

    /// What the journal says so far.
    pub fn state(&self) -> &JournalState {
        self.ledger.journal.state()
    }

    /// The journal writer, for recovery to end an op whose intent was open
    /// (`JournalWriter::resume_intent`, then `done`). The next [`Run::run_item`] hands the `done` records
    /// written through it to the gate context ([`GateCtx::note_journal`]), so an op recovery completed
    /// counts as this run's own change for the items after it.
    pub fn journal_mut(&mut self) -> &mut JournalWriter {
        self.journal_lent = true;
        &mut self.ledger.journal
    }

    fn emit(&self, progress: Progress<'_>) {
        if let Some(callback) = self.env.progress {
            callback(&progress);
        }
    }

    /// The plan's candidate of op `op`.
    fn op_candidate(&self, op: OpId) -> Option<&Candidate> {
        self.plan
            .item(op)
            .and_then(|item| self.plan.candidate(item))
    }

    /// The plan-time exemptions of op `op`'s item: `purge_plan::decide::deny_exemptions`, the
    /// derivation the plan's decide step uses, with the machine layout of the deny-list and the run's
    /// `user_sid` and `long_names_resolved`, and the run's M1b lists ([`GateCtx::set_gone`]). The act is
    /// gated with the journalled copy of these, never with this value.
    fn exemptions(&self, op: OpId) -> Exemptions<'static> {
        let exemptions = self
            .op_candidate(op)
            .map_or_else(Exemptions::default, |candidate| {
                purge_plan::decide::deny_exemptions(
                    candidate,
                    self.env.deny.env(),
                    self.settings.user_sid.as_deref(),
                    self.settings.long_names_resolved,
                )
            });
        // The run's M1b lists, which the plan's decide step gives every candidate too.
        self.ctx.with_gone(exemptions)
    }

    /// The gate's view of op `op` (`exec_op`) at validation: its exemptions ([`Run::exemptions`]), the
    /// scan-time identity its candidate carries (`Candidate::item_fp`), which the validate pass
    /// compares with the identity it reads, and the run's key limit, which the act applies too.
    fn gate_item<'e>(&self, op: OpId, exec_op: &'e ExecOp) -> GateItem<'e> {
        let scan_identity = self
            .op_candidate(op)
            .and_then(|candidate| candidate.item_fp);
        GateItem::new(exec_op, self.exemptions(op))
            .with_scan_identity(scan_identity)
            .with_key_limit(self.settings.key_limit)
    }

    /// Step 7: validates every selected item read-only, writes one `validated` record per item and
    /// hands each written record to the gate context. An item that is gone is recorded with
    /// [`ItemFacts::Absent`]; one that did not pass otherwise with [`ItemFacts::Refused`] and why
    /// ([`refused_facts`]). Neither binds anything in the gate, so nothing can act on such an item.
    /// A path item that is not the object its candidate's scan-time identity names is refused
    /// (`gate.scan-identity`, changed since the scan) and so later skipped as `ChangedSinceScan`.
    ///
    /// Only items without a `validated` record in the journal are looked at (all of them in a fresh
    /// run; in a resumed one those the interrupted pass had not reached). Returns every item's record,
    /// the journalled ones included, in plan order.
    fn validate(&mut self) -> Result<Vec<Validated>, Abort> {
        let state = self.ledger.journal.state();
        let todo: Vec<&BoundItem> = self
            .plan
            .items()
            .iter()
            .filter(|item| state.op(item.op).is_none())
            .collect();
        let exemptions: BTreeMap<OpId, Exemptions> = todo
            .iter()
            .map(|item| (item.op, self.exemptions(item.op)))
            .collect();
        let outcomes: BTreeMap<OpId, GateOutcome<gate::Validation>> = gate::validate_all(
            &self.ctx,
            todo.iter().filter_map(|item| {
                // An object op is validated by its module below.
                let exec_op = item.exec_op.as_ref().filter(|op| !op.is_object())?;
                Some((item.op, self.gate_item(item.op, exec_op)))
            }),
        )
        .into_iter()
        .collect();

        let mut records = Vec::with_capacity(self.plan.items().len());
        for item in self.plan.items() {
            if let Some(journalled) = self.ledger.journal.state().op(item.op) {
                records.push(journalled.validated());
                continue;
            }
            let Some(candidate) = self.plan.candidate(item) else {
                continue;
            };
            let target = item
                .exec_op
                .as_ref()
                .map_or_else(|| candidate.target.clone(), ExecOp::target);
            let exemptions_of = |op: OpId| {
                gate::exemptions_to_journal(&exemptions.get(&op).copied().unwrap_or_default())
            };
            let object = item.exec_op.as_ref().filter(|op| op.is_object());
            let record = match (object, outcomes.get(&item.op)) {
                (Some(exec_op), _) => Validated {
                    op: item.op,
                    item: candidate.id.clone(),
                    target,
                    facts: match validate_object(self.env.objects, &self.ctx, exec_op, candidate) {
                        Ok(facts) => facts,
                        Err((facts, result)) => {
                            if !result.detail.is_empty() {
                                self.ledger.notes.details.insert(item.op, result.detail);
                            }
                            facts
                        }
                    },
                    exemptions: exemptions_of(item.op),
                },
                (None, Some(GateOutcome::Pass(validation))) => {
                    validation.to_journal(item.op, candidate.id.clone(), target)
                }
                (None, outcome) => Validated {
                    op: item.op,
                    item: candidate.id.clone(),
                    target,
                    facts: refused_facts(outcome),
                    exemptions: exemptions_of(item.op),
                },
            };
            self.ledger
                .journal
                .validated(record.clone())
                .map_err(Abort::journal)?;
            if let Some(exec_op) = &item.exec_op {
                let max_files = GateItem::new(exec_op, Exemptions::default()).max_files;
                if let Err(refusal) = self.ctx.record(exec_op, &record, max_files) {
                    self.ledger.notes.details.insert(
                        item.op,
                        format!("its validated record was not accepted: {refusal}"),
                    );
                }
            }
            records.push(record);
        }
        self.ledger.journal.sync().map_err(Abort::journal)?;
        Ok(records)
    }

    /// Step 8: the restore point (per setting) and the Restart Manager query. Never fails.
    fn prepare<R: RestorePointBackend>(&mut self, validated: &[Validated], restore_points: R) {
        let scan = self.plan.scan();
        let request = PrepareRequest {
            setting: self.settings.restore_point,
            risk: self.risk_reasons(),
            description: prepare::restore_point_description(&scan.app),
            validated,
            wait: self.env.restore_point_wait,
        };
        self.prepared = Some(prepare::prepare(request, restore_points, self.env.lockers));
    }

    /// Why the plan is high-risk, from its selected items and their absorbed children.
    fn risk_reasons(&self) -> Vec<prepare::RiskReason> {
        let state = self.ledger.journal.state();
        let risk_items = risk_items(&self.plan, |op| {
            state.op(op).map(|journalled| journalled.validated().facts)
        });
        prepare::risk_reasons(&risk_items, self.plan.scan().mode)
    }

    // ---- One item ---------------------------------------------------------------------------------

    /// Runs op `op` from where the journal says it stands to its `done` record (see "One item" in the
    /// module docs). Returns `Err` only when the run must stop: the caller then calls [`Run::abort`]
    /// and runs no further item.
    pub fn run_item(&mut self, op: OpId) -> Result<ItemStep, Abort> {
        if let Some(abort) = self.stopped.take() {
            return Err(abort);
        }
        if std::mem::take(&mut self.journal_lent) {
            self.ctx.note_journal(self.ledger.journal.state());
        }
        let (item, standing) = match self.state().op(op) {
            None => return Ok(ItemStep::NotInRun),
            Some(state) => (state.item.clone(), state.status()),
        };
        match standing {
            OpStatus::Done(_) => return Ok(ItemStep::AlreadyDone),
            OpStatus::IntentOnly => return Ok(ItemStep::OpenIntent),
            OpStatus::Validated => {}
        }
        self.emit(Progress::ItemStarting { op, item: &item });
        let outcome = match self.route(op) {
            Route::NoObjectFp => self.ledger.decided(
                op,
                ItemOutcome::Skipped {
                    reason: SkipReason::ChangedSinceScan,
                },
                format!(
                    "{}: the scan recorded no digest of the object, so it cannot be told that it is \
                     the one the scan saw; left untouched",
                    gate::reason::NO_OBJECT_FP
                ),
            ),
            Route::NotValidated => self.unvalidated_item(op),
            Route::File => self.file_item(op),
            Route::Registry => self.registry_item(op),
            Route::Package => self.package_item(op),
            Route::Object => self.object_item(op),
        }?;
        self.emit(Progress::ItemFinished {
            op,
            outcome: &outcome,
        });
        Ok(ItemStep::Finished(outcome))
    }

    /// Crash recovery: settles op `op`, whose intent the journal holds without a `done`, under that
    /// intent's own token (`JournalWriter::resume_intent`). Its action module probes what really
    /// happened ([`crate::recover::probe_intent`]): `Done` gets the missing `done`, `Attention` a `done`
    /// `Failed{VerifyFailed}` (the item is left as it is), and `NotDone` or `Partial` is completed
    /// forward, bound to the journalled intent ([`act_fs::complete_fs`], [`act_reg::complete_reg`],
    /// [`act_typed::complete_package`]). A file found in use goes to the locked-file ladder
    /// ([`Ladder::in_store`]) with the journalled intent, exactly as a run hands one over after its
    /// intent. What the op changed counts toward the size cap and, for a registry op, as this run's own
    /// change for the items after it.
    ///
    /// `Ok(None)` when the op has no open intent. `Err` only when the run must stop (a journal write
    /// failed): the caller then calls [`Run::abort`].
    pub fn settle_open(&mut self, op: OpId) -> Result<Option<SettledOp>, Abort> {
        if let Some(abort) = self.stopped.take() {
            return Err(abort);
        }
        if std::mem::take(&mut self.journal_lent) {
            self.ctx.note_journal(self.ledger.journal.state());
        }
        let Some(intent) = self
            .state()
            .op(op)
            .filter(|state| state.status() == OpStatus::IntentOnly)
            .and_then(|state| state.intent.clone())
        else {
            return Ok(None);
        };
        let Some(token) = self.ledger.journal.resume_intent(op) else {
            return Ok(None);
        };
        let probe = crate::recover::probe_intent(
            &self.ctx,
            &self.session,
            &intent,
            &*self.env.pending_renames,
            self.env.packages,
            self.env.objects,
        );
        let size = self.move_size(op);
        let outcome = match &probe {
            Probe::Done(outcome) => self.ledger.done(
                token,
                outcome.clone(),
                "found done after the interruption".to_owned(),
            )?,
            Probe::Attention { detail } => self.ledger.done(
                token,
                ItemOutcome::Failed {
                    code: FailCode::VerifyFailed,
                    os_error: None,
                    detail: detail.clone(),
                },
                format!("after the interruption: {detail}"),
            )?,
            Probe::NotDone | Probe::Partial { .. } => self.complete_open(&intent, token)?,
        };
        if let Some((serial, bytes)) = size.filter(|_| outcome.changed_system()) {
            self.budget.spend(serial, bytes);
        }
        if let Some(state) = self.ledger.journal.state().op(op) {
            self.ctx.note_done(state);
        }
        Ok(Some(SettledOp { op, probe, outcome }))
    }

    /// Crash recovery after a restart that may have taken registry changes, before
    /// [`Run::settle_open`]: probes again, in op order, every registry op whose `done` says `Done` and
    /// that no hive flush vouched for ([`JournalState::unconfirmed`]; see [`crate::durable`]) and makes
    /// a lost change again ([`crate::recover::reprobe_unconfirmed`]): the journal keeps its `done`, and
    /// the hives are flushed before the run's `group_end`, `commit` or `aborted`. An op the run's later
    /// ops explain counts as done. What does not match the journal afterwards gets a `reconcile`
    /// `Retried` whose outcome replaces its `Done`, and a warning in the report. Each op is pushed to
    /// `found`; `Err` only when the run must stop (a journal write failed).
    pub fn reprobe_unconfirmed(
        &mut self,
        found: &mut Vec<crate::recover::ReprobedOp>,
    ) -> Result<(), Abort> {
        if let Some(abort) = self.stopped.take() {
            return Err(abort);
        }
        let start = found.len();
        let result = crate::recover::reprobe_unconfirmed(
            &self.ctx,
            &self.session,
            &mut self.ledger.journal,
            found,
        );
        for entry in found.iter().skip(start) {
            if entry.matches_journal() {
                continue;
            }
            let item = self
                .state()
                .op(entry.op)
                .map_or_else(String::new, |op| op.item.0.clone());
            let now = entry
                .corrected
                .as_ref()
                .map_or_else(|| "Done".to_owned(), |outcome| format!("{outcome:?}"));
            self.ledger.notes.warnings.push(format!(
                "item {item} (op {}): the journal said it was done, but after the restart the \
                 registry does not show it and it could not be done again ({:?}): {}; it stands at \
                 {now}",
                entry.op, entry.probe, entry.detail
            ));
        }
        result.map_err(Abort::journal)
    }

    /// The forward completion of [`Run::settle_open`] for an intent the probe found not done or half
    /// done.
    fn complete_open(&mut self, intent: &Intent, token: IntentToken) -> Result<ItemOutcome, Abort> {
        match &intent.exec_op {
            ExecOp::QuarantineMove { .. } | ExecOp::RemoveDirIfEmpty { .. } => {
                let completion =
                    act_fs::complete_fs(&self.ctx, &self.session, intent, &token, &self.env.retry);
                match completion {
                    FsCompletion::Finished(result) => {
                        self.ledger.done(token, result.outcome, result.detail)
                    }
                    FsCompletion::Locked(locked) => {
                        self.locked_item(*locked, Some((intent.clone(), token)))
                    }
                }
            }
            exec_op if exec_op.is_object() => {
                let roots = header_roots(self.ledger.journal.state());
                let result = complete_object(
                    self.env.objects,
                    &self.ctx,
                    &self.session,
                    intent,
                    &token,
                    &roots,
                );
                self.ledger.done(token, result.outcome, result.detail)
            }
            ExecOp::RemovePackage { .. } => {
                let result = act_typed::complete_package(
                    self.env.packages,
                    &self.ctx,
                    &self.session,
                    intent,
                    self.ledger.journal.state().header().allow_irreversible,
                    &token,
                );
                self.ledger.done(token, result.outcome, result.detail)
            }
            _ => {
                let result = act_reg::complete_reg(&self.ctx, &self.session, intent, &token);
                self.ledger.done(token, result.outcome, result.detail)
            }
        }
    }

    fn route(&self, op: OpId) -> Route {
        let bound = self.plan.item(op);
        if let Some(item) = bound.filter(|item| item.exec_op.is_none()) {
            let object = self
                .plan
                .candidate(item)
                .is_some_and(|candidate| ObjectKind::of(&candidate.target).is_some());
            if object {
                return Route::NoObjectFp;
            }
        }
        match self.ctx.journalled(op) {
            None => Route::NotValidated,
            Some((ExecOp::QuarantineMove { .. } | ExecOp::RemoveDirIfEmpty { .. }, _)) => {
                Route::File
            }
            Some((ExecOp::RemovePackage { .. }, _)) => Route::Package,
            Some((exec_op, _)) if exec_op.is_object() => Route::Object,
            Some(_) => Route::Registry,
        }
    }

    /// An op the gate holds no `validated` record for. Nothing may act on it; a fresh read-only look
    /// only says how to report it: gone (`Vanished`), refused or unreadable. An item that passes now
    /// did not when the run started, so it is skipped as changed; the next scan takes it up. The look
    /// is taken for an item journalled as gone or refused ([`ItemFacts::is_actionable`] false); an item
    /// with actionable facts that the gate did not accept is an internal failure.
    fn unvalidated_item(&mut self, op: OpId) -> Result<ItemOutcome, Abort> {
        let journalled_absent = self
            .state()
            .op(op)
            .is_some_and(|state| !state.facts.is_actionable());
        let exec_op = self.plan.item(op).and_then(|item| item.exec_op.clone());
        let (outcome, detail) = match exec_op {
            Some(_) if !journalled_absent => internal(
                self.ledger
                    .notes
                    .details
                    .get(&op)
                    .cloned()
                    .unwrap_or_else(|| "the gate holds no record of its validation".into()),
            ),
            Some(exec_op) if exec_op.is_object() => {
                // The same read-only look as the validate pass, through the op's module.
                let candidate = self.op_candidate(op);
                let look = candidate.map(|candidate| {
                    validate_object(self.env.objects, &self.ctx, &exec_op, candidate)
                });
                match look {
                    Some(Err((_, result))) if result.outcome.allowed_without_intent() => {
                        (result.outcome, result.detail)
                    }
                    Some(Err((_, result))) => internal(result.detail),
                    Some(Ok(_)) => (
                        ItemOutcome::Skipped {
                            reason: SkipReason::ChangedSinceScan,
                        },
                        "it did not pass validation when the run started; left for the next scan"
                            .into(),
                    ),
                    None => internal("the op has no plan item"),
                }
            }
            Some(exec_op) => {
                // The same view as the validate pass, scan-time identity included, so an item refused
                // for its identity is reported as such again.
                let look = gate::validate(&self.ctx, &self.gate_item(op, &exec_op));
                let result = if exec_op.is_registry() {
                    act_reg::gate_result(&look, &exec_op).map(|r| (r.outcome, r.detail))
                } else {
                    act_fs::gate_result(&look).map(|r| (r.outcome, r.detail))
                };
                match result {
                    Some(result) => result,
                    None => (
                        ItemOutcome::Skipped {
                            reason: SkipReason::ChangedSinceScan,
                        },
                        "it did not pass validation when the run started; left for the next scan"
                            .into(),
                    ),
                }
            }
            None => internal("the plan item has no executor op"),
        };
        self.ledger.decided(op, outcome, detail)
    }

    /// The bytes a quarantine move of op `op` adds, and the volume they land on, from its journalled
    /// facts.
    fn move_size(&self, op: OpId) -> Option<(u64, u64)> {
        match self.ctx.journalled(op)? {
            (ExecOp::QuarantineMove { .. }, record) => match &record.facts {
                ItemFacts::File(facts) => {
                    Some((facts.volume_serial, facts.tree_bytes.unwrap_or(facts.size)))
                }
                _ => None,
            },
            _ => None,
        }
    }

    /// A quarantine move or a remove-dir-if-empty: cap, gate and quarantine directory, intent, act,
    /// done. A locked item goes to the ladder.
    fn file_item(&mut self, op: OpId) -> Result<ItemOutcome, Abort> {
        let size = self.move_size(op);
        if let Some((serial, bytes)) =
            size.filter(|(serial, bytes)| !self.budget.allows(*serial, *bytes))
        {
            return self.ledger.decided(
                op,
                ItemOutcome::Skipped {
                    reason: SkipReason::CapExceeded,
                },
                format!(
                    "its {bytes} bytes would exceed the quarantine size cap of volume {serial:#x}"
                ),
            );
        }
        let prepared = prepare_fs(&self.ctx, &self.session, op, &self.env.retry)
            .map_err(|e| Abort::store(&e))?;
        let outcome = match prepared {
            FsPrepared::Decided(result) => self.ledger.decided(op, result.outcome, result.detail),
            FsPrepared::Locked(locked) => self.locked_item(*locked, None),
            FsPrepared::Ready(action) => {
                let intent = action.intent().clone();
                let token = self.ledger.intent(intent.clone())?;
                fault::point(fault::ACT_BEFORE);
                match act_fs(action, &token, &self.env.retry) {
                    FsActed::Finished(result) => {
                        self.ledger.done(token, result.outcome, result.detail)
                    }
                    FsActed::Locked(locked) => self.locked_item(*locked, Some((intent, token))),
                }
            }
        }?;
        if let Some((serial, bytes)) = size.filter(|_| outcome.changed_system()) {
            self.budget.spend(serial, bytes);
        }
        Ok(outcome)
    }

    /// The quarantine path of an item found locked: the one its intent recorded, or `<op dir>\<leaf>`
    /// in an op directory made now for an item locked before any intent, which is returned too, so
    /// that a ladder that decides without acting takes it away again (review M2 M5).
    fn locked_destination(
        &self,
        locked: &act_fs::LockedItem,
    ) -> Result<(String, Option<QuarantineDir>), StorageError> {
        if let Some(path) = &locked.quarantine_path {
            return Ok((path.clone(), None));
        }
        let source = Path::new(&locked.path);
        let leaf = source
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| StorageError::InvalidPath(locked.path.clone()))?;
        let serial = locked.locked.stamp.identity.volume_serial;
        // An empty op directory left by a run that stopped before this op's intent is adopted, as the
        // file action adopts one (review M2 M5); a directory that holds something still refuses.
        let dir = act_fs::create_op_dir_for(&self.session, source, serial, locked.op)?;
        Ok((
            dir.item_path(&leaf).to_string_lossy().into_owned(),
            Some(dir),
        ))
    }

    /// The locked-file ladder for an item that stayed locked after its retries. `held` is the intent
    /// and token the file action already journalled, when the lock was met at the rename.
    fn locked_item(
        &mut self,
        locked: act_fs::LockedItem,
        held: Option<(Intent, IntentToken)>,
    ) -> Result<ItemOutcome, Abort> {
        let op = locked.op;
        let (journalled, token) = match held {
            Some((intent, token)) => (Some(intent), Some(token)),
            None => (None, None),
        };
        let (destination, made) = match self.locked_destination(&locked) {
            Ok(made) => made,
            Err(StorageError::CannotBackUp { reason, .. }) => {
                let outcome = ItemOutcome::Skipped {
                    reason: SkipReason::GateBlocked {
                        blocker: purge_model::Blocker::CannotBackUp,
                    },
                };
                return self.ledger.end(op, token, outcome, reason.to_string());
            }
            Err(e) => return Err(Abort::store(&e)),
        };
        // The op directory made for the ladder goes again, while empty, when nothing is acted on.
        let discard = |made: Option<QuarantineDir>| {
            if let Some(dir) = made {
                act_fs::remove_empty_op_dir(dir);
            }
        };
        let Some(item) = locked::LockedItem::from_gate(&self.ctx, op, &locked.locked, destination)
        else {
            discard(made);
            let (outcome, detail) = internal("a locked item without journalled file facts");
            return self.ledger.end(op, token, outcome, detail);
        };
        let store_ladder = StoreLadder::new(&self.ctx, &self.session);
        let ladder = Ladder {
            consent: self.env.consent,
            ..Ladder::in_store(&store_ladder, self.env.lockers)
        };
        let result = match ladder.prepare(&item, journalled.as_ref()) {
            LockPrepared::Decided(result) => {
                discard(made);
                Self::note_lockers(&mut self.ledger, op, &result);
                return self.ledger.end(op, token, result.outcome, result.detail);
            }
            LockPrepared::Ready(action) => {
                drop(made);
                let token = match (token, action.intent_to_write()) {
                    (Some(token), _) => token,
                    (None, Some(intent)) => self.ledger.intent(intent.clone())?,
                    (None, None) => {
                        let (outcome, detail) =
                            internal("the ladder expects an intent that was never journalled");
                        return self.ledger.decided(op, outcome, detail);
                    }
                };
                fault::point(fault::ACT_BEFORE);
                let result = ladder.act(action, &token, &mut *self.env.pending_renames);
                (token, result)
            }
        };
        let (token, result) = result;
        Self::note_lockers(&mut self.ledger, op, &result);
        self.ledger.done(token, result.outcome, result.detail)
    }

    /// Keeps what the ladder learned for the report: who holds the item, and that a "close them"
    /// answer changed nothing.
    fn note_lockers(ledger: &mut Ledger, op: OpId, result: &LockResult) {
        if !result.lockers.is_empty() {
            ledger.notes.lockers.insert(op, result.lockers.clone());
        }
        if result.close_consent == ConsentAnswer::Allowed {
            let item = ledger
                .journal
                .state()
                .op(op)
                .map_or_else(String::new, |state| state.item.0.clone());
            ledger.notes.warnings.push(format!(
                "item {item} (op {op}): closing the programs that hold it was allowed, but nothing is \
                 closed in this version"
            ));
        }
    }

    /// A registry action: gate and verified backup, intent, act, done.
    fn registry_item(&mut self, op: OpId) -> Result<ItemOutcome, Abort> {
        let prepared = match prepare_reg(&self.ctx, &self.session, op, self.settings.key_limit) {
            Ok(prepared) => prepared,
            Err(e @ BackupWriteError::Encode(_)) => {
                return self.ledger.decided(op, e.outcome(), e.to_string());
            }
            Err(e) => return Err(Abort::backup(e.is_storage_integrity(), e.to_string())),
        };
        match prepared {
            RegPrepared::Decided(result) => self.ledger.decided(op, result.outcome, result.detail),
            RegPrepared::Ready(action) => {
                let token = self.ledger.intent(action.intent().clone())?;
                fault::point(fault::ACT_BEFORE);
                let result = act_reg(action, &token);
                let outcome = self.ledger.done(token, result.outcome, result.detail)?;
                // What the op did to its key (or its parent) is this run's own change from now on, for
                // the items after it that are bound to that key.
                if let Some(state) = self.ledger.journal.state().op(op) {
                    self.ctx.note_done(state);
                }
                Ok(outcome)
            }
        }
    }

    /// A package removal, which has no undo: acknowledgement, checks and definition file, intent,
    /// remove, done. Op and plan item are those of the op's journalled `validated` record
    /// ([`prepare_remove_package_recorded`]).
    fn package_item(&mut self, op: OpId) -> Result<ItemOutcome, Abort> {
        let ack = if self.plan.allow_irreversible() {
            IrreversibleAck::Acknowledged
        } else {
            IrreversibleAck::Missing
        };
        let backend = self.env.packages;
        let prepared =
            match prepare_remove_package_recorded(backend, &self.ctx, &self.session, op, ack) {
                Ok(prepared) => prepared,
                Err(e @ DefinitionError::Encode(_)) => {
                    return self.ledger.decided(op, e.outcome(), e.to_string());
                }
                Err(e) => return Err(Abort::backup(e.is_storage_integrity(), e.to_string())),
            };
        match prepared {
            act_typed::Prepared::Decided(result) => {
                self.ledger.decided(op, result.outcome, result.detail)
            }
            act_typed::Prepared::Ready(removal) => {
                let token = self.ledger.intent(removal.intent().clone())?;
                fault::point(fault::ACT_BEFORE);
                let result = remove_package(backend, removal, &token);
                self.ledger.done(token, result.outcome, result.detail)
            }
        }
    }

    /// A service, scheduled task or firewall rule delete (C-ACT): its module's prepare (the object read
    /// and gated against the journalled stamp, the definition written and verified), intent, `act.before`,
    /// the module's act (read and gated again, delete, `objdelete.after`, flush of the object's hive,
    /// `act.after`, verdict from a fresh read), done. Op, plan item and stamp come from the op's
    /// journalled `validated` record; the program roots from the journal header. A definition that
    /// cannot be written as verified skips the item (`NoVerifiedBackup`); a store that fails its
    /// integrity check aborts the run.
    fn object_item(&mut self, op: OpId) -> Result<ItemOutcome, Abort> {
        let Some(objects) = self.env.objects else {
            let exec_op = self.ctx.journalled(op).map(|(exec_op, _)| exec_op.clone());
            let result = exec_op.map_or_else(
                || TypedResult {
                    outcome: internal("no journalled op").0,
                    detail: "no journalled op".into(),
                },
                |exec_op| no_backends(&exec_op),
            );
            return self.ledger.decided(op, result.outcome, result.detail);
        };
        let Some(planned) = self
            .op_candidate(op)
            .map(|candidate| candidate.reversibility)
        else {
            let (outcome, detail) = internal("the op has no plan item");
            return self.ledger.decided(op, outcome, detail);
        };
        let roots = header_roots(self.ledger.journal.state());
        let kind = self.ctx.journalled(op).map(|(exec_op, _)| exec_op.clone());
        match kind {
            Some(ExecOp::DeleteService { .. }) => {
                self.service_item(objects.services, op, planned, &roots)
            }
            Some(ExecOp::DeleteTask { .. }) => self.task_item(objects.tasks, op, planned, &roots),
            Some(ExecOp::DeleteFirewallRule { .. }) => {
                self.firewall_item(objects.firewall, op, &roots)
            }
            _ => {
                let (outcome, detail) = internal("the op is not an object op");
                self.ledger.decided(op, outcome, detail)
            }
        }
    }

    fn service_item(
        &mut self,
        backend: &dyn ServiceBackend,
        op: OpId,
        planned: Reversibility,
        roots: &[String],
    ) -> Result<ItemOutcome, Abort> {
        let prepared = act_service::prepare_recorded(
            backend,
            &self.ctx,
            &self.session,
            op,
            planned,
            self.settings.key_limit,
            roots,
        );
        match prepared {
            Err(e) if e.is_storage_integrity() => Err(Abort::backup(true, e.to_string())),
            Err(e) => self.ledger.decided(op, e.outcome(), e.to_string()),
            Ok(SvcPrepared::Decided(result)) => {
                self.ledger.decided(op, result.outcome, result.detail)
            }
            Ok(SvcPrepared::Ready(removal)) => {
                let token = self.ledger.intent(removal.intent().clone())?;
                fault::point(fault::ACT_BEFORE);
                let result = act_service::act(
                    backend,
                    self.ctx.deny(),
                    &self.session,
                    removal,
                    &token,
                    roots,
                );
                self.ledger.done(token, result.outcome, result.detail)
            }
        }
    }

    fn task_item(
        &mut self,
        backend: &dyn TaskBackend,
        op: OpId,
        planned: Reversibility,
        roots: &[String],
    ) -> Result<ItemOutcome, Abort> {
        let prepared =
            act_task::prepare_task(backend, &self.ctx, &self.session, op, planned, roots);
        match prepared {
            Err(e) if e.is_storage_integrity() => Err(Abort::backup(true, e.to_string())),
            Err(e) => self.ledger.decided(op, e.outcome(), e.to_string()),
            Ok(TaskPrepared::Decided(decision)) => {
                self.ledger
                    .decided(op, decision.result.outcome, decision.result.detail)
            }
            Ok(TaskPrepared::Ready(delete)) => {
                let token = self.ledger.intent(delete.intent().clone())?;
                fault::point(fault::ACT_BEFORE);
                let result = act_task::delete_task(
                    backend,
                    &self.ctx,
                    &self.session,
                    delete.intent(),
                    &token,
                    roots,
                );
                self.ledger.done(token, result.outcome, result.detail)
            }
        }
    }

    fn firewall_item(
        &mut self,
        backend: &dyn FirewallBackend,
        op: OpId,
        roots: &[String],
    ) -> Result<ItemOutcome, Abort> {
        let prepared = act_firewall::prepare_recorded(
            backend,
            self.ctx.deny(),
            &self.ctx,
            &self.session,
            op,
            roots,
        );
        match prepared {
            Err(e) if e.is_storage_integrity() => Err(Abort::backup(true, e.to_string())),
            Err(e) => self.ledger.decided(op, e.outcome(), e.to_string()),
            Ok(FwPrepared::Decided(result)) => {
                self.ledger.decided(op, result.outcome, result.detail)
            }
            Ok(FwPrepared::Ready(removal)) => {
                let token = self.ledger.intent(removal.intent().clone())?;
                fault::point(fault::ACT_BEFORE);
                let result = act_firewall::act(
                    backend,
                    self.ctx.deny(),
                    &self.session,
                    removal,
                    &token,
                    roots,
                );
                self.ledger.done(token, result.outcome, result.detail)
            }
        }
    }

    // ---- The end ----------------------------------------------------------------------------------

    /// Step 10 and 11: closes the last group, writes `commit`, then the index entry and the report. A
    /// commit that cannot be written is an abort.
    pub fn finish(mut self) -> ExecOutput {
        if let Some(abort) = self.stopped.take() {
            return self.abort(abort);
        }
        let bytes = report::backup_bytes(self.state());
        if let Err(e) = self.ledger.journal.commit(now(), bytes) {
            return self.abort(Abort::journal(e));
        }
        let Run {
            env,
            plan,
            session,
            ledger,
            data_volume,
            prepared,
            ..
        } = self;
        let state = ledger.journal.state().clone();
        drop(ledger.journal);
        close(
            &env,
            &plan,
            &session,
            &state,
            true,
            ledger.notes,
            data_volume.as_ref(),
            prepared,
        )
    }

    /// Stops the run: writes `aborted` (through a fresh handle when the writer failed), then the index
    /// entry and the report. Items without a `done` stay as they are and are reported as not attempted.
    pub fn abort(self, abort: Abort) -> ExecOutput {
        self.emit(Progress::Aborting {
            reason: abort.reason,
        });
        let Run {
            env,
            plan,
            session,
            ledger,
            data_volume,
            prepared,
            ..
        } = self;
        let Ledger { journal, mut notes } = ledger;
        let (state, recorded) = record_abort(journal, &session, &abort);
        if !recorded {
            notes.warnings.push(format!(
                "the run was aborted ({:?}: {}) and the journal could not record it",
                abort.reason, abort.detail
            ));
        }
        // Without the `aborted` record the state may hold lines that were written and never flushed,
        // so the index entry does not record how far the journal reaches.
        let mut output = close(
            &env,
            &plan,
            &session,
            &state,
            recorded,
            notes,
            data_volume.as_ref(),
            prepared,
        );
        output.report.state = SessionState::Aborted;
        output
    }
}

/// Writes the `aborted` record. A writer that failed takes no more records, and its handle excludes a
/// second writer, so it is dropped and the record is tried once through a fresh handle. Returns what
/// the journal says afterwards and whether it holds the record.
fn record_abort(
    mut journal: JournalWriter,
    session: &SessionDir,
    abort: &Abort,
) -> (JournalState, bool) {
    if !journal.is_poisoned()
        && journal
            .abort(now(), abort.reason, abort.detail.clone())
            .is_ok()
    {
        return (journal.state().clone(), true);
    }
    let last = journal.state().clone();
    drop(journal);
    match JournalWriter::open_append(session) {
        Ok(mut again) => {
            let recorded = again
                .abort(now(), abort.reason, abort.detail.clone())
                .is_ok();
            (again.state().clone(), recorded)
        }
        Err(_) => (last, false),
    }
}

/// Step 11: the restore point's outcome, the index entry and the report, all read from `state`.
/// `durable` says that every line of `state` is flushed (the run ended with a written `commit` or
/// `aborted`); only then does the index entry record the journal's mark (review M7), which a later
/// read checks.
#[allow(clippy::too_many_arguments)]
fn close(
    env: &ExecEnv<'_>,
    plan: &BoundPlan,
    session: &SessionDir,
    state: &JournalState,
    durable: bool,
    mut notes: RunNotes,
    data_volume: Option<&DataVolume>,
    prepared: Option<Prepared>,
) -> ExecOutput {
    if let Some(prepared) = prepared {
        let record = prepared.finish(env.restore_point_finish_wait);
        notes.restore_point = record.report_outcome();
        for item in &record.lockers.items {
            notes
                .lockers
                .entry(item.op)
                .or_insert_with(|| item.lockers.clone());
        }
        notes.warnings.extend(record.warnings);
    }
    let mut summary = report::summary(state, plan.scan(), data_volume);
    if !durable {
        summary.journal = None;
    }
    let index_updated = match env.roots.update_index(|index| index.upsert(summary)) {
        Ok(_) => true,
        Err(e) => {
            notes
                .warnings
                .push(format!("the session index was not updated: {e}"));
            false
        }
    };
    let mut report = report::build(state, plan.scan(), &notes, now());
    let report_written = match report::write_report(session, &report) {
        Ok(()) => true,
        Err(e) => {
            report
                .warnings
                .push(format!("report.json was not written: {e}"));
            false
        }
    };
    ExecOutput {
        session: session.id().clone(),
        report,
        closed: durable,
        report_written,
        index_updated,
    }
}

/// Executes a confirmed plan (see the module docs for every step).
///
/// `Err` means the run did not start: nothing outside Purge's store was changed. Once the journal
/// exists the result is always an [`ExecOutput`], whose report states `Committed` or `Aborted`.
pub fn execute<R: RestorePointBackend>(
    request: ExecRequest,
    env: ExecEnv<'_>,
    restore_points: R,
) -> Result<ExecOutput, ExecError> {
    let mut run = Run::start(request, env)?;
    let validated = match run.validate() {
        Ok(validated) => validated,
        Err(abort) => return Ok(run.abort(abort)),
    };
    run.prepare(&validated, restore_points);
    let ops: Vec<OpId> = run.plan.items().iter().map(|item| item.op).collect();
    for op in ops {
        if let Err(abort) = run.run_item(op) {
            return Ok(run.abort(abort));
        }
    }
    Ok(run.finish())
}
