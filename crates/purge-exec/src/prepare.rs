//! Prepare step: restore-point policy and Restart Manager query (M2-X-PREPARE; ENGINE_PLAN.md §7.3,
//! §7.7, §9.4 S5).
//!
//! Runs once per execute run, after the `validated` records and before the first item:
//!
//! 1. **Risk.** [`risk_reasons`] lists why the selected items are high-risk (§7.7): a service or driver
//!    target, more than [`CLASSES_KEY_LIMIT`] keys under a `Classes` root, or [`ScanMode::Forced`].
//!    [`is_high_risk`] is "the list is not empty". [`RestorePointSetting`] (Settings S5: Off /
//!    High-risk only / Always) turns that into "ask for a restore point or not" ([`RestorePointSetting::requests`]).
//! 2. **Restore point.** When requested, [`prepare`] asks for one on a helper thread through a
//!    [`RestorePointBackend`] ([`SystemRestore`] = `purge_win::sr`), in parallel with step 3. It then waits
//!    at most the request's `wait` (default [`RESTORE_POINT_WAIT`]) from the moment the thread started, so
//!    that the system changes come after the snapshot when Windows is quick enough, and goes on either
//!    way. No answer, a disabled System Restore, a throttled request or a failure never stops the run:
//!    each becomes a warning. Purge never reads or writes `SystemRestorePointCreationFrequency` or any
//!    other System Restore setting, and never enables System Protection.
//! 3. **Restart Manager, query only.** The selected items that validation saw as plain files (not
//!    directories) are registered with a [`LockerQuery`] ([`RestartManager`] = `purge_win::rm`), and the
//!    processes and services holding them are listed for the report, per item where it can tell
//!    ([`LockerReport`]). Nothing is shut down or restarted: the trait has no such method. A session that
//!    cannot be started or queried is a warning, never a failure of the run.
//!
//! # A restore point never replaces a backup
//!
//! Restore points supplement quarantine; they never replace it (§7.7). This is structural, not a
//! convention:
//!
//! - The per-item path cannot consult the restore point. [`prepare`] returns a [`Prepared`] whose only
//!   readable part is the locker report; the restore-point state sits in a private field and comes out
//!   only through [`Prepared::finish`], which consumes the value and yields a [`PrepareRecord`] for the
//!   report. There is no boolean, getter or method that says "a restore point exists".
//! - Nothing in this module takes or returns anything the backup or act code uses: no `IntentToken`, no
//!   `BackupRef`, no storage type. Acting needs an `IntentToken`, and an intent names its verified backup
//!   (`journal::JournalWriter::intent`); that chain does not pass through here.
//!
//! # What the executor writes
//!
//! The journal model has no header extension and no warning record, and the header is written before
//! this step runs, so prepare writes nothing to the journal. The outcome is the serialisable
//! [`PrepareRecord`]; the executor puts [`PrepareRecord::report_outcome`] into `ExecReport.restore_point`,
//! appends [`PrepareRecord::warnings`] to `ExecReport.warnings`, and fills `ItemReport.lockers` from
//! [`LockerReport::for_op`]. It may also keep the whole record as a session file.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use purge_model::exec::journal::{ItemFacts, Validated};
use purge_model::exec::op::OpId;
use purge_model::exec::session::{Locker, RestorePointOutcome};
use purge_model::{Candidate, Harm, Hive, ScanMode, Target, TypedTarget};
use purge_win::os::Win32Error;
use purge_win::rm::{LockerList, RebootReasons, RmSession};
use purge_win::sr::{self, SrOutcome};
use serde::{Deserialize, Serialize};

/// More keys than this under `Classes` roots make a run high-risk (§7.7).
pub const CLASSES_KEY_LIMIT: u64 = 500;

/// How long [`prepare`] waits for the restore point, counted from the start of the helper thread, before
/// the run goes on without it. Creating a restore point takes from a few seconds to a few minutes; 90
/// seconds covers the usual case without holding a run up indefinitely.
pub const RESTORE_POINT_WAIT: Duration = Duration::from_secs(90);

/// The wait the executor should give [`Prepared::finish`] after the last item, so that a restore point
/// still being created is recorded when it arrives in that time, and as still running otherwise.
pub const RESTORE_POINT_FINISH_WAIT: Duration = Duration::from_secs(30);

/// At most this many files are queried one by one to tell which item each holder holds. Holders of the
/// other files are still listed in [`LockerReport::lockers`].
pub const MAX_ATTRIBUTED_FILES: usize = 64;

/// Time budget for the one-by-one queries of [`MAX_ATTRIBUTED_FILES`].
pub const ATTRIBUTION_BUDGET: Duration = Duration::from_secs(5);

/// Files registered with one `RmRegisterResources` call.
const RM_REGISTER_CHUNK: usize = 512;

/// `ERROR_NOT_ENOUGH_MEMORY`: the helper thread could not be started.
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
/// `ERROR_IO_PENDING`: the code a still-running restore point is reported with in `purge.exec/1`.
const ERROR_IO_PENDING: u32 = 997;
/// `ERROR_INTERNAL_ERROR`: the helper thread ended without an answer (it panicked).
const ERROR_INTERNAL_ERROR: u32 = 1359;

// ---- Policy ---------------------------------------------------------------------------------------

/// When to ask for a restore point (Settings S5, "Restore point").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RestorePointSetting {
    /// Never.
    Off,
    /// Only for a high-risk run (the default).
    #[default]
    HighRiskOnly,
    /// For every run.
    Always,
}

impl RestorePointSetting {
    /// Whether a run with these risk reasons asks for a restore point.
    pub fn requests(self, reasons: &[RiskReason]) -> bool {
        match self {
            RestorePointSetting::Off => false,
            RestorePointSetting::HighRiskOnly => !reasons.is_empty(),
            RestorePointSetting::Always => true,
        }
    }
}

/// Why a run is high-risk (§7.7). Serialised as an object tagged by `"kind"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum RiskReason {
    /// Items target a service or a driver: a [`Target::Service`], a registry item at or below
    /// `HKLM\SYSTEM\<control set>\Services\<name>`, a `.sys` file or a file under `System32\drivers`,
    /// `SysWOW64\drivers` or `System32\DriverStore`, or a candidate rated [`Harm::Critical`] (drivers and
    /// filters, §5.8.5). Service and driver execution itself is not part of M2; the rule holds anyway.
    ServiceOrDriver {
        /// How many items matched.
        items: u32,
        /// The first of them.
        first: Target,
    },
    /// More than [`CLASSES_KEY_LIMIT`] keys under `Classes` roots.
    ClassesKeys {
        /// The count (see [`risk_reasons`]).
        keys: u64,
    },
    /// The plan comes from a forced scan (no uninstaller ran).
    ForcedMode,
}

/// One selected item as the risk rules see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RiskItem<'a> {
    /// What the item acts on.
    pub target: &'a Target,
    /// What is lost if the removal is wrong.
    pub harm: Harm,
    /// For a key item: how many keys its subtree holds, the key included, when the executor counted
    /// them; `None` counts the key as one.
    pub subtree_keys: Option<u64>,
}

impl<'a> RiskItem<'a> {
    /// The risk view of a candidate, with its subtree counted as one key.
    pub fn from_candidate(candidate: &'a Candidate) -> Self {
        RiskItem {
            target: &candidate.target,
            harm: candidate.harm,
            subtree_keys: None,
        }
    }

    /// The same item with a counted subtree.
    pub fn with_subtree_keys(self, keys: u64) -> Self {
        RiskItem {
            subtree_keys: Some(keys),
            ..self
        }
    }
}

/// Why the selected items are high-risk; empty when they are not.
///
/// `items` should hold every item the run acts on: the selected items and the absorbed children that ride
/// with them. The `Classes` count adds up, per distinct key path (compared without case), the key's
/// [`RiskItem::subtree_keys`] (1 when unknown, and 1 for the key of a value or segment item). A key below
/// another selected key is counted again; that can only make a run high-risk sooner.
pub fn risk_reasons(items: &[RiskItem<'_>], mode: ScanMode) -> Vec<RiskReason> {
    let mut reasons = Vec::new();

    let mut service_items = 0u32;
    let mut first_service = None;
    for item in items {
        if is_service_or_driver(item) {
            service_items = service_items.saturating_add(1);
            first_service.get_or_insert(item.target);
        }
    }
    if let Some(first) = first_service {
        reasons.push(RiskReason::ServiceOrDriver {
            items: service_items,
            first: first.clone(),
        });
    }

    let mut keys: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for item in items {
        if let Some((path, is_key_item)) = classes_key(item.target) {
            let weight = if is_key_item {
                item.subtree_keys.unwrap_or(1).max(1)
            } else {
                1
            };
            let slot = keys.entry(path).or_insert(0);
            *slot = (*slot).max(weight);
        }
    }
    let classes = keys.values().fold(0u64, |sum, n| sum.saturating_add(*n));
    if classes > CLASSES_KEY_LIMIT {
        reasons.push(RiskReason::ClassesKeys { keys: classes });
    }

    if mode == ScanMode::Forced {
        reasons.push(RiskReason::ForcedMode);
    }
    reasons
}

/// Whether the selected items are high-risk: any service or driver target, more than
/// [`CLASSES_KEY_LIMIT`] keys under `Classes`, or a forced scan.
pub fn is_high_risk(items: &[RiskItem<'_>], mode: ScanMode) -> bool {
    !risk_reasons(items, mode).is_empty()
}

/// The restore point's description for a run on `app`.
pub fn restore_point_description(app: &str) -> String {
    format!("Purge: leftovers of {app}")
}

/// Whether two path segments are equal, ignoring ASCII case.
fn seg_eq(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// `CurrentControlSet` or `ControlSet` followed by three digits.
fn is_control_set(segment: &str) -> bool {
    if seg_eq(segment, "CurrentControlSet") {
        return true;
    }
    let bytes = segment.as_bytes();
    bytes.len() == 13
        && segment.is_char_boundary(10)
        && seg_eq(&segment[..10], "ControlSet")
        && bytes[10..].iter().all(u8::is_ascii_digit)
}

fn is_service_or_driver(item: &RiskItem<'_>) -> bool {
    if item.harm == Harm::Critical {
        return true;
    }
    match item.target {
        Target::Service { .. } => true,
        Target::Path { path } => is_driver_path(path),
        target if target.is_registry() => match TypedTarget::try_from(target) {
            Ok(typed) => {
                let segments: Vec<&str> = typed.path().split('\\').collect();
                typed.hive().is_machine()
                    && segments.len() >= 4
                    && seg_eq(segments[0], "SYSTEM")
                    && is_control_set(segments[1])
                    && seg_eq(segments[2], "Services")
                    && !segments[3].is_empty()
            }
            Err(_) => false,
        },
        _ => false,
    }
}

/// A `.sys` file, or anything under `System32\drivers`, `SysWOW64\drivers` or `System32\DriverStore`.
fn is_driver_path(path: &str) -> bool {
    let segments: Vec<&str> = path.split(['\\', '/']).filter(|s| !s.is_empty()).collect();
    let sys_file = segments.last().is_some_and(|leaf| {
        leaf.len() > 4
            && leaf.is_char_boundary(leaf.len() - 4)
            && seg_eq(&leaf[leaf.len() - 4..], ".sys")
    });
    sys_file
        || segments.windows(2).any(|pair| {
            let drivers = (seg_eq(pair[0], "System32") || seg_eq(pair[0], "SysWOW64"))
                && seg_eq(pair[1], "drivers");
            let store = seg_eq(pair[0], "System32") && seg_eq(pair[1], "DriverStore");
            drivers || store
        })
}

/// For a registry item under a `Classes` root: its key path in lower case, and whether the item is a key
/// (as opposed to a value or segment of the key).
fn classes_key(target: &Target) -> Option<(String, bool)> {
    let is_key_item = matches!(target, Target::RegKey { .. });
    if !target.is_registry() {
        return None;
    }
    let typed = TypedTarget::try_from(target).ok()?;
    let segments: Vec<&str> = typed.path().split('\\').collect();
    let under = |root: &str| {
        segments.len() >= 2 && seg_eq(segments[0], root) && seg_eq(segments[1], "Classes")
    };
    let classes = match typed.hive() {
        Hive::HkuClasses(_) => true,
        Hive::Hklm => under("SOFTWARE"),
        Hive::Hku(_) => under("Software"),
    };
    classes.then(|| (typed.key_path().to_lowercase(), is_key_item))
}

// ---- Backends -------------------------------------------------------------------------------------

/// Creates a restore point. Called on a helper thread, once per requested run.
pub trait RestorePointBackend: Send + 'static {
    /// Asks for a restore point named `description` and reports the answer. May block for minutes.
    fn create(&self, description: &str) -> SrOutcome;
}

/// The real backend: `purge_win::sr::create_restore_point` (`SRSetRestorePointW`,
/// `APPLICATION_UNINSTALL`). It changes no System Restore setting.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRestore;

impl RestorePointBackend for SystemRestore {
    fn create(&self, description: &str) -> SrOutcome {
        sr::create_restore_point(description)
    }
}

/// Asks who holds files. Query only: there is deliberately no way to shut anything down through this
/// trait.
pub trait LockerQuery {
    /// The processes and services holding any of `files` (absolute paths of files, not directories),
    /// with the reboot reasons. Each call is a session of its own, ended before it returns.
    fn query(&self, files: &[PathBuf]) -> Result<LockerList, Win32Error>;
}

/// The real backend: one Restart Manager session per call (`RmStartSession`, `RmRegisterResources` with
/// files only, `RmGetList`, `RmEndSession`). Never calls `RmShutdown` or `RmRestart`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RestartManager;

impl LockerQuery for RestartManager {
    fn query(&self, files: &[PathBuf]) -> Result<LockerList, Win32Error> {
        let mut session = RmSession::start()?;
        for chunk in files.chunks(RM_REGISTER_CHUNK) {
            session.register_files(chunk)?;
        }
        let list = session.list()?;
        // The list is complete at this point; a failure to end the session does not change it (dropping
        // would end it the same way, silently).
        let _ = session.end();
        Ok(list)
    }
}

// ---- Lockers --------------------------------------------------------------------------------------

/// The holders of one item's file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemLockers {
    /// The op id of the item.
    pub op: OpId,
    /// Who holds its file.
    pub lockers: Vec<Locker>,
}

/// What Restart Manager said about the selected files, for the report (the "needs" list: programs to
/// close). This process itself is never listed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockerReport {
    /// How many files were registered.
    pub files: u32,
    /// Every holder of any registered file, each once, in Restart Manager's order.
    pub lockers: Vec<Locker>,
    /// The holders per item, for the items it could tell; items without holders are not listed.
    pub items: Vec<ItemLockers>,
    /// Whether the lists are complete: false when a query failed, when Restart Manager could not see
    /// every holder (not elevated), or when not every file could be matched to its holders.
    pub complete: bool,
}

impl LockerReport {
    /// The holders recorded for one item; empty when none were found or the item was not attributed.
    pub fn for_op(&self, op: OpId) -> &[Locker] {
        self.items
            .iter()
            .find(|i| i.op == op)
            .map_or(&[], |i| i.lockers.as_slice())
    }
}

/// The model's view of a Restart Manager list, without this process, each holder once.
fn holders(list: &LockerList, own_pid: u32) -> Vec<Locker> {
    let mut out: Vec<Locker> = Vec::new();
    for raw in list.lockers.iter().filter(|l| l.pid != own_pid) {
        let locker = Locker {
            pid: raw.pid,
            name: raw.app_name.clone(),
            service: raw.service_name.clone(),
        };
        if !out.contains(&locker) {
            out.push(locker);
        }
    }
    out
}

/// "Name (pid 12)" or "Name (service Svc, pid 12)".
fn describe(locker: &Locker) -> String {
    match &locker.service {
        Some(service) => format!("{} (service {service}, pid {})", locker.name, locker.pid),
        None => format!("{} (pid {})", locker.name, locker.pid),
    }
}

/// The plain files among the validated items: `Path` targets whose validated facts show a file that is
/// not a directory, with an absolute path.
fn plain_files(validated: &[Validated]) -> Vec<(OpId, PathBuf)> {
    validated
        .iter()
        .filter_map(|v| match (&v.target, &v.facts) {
            (Target::Path { path }, ItemFacts::File(facts)) if !facts.is_dir => {
                let path = PathBuf::from(path);
                path.is_absolute().then_some((v.op, path))
            }
            _ => None,
        })
        .collect()
}

/// Registers the plain files, lists their holders and matches holders to items. Never fails; problems
/// become warnings.
fn collect_lockers<Q: LockerQuery + ?Sized>(
    validated: &[Validated],
    rm: &Q,
    own_pid: u32,
    warnings: &mut Vec<String>,
) -> LockerReport {
    let files = plain_files(validated);
    let mut report = LockerReport {
        files: u32::try_from(files.len()).unwrap_or(u32::MAX),
        complete: true,
        ..LockerReport::default()
    };
    if files.is_empty() {
        return report;
    }
    let paths: Vec<PathBuf> = files.iter().map(|(_, p)| p.clone()).collect();
    let list = match rm.query(&paths) {
        Ok(list) => list,
        Err(e) => {
            warnings.push(format!(
                "Restart Manager could not list the programs holding the {} selected files (Win32 \
                 error {}); the run went on without that list.",
                files.len(),
                e.code()
            ));
            report.complete = false;
            return report;
        }
    };
    if list.reboot_reasons.has(RebootReasons::PERMISSION_DENIED) {
        report.complete = false;
        warnings.push(
            "Some programs holding selected files could not be identified without administrator \
             rights."
                .to_owned(),
        );
    }
    report.lockers = holders(&list, own_pid);
    if report.lockers.is_empty() {
        return report;
    }
    warnings.push(format!(
        "Programs holding files selected for removal: {}.",
        report
            .lockers
            .iter()
            .map(describe)
            .collect::<Vec<_>>()
            .join(", ")
    ));

    if let [(op, _)] = files.as_slice() {
        report.items.push(ItemLockers {
            op: *op,
            lockers: report.lockers.clone(),
        });
        return report;
    }
    let started = Instant::now();
    let mut attributed = 0usize;
    for (op, path) in files.iter().take(MAX_ATTRIBUTED_FILES) {
        if started.elapsed() >= ATTRIBUTION_BUDGET {
            break;
        }
        attributed += 1;
        match rm.query(std::slice::from_ref(path)) {
            Ok(list) => {
                let lockers = holders(&list, own_pid);
                if !lockers.is_empty() {
                    report.items.push(ItemLockers { op: *op, lockers });
                }
            }
            Err(_) => report.complete = false,
        }
    }
    if attributed < files.len() {
        report.complete = false;
        warnings.push(format!(
            "Holders were matched to items for {attributed} of {} files only.",
            files.len()
        ));
    }
    report
}

// ---- Restore point --------------------------------------------------------------------------------

/// What became of the restore point, as prepare records it. Serialised as an object tagged by `"kind"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum RestorePointStatus {
    /// The setting did not ask for one.
    NotRequested,
    /// A new restore point was created.
    Created {
        /// Its sequence number.
        sequence: u64,
    },
    /// Windows created none because one was created within its throttle window.
    Throttled {
        /// The sequence number Windows returned (that of the existing point).
        sequence: u64,
    },
    /// System Restore is off, or this edition has none.
    Disabled,
    /// The request failed, or the helper thread could not run or ended without an answer.
    Failed {
        /// The Win32 error code.
        os_error: u32,
    },
    /// No answer had arrived when the run stopped waiting; the request may still complete.
    StillRunning {
        /// Milliseconds since the request started.
        waited_ms: u64,
    },
}

impl RestorePointStatus {
    fn from_sr(outcome: SrOutcome) -> Self {
        match outcome {
            SrOutcome::Created { seq } => RestorePointStatus::Created { sequence: seq },
            SrOutcome::Throttled { seq } => RestorePointStatus::Throttled { sequence: seq },
            SrOutcome::Disabled => RestorePointStatus::Disabled,
            SrOutcome::Failed(code) => RestorePointStatus::Failed { os_error: code },
        }
    }

    /// The `purge.exec/1` form. That model has no "still running": it is reported as
    /// `Failed { os_error: 997 }` (`ERROR_IO_PENDING`) with a warning that says so. A sequence number
    /// above `i64::MAX` is reported as `i64::MAX`.
    pub fn report_outcome(self) -> RestorePointOutcome {
        match self {
            RestorePointStatus::NotRequested => RestorePointOutcome::NotRequested,
            RestorePointStatus::Created { sequence } => RestorePointOutcome::Created {
                sequence: i64::try_from(sequence).unwrap_or(i64::MAX),
            },
            RestorePointStatus::Throttled { .. } => RestorePointOutcome::Throttled,
            RestorePointStatus::Disabled => RestorePointOutcome::Disabled,
            RestorePointStatus::Failed { os_error } => RestorePointOutcome::Failed { os_error },
            RestorePointStatus::StillRunning { .. } => RestorePointOutcome::Failed {
                os_error: ERROR_IO_PENDING,
            },
        }
    }

    /// The report warning for this status; `None` when there is nothing to say.
    pub fn warning(self) -> Option<String> {
        const GOES_ON: &str = "the run went on; quarantine and backups are unaffected.";
        match self {
            RestorePointStatus::NotRequested | RestorePointStatus::Created { .. } => None,
            RestorePointStatus::Throttled { sequence } => Some(format!(
                "Windows created no new restore point because one was created recently (sequence \
                 {sequence}); {GOES_ON}"
            )),
            RestorePointStatus::Disabled => Some(format!(
                "No restore point was created because System Restore is turned off; {GOES_ON}"
            )),
            RestorePointStatus::Failed { os_error } => Some(format!(
                "Creating a restore point failed (Win32 error {os_error}); {GOES_ON}"
            )),
            RestorePointStatus::StillRunning { waited_ms } => Some(format!(
                "The restore point was still being created after {} s; {GOES_ON}",
                waited_ms / 1000
            )),
        }
    }
}

/// The restore-point request in flight. Private: the per-item path has no way to look at it.
#[derive(Debug)]
enum RestorePointRun {
    /// Settled: not requested, answered, or the thread could not run.
    Settled(RestorePointStatus),
    /// The helper thread is working.
    Running {
        rx: Receiver<SrOutcome>,
        started: Instant,
        thread: JoinHandle<()>,
    },
}

impl RestorePointRun {
    /// Starts the helper thread when `requested`.
    fn start<R: RestorePointBackend>(requested: bool, backend: R, description: String) -> Self {
        if !requested {
            return RestorePointRun::Settled(RestorePointStatus::NotRequested);
        }
        let (tx, rx) = mpsc::channel();
        let spawned = thread::Builder::new()
            .name("purge-restore-point".into())
            .spawn(move || {
                let outcome = backend.create(&description);
                // The receiver may be gone (the run finished without waiting); nothing to do then.
                let _ = tx.send(outcome);
            });
        match spawned {
            Ok(thread) => RestorePointRun::Running {
                rx,
                started: Instant::now(),
                thread,
            },
            Err(e) => RestorePointRun::Settled(RestorePointStatus::Failed {
                os_error: e
                    .raw_os_error()
                    .and_then(|c| u32::try_from(c).ok())
                    .unwrap_or(ERROR_NOT_ENOUGH_MEMORY),
            }),
        }
    }

    /// Waits for the answer until `deadline(start of the request)` at most; `None` (a deadline beyond
    /// what `Instant` holds) waits for as long as it takes.
    fn wait_until(self, deadline: impl Fn(Instant) -> Option<Instant>) -> Self {
        let RestorePointRun::Running {
            rx,
            started,
            thread,
        } = self
        else {
            return self;
        };
        let remaining = deadline(started).map_or(Duration::MAX, |deadline| {
            deadline.saturating_duration_since(Instant::now())
        });
        match rx.recv_timeout(remaining) {
            Ok(outcome) => {
                let _ = thread.join();
                RestorePointRun::Settled(RestorePointStatus::from_sr(outcome))
            }
            Err(RecvTimeoutError::Disconnected) => {
                // The thread ended without an answer: the backend panicked.
                let _ = thread.join();
                RestorePointRun::Settled(RestorePointStatus::Failed {
                    os_error: ERROR_INTERNAL_ERROR,
                })
            }
            Err(RecvTimeoutError::Timeout) => RestorePointRun::Running {
                rx,
                started,
                thread,
            },
        }
    }

    /// The final status: still running when no answer has come; the thread is then left to finish on its
    /// own.
    fn status(self) -> RestorePointStatus {
        match self {
            RestorePointRun::Settled(status) => status,
            RestorePointRun::Running { started, .. } => RestorePointStatus::StillRunning {
                waited_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            },
        }
    }
}

// ---- Prepare --------------------------------------------------------------------------------------

/// What [`prepare`] needs.
#[derive(Debug, Clone)]
pub struct PrepareRequest<'a> {
    /// The user's restore-point setting.
    pub setting: RestorePointSetting,
    /// Why the run is high-risk ([`risk_reasons`]).
    pub risk: Vec<RiskReason>,
    /// The restore point's description ([`restore_point_description`]).
    pub description: String,
    /// The `validated` records of the run: the plain files among them are queried for holders.
    pub validated: &'a [Validated],
    /// How long to wait for the restore point, from the start of its thread
    /// ([`RESTORE_POINT_WAIT`]).
    pub wait: Duration,
}

/// The prepare step in progress. Only the locker report can be read; the restore point's outcome comes
/// out through [`Prepared::finish`] alone, after the run (see the module documentation).
#[derive(Debug)]
#[must_use = "call finish() after the last item to record the restore point's outcome"]
pub struct Prepared {
    setting: RestorePointSetting,
    risk: Vec<RiskReason>,
    lockers: LockerReport,
    warnings: Vec<String>,
    restore_point: RestorePointRun,
}

impl Prepared {
    /// Who holds the selected files, for the report.
    pub fn lockers(&self) -> &LockerReport {
        &self.lockers
    }

    /// Ends the prepare step: waits at most `wait` more for a restore point still being created
    /// ([`RESTORE_POINT_FINISH_WAIT`]) and returns the record for the report. A request still running
    /// after that is recorded as [`RestorePointStatus::StillRunning`] and left to finish on its own.
    pub fn finish(self, wait: Duration) -> PrepareRecord {
        let now = Instant::now();
        let status = self
            .restore_point
            .wait_until(|_| now.checked_add(wait))
            .status();
        let mut warnings = self.warnings;
        warnings.extend(status.warning());
        PrepareRecord {
            setting: self.setting,
            risk: self.risk,
            restore_point: status,
            lockers: self.lockers,
            warnings,
        }
    }
}

/// The outcome of the prepare step, for the report (and, if the executor wishes, a session file).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareRecord {
    /// The setting the run used.
    pub setting: RestorePointSetting,
    /// Why the run was high-risk; empty when it was not.
    pub risk: Vec<RiskReason>,
    /// What became of the restore point.
    pub restore_point: RestorePointStatus,
    /// Who held the selected files.
    pub lockers: LockerReport,
    /// Messages for `ExecReport.warnings`, in order.
    pub warnings: Vec<String>,
}

impl PrepareRecord {
    /// `ExecReport.restore_point` ([`RestorePointStatus::report_outcome`]).
    pub fn report_outcome(&self) -> RestorePointOutcome {
        self.restore_point.report_outcome()
    }
}

/// Runs the prepare step: starts the restore point on a helper thread when the setting asks for one,
/// queries Restart Manager meanwhile, then waits for the restore point until `request.wait` after its
/// start at most. Never fails and never blocks longer than that wait plus the queries; every problem
/// becomes a warning in the eventual [`PrepareRecord`].
pub fn prepare<R: RestorePointBackend, Q: LockerQuery + ?Sized>(
    request: PrepareRequest<'_>,
    restore_points: R,
    rm: &Q,
) -> Prepared {
    let requested = request.setting.requests(&request.risk);
    let run = RestorePointRun::start(requested, restore_points, request.description);
    let mut warnings = Vec::new();
    let lockers = collect_lockers(request.validated, rm, std::process::id(), &mut warnings);
    let wait = request.wait;
    let run = run.wait_until(|started| started.checked_add(wait));
    Prepared {
        setting: request.setting,
        risk: request.risk,
        lockers,
        warnings,
        restore_point: run,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::Sender;
    use std::sync::{Arc, Mutex};

    use purge_model::CandidateId;
    use purge_model::exec::journal::{FileFacts, GateExemptions, RegFacts};
    use purge_model::exec::op::FileIdHex;
    use purge_win::rm::LockerKind;

    const SID: &str = "S-1-5-21-1-2-3-1001";

    // ---- fakes ----

    /// A restore-point backend that returns a fixed outcome, optionally only after a signal.
    struct FakeSr {
        outcome: SrOutcome,
        calls: Arc<AtomicUsize>,
        descriptions: Arc<Mutex<Vec<String>>>,
        /// When set, `create` blocks until this receives a message or its sender is dropped.
        hold: Option<Receiver<()>>,
        panic: bool,
    }

    impl FakeSr {
        fn new(outcome: SrOutcome) -> FakeSr {
            FakeSr {
                outcome,
                calls: Arc::new(AtomicUsize::new(0)),
                descriptions: Arc::new(Mutex::new(Vec::new())),
                hold: None,
                panic: false,
            }
        }

        /// The same backend, held until the returned sender sends or is dropped.
        fn held(mut self) -> (FakeSr, Sender<()>) {
            let (tx, rx) = mpsc::channel();
            self.hold = Some(rx);
            (self, tx)
        }
    }

    impl RestorePointBackend for FakeSr {
        fn create(&self, description: &str) -> SrOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.descriptions
                .lock()
                .unwrap()
                .push(description.to_owned());
            if let Some(hold) = &self.hold {
                let _ = hold.recv();
            }
            assert!(!self.panic, "fake restore-point backend failure");
            self.outcome
        }
    }

    /// A Restart Manager stand-in: holders per file, a fixed error, the reboot reasons, and a log of the
    /// file lists it was asked about.
    #[derive(Default)]
    struct FakeRm {
        holders: HashMap<PathBuf, Vec<purge_win::rm::Locker>>,
        fail: Option<Win32Error>,
        /// Fails every call after the first.
        fail_after_first: bool,
        reasons: u32,
        calls: RefCell<Vec<Vec<PathBuf>>>,
        /// Sent on every call (to show the query runs while the restore point is being created).
        notify: Option<Sender<()>>,
    }

    impl LockerQuery for FakeRm {
        fn query(&self, files: &[PathBuf]) -> Result<LockerList, Win32Error> {
            let first = self.calls.borrow().is_empty();
            self.calls.borrow_mut().push(files.to_vec());
            if let Some(notify) = &self.notify {
                let _ = notify.send(());
            }
            if let Some(e) = self.fail {
                return Err(e);
            }
            if self.fail_after_first && !first {
                return Err(Win32Error::ACCESS_DENIED);
            }
            let mut lockers = Vec::new();
            for f in files {
                lockers.extend(self.holders.get(f).cloned().unwrap_or_default());
            }
            Ok(LockerList {
                lockers,
                reboot_reasons: RebootReasons(self.reasons),
            })
        }
    }

    fn raw_locker(pid: u32, name: &str, service: Option<&str>) -> purge_win::rm::Locker {
        purge_win::rm::Locker {
            pid,
            start_time: 1,
            app_name: name.into(),
            service_name: service.map(str::to_owned),
            kind: if service.is_some() {
                LockerKind::Service
            } else {
                LockerKind::MainWindow
            },
            restartable: false,
            ts_session: Some(1),
        }
    }

    fn locker(pid: u32, name: &str, service: Option<&str>) -> Locker {
        Locker {
            pid,
            name: name.into(),
            service: service.map(str::to_owned),
        }
    }

    // ---- builders ----

    fn path(p: &str) -> Target {
        Target::Path { path: p.into() }
    }

    fn key(p: &str) -> Target {
        Target::RegKey { path: p.into() }
    }

    fn value(p: &str, name: &str) -> Target {
        Target::RegValue {
            path: p.into(),
            name: name.into(),
        }
    }

    fn item(target: &Target) -> RiskItem<'_> {
        RiskItem {
            target,
            harm: Harm::Low,
            subtree_keys: None,
        }
    }

    fn file_facts(p: &str, is_dir: bool) -> ItemFacts {
        ItemFacts::File(FileFacts {
            final_path: p.into(),
            file_id: FileIdHex([1; 16]),
            volume_serial: 7,
            reparse_tag: 0,
            attributes: if is_dir { 16 } else { 32 },
            n_links: 1,
            is_dir,
            size: 0,
            tree_entries: None,
            tree_bytes: None,
        })
    }

    fn validated(op: u32, target: Target, facts: ItemFacts) -> Validated {
        Validated {
            op: OpId(op),
            item: CandidateId(format!("c-{op:02}")),
            target,
            facts,
            exemptions: GateExemptions::default(),
        }
    }

    fn file_item(op: u32, p: &str) -> Validated {
        validated(op, path(p), file_facts(p, false))
    }

    fn request(
        setting: RestorePointSetting,
        risk: Vec<RiskReason>,
        v: &[Validated],
    ) -> PrepareRequest<'_> {
        PrepareRequest {
            setting,
            risk,
            description: restore_point_description("vendor-app"),
            validated: v,
            wait: Duration::from_secs(10),
        }
    }

    fn forced() -> Vec<RiskReason> {
        vec![RiskReason::ForcedMode]
    }

    // ---- policy ----

    #[test]
    fn policy_table() {
        use RestorePointSetting::*;
        let high = forced();
        let low: Vec<RiskReason> = Vec::new();
        // (setting, high-risk run, requests)
        let table = [
            (Off, false, false),
            (Off, true, false),
            (HighRiskOnly, false, false),
            (HighRiskOnly, true, true),
            (Always, false, true),
            (Always, true, true),
        ];
        for (setting, is_high, expected) in table {
            let reasons = if is_high { &high } else { &low };
            assert_eq!(
                setting.requests(reasons),
                expected,
                "{setting:?} high={is_high}"
            );
        }
        assert_eq!(RestorePointSetting::default(), HighRiskOnly);
        for (text, setting) in [
            (r#""Off""#, Off),
            (r#""HighRiskOnly""#, HighRiskOnly),
            (r#""Always""#, Always),
        ] {
            assert_eq!(serde_json::to_string(&setting).unwrap(), text);
            assert_eq!(
                serde_json::from_str::<RestorePointSetting>(text).unwrap(),
                setting
            );
        }
    }

    #[test]
    fn each_risk_rule_on_its_own() {
        let plain = [
            path(r"C:\Program Files\Vendor\app.exe"),
            key(r"HKLM\SOFTWARE\Vendor"),
            value(&format!(r"HKU\{SID}\Software\Vendor"), "x"),
        ];
        let plain_items: Vec<_> = plain.iter().map(item).collect();
        for mode in [ScanMode::Post, ScanMode::External] {
            assert!(risk_reasons(&plain_items, mode).is_empty());
            assert!(!is_high_risk(&plain_items, mode));
        }
        assert!(!is_high_risk(&[], ScanMode::Post));
        // Forced mode alone.
        assert_eq!(
            risk_reasons(&plain_items, ScanMode::Forced),
            vec![RiskReason::ForcedMode]
        );
        assert!(is_high_risk(&[], ScanMode::Forced));

        // Service and driver targets.
        let service_like = [
            Target::Service {
                name: "VendorSvc".into(),
            },
            key(r"HKLM\SYSTEM\CurrentControlSet\Services\VendorSvc"),
            key(r"HKLM\SYSTEM\ControlSet001\Services\vendordrv"),
            value(
                r"hklm\system\currentcontrolset\services\VendorSvc\Parameters",
                "x",
            ),
            path(r"C:\Windows\System32\drivers\vendordrv.sys"),
            path(r"C:\Windows\System32\DRIVERS\etc-not-a-driver-but-under-drivers"),
            path(r"C:\Windows\SysWOW64\drivers\x.dll"),
            path(r"C:\Windows\System32\DriverStore\FileRepository\vendor.inf_amd64_1"),
            path(r"C:\Program Files\Vendor\filter.SYS"),
        ];
        for target in &service_like {
            assert_eq!(
                risk_reasons(&[item(target)], ScanMode::Post),
                vec![RiskReason::ServiceOrDriver {
                    items: 1,
                    first: target.clone()
                }],
                "{target:?}"
            );
        }
        let all: Vec<_> = service_like.iter().map(item).collect();
        assert_eq!(
            risk_reasons(&all, ScanMode::Post),
            vec![RiskReason::ServiceOrDriver {
                items: service_like.len() as u32,
                first: service_like[0].clone()
            }]
        );
        // A critical candidate is a driver or filter by the policy's rating.
        let mut critical = item(&plain[0]);
        critical.harm = Harm::Critical;
        assert!(is_high_risk(&[critical], ScanMode::Post));

        // Near misses.
        for target in [
            key(r"HKLM\SYSTEM\CurrentControlSet\Services"),
            key(r"HKLM\SYSTEM\ControlSet01\Services\X"),
            key(r"HKLM\SYSTEM\ControlSetABC\Services\X"),
            key(r"HKLM\SOFTWARE\Services\X"),
            key(&format!(r"HKU\{SID}\SYSTEM\CurrentControlSet\Services\X")),
            path(r"C:\Program Files\Vendor\drivers\readme.txt"),
            path(r"C:\Program Files\Vendor\.sys"),
            path(r"C:\Program Files\Vendor\x.sysx"),
            Target::Task {
                path: r"\Vendor\Update".into(),
            },
            key(r"HKCU\SYSTEM\CurrentControlSet\Services\X"),
        ] {
            assert!(
                !is_high_risk(&[item(&target)], ScanMode::Post),
                "{target:?}"
            );
        }
    }

    #[test]
    fn classes_key_count() {
        let roots = [
            r"HKLM\SOFTWARE\Classes".to_owned(),
            r"HKLM\SOFTWARE\WOW6432Node\Classes".to_owned(),
            format!(r"HKU\{SID}_Classes"),
            format!(r"HKU\{SID}\Software\Classes"),
        ];
        for root in &roots {
            let targets: Vec<Target> = (0..CLASSES_KEY_LIMIT + 1)
                .map(|i| key(&format!(r"{root}\CLSID\{{{i}}}")))
                .collect();
            let items: Vec<_> = targets.iter().map(item).collect();
            assert!(!is_high_risk(&items[..500], ScanMode::Post), "{root}");
            assert_eq!(
                risk_reasons(&items, ScanMode::Post),
                vec![RiskReason::ClassesKeys { keys: 501 }],
                "{root}"
            );
        }

        // Counted subtrees; a key named twice counts once, with its larger count; values count their
        // key once; spelling differences in case do not add keys.
        let big = key(r"HKLM\SOFTWARE\Classes\Vendor.Doc");
        let same = key(r"hklm\software\classes\VENDOR.DOC");
        let v = value(r"HKLM\SOFTWARE\Classes\Vendor.Doc", "");
        let other = value(r"HKLM\SOFTWARE\Classes\.vdoc", "");
        let items = [
            item(&big).with_subtree_keys(499),
            item(&same).with_subtree_keys(10),
            item(&v),
            item(&other),
        ];
        assert!(!is_high_risk(&items, ScanMode::Post));
        let items = [item(&big).with_subtree_keys(500), item(&other)];
        assert_eq!(
            risk_reasons(&items, ScanMode::Post),
            vec![RiskReason::ClassesKeys { keys: 501 }]
        );
        // A zero count still counts the key itself.
        assert!(!is_high_risk(
            &[item(&big).with_subtree_keys(0)],
            ScanMode::Post
        ));

        // Not under Classes.
        let elsewhere: Vec<Target> = (0..600)
            .map(|i| key(&format!(r"HKLM\SOFTWARE\ClassesX\{i}")))
            .chain((0..600).map(|i| key(&format!(r"HKU\{SID}\Software\Vendor\Classes\{i}"))))
            .chain((0..600).map(|i| key(&format!(r"HKLM\SYSTEM\Classes\{i}"))))
            .collect();
        let items: Vec<_> = elsewhere.iter().map(item).collect();
        assert!(!is_high_risk(&items, ScanMode::Post));
        let huge = key(r"HKLM\SOFTWARE\Vendor");
        assert!(!is_high_risk(
            &[item(&huge).with_subtree_keys(100_000)],
            ScanMode::Post
        ));
    }

    #[test]
    fn reasons_combine_in_a_fixed_order() {
        let svc = Target::Service { name: "S".into() };
        let classes = key(r"HKLM\SOFTWARE\Classes\CLSID\{X}");
        let items = [item(&classes).with_subtree_keys(1000), item(&svc)];
        assert_eq!(
            risk_reasons(&items, ScanMode::Forced),
            vec![
                RiskReason::ServiceOrDriver {
                    items: 1,
                    first: svc.clone()
                },
                RiskReason::ClassesKeys { keys: 1000 },
                RiskReason::ForcedMode,
            ]
        );
    }

    // ---- restore point ----

    #[test]
    fn outcome_mapping_with_a_fake_backend() {
        let cases = [
            (
                SrOutcome::Created { seq: 118 },
                RestorePointStatus::Created { sequence: 118 },
                RestorePointOutcome::Created { sequence: 118 },
                false,
            ),
            (
                SrOutcome::Throttled { seq: 117 },
                RestorePointStatus::Throttled { sequence: 117 },
                RestorePointOutcome::Throttled,
                true,
            ),
            (
                SrOutcome::Disabled,
                RestorePointStatus::Disabled,
                RestorePointOutcome::Disabled,
                true,
            ),
            (
                SrOutcome::Failed(5),
                RestorePointStatus::Failed { os_error: 5 },
                RestorePointOutcome::Failed { os_error: 5 },
                true,
            ),
        ];
        let files = [file_item(1, r"C:\Vendor\a.dll")];
        for (sr_outcome, status, report, warns) in cases {
            let fake = FakeSr::new(sr_outcome);
            let calls = fake.calls.clone();
            let descriptions = fake.descriptions.clone();
            let rm = FakeRm::default();
            let prepared = prepare(
                request(RestorePointSetting::HighRiskOnly, forced(), &files),
                fake,
                &rm,
            );
            // The run goes on: prepare returned, and the files were queried.
            assert_eq!(rm.calls.borrow().len(), 1);
            let record = prepared.finish(Duration::ZERO);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(
                descriptions.lock().unwrap().as_slice(),
                ["Purge: leftovers of vendor-app"]
            );
            assert_eq!(record.restore_point, status, "{sr_outcome:?}");
            assert_eq!(record.report_outcome(), report, "{sr_outcome:?}");
            assert_eq!(record.warnings.len(), usize::from(warns), "{record:?}");
            if warns {
                assert!(record.warnings[0].contains("the run went on"), "{record:?}");
            }
            assert_eq!(record.risk, forced());
        }
        // A sequence number beyond i64 is clamped in the report.
        assert_eq!(
            RestorePointStatus::Created { sequence: u64::MAX }.report_outcome(),
            RestorePointOutcome::Created { sequence: i64::MAX }
        );
    }

    #[test]
    fn not_requested_never_calls_the_backend() {
        for (setting, risk) in [
            (RestorePointSetting::Off, forced()),
            (RestorePointSetting::HighRiskOnly, Vec::new()),
        ] {
            let fake = FakeSr::new(SrOutcome::Created { seq: 1 });
            let calls = fake.calls.clone();
            let record = prepare(request(setting, risk, &[]), fake, &FakeRm::default())
                .finish(RESTORE_POINT_FINISH_WAIT);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(record.restore_point, RestorePointStatus::NotRequested);
            assert_eq!(record.report_outcome(), RestorePointOutcome::NotRequested);
            assert!(record.warnings.is_empty());
        }
        // Always asks even for a low-risk run.
        let fake = FakeSr::new(SrOutcome::Created { seq: 3 });
        let calls = fake.calls.clone();
        let record = prepare(
            request(RestorePointSetting::Always, Vec::new(), &[]),
            fake,
            &FakeRm::default(),
        )
        .finish(Duration::ZERO);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            record.restore_point,
            RestorePointStatus::Created { sequence: 3 }
        );
    }

    #[test]
    fn a_slow_restore_point_does_not_hold_the_run() {
        let (fake, release) = FakeSr::new(SrOutcome::Created { seq: 9 }).held();
        let mut req = request(RestorePointSetting::Always, Vec::new(), &[]);
        req.wait = Duration::from_millis(50);
        let started = Instant::now();
        let prepared = prepare(req, fake, &FakeRm::default());
        // Prepare returned after its bounded wait, without an answer.
        assert!(started.elapsed() < Duration::from_secs(5));
        let record = prepared.finish(Duration::from_millis(20));
        match record.restore_point {
            RestorePointStatus::StillRunning { waited_ms } => assert!(waited_ms >= 50),
            other => panic!("expected StillRunning, got {other:?}"),
        }
        assert_eq!(
            record.report_outcome(),
            RestorePointOutcome::Failed {
                os_error: ERROR_IO_PENDING
            }
        );
        assert_eq!(record.warnings.len(), 1);
        assert!(record.warnings[0].contains("still being created"));
        // The helper finishes on its own; its answer has nowhere to go and is dropped.
        release.send(()).unwrap();
    }

    #[test]
    fn a_late_answer_is_recorded_by_finish() {
        let (fake, release) = FakeSr::new(SrOutcome::Created { seq: 42 }).held();
        let mut req = request(RestorePointSetting::Always, Vec::new(), &[]);
        req.wait = Duration::from_millis(10);
        let prepared = prepare(req, fake, &FakeRm::default());
        release.send(()).unwrap();
        let record = prepared.finish(Duration::from_secs(10));
        assert_eq!(
            record.restore_point,
            RestorePointStatus::Created { sequence: 42 }
        );
        assert!(record.warnings.is_empty());
    }

    #[test]
    fn a_panicking_backend_is_a_failure_not_a_crash() {
        let mut fake = FakeSr::new(SrOutcome::Created { seq: 1 });
        fake.panic = true;
        let files = [file_item(1, r"C:\Vendor\a.dll")];
        let rm = FakeRm::default();
        let record = prepare(
            request(RestorePointSetting::Always, Vec::new(), &files),
            fake,
            &rm,
        )
        .finish(Duration::from_secs(10));
        assert_eq!(
            record.restore_point,
            RestorePointStatus::Failed {
                os_error: ERROR_INTERNAL_ERROR
            }
        );
        assert_eq!(rm.calls.borrow().len(), 1);
        assert_eq!(record.warnings.len(), 1);
    }

    #[test]
    fn restart_manager_runs_while_the_restore_point_is_created() {
        // The restore point completes only once Restart Manager has been queried: if prepare ran the two
        // one after the other, the restore point would still be running when prepare stopped waiting.
        let (fake, release) = FakeSr::new(SrOutcome::Created { seq: 5 }).held();
        let (notify, notified) = mpsc::channel();
        let relay = thread::spawn(move || {
            if notified.recv().is_ok() {
                let _ = release.send(());
            }
        });
        let rm = FakeRm {
            notify: Some(notify),
            ..FakeRm::default()
        };
        let files = [file_item(1, r"C:\Vendor\a.dll")];
        let mut req = request(RestorePointSetting::Always, Vec::new(), &files);
        req.wait = Duration::from_secs(10);
        let prepared = prepare(req, fake, &rm);
        drop(rm);
        relay.join().unwrap();
        let record = prepared.finish(Duration::ZERO);
        assert_eq!(
            record.restore_point,
            RestorePointStatus::Created { sequence: 5 }
        );
    }

    // ---- lockers ----

    #[test]
    fn only_plain_files_are_registered() {
        let v = [
            file_item(1, r"C:\Vendor\a.dll"),
            validated(
                2,
                path(r"C:\Vendor\dir"),
                file_facts(r"C:\Vendor\dir", true),
            ),
            validated(
                3,
                key(r"HKLM\SOFTWARE\Vendor"),
                ItemFacts::Key(RegFacts {
                    subkeys: 0,
                    values: 0,
                    is_link: false,
                    owner: "S-1-5-32-544".into(),
                    last_write_time: purge_model::FileTime(1),
                }),
            ),
            validated(4, path(r"C:\Vendor\gone.txt"), ItemFacts::Absent),
            validated(
                5,
                path(r"relative\x.txt"),
                file_facts(r"relative\x.txt", false),
            ),
            file_item(6, r"C:\Vendor\b.exe"),
        ];
        let rm = FakeRm::default();
        let record = prepare(
            request(RestorePointSetting::Off, Vec::new(), &v),
            FakeSr::new(SrOutcome::Disabled),
            &rm,
        )
        .finish(Duration::ZERO);
        assert_eq!(
            *rm.calls.borrow(),
            vec![vec![
                PathBuf::from(r"C:\Vendor\a.dll"),
                PathBuf::from(r"C:\Vendor\b.exe")
            ]]
        );
        assert_eq!(record.lockers.files, 2);
        assert!(record.lockers.complete);
        assert!(record.lockers.lockers.is_empty());
        assert!(record.warnings.is_empty());

        // Nothing to register: Restart Manager is not asked at all.
        let rm = FakeRm::default();
        let record = prepare(
            request(RestorePointSetting::Off, Vec::new(), &v[1..5]),
            FakeSr::new(SrOutcome::Disabled),
            &rm,
        )
        .finish(Duration::ZERO);
        assert!(rm.calls.borrow().is_empty());
        assert_eq!(
            record.lockers,
            LockerReport {
                complete: true,
                ..LockerReport::default()
            }
        );
    }

    #[test]
    fn holders_are_named_per_item_without_this_process() {
        let own = std::process::id();
        let a = PathBuf::from(r"C:\Vendor\a.dll");
        let b = PathBuf::from(r"C:\Vendor\b.dll");
        let c = PathBuf::from(r"C:\Vendor\c.dll");
        let rm = FakeRm {
            holders: HashMap::from([
                (
                    a.clone(),
                    vec![
                        raw_locker(100, "Vendor App", None),
                        raw_locker(own, "purge", None),
                    ],
                ),
                (
                    b.clone(),
                    vec![
                        raw_locker(100, "Vendor App", None),
                        raw_locker(200, "Vendor Service", Some("VendorSvc")),
                    ],
                ),
                (c.clone(), vec![raw_locker(own, "purge", None)]),
            ]),
            ..FakeRm::default()
        };
        let v = [
            file_item(1, r"C:\Vendor\a.dll"),
            file_item(2, r"C:\Vendor\b.dll"),
            file_item(3, r"C:\Vendor\c.dll"),
        ];
        let prepared = prepare(
            request(RestorePointSetting::Off, Vec::new(), &v),
            FakeSr::new(SrOutcome::Disabled),
            &rm,
        );
        // Readable during the run: the lockers, nothing about the restore point.
        assert_eq!(prepared.lockers().for_op(OpId(2)).len(), 2);
        let record = prepared.finish(Duration::ZERO);
        let report = &record.lockers;
        assert!(report.complete);
        assert_eq!(
            report.lockers,
            vec![
                locker(100, "Vendor App", None),
                locker(200, "Vendor Service", Some("VendorSvc"))
            ]
        );
        assert_eq!(report.for_op(OpId(1)), [locker(100, "Vendor App", None)]);
        assert_eq!(
            report.for_op(OpId(2)),
            [
                locker(100, "Vendor App", None),
                locker(200, "Vendor Service", Some("VendorSvc"))
            ]
        );
        assert!(report.for_op(OpId(3)).is_empty());
        assert!(report.for_op(OpId(9)).is_empty());
        // One query for all files, then one per file.
        let calls = rm.calls.borrow();
        assert_eq!(calls.len(), 4);
        assert_eq!(calls[1], vec![a]);
        assert_eq!(calls[3], vec![c]);
        assert_eq!(
            record.warnings,
            [
                "Programs holding files selected for removal: Vendor App (pid 100), Vendor Service \
                 (service VendorSvc, pid 200)."
            ]
        );
    }

    #[test]
    fn one_file_needs_one_query() {
        let a = PathBuf::from(r"C:\Vendor\a.dll");
        let rm = FakeRm {
            holders: HashMap::from([(a, vec![raw_locker(100, "Vendor App", None)])]),
            ..FakeRm::default()
        };
        let v = [file_item(4, r"C:\Vendor\a.dll")];
        let record = prepare(
            request(RestorePointSetting::Off, Vec::new(), &v),
            FakeSr::new(SrOutcome::Disabled),
            &rm,
        )
        .finish(Duration::ZERO);
        assert_eq!(rm.calls.borrow().len(), 1);
        assert_eq!(
            record.lockers.for_op(OpId(4)),
            [locker(100, "Vendor App", None)]
        );
    }

    #[test]
    fn restart_manager_failures_are_warnings() {
        // Start or query fails: the run goes on with a warning, and the restore point still happens.
        let rm = FakeRm {
            fail: Some(Win32Error(353)), // ERROR_MAX_SESSIONS_REACHED
            ..FakeRm::default()
        };
        let v = [
            file_item(1, r"C:\Vendor\a.dll"),
            file_item(2, r"C:\Vendor\b.dll"),
        ];
        let record = prepare(
            request(RestorePointSetting::Always, Vec::new(), &v),
            FakeSr::new(SrOutcome::Created { seq: 7 }),
            &rm,
        )
        .finish(Duration::from_secs(10));
        assert!(!record.lockers.complete);
        assert_eq!(record.lockers.files, 2);
        assert!(record.lockers.lockers.is_empty());
        assert_eq!(record.warnings.len(), 1);
        assert!(record.warnings[0].contains("Restart Manager"), "{record:?}");
        assert_eq!(
            record.restore_point,
            RestorePointStatus::Created { sequence: 7 }
        );

        // Holders the caller may not see: the list is marked incomplete.
        let a = PathBuf::from(r"C:\Vendor\a.dll");
        let rm = FakeRm {
            holders: HashMap::from([(a, vec![raw_locker(100, "Vendor App", None)])]),
            reasons: RebootReasons::PERMISSION_DENIED,
            ..FakeRm::default()
        };
        let record = prepare(
            request(RestorePointSetting::Off, Vec::new(), &v[..1]),
            FakeSr::new(SrOutcome::Disabled),
            &rm,
        )
        .finish(Duration::ZERO);
        assert!(!record.lockers.complete);
        assert_eq!(record.lockers.lockers.len(), 1);
        assert!(record.warnings[0].contains("administrator"), "{record:?}");

        // The per-file queries fail after the first: holders stay listed, attribution is incomplete.
        let b = PathBuf::from(r"C:\Vendor\b.dll");
        let rm = FakeRm {
            holders: HashMap::from([(b, vec![raw_locker(300, "Other", None)])]),
            fail_after_first: true,
            ..FakeRm::default()
        };
        let record = prepare(
            request(RestorePointSetting::Off, Vec::new(), &v),
            FakeSr::new(SrOutcome::Disabled),
            &rm,
        )
        .finish(Duration::ZERO);
        assert!(!record.lockers.complete);
        assert_eq!(record.lockers.lockers, [locker(300, "Other", None)]);
        assert!(record.lockers.items.is_empty());
    }

    #[test]
    fn attribution_is_capped() {
        let n = MAX_ATTRIBUTED_FILES + 3;
        let v: Vec<Validated> = (1..=n)
            .map(|i| file_item(i as u32, &format!(r"C:\Vendor\f{i}.dll")))
            .collect();
        let last = PathBuf::from(format!(r"C:\Vendor\f{n}.dll"));
        let rm = FakeRm {
            holders: HashMap::from([(last, vec![raw_locker(100, "Vendor App", None)])]),
            ..FakeRm::default()
        };
        let record = prepare(
            request(RestorePointSetting::Off, Vec::new(), &v),
            FakeSr::new(SrOutcome::Disabled),
            &rm,
        )
        .finish(Duration::ZERO);
        assert_eq!(rm.calls.borrow().len(), 1 + MAX_ATTRIBUTED_FILES);
        assert_eq!(rm.calls.borrow()[0].len(), n);
        assert!(!record.lockers.complete);
        assert_eq!(record.lockers.lockers.len(), 1);
        assert!(record.lockers.items.is_empty());
        assert_eq!(record.warnings.len(), 2, "{record:?}");
        assert!(record.warnings[1].contains(&format!("{MAX_ATTRIBUTED_FILES} of {n}")));
    }

    #[test]
    fn record_round_trips_as_json() {
        let a = PathBuf::from(r"C:\Vendor\a.dll");
        let rm = FakeRm {
            holders: HashMap::from([(a, vec![raw_locker(100, "Vendor App", Some("Svc"))])]),
            ..FakeRm::default()
        };
        let v = [file_item(1, r"C:\Vendor\a.dll")];
        let record = prepare(
            request(RestorePointSetting::HighRiskOnly, forced(), &v),
            FakeSr::new(SrOutcome::Throttled { seq: 12 }),
            &rm,
        )
        .finish(Duration::from_secs(10));
        let text = serde_json::to_string(&record).unwrap();
        assert!(
            text.contains(r#""restore_point":{"kind":"Throttled","sequence":12}"#),
            "{text}"
        );
        assert!(text.contains(r#""risk":[{"kind":"ForcedMode"}]"#), "{text}");
        assert!(text.contains(r#""setting":"HighRiskOnly""#), "{text}");
        assert_eq!(
            serde_json::from_str::<PrepareRecord>(&text).unwrap(),
            record
        );
        for status in [
            RestorePointStatus::NotRequested,
            RestorePointStatus::Created { sequence: u64::MAX },
            RestorePointStatus::Disabled,
            RestorePointStatus::Failed { os_error: 1460 },
            RestorePointStatus::StillRunning { waited_ms: 90_000 },
        ] {
            let text = serde_json::to_string(&status).unwrap();
            assert_eq!(
                serde_json::from_str::<RestorePointStatus>(&text).unwrap(),
                status
            );
        }
    }

    #[test]
    fn candidates_feed_the_risk_rules() {
        let candidate = |target: serde_json::Value, harm: &str| -> Candidate {
            serde_json::from_value(serde_json::json!({
                "id": "c-01", "target": target, "action": "ReportOnly",
                "owner": {"program_id": "HKLM|64|Vendor_is1", "display_name": "Vendor"},
                "origin": "Scanner", "scanner": "SYS-SERVICE", "category": "System",
                "harm": harm, "reversibility": "Full",
                "size_bytes": null, "child_count": null, "decision": null
            }))
            .unwrap()
        };
        let service = candidate(
            serde_json::json!({"type": "Service", "name": "VendorSvc"}),
            "Medium",
        );
        let risk = RiskItem::from_candidate(&service);
        assert_eq!(risk.subtree_keys, None);
        assert_eq!(risk.harm, Harm::Medium);
        assert!(is_high_risk(&[risk], ScanMode::Post));
        let plain = candidate(
            serde_json::json!({"type": "Path", "path": r"C:\Vendor\x.dll"}),
            "Low",
        );
        assert!(!is_high_risk(
            &[RiskItem::from_candidate(&plain)],
            ScanMode::Post
        ));
        let critical = candidate(
            serde_json::json!({"type": "Path", "path": r"C:\Vendor\x.dll"}),
            "Critical",
        );
        assert!(is_high_risk(
            &[RiskItem::from_candidate(&critical)],
            ScanMode::Post
        ));
    }

    // ---- real backends (no system change, but outside the unit-test sandbox) ----

    #[test]
    #[ignore = "real Restart Manager query with a child process holding a temp file; run on demand"]
    fn real_restart_manager_names_a_holder() {
        use std::process::{Command, Stdio};
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "purge-exec-prepare-rm-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let held = dir.join("held.txt");
        let file = std::fs::File::create(&held).unwrap();
        let mut child = Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(file)
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let v = [file_item(1, held.to_str().unwrap())];
        let record = prepare(
            request(RestorePointSetting::Off, Vec::new(), &v),
            SystemRestore,
            &RestartManager,
        )
        .finish(Duration::ZERO);
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        println!("{record:?}");
        assert!(
            record
                .lockers
                .for_op(OpId(1))
                .iter()
                .any(|l| l.pid == child.id()),
            "{record:?}"
        );
    }

    #[test]
    #[ignore = "creates a real restore point; VM only (elevated, System Protection on)"]
    fn real_restore_point_vm() {
        let record = prepare(
            request(RestorePointSetting::Always, Vec::new(), &[]),
            SystemRestore,
            &RestartManager,
        )
        .finish(RESTORE_POINT_FINISH_WAIT);
        println!("{record:?}");
        assert!(matches!(
            record.restore_point,
            RestorePointStatus::Created { .. }
                | RestorePointStatus::Throttled { .. }
                | RestorePointStatus::Disabled
        ));
    }
}
