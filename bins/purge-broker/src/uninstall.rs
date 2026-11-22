//! `uninstall.prepare`, `uninstall.run`, `uninstall.observed` and `leftovers.stored` (M3 design 3.2,
//! 3.6; package M3-BROKER-FLOW).
//!
//! # What the broker decides, and what the client decides
//!
//! `uninstall.prepare` harvests every requested program, **for every route**: the harvest, the
//! fingerprint and the commands are the broker's own reading of its inventory. A medium-route program
//! is prepared too, because the medium engine runs its uninstaller; the broker's `uninstall.run`
//! refuses such a session with [`ErrorData::WrongRoute`].
//!
//! The commands a session runs are the ones `prepare` resolved and returned. `uninstall.run` never
//! resolves them again: it picks the interactive or the quiet [`QuietCommand`] out of the session and
//! passes it verbatim to [`Machine::run_uninstall`]. So the command shown is the command run, even if
//! the Uninstall key changes between the two requests. Before it starts anything, `uninstall.run` asks
//! the broker's consent dialog (program, exact command, signer, quiet or interactive, restore point),
//! drawn from that same command (review M3-R2 M1).
//!
//! # The fingerprint
//!
//! `prepare` writes the harvest's fingerprint under `<data root>\fp` (administrators only), keyed by a
//! SHA-256 of the program id, never by a file name a client chose. `leftovers.stored` and a scan from
//! a stored fingerprint read it back. After a run or an observation the broker writes the updated
//! fingerprint again (best effort: the session in memory is what this broker scans with).
//!
//! # Refusals
//!
//! A program id is looked up in the broker's own inventory only; one that is not there is `gone`
//! (`program`). Anything that runs is a session this broker created, and a session id that is not in
//! the tables is `gone` (`uninstall_session`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use purge_engine::pipeline::{
    self, Harvested, PipelineError, Sources, UninstallCommands, Uninstalled,
};
use purge_exec::storage::{StorageError, StorageRoots};
use purge_identity::kbdata::Kb;
use purge_inventory::quiet::QuietCommand;
use purge_inventory::runner::{LiveHost, RunOptions};
use purge_inventory::verify_gone::{self, VerifyTarget};
use purge_model::{
    Candidate, FileTime, Fingerprint, InventoryEntry, ProgramId, Target, VerifyGone,
};
use purge_rpc::error::{ErrorData, ErrorObject, IdKind, Refusal};
use purge_rpc::methods::PipeCall;
use purge_rpc::methods::{
    CoProduct, FingerprintSummary, ObservedParams, ObservedResult, PrepareResult, Prepared,
    ProgramsParams, Progress, Route, RunParams, RunResult, RunningProcess, ServerNotification,
    StoredResult,
};
use purge_rpc::table::CallSet;
use purge_source::live::Live;
use purge_source::types::ProcessInfo;
use purge_win::taskdialog::Outcome as Answer;
use serde_json::Value;

use crate::consent::dialog;
use crate::consent::view::{self, UninstallFacts};
use crate::serve::{Ctx, Handler};
use crate::session::gone;

/// The subdirectory of the data root the prepared fingerprints are stored in.
const FP_DIR: &str = "fp";
/// Largest stored fingerprint the broker reads back.
const MAX_FP_BYTES: u64 = 64 << 20;

/// What one uninstall run is given: the program, the fingerprint it updates and the exact command line
/// `prepare` showed.
pub struct RunRequest<'a> {
    /// The program being uninstalled.
    pub program: &'a ProgramId,
    /// The session's fingerprint; the run adds the uninstall window, verify-gone and co-removed products.
    pub fingerprint: &'a mut Fingerprint,
    /// The command to run, exactly as `prepare` reported it.
    pub command: &'a QuietCommand,
    /// One call per pipeline progress line.
    pub progress: &'a mut dyn FnMut(&str),
}

/// The machine behind the handler. The binary's [`LiveMachine`] reads the real registry, file system and
/// processes; the tests give a fixture and a scripted uninstaller. Nothing above this trait turns a
/// client value into a path: a client sends ids only.
pub trait Machine: Send + Sync + 'static {
    /// The machine's three sources for one call.
    fn sources(&self) -> Sources<'_>;

    /// Runs `request.command` for `request.program` and updates its fingerprint, exactly as the engine's
    /// `uninstall` verb does.
    ///
    /// # Errors
    ///
    /// As [`pipeline::uninstall_with_command`]: the program id names no single entry of the inventory, or
    /// there is no command.
    fn run_uninstall(&self, request: RunRequest<'_>) -> Result<Uninstalled, PipelineError>;

    /// The broker's own verify-gone of `program` against the fingerprint's main exes. An unknown answer
    /// is not "gone" (see [`purge_model::VerifyGone`]).
    fn verify_gone(&self, program: &ProgramId, fingerprint: &Fingerprint) -> VerifyGone {
        let main_exes: Vec<String> = fingerprint
            .main_exes()
            .map(|exe| exe.path.clone())
            .collect();
        let sources = self.sources();
        verify_gone::verify_gone(
            sources.reg,
            sources.fs,
            sources.sys,
            &VerifyTarget {
                arp_key: program.key_path(),
                product_code: None,
                main_exes,
            },
        )
    }

    /// The fingerprint stored for `program`, or `None` when there is none. A stored document that names
    /// another program is not that program's.
    ///
    /// # Errors
    ///
    /// When the store cannot be read and the failure is not "no such fingerprint".
    fn read_fingerprint(&self, program: &ProgramId) -> Result<Option<Fingerprint>, ErrorObject>;

    /// Stores `fingerprint` for `program`, replacing an older one.
    ///
    /// # Errors
    ///
    /// When the store cannot be written.
    fn write_fingerprint(
        &self,
        program: &ProgramId,
        fingerprint: &Fingerprint,
    ) -> Result<(), ErrorObject>;

    /// The selected items the executor must not quarantine: a volume that cannot hold a quarantine, or a
    /// plan that would pass the volume's size cap.
    ///
    /// # Errors
    ///
    /// [`ErrorData::CapExceeded`] when the plan would pass a cap; a `runtime` error when the store cannot
    /// be read.
    fn unstorable(&self, candidates: &[&Candidate]) -> Result<Vec<Refusal>, ErrorObject> {
        let _ = candidates;
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------------------------------
// The live machine
// ---------------------------------------------------------------------------------------------------

/// A temporary fingerprint file this much older than now belongs to no write in progress (a write takes
/// milliseconds): one a broker that crashed between the write and the rename left behind.
const FP_TEMP_STALE: Duration = Duration::from_secs(10 * 60);

/// Whether `name` is exactly a temporary fingerprint file of [`LiveMachine::write_fingerprint`]:
/// `fp-<64 lower-case hex>.json.<pid>-<call>.tmp`, both decimal. Nothing else is ever removed.
fn is_fingerprint_temp(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("fp-") else {
        return false;
    };
    let Some((hash, rest)) = rest.split_at_checked(64) else {
        return false;
    };
    let Some(rest) = rest
        .strip_prefix(".json.")
        .and_then(|r| r.strip_suffix(".tmp"))
    else {
        return false;
    };
    let Some((pid, call)) = rest.split_once('-') else {
        return false;
    };
    let decimal = |s: &str| !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit());
    hash.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && decimal(pid)
        && decimal(call)
}

/// Removes the temporary fingerprint files in `dir` (the admin-only `fp` directory of the data root)
/// last written before `before`: only names [`is_fingerprint_temp`] accepts, only plain files (not a
/// directory, a link or any reparse point; the attributes are read without following one). Failures are
/// ignored: a file left stays harmless. Returns how many were removed.
fn sweep_fingerprint_temps(dir: &Path, before: SystemTime) -> usize {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        if !name.to_str().is_some_and(is_fingerprint_temp) {
            continue;
        }
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        let plain = meta.file_type().is_file()
            && !meta.file_type().is_symlink()
            && meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0;
        if plain
            && meta.modified().is_ok_and(|written| written < before)
            && std::fs::remove_file(&path).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

/// The broker's machine: the live sources, the checked data root and the runner's options.
pub struct LiveMachine {
    live: Live,
    store: StorageRoots,
    options: RunOptions,
    /// When this machine was made (at the broker's start): a temporary fingerprint file older than
    /// this is not one of this broker's writes.
    started: SystemTime,
}

impl LiveMachine {
    /// The live machine over the checked storage `store`.
    pub fn new(store: StorageRoots) -> Self {
        LiveMachine {
            live: Live::new(),
            store,
            options: RunOptions::default(),
            started: SystemTime::now(),
        }
    }

    /// The file a program's fingerprint is stored in. The name is a SHA-256 of the program id, so no
    /// client-chosen text ever becomes a path.
    fn fingerprint_path(&self, program: &ProgramId) -> PathBuf {
        let hash = purge_exec::journal::sha256_bytes(program.to_string().as_bytes());
        self.store
            .data_root()
            .join(FP_DIR)
            .join(format!("fp-{hash}.json"))
    }

    /// The volume facts of `path`, or of the nearest ancestor that exists.
    fn volume_of(&self, path: &Path) -> Option<purge_exec::storage::VolumeFacts> {
        let mut here = path.to_path_buf();
        loop {
            if let Ok(facts) = self.store.volume(&here) {
                return Some(facts);
            }
            if !here.pop() {
                return None;
            }
        }
    }
}

impl Machine for LiveMachine {
    fn sources(&self) -> Sources<'_> {
        Sources {
            reg: &self.live.registry,
            fs: &self.live.fs,
            sys: &self.live.system,
        }
    }

    fn run_uninstall(&self, request: RunRequest<'_>) -> Result<Uninstalled, PipelineError> {
        let mut host = LiveHost::new();
        pipeline::uninstall_with_command(
            self.sources(),
            &mut host,
            &request.program.to_string(),
            Some(request.fingerprint),
            &self.options,
            request.command,
            request.progress,
        )
    }

    fn read_fingerprint(&self, program: &ProgramId) -> Result<Option<Fingerprint>, ErrorObject> {
        let path = self.fingerprint_path(program);
        let meta = match std::fs::metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(ErrorObject::runtime(format!(
                    "cannot read {}: {e}",
                    path.display()
                )));
            }
        };
        if meta.len() > MAX_FP_BYTES {
            return Err(ErrorObject::runtime(format!(
                "{} is over the {MAX_FP_BYTES}-byte limit",
                path.display()
            )));
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| ErrorObject::runtime(format!("cannot read {}: {e}", path.display())))?;
        let fingerprint: Fingerprint = serde_json::from_str(&text).map_err(|e| {
            ErrorObject::runtime(format!("{} is not a fingerprint: {e}", path.display()))
        })?;
        Ok((fingerprint.program_id() == program).then_some(fingerprint))
    }

    fn write_fingerprint(
        &self,
        program: &ProgramId,
        fingerprint: &Fingerprint,
    ) -> Result<(), ErrorObject> {
        let dir = self.store.data_root().join(FP_DIR);
        std::fs::create_dir_all(&dir)
            .map_err(|e| ErrorObject::runtime(format!("cannot create {}: {e}", dir.display())))?;
        let bytes = serde_json::to_vec(fingerprint)
            .map_err(|e| ErrorObject::runtime(format!("cannot serialise the fingerprint: {e}")))?;
        // Temporary files a crashed broker left are removed first (never one of a write in progress).
        if let Some(stale) = SystemTime::now().checked_sub(FP_TEMP_STALE) {
            sweep_fingerprint_temps(&dir, self.started.min(stale));
        }
        let path = self.fingerprint_path(program);
        // A temporary name of this process and call: two brokers storing the same program's
        // fingerprint at once never write into one temporary file, so the rename puts one whole
        // document in place, never a mix of two (review R3, single writer).
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let call = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temp = path.with_extension(format!("json.{}-{call}.tmp", std::process::id()));
        std::fs::write(&temp, &bytes)
            .map_err(|e| ErrorObject::runtime(format!("cannot write {}: {e}", temp.display())))?;
        // `std::fs::rename` replaces an existing file on Windows (`MOVEFILE_REPLACE_EXISTING`), so the
        // old fingerprint stays until the new one takes its place; no removal first, which would open
        // a window in which a crash loses it (review M3-R2 N1).
        std::fs::rename(&temp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&temp);
            ErrorObject::runtime(format!("cannot replace {}: {e}", path.display()))
        })
    }

    fn unstorable(&self, candidates: &[&Candidate]) -> Result<Vec<Refusal>, ErrorObject> {
        let mut refusals = Vec::new();
        // Serial -> (volume root, total bytes, planned bytes).
        let mut planned: BTreeMap<u64, (String, u64, u64)> = BTreeMap::new();
        for candidate in candidates {
            let Target::Path { path } = &candidate.target else {
                continue;
            };
            let Some(facts) = self.volume_of(Path::new(path)) else {
                refusals.push(refusal(
                    candidate,
                    "the volume this item is on cannot be read, so it cannot be quarantined",
                ));
                continue;
            };
            if let Err(reason) = facts.quarantine_capable() {
                refusals.push(refusal(
                    candidate,
                    format!("this volume cannot hold a quarantine: {reason}"),
                ));
                continue;
            }
            // A volume mounted in a folder has no drive root for `X:\.purge-q`; the executor refuses
            // it too (`CannotBackUpReason::MountedFolder`), so it is refused here rather than later.
            if !facts.root.to_string_lossy().ends_with(":\\") {
                refusals.push(refusal(
                    candidate,
                    "this volume is mounted in a folder, so it cannot hold a quarantine",
                ));
                continue;
            }
            let info = match purge_win::fs::volume_info(&facts.root) {
                Ok(info) => info,
                Err(e) => {
                    refusals.push(refusal(
                        candidate,
                        format!("the volume of this item cannot be read: {e}"),
                    ));
                    continue;
                }
            };
            let slot = planned
                .entry(u64::from(info.serial))
                .or_insert_with(|| (info.root.clone(), facts.total_bytes, 0));
            slot.2 = slot.2.saturating_add(candidate.size_bytes.unwrap_or(0));
        }
        if !refusals.is_empty() {
            return Ok(refusals);
        }
        if planned.is_empty() {
            return Ok(Vec::new());
        }
        let index = self.store.read_index().map_err(|e| runtime_store(&e))?;
        let usages: Vec<purge_model::exec::session::VolumeUsage> = planned
            .iter()
            .map(
                |(serial, (root, _, bytes))| purge_model::exec::session::VolumeUsage {
                    serial: *serial,
                    root: root.clone(),
                    bytes: *bytes,
                },
            )
            .collect();
        match self.store.check_cap(&index, &usages) {
            Ok(()) => Ok(Vec::new()),
            Err(StorageError::Cap(cap)) => Err(ErrorObject::server(ErrorData::CapExceeded {
                volume: cap.root.clone(),
                used: cap.held,
                needed: cap.planned,
                cap: cap.cap,
            })),
            Err(e) => Err(runtime_store(&e)),
        }
    }
}

fn runtime_store(error: &StorageError) -> ErrorObject {
    ErrorObject::server(ErrorData::StoreIntegrity {
        message: error.to_string(),
    })
}

fn refusal(candidate: &Candidate, reason: impl Into<String>) -> Refusal {
    Refusal {
        candidate_id: purge_rpc::methods::CandidateRef::try_from(&candidate.id).ok(),
        reason: reason.into(),
    }
}

// ---------------------------------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------------------------------

/// One prepared program: its harvest, the commands `prepare` showed and whether its uninstaller ran.
pub struct Session {
    /// The program.
    pub program: ProgramId,
    /// Its display name, for messages.
    pub display_name: String,
    /// Where its uninstaller belongs (broker or medium).
    pub route: Route,
    /// The commands `prepare` resolved and reported.
    pub commands: UninstallCommands,
    /// When `prepare` harvested the program: the uninstall window's start when an observation records
    /// one (the medium engine runs the uninstaller between the two requests).
    window_start: FileTime,
    /// The fingerprint, updated by the run and the observation.
    fingerprint: Mutex<Fingerprint>,
    /// The broker's own verify-gone, once the uninstaller ran or was observed.
    verify_gone: Mutex<Option<VerifyGone>>,
    /// Whether this session's uninstaller ran in the broker or the medium engine.
    ran: AtomicBool,
    /// Whether it reported success (or, for an observation, the broker's verify-gone passed). A failed
    /// uninstaller always scans forced, even when the program did vanish.
    uninstaller_ok: AtomicBool,
}

impl Session {
    /// The fingerprint as it stands now.
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The install roots of the fingerprint, for the plan's object binding.
    pub fn program_roots(&self) -> Vec<String> {
        self.fingerprint
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .roots
            .iter()
            .map(|root| root.path.clone())
            .collect()
    }

    /// Whether the uninstaller ran.
    pub fn ran(&self) -> bool {
        self.ran.load(Ordering::SeqCst)
    }

    /// Whether the run reported success (or the observation's verify-gone passed). A scan is `post`
    /// only when this and the broker's verify-gone both hold.
    pub fn uninstaller_ok(&self) -> bool {
        self.uninstaller_ok.load(Ordering::SeqCst)
    }

    /// The broker's verify-gone, if there is one.
    pub fn verify_gone(&self) -> Option<VerifyGone> {
        *self.verify_gone.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set_ran(&self, uninstaller_ok: bool) {
        self.ran.store(true, Ordering::SeqCst);
        self.uninstaller_ok.store(uninstaller_ok, Ordering::SeqCst);
    }

    /// Records an observation. A session that already ran is never raised: `uninstaller_ok` may only
    /// go from true to false, so a failed run cannot be turned into a `post` scan by a later
    /// `uninstall.observed` (review M3-R2 M3).
    fn record_observation(&self, uninstaller_ok: bool) {
        let already_ran = self.ran.swap(true, Ordering::SeqCst);
        if !uninstaller_ok {
            self.uninstaller_ok.store(false, Ordering::SeqCst);
        } else if !already_ran {
            self.uninstaller_ok.store(true, Ordering::SeqCst);
        }
    }

    fn set_verify(&self, verify: VerifyGone) {
        *self.verify_gone.lock().unwrap_or_else(|e| e.into_inner()) = Some(verify);
    }
}

// ---------------------------------------------------------------------------------------------------
// The handler
// ---------------------------------------------------------------------------------------------------

/// A handler whose tables hold this package's session, scan and plan types. The request functions are
/// generic over it so that a test can wrap [`Flow`] in its own handler (to keep the plans it made) and
/// still serve its requests.
pub trait FlowHandler:
    Handler<Session = Session, Scan = crate::scan::Scan, Plan = crate::plan::Plan>
{
}

impl<H> FlowHandler for H where
    H: Handler<Session = Session, Scan = crate::scan::Scan, Plan = crate::plan::Plan>
{
}

/// The broker's methods of this package over one machine.
pub struct Flow {
    machine: Arc<dyn Machine>,
}

impl Flow {
    /// A handler over `machine`. The tables stay the broker's.
    pub fn new(machine: Arc<dyn Machine>) -> Self {
        Flow { machine }
    }

    /// The machine, for the other modules of this package.
    pub(crate) fn machine(&self) -> &dyn Machine {
        &*self.machine
    }

    /// Runs one request. Generic over the handler's tables so a test can wrap the flow in its own
    /// handler (to keep the plans it made) and still get these methods.
    pub(crate) fn dispatch<H: FlowHandler>(
        &self,
        ctx: &Ctx<'_, H>,
        call: PipeCall,
    ) -> Result<Value, ErrorObject> {
        match call {
            PipeCall::UninstallPrepare(params) => prepare(self, ctx, &params),
            PipeCall::UninstallRun(params) => run(self, ctx, &params),
            PipeCall::UninstallObserved(params) => observed(self, ctx, &params),
            PipeCall::LeftoversStored(params) => stored(self, ctx, &params),
            PipeCall::LeftoversScan(params) => crate::scan::handle(self, ctx, params),
            PipeCall::ScanCandidates(params) => crate::scan::candidates(ctx, &params),
            PipeCall::CandidateExplain(params) => crate::scan::explain(ctx, &params),
            PipeCall::PlanCreate(params) => crate::plan::create(self, ctx, params),
            other => Err(ErrorObject::runtime(format!(
                "{} is not implemented in this build",
                other.method().name()
            ))),
        }
    }
}

impl Handler for Flow {
    type Session = Session;
    type Scan = crate::scan::Scan;
    type Plan = crate::plan::Plan;

    fn call(&self, ctx: &Ctx<'_, Self>, call: PipeCall) -> Result<Value, ErrorObject> {
        self.dispatch(ctx, call)
    }
}

// ---------------------------------------------------------------------------------------------------
// uninstall.prepare
// ---------------------------------------------------------------------------------------------------

/// A progress sink that sends `prepare.progress` lines and stops after the first failure.
struct NotifyProgress<'a, H: FlowHandler> {
    ctx: &'a Ctx<'a, H>,
    program: ProgramId,
    done: u64,
    failed: bool,
}

impl<H: FlowHandler> NotifyProgress<'_, H> {
    fn line(&mut self, line: &str) {
        if self.failed {
            return;
        }
        self.done += 1;
        let notification = ServerNotification::PrepareProgress(Progress {
            request: self.ctx.request(),
            program_id: Some(self.program.clone()),
            phase: line.to_owned(),
            done: self.done,
            total: None,
        });
        if self.ctx.notify(&notification).is_err() {
            self.failed = true;
        }
    }
}

/// `uninstall.prepare`: harvests every requested program, stores each fingerprint and opens one session
/// per program, in request order.
fn prepare<H: FlowHandler>(
    flow: &Flow,
    ctx: &Ctx<'_, H>,
    params: &ProgramsParams,
) -> Result<Value, ErrorObject> {
    let machine = flow.machine();
    let sources = machine.sources();
    let env = sources.sys.env().unwrap_or_default();
    let machine_env = sources.sys.machine_env().unwrap_or_default();
    let inventory = pipeline::inventory(sources);
    let mut programs = Vec::with_capacity(params.program_ids.as_slice().len());
    for program in params.program_ids.as_slice() {
        if ctx.cancelled() {
            return Err(ErrorObject::runtime("the request was cancelled"));
        }
        let entry = inventory
            .doc
            .entry(program)
            .ok_or_else(|| gone(IdKind::Program))?;
        let route = pipeline::route(entry, sources.fs, &env, &machine_env);
        // A machine-scope command is expanded with the machine environment only. The broker starts
        // such a command (or shows what would run), so a value in `HKCU\Environment` must never choose
        // its executable or arguments (review M3-R2 B1). A per-user program keeps the interactive
        // user's environment, which is the only one that can resolve its paths.
        let command_env = if entry.hive_sid.is_none() {
            &machine_env
        } else {
            &env
        };
        let commands = pipeline::uninstall_commands(entry, command_env);
        let command = commands
            .command_line()
            .or_else(|| commands.quiet_command_line())
            .ok_or_else(|| {
                ErrorObject::runtime(format!("{} has no uninstall command", entry.display_name))
            })?;
        let quiet_command = commands.quiet_command_line();
        let signer = signer_of(sources, &commands);
        let running = running_under(
            &sources.sys.processes().unwrap_or_default(),
            &running_roots(entry, &commands),
        );

        let window_start = crate::purge::system_now();
        let harvested = {
            let mut progress = NotifyProgress {
                ctx,
                program: program.clone(),
                done: 0,
                failed: false,
            };
            let result = pipeline::harvest(
                sources,
                &program.to_string(),
                Kb::shipped(),
                ctx.settings(),
                &mut |line| progress.line(line),
            );
            if progress.failed {
                return Err(ErrorObject::runtime(
                    "cannot send prepare.progress: the client is gone",
                ));
            }
            result.map_err(pipeline_error)?
        };
        if ctx.cancelled() {
            return Err(ErrorObject::runtime("the request was cancelled"));
        }

        machine.write_fingerprint(program, &harvested.report.fingerprint)?;
        let summary = fingerprint_summary(&harvested);
        let co_products = co_products(&harvested);
        let fingerprint_warnings = harvested.report.fingerprint.warnings.clone();
        let fingerprint = harvested.report.fingerprint;
        let session_id = ctx.tables().sessions.insert(Session {
            program: program.clone(),
            display_name: entry.display_name.clone(),
            route,
            commands,
            window_start,
            fingerprint: Mutex::new(fingerprint),
            verify_gone: Mutex::new(None),
            ran: AtomicBool::new(false),
            uninstaller_ok: AtomicBool::new(false),
        })?;
        programs.push(Prepared {
            program_id: program.clone(),
            session_id,
            route,
            command,
            quiet_command,
            signer,
            co_products,
            running,
            fingerprint_summary: summary,
            warnings: harvested
                .warnings
                .iter()
                .chain(fingerprint_warnings.iter())
                .map(|line| purge_rpc::methods::Warning {
                    code: purge_model::WarningKind::of(line).code().to_owned(),
                    message: line.clone(),
                })
                .collect(),
        });
    }
    serde_json::to_value(PrepareResult { programs })
        .map_err(|e| ErrorObject::runtime(e.to_string()))
}

fn pipeline_error(error: PipelineError) -> ErrorObject {
    ErrorObject::runtime(error.to_string())
}

fn fingerprint_summary(harvested: &Harvested) -> FingerprintSummary {
    let fingerprint = &harvested.report.fingerprint;
    FingerprintSummary {
        roots: u32::try_from(fingerprint.roots.len()).unwrap_or(u32::MAX),
        files: u32::try_from(fingerprint.exes.len()).unwrap_or(u32::MAX),
        registry: u32::try_from(fingerprint.tokens.len()).unwrap_or(u32::MAX),
        objects: u32::try_from(
            fingerprint.sys.services.len()
                + fingerprint.sys.tasks.len()
                + fingerprint.sys.firewall_rules.len(),
        )
        .unwrap_or(u32::MAX),
    }
}

fn co_products(harvested: &Harvested) -> Vec<CoProduct> {
    harvested
        .report
        .co_candidates
        .iter()
        .map(|candidate| CoProduct {
            name: candidate.app.display_name.clone(),
            program_id: Some(candidate.app.program_id.clone()),
        })
        .collect()
}

fn signer_of(sources: Sources<'_>, commands: &UninstallCommands) -> Option<String> {
    [commands.command.as_ref(), commands.quiet.as_ref()]
        .into_iter()
        .flatten()
        .find_map(|command| sources.fs.signer_cn(&command.exe).ok().flatten())
}

/// The directories a running process must be under to count as the program's own: its
/// `InstallLocation`, and the directory of each command the entry names.
fn running_roots(entry: &InventoryEntry, commands: &UninstallCommands) -> Vec<String> {
    let mut roots: Vec<String> = Vec::new();
    let mut push = |root: String| {
        let root = root.trim_end_matches(['\\', '/']).to_owned();
        if !root.is_empty() && !roots.iter().any(|r| r.eq_ignore_ascii_case(&root)) {
            roots.push(root);
        }
    };
    if let Some(location) = entry.install_location.as_deref() {
        push(location.to_owned());
    }
    for command in [commands.command.as_ref(), commands.quiet.as_ref()]
        .into_iter()
        .flatten()
    {
        if let Some(parent) = Path::new(&command.exe).parent() {
            push(parent.to_string_lossy().into_owned());
        }
    }
    roots
}

/// Processes whose image lies under one of `roots` (case-insensitive, like the rest of the paths).
fn running_under(processes: &[ProcessInfo], roots: &[String]) -> Vec<RunningProcess> {
    if roots.is_empty() {
        return Vec::new();
    }
    processes
        .iter()
        .filter(|process| {
            process
                .path
                .as_deref()
                .is_some_and(|path| roots.iter().any(|root| is_under(path, root)))
        })
        .map(|process| RunningProcess {
            pid: process.pid,
            name: process.name.clone(),
        })
        .collect()
}

fn is_under(path: &str, root: &str) -> bool {
    let path = path.replace('/', "\\").to_ascii_lowercase();
    let root = root
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    path == root || path.starts_with(&format!("{root}\\"))
}

// ---------------------------------------------------------------------------------------------------
// uninstall.run and uninstall.observed
// ---------------------------------------------------------------------------------------------------

/// A progress sink for `uninstall.progress`; a lost client stops the notifications, not the run.
struct RunProgress<'a, H: FlowHandler> {
    ctx: &'a Ctx<'a, H>,
    program: ProgramId,
    done: u64,
    failed: bool,
}

impl<H: FlowHandler> RunProgress<'_, H> {
    fn line(&mut self, line: &str) {
        if self.failed {
            return;
        }
        self.done += 1;
        let notification = ServerNotification::UninstallProgress(Progress {
            request: self.ctx.request(),
            program_id: Some(self.program.clone()),
            phase: line.to_owned(),
            done: self.done,
            total: None,
        });
        if self.ctx.notify(&notification).is_err() {
            // A lost client ends the notifications; the run itself still finishes.
            self.failed = true;
        }
    }
}

/// `uninstall.run`: runs the session's own command in the broker, and only for a broker-route session,
/// and only after the broker's own consent dialog, drawn from that command, was approved (B4).
fn run<H: FlowHandler>(
    flow: &Flow,
    ctx: &Ctx<'_, H>,
    params: &RunParams,
) -> Result<Value, ErrorObject> {
    let session = ctx.tables().sessions.get(params.session_id)?;
    if session.route != Route::Broker {
        return Err(ErrorObject::server(ErrorData::WrongRoute {
            route: session.route,
        }));
    }
    let command = if params.quiet {
        session.commands.quiet.clone()
    } else {
        session.commands.command.clone()
    }
    .ok_or_else(|| {
        ErrorObject::runtime(format!(
            "{} has no {} uninstall command",
            session.display_name,
            if params.quiet { "quiet" } else { "interactive" }
        ))
    })?;

    let machine = flow.machine();
    let program = session.program.clone();

    // The dialog is drawn from the very command that is started below (review M3-R2 M1): a declined
    // dialog, a dialog that cannot be drawn or shown, and a lost client or parent start nothing.
    let facts = UninstallFacts {
        app_name: session.display_name.clone(),
        program_id: program.to_string(),
        command: command.clone(),
        quiet: params.quiet,
        signer: machine.sources().fs.signer_cn(&command.exe).ok().flatten(),
        restore_point: params.restore_point,
    };
    let consent = view::view_uninstall(&facts)
        .map_err(|e| ErrorObject::runtime(format!("the dialog cannot be built: {e}")))?;
    if !consent.describes_uninstall(&command, params.quiet) {
        return Err(ErrorObject::runtime(
            "the consent dialog does not describe this command",
        ));
    }
    if dialog::ask(ctx, &consent) != Answer::Approved || ctx.lost() {
        return Err(ErrorObject::server(ErrorData::ConsentDeclined));
    }
    if !consent.describes_uninstall(&command, params.quiet) {
        return Err(ErrorObject::runtime(
            "the consent dialog does not describe this command",
        ));
    }

    let uninstalled = {
        let mut fingerprint = session
            .fingerprint
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut progress = RunProgress {
            ctx,
            program: program.clone(),
            done: 0,
            failed: false,
        };
        let result = machine.run_uninstall(RunRequest {
            program: &program,
            fingerprint: &mut fingerprint,
            command: &command,
            progress: &mut |line| progress.line(line),
        });
        let _ = machine.write_fingerprint(&program, &fingerprint);
        result.map_err(pipeline_error)?
    };
    let doc = &uninstalled.report.doc;
    session.set_ran(doc.outcome.is_success());
    session.set_verify(doc.verify_gone);
    if !doc.outcome.is_success() {
        return Err(ErrorObject::server(ErrorData::UninstallFailed {
            exit_code: doc.exit_code,
            forced_offered: true,
        }));
    }
    serde_json::to_value(RunResult {
        exit_code: doc.exit_code,
        outcome: doc.outcome,
        verify_gone: doc.verify_gone,
    })
    .map_err(|e| ErrorObject::runtime(e.to_string()))
}

/// `uninstall.observed`: the broker's own verify-gone after a medium-route run.
///
/// The medium engine may report how its run ended (`params.outcome`). A run it reports as failed,
/// cancelled or timed out is a failed uninstaller whatever the broker finds: the scan is `forced` with
/// nothing preselected, as after a failed run of the broker's own. A reported success is never taken
/// as one: the broker's verify-gone still has to pass. So the report can only make the scan safer.
///
/// Only a medium-route session may be observed: a broker-route session's run is the broker's own, and a
/// session that already ran is never raised (`uninstaller_ok` may only go from true to false). This is
/// the attack of review M3-R2 M3: a failed `uninstall.run` cannot be turned into a `post` scan.
///
/// When both hold, the session's fingerprint gets the uninstall window `prepare`'s harvest opened and
/// this observation closed, which is what a `post` scan checks for (as `uninstall.run` records for a
/// broker-route run). The first passing observation records it; a later one leaves it where it is. An
/// observation more than two hours after `prepare` records none, so a client cannot stretch the window
/// (ruling on flagged point 7). No window is recorded in every other case, so the scan stays forced.
fn observed<H: FlowHandler>(
    flow: &Flow,
    ctx: &Ctx<'_, H>,
    params: &ObservedParams,
) -> Result<Value, ErrorObject> {
    let session = ctx.tables().sessions.get(params.session_id)?;
    if session.route != Route::Medium {
        return Err(ErrorObject::server(ErrorData::WrongRoute {
            route: session.route,
        }));
    }
    let machine = flow.machine();
    let reported_ok = params.outcome.is_none_or(|outcome| outcome.is_success());
    let verify = {
        let mut fingerprint = session
            .fingerprint
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let verify = machine.verify_gone(&session.program, &fingerprint);
        fingerprint.verify_gone = Some(verify);
        if reported_ok && verify.is_passed() && fingerprint.window.t_end.is_none() {
            // The medium engine ran the uninstaller between `prepare`'s harvest and this observation,
            // so that is the window a `post` scan needs (which only the broker's `run` recorded
            // before). A failed report, a failed verify-gone or a cancel records no window: the scan
            // is forced, as it is after such a run of the broker's own.
            let end = crate::purge::system_now();
            if within_observation_cap(session.window_start, end) {
                let start = session.window_start;
                fingerprint.window.t_start = Some(start);
                fingerprint.window.t_end = Some(FileTime(end.0.max(start.0)));
            }
        }
        let _ = machine.write_fingerprint(&session.program, &fingerprint);
        verify
    };
    let window_recorded = {
        let fingerprint = session
            .fingerprint
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        fingerprint.window.t_end.is_some()
    };
    session.record_observation(reported_ok && verify.is_passed() && window_recorded);
    session.set_verify(verify);
    serde_json::to_value(ObservedResult {
        verify_gone: verify,
    })
    .map_err(|e| ErrorObject::runtime(e.to_string()))
}

/// The longest uninstall window an observation may record, counted from `prepare` (two hours).
const OBSERVATION_WINDOW_CAP: FileTime = FileTime(2 * 60 * 60 * 10_000_000);

fn within_observation_cap(start: FileTime, end: FileTime) -> bool {
    end.0.saturating_sub(start.0) <= OBSERVATION_WINDOW_CAP.0
}

// ---------------------------------------------------------------------------------------------------
// leftovers.stored
// ---------------------------------------------------------------------------------------------------

/// `leftovers.stored`: which of the asked programs have a fingerprint under `<data root>\fp`.
fn stored<H: FlowHandler>(
    flow: &Flow,
    _ctx: &Ctx<'_, H>,
    params: &ProgramsParams,
) -> Result<Value, ErrorObject> {
    let machine = flow.machine();
    let mut stored = Vec::new();
    for program in params.program_ids.as_slice() {
        if machine.read_fingerprint(program)?.is_some() {
            stored.push(program.clone());
        }
    }
    serde_json::to_value(StoredResult { stored }).map_err(|e| ErrorObject::runtime(e.to_string()))
}

#[cfg(test)]
mod tests {
    use purge_model::View;
    use purge_rpc::methods::Route;

    use super::*;

    fn session(ran: bool, uninstaller_ok: bool) -> Session {
        let program = ProgramId::machine(View::K64, "App_is1").expect("program id");
        let fingerprint: Fingerprint = serde_json::from_value(serde_json::json!({
            "schema": "purge.fp/0",
            "app": {"program_id": program.to_string(), "display_name": "App"},
            "identity": {"names": [], "vendors": [], "tokens": [], "mega_vendor": false},
            "os": {"edition": "Professional", "build": 26340, "ubr": 9882},
            "user_sid": "S-1-5-21-1-2-3-1001"
        }))
        .expect("fingerprint");
        Session {
            program,
            display_name: "App".into(),
            route: Route::Medium,
            commands: UninstallCommands::default(),
            window_start: FileTime(0),
            fingerprint: Mutex::new(fingerprint),
            verify_gone: Mutex::new(None),
            ran: AtomicBool::new(ran),
            uninstaller_ok: AtomicBool::new(uninstaller_ok),
        }
    }

    #[test]
    fn an_observation_never_raises_a_session_that_ran() {
        let failed = session(true, false);
        failed.record_observation(true);
        assert!(failed.ran());
        assert!(
            !failed.uninstaller_ok(),
            "a failed run was raised by an observation"
        );

        let passed = session(true, true);
        passed.record_observation(true);
        assert!(passed.uninstaller_ok());
        passed.record_observation(false);
        assert!(
            !passed.uninstaller_ok(),
            "a later failure must still lower the session"
        );

        let fresh = session(false, false);
        fresh.record_observation(true);
        assert!(fresh.ran());
        assert!(
            fresh.uninstaller_ok(),
            "the first passing observation records"
        );
    }

    #[test]
    fn an_observation_window_is_capped_at_two_hours() {
        let start = FileTime(1_000);
        assert!(within_observation_cap(
            start,
            FileTime(start.0 + OBSERVATION_WINDOW_CAP.0)
        ));
        assert!(!within_observation_cap(
            start,
            FileTime(start.0 + OBSERVATION_WINDOW_CAP.0 + 1)
        ));
        assert!(within_observation_cap(
            start,
            FileTime(start.0.saturating_sub(10))
        ));
    }

    #[test]
    fn only_stale_temporary_fingerprint_files_of_the_exact_pattern_are_swept() {
        let dir = std::env::temp_dir().join(format!(
            "purge-fp-sweep-{}-{:x}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let hash = "a".repeat(64);
        let old = SystemTime::now() - Duration::from_secs(3600);
        let make = |name: &str, written: SystemTime| {
            let path = dir.join(name);
            let file = std::fs::File::create(&path).unwrap();
            file.set_modified(written).unwrap();
            path
        };
        let stale = make(&format!("fp-{hash}.json.4242-0.tmp"), old);
        let fresh = make(&format!("fp-{hash}.json.4242-1.tmp"), SystemTime::now());
        let document = make(&format!("fp-{hash}.json"), old);
        let other = [
            make(&format!("fp-{hash}.json.tmp"), old),
            make(&format!("fp-{}.json.1-2.tmp", "A".repeat(64)), old),
            make(&format!("fp-{hash}.json.1-x.tmp"), old),
            make("notes.tmp", old),
        ];
        // A directory with the pattern's name is never entered or removed.
        let folder = dir.join(format!("fp-{hash}.json.7-7.tmp"));
        std::fs::create_dir(&folder).unwrap();

        let cutoff = SystemTime::now() - Duration::from_secs(60);
        assert_eq!(sweep_fingerprint_temps(&dir, cutoff), 1);
        assert!(!stale.exists());
        assert!(
            fresh.exists(),
            "a temporary file younger than the cutoff may be a write in progress"
        );
        assert!(document.exists());
        assert!(other.iter().all(|p| p.exists()));
        assert!(folder.is_dir());
        assert_eq!(sweep_fingerprint_temps(&dir, cutoff), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_temporary_name_of_a_write_is_the_pattern_the_sweep_knows() {
        let hash = purge_exec::journal::sha256_bytes(b"HKLM|64|Vendor_is1");
        let name = format!("fp-{hash}.json.{}-{}.tmp", std::process::id(), 17);
        assert!(is_fingerprint_temp(&name), "{name}");
        assert!(!is_fingerprint_temp(&format!("fp-{hash}.json")));
    }
}
