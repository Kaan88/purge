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
//! the Uninstall key changes between the two requests.
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

use purge_engine::pipeline::{
    self, Harvested, PipelineError, Sources, UninstallCommands, Uninstalled,
};
use purge_exec::storage::{StorageError, StorageRoots};
use purge_identity::kbdata::Kb;
use purge_inventory::quiet::QuietCommand;
use purge_inventory::runner::{LiveHost, RunOptions};
use purge_inventory::verify_gone::{self, VerifyTarget};
use purge_model::{Candidate, Fingerprint, InventoryEntry, ProgramId, Target, VerifyGone};
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
use serde_json::Value;

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

/// The broker's machine: the live sources, the checked data root and the runner's options.
pub struct LiveMachine {
    live: Live,
    store: StorageRoots,
    options: RunOptions,
}

impl LiveMachine {
    /// The live machine over the checked storage `store`.
    pub fn new(store: StorageRoots) -> Self {
        LiveMachine {
            live: Live::new(),
            store,
            options: RunOptions::default(),
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
        let path = self.fingerprint_path(program);
        let temp = path.with_extension("json.tmp");
        std::fs::write(&temp, &bytes)
            .map_err(|e| ErrorObject::runtime(format!("cannot write {}: {e}", temp.display())))?;
        // A rename over an existing file fails on Windows; the fingerprint is only ever read whole, so
        // removing the old one first is safe (a crash between the two loses it, and the next harvest
        // writes it again).
        let _ = std::fs::remove_file(&path);
        std::fs::rename(&temp, &path)
            .map_err(|e| ErrorObject::runtime(format!("cannot replace {}: {e}", path.display())))
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
        let route = pipeline::route(entry, sources.fs, &env);
        let commands = pipeline::uninstall_commands(entry, &env);
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

/// `uninstall.run`: runs the session's own command in the broker, and only for a broker-route session.
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
fn observed<H: FlowHandler>(
    flow: &Flow,
    ctx: &Ctx<'_, H>,
    params: &ObservedParams,
) -> Result<Value, ErrorObject> {
    let session = ctx.tables().sessions.get(params.session_id)?;
    let machine = flow.machine();
    let verify = {
        let mut fingerprint = session
            .fingerprint
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let verify = machine.verify_gone(&session.program, &fingerprint);
        fingerprint.verify_gone = Some(verify);
        let _ = machine.write_fingerprint(&session.program, &fingerprint);
        verify
    };
    session.set_ran(verify.is_passed());
    session.set_verify(verify);
    serde_json::to_value(ObservedResult {
        verify_gone: verify,
    })
    .map_err(|e| ErrorObject::runtime(e.to_string()))
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
