//! The minimal uninstall runner (ENGINE_PLAN.md §4.4 "Launch and wait", "Exit codes"; §3.4 `uninstall`).
//!
//! [`run_uninstall`] runs one inventory entry's quiet uninstall command and records what happened as a
//! `purge.run/0` [`RunDoc`]. The sequence:
//!
//! 1. Resolve the quiet command ([`crate::quiet::quiet_command`]) and expand it with the interactive
//!    user's environment; when the caller passes [`RunRequest::command`], it is already the string
//!    that was shown and is run exactly as given, never expanded again.
//! 2. Record the Authenticode signer CN of the uninstaller exe, and the routing facts of §4.4
//!    ([`Routing`]: how the engine runs and whether the entry should run at medium integrity). The routing
//!    rule is **recorded, not enforced** in M1a: the CLI runs the command with its own token. An elevated
//!    start gets the machine environment plus the profile variables and the uninstaller's own directory,
//!    never the engine's environment or working directory (review M3-R2 S4).
//! 3. List running processes whose image is under the app's roots. M1a does not close or terminate them
//!    (`WM_CLOSE` and termination need consent, M2/M3); they only appear in [`RunDoc::processes`].
//! 4. Start the command inside a Job object with breakaway disallowed, so NSIS/Inno copies re-launched from
//!    `%TEMP%` stay tracked.
//! 5. Wait, polling every [`RunOptions::poll`], until the job has no live process **and**
//!    `Global\_MSIExecute` is absent **and** the ARP key is gone, on [`RunOptions::quiet_polls`] (two)
//!    consecutive polls ([`WaitEnd::Settled`]). If the tree and MSI are idle but the ARP key stays for
//!    [`RunOptions::arp_grace`] (180 s), the wait gives up ([`WaitEnd::ArpStayed`]); that is not a
//!    timeout, and verify-gone will fail. After [`RunOptions::timeout`] (30 min) the wait ends with
//!    [`RunOutcome::TimedOut`] and **nothing is killed**: there is no kill-on-timeout behaviour, and the
//!    [`ProcessHost`] trait has no way to terminate anything.
//! 6. Map the root's exit code (§4.4 table, [`RunOutcome::from_exit_code`]): 0 success candidate, 1605
//!    already gone, 1641/3010 success with reboot, 1602 cancelled, anything else failed. A command that
//!    cannot be started is [`RunOutcome::Failed`] with no exit code.
//! 7. Run verify-gone ([`crate::verify_gone::check`]) and, when the caller passes the inventory taken
//!    before the run, list the co-removed entries ([`crate::verify_gone::disappeared`]).
//!
//! Process creation sits behind [`ProcessHost`], so the wait state machine is tested with a scripted fake;
//! [`LiveHost`] implements it over `purge-win`'s `run` feature. A probe that fails (job list, MSI mutex)
//! counts as "busy", so a broken probe can only make the wait longer, never end it early; the overall
//! timeout bounds it.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use purge_model::{
    FileTime, InventoryEntry, ProcessSeen, RunDoc, RunOutcome, RunSchema, WritableBy,
};
use purge_source::filesystem::FileSystemSource;
use purge_source::registry::RegistrySource;
use purge_source::system::SystemSource;
use purge_source::types::ExistsState;
use purge_win::process::{self as winproc, JobProcess, SpawnOptions};
use serde::{Deserialize, Serialize};

use crate::quiet::{QuietCommand, QuietError, quiet_command};
use crate::verify_gone::{self, VerifyGoneCheck, VerifyTarget};

pub use purge_win::process::MSI_EXECUTE_MUTEX;

/// Identifies a job started by a [`ProcessHost`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct JobId(pub u64);

/// What a started command runs with. `None` fields inherit the engine's own (the default).
#[derive(Debug, Clone, Copy, Default)]
pub struct SpawnContext<'a> {
    /// The full environment block; `None` inherits the engine's.
    pub environment: Option<&'a BTreeMap<String, String>>,
    /// The working directory; `None` inherits the engine's.
    pub current_dir: Option<&'a Path>,
}

/// What the runner needs from the machine to start and watch an uninstaller.
///
/// There is deliberately no method to terminate or close anything: M1a never kills an uninstaller or an
/// app process.
pub trait ProcessHost {
    /// Starts `command_line` (passed verbatim to `CreateProcessW`) inside a new Job object that does not
    /// allow breakaway, with `context`'s environment and working directory.
    fn spawn_in_job(&mut self, command_line: &str, context: SpawnContext<'_>) -> io::Result<JobId>;

    /// The ids of the processes currently alive in the job (the root included while it runs).
    fn job_active_pids(&mut self, job: JobId) -> io::Result<Vec<u32>>;

    /// The exit code of the job's root process, or `None` while it runs.
    fn job_exit_code(&mut self, job: JobId) -> io::Result<Option<u32>>;

    /// Name and image path of a running process; `None` when it is gone or cannot be read.
    fn process_info(&mut self, pid: u32) -> Option<ProcessSeen>;

    /// Every running process, with its image path where readable.
    fn running_processes(&mut self) -> io::Result<Vec<ProcessSeen>>;

    /// Whether a named mutex exists (for [`MSI_EXECUTE_MUTEX`]).
    fn mutex_exists(&mut self, name: &str) -> io::Result<bool>;

    /// The current time. Must not go backwards; the runner measures its timeouts with it.
    fn now(&self) -> FileTime;

    /// Waits for `d`.
    fn sleep(&mut self, d: Duration);
}

/// How long and how often the runner waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunOptions {
    /// Time between two polls.
    pub poll: Duration,
    /// Consecutive quiet polls (tree empty, MSI idle, ARP key gone) that end the wait. At least 1.
    pub quiet_polls: u32,
    /// How long the ARP key may stay after the tree and MSI went idle before the wait gives up.
    pub arp_grace: Duration,
    /// Overall limit of the wait, from the start of the command. Nothing is killed when it elapses.
    pub timeout: Duration,
}

impl Default for RunOptions {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(1),
            quiet_polls: 2,
            arp_grace: Duration::from_secs(180),
            timeout: Duration::from_secs(30 * 60),
        }
    }
}

/// The token the engine ran the uninstaller with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RanAs {
    /// An elevated (administrator) token.
    Elevated,
    /// A medium-integrity (standard user) token.
    Medium,
}

/// The §4.4 routing facts of one run. Recorded, not enforced, in M1a.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Routing {
    /// How the engine ran the command.
    pub ran_as: RanAs,
    /// The entry should run in the medium engine: it is a per-user entry (`HKU` key or user-writable key),
    /// or its uninstaller is not provably writable by administrators only, its directory included
    /// (`is_admin_only_executable`).
    pub should_run_medium: bool,
}

/// Why the wait ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WaitEnd {
    /// Tree empty, MSI idle and the ARP key gone on enough consecutive polls.
    Settled,
    /// Tree and MSI idle, but the ARP key stayed for the whole grace period.
    ArpStayed,
    /// The overall timeout elapsed.
    TimedOut,
    /// The command could not be started.
    NotStarted,
}

/// What to uninstall, and what the caller knows about the app.
#[derive(Debug, Clone, Copy)]
pub struct RunRequest<'a> {
    /// The inventory entry to uninstall.
    pub entry: &'a InventoryEntry,
    /// Canonical paths of the fingerprint's main exes (verify-gone).
    pub main_exes: &'a [String],
    /// The app's roots: running processes with an image below one of them are listed.
    pub roots: &'a [String],
    /// The inventory entries before the run; when given, entries that disappeared with the target are
    /// reported as co-removed.
    pub before: Option<&'a [InventoryEntry]>,
    /// The exact command to run instead of the entry's quiet uninstall command, already expanded by
    /// the caller. The engine's `uninstall.run_user` uses it to run the quiet or the interactive
    /// command that `uninstall.route` showed; `None` keeps the quiet-command rule of
    /// [`quiet_command`]. It is never expanded again.
    pub command: Option<&'a QuietCommand>,
}

/// Everything one run produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    /// The `purge.run/0` document.
    pub doc: RunDoc,
    /// The command that was run, expanded.
    pub command: QuietCommand,
    /// The routing facts.
    pub routing: Routing,
    /// Why the wait ended.
    pub wait_end: WaitEnd,
    /// The verify-gone facts behind [`RunDoc::verify_gone`].
    pub verify: VerifyGoneCheck,
    /// Things that could not be read on the way (signer, environment, probes).
    pub warnings: Vec<String>,
}

/// Why nothing was run.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunError {
    /// The entry has no usable quiet uninstall command.
    #[error("no quiet uninstall command: {0}")]
    NoQuietCommand(#[from] QuietError),
}

/// Collects warnings without repeating one.
#[derive(Default)]
struct Warnings(Vec<String>);

impl Warnings {
    fn push(&mut self, w: String) {
        if !self.0.contains(&w) {
            self.0.push(w);
        }
    }
}

/// Folds a path for prefix comparison: lower case, backslashes, no `\\?\` prefix, no trailing separator.
fn fold_path(p: &str) -> String {
    let p = p.replace('/', "\\");
    let p = p.strip_prefix(r"\\?\").unwrap_or(&p);
    p.trim_end_matches('\\').to_lowercase()
}

/// Whether `path` is `root` or lies below it (case-insensitive, whole segments).
fn is_under(path: &str, root: &str) -> bool {
    let (p, r) = (fold_path(path), fold_path(root));
    !r.is_empty()
        && p.strip_prefix(&r)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('\\'))
}

/// Records processes once each (by pid and name).
#[derive(Default)]
struct Seen(Vec<ProcessSeen>);

impl Seen {
    fn has_pid(&self, pid: u32) -> bool {
        self.0.iter().any(|p| p.pid == pid)
    }

    fn add(&mut self, p: ProcessSeen) {
        if !self
            .0
            .iter()
            .any(|q| q.pid == p.pid && q.name.eq_ignore_ascii_case(&p.name))
        {
            self.0.push(p);
        }
    }
}

/// What the run observed on the way: processes and warnings.
#[derive(Default)]
struct Log {
    seen: Seen,
    warnings: Warnings,
}

fn elapsed(from: FileTime, to: FileTime) -> Duration {
    Duration::from_nanos(to.0.saturating_sub(from.0).saturating_mul(100))
}

/// Adds the running processes under `roots` to `seen`.
fn note_processes_under_roots(host: &mut dyn ProcessHost, roots: &[String], log: &mut Log) {
    if roots.is_empty() {
        return;
    }
    match host.running_processes() {
        Ok(list) => {
            for p in list {
                if p.path
                    .as_deref()
                    .is_some_and(|path| roots.iter().any(|r| is_under(path, r)))
                {
                    log.seen.add(p);
                }
            }
        }
        Err(e) => log
            .warnings
            .push(format!("cannot list running processes: {e}")),
    }
}

/// The result of the wait.
struct Waited {
    end: WaitEnd,
    t_end: FileTime,
}

/// The wait state machine of step 5 (see the module documentation).
fn wait(
    host: &mut dyn ProcessHost,
    reg: &dyn RegistrySource,
    arp_key: &str,
    job: JobId,
    t_start: FileTime,
    opts: &RunOptions,
    log: &mut Log,
) -> Waited {
    let Log { seen, warnings } = log;
    let quiet_needed = opts.quiet_polls.max(1);
    let mut quiet_count = 0u32;
    let mut idle_since: Option<FileTime> = None;
    loop {
        let now = host.now();

        let tree_idle = match host.job_active_pids(job) {
            Ok(pids) => {
                for &pid in &pids {
                    if !seen.has_pid(pid) {
                        seen.add(host.process_info(pid).unwrap_or(ProcessSeen {
                            pid,
                            name: String::new(),
                            path: None,
                            start: None,
                        }));
                    }
                }
                pids.is_empty()
            }
            Err(e) => {
                warnings.push(format!("cannot list the job's processes: {e}"));
                false
            }
        };
        let msi_idle = match host.mutex_exists(MSI_EXECUTE_MUTEX) {
            Ok(present) => !present,
            Err(e) => {
                warnings.push(format!("cannot probe {MSI_EXECUTE_MUTEX}: {e}"));
                false
            }
        };
        let arp = reg.key_exists(arp_key);
        let idle = tree_idle && msi_idle;

        if idle && arp == ExistsState::Absent {
            quiet_count += 1;
            if quiet_count >= quiet_needed {
                return Waited {
                    end: WaitEnd::Settled,
                    t_end: now,
                };
            }
        } else {
            quiet_count = 0;
        }

        if idle && arp != ExistsState::Absent {
            let since = *idle_since.get_or_insert(now);
            if elapsed(since, now) >= opts.arp_grace {
                return Waited {
                    end: WaitEnd::ArpStayed,
                    t_end: now,
                };
            }
        } else {
            idle_since = None;
        }

        if elapsed(t_start, now) >= opts.timeout {
            return Waited {
                end: WaitEnd::TimedOut,
                t_end: now,
            };
        }
        host.sleep(opts.poll);
    }
}

/// The routing facts of §4.4 for `entry` whose uninstaller is `exe`.
fn routing(
    entry: &InventoryEntry,
    exe: &str,
    fs: &dyn FileSystemSource,
    sys: &dyn SystemSource,
) -> Routing {
    let per_user = entry.hive_sid.is_some() || entry.writable_by == WritableBy::User;
    let exe_admin_only = matches!(fs.is_admin_only_executable(exe), Ok(true));
    Routing {
        ran_as: if sys.elevated() {
            RanAs::Elevated
        } else {
            RanAs::Medium
        },
        should_run_medium: per_user || !exe_admin_only,
    }
}

/// The environment an elevated uninstaller starts with: the machine block (Windows-derived values and
/// `HKLM\...\Session Manager\Environment`) plus the interactive user's profile variables. It never
/// carries a value from `HKCU\Environment`, so a medium process cannot choose `SystemRoot`, `PATH`,
/// `ComSpec`, `ProgramData` and the like through that key (review M3-R2 B1/S4).
///
/// The machine `PATH` keeps only the entries that are admin-only directories (`is_admin_only_writable`,
/// whose leaf mask also refuses "add file"), in their order: a bare name in a vendor script, or a DLL
/// the loader does not find earlier, must not resolve into a folder a standard user can write. A
/// user-writable, missing, relative, empty or unreadable entry is dropped (review M3-R2, third Fable
/// review). Only the environment is filtered; the command text stays the one shown (B1).
fn uninstaller_environment(
    sys: &dyn SystemSource,
    fs: &dyn FileSystemSource,
) -> BTreeMap<String, String> {
    let mut env = sys.machine_env().unwrap_or_default();
    for (name, value) in env.iter_mut() {
        if name.eq_ignore_ascii_case("PATH") {
            *value = admin_only_path(value, fs);
        }
    }
    let user = sys.env().unwrap_or_default();
    let profile = sys
        .user_sid()
        .ok()
        .and_then(|sid| {
            sys.profiles()
                .ok()?
                .into_iter()
                .find(|p| p.sid.eq_ignore_ascii_case(&sid))
        })
        .map(|p| p.path)
        .or_else(|| user.get("USERPROFILE").cloned());
    if let Some(profile) = profile {
        let drive: String = profile.chars().take(2).collect();
        let tail: String = profile.chars().skip(2).collect();
        let user_name = profile.rsplit('\\').next().unwrap_or_default().to_owned();
        let local = format!(r"{profile}\AppData\Local");
        env.insert("USERPROFILE".into(), profile.clone());
        env.insert("HOMEDRIVE".into(), drive);
        env.insert("HOMEPATH".into(), tail);
        env.insert("APPDATA".into(), format!(r"{profile}\AppData\Roaming"));
        env.insert("LOCALAPPDATA".into(), local.clone());
        env.insert("TEMP".into(), format!(r"{local}\Temp"));
        env.insert("TMP".into(), format!(r"{local}\Temp"));
        if !user_name.is_empty() {
            env.insert("USERNAME".into(), user_name);
        }
    }
    env
}

/// The entries of the `;`-separated `path` that are admin-only directories, in their order. Quotes
/// around an entry are ignored for the check and kept in the result.
fn admin_only_path(path: &str, fs: &dyn FileSystemSource) -> String {
    path.split(';')
        .filter(|entry| {
            let dir = entry.trim().trim_matches('"');
            Path::new(dir).is_absolute() && fs.is_admin_only_writable(dir) == Ok(true)
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// Runs the quiet uninstall command of `req.entry` and waits for it (see the module documentation).
///
/// `reg`, `fs` and `sys` are read before and after the run (environment, signer, routing, the ARP key while
/// waiting, verify-gone); `host` starts and watches the process. Errors only when there is no command to
/// run; a command that cannot be started gives a report with [`RunOutcome::Failed`].
pub fn run_uninstall(
    host: &mut dyn ProcessHost,
    reg: &dyn RegistrySource,
    fs: &dyn FileSystemSource,
    sys: &dyn SystemSource,
    req: &RunRequest<'_>,
    opts: &RunOptions,
) -> Result<RunReport, RunError> {
    let entry = req.entry;
    let mut log = Log::default();

    let env: BTreeMap<String, String> = sys.env().unwrap_or_else(|e| {
        log.warnings
            .push(format!("cannot read the environment: {e}"));
        BTreeMap::new()
    });
    let command = match req.command {
        // The caller already expanded the command it showed (`prepare` or `uninstall.route`);
        // expanding it again here would run a different string than the one shown (review M3-R2 B1).
        Some(command) => command.clone(),
        None => quiet_command(entry)?.expand(&env),
    };
    let cmd = command.to_command_line();

    let signer = match fs.signer_cn(&command.exe) {
        Ok(cn) => cn,
        Err(e) => {
            log.warnings
                .push(format!("cannot read the signer of {}: {e}", command.exe));
            None
        }
    };
    let routing = routing(entry, &command.exe, fs, sys);

    note_processes_under_roots(host, req.roots, &mut log);

    // An elevated uninstaller must not inherit the broker's environment or working directory
    // (review M3-R2 S4). A medium run keeps the engine's own environment: that is the user's.
    let elevated = sys.elevated();
    let clean_environment = elevated.then(|| uninstaller_environment(sys, fs));
    let working_dir = elevated
        .then(|| Path::new(&command.exe).parent())
        .flatten()
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(Path::to_path_buf);
    let spawn = SpawnContext {
        environment: clean_environment.as_ref(),
        current_dir: working_dir.as_deref(),
    };

    let t_start = host.now();
    let (wait_end, t_end, exit_code) = match host.spawn_in_job(&cmd, spawn) {
        Err(e) => {
            log.warnings
                .push(format!("cannot start the uninstaller: {e}"));
            (WaitEnd::NotStarted, host.now(), None)
        }
        Ok(job) => {
            let waited = wait(host, reg, &entry.key_path, job, t_start, opts, &mut log);
            let exit_code = match host.job_exit_code(job) {
                Ok(code) => code,
                Err(e) => {
                    log.warnings.push(format!("cannot read the exit code: {e}"));
                    None
                }
            };
            (waited.end, waited.t_end, exit_code)
        }
    };
    let outcome = match (wait_end, exit_code) {
        (WaitEnd::TimedOut, _) => RunOutcome::TimedOut,
        (WaitEnd::NotStarted, _) | (_, None) => RunOutcome::Failed,
        (_, Some(code)) => RunOutcome::from_exit_code(code),
    };

    note_processes_under_roots(host, req.roots, &mut log);

    let verify = verify_gone::check(
        reg,
        fs,
        sys,
        &VerifyTarget::from_entry(entry, req.main_exes),
    );
    let co_removed = req
        .before
        .map(|before| verify_gone::disappeared(reg, before, &entry.program_id))
        .unwrap_or_default();

    Ok(RunReport {
        doc: RunDoc {
            schema: RunSchema,
            program_id: entry.program_id.clone(),
            cmd,
            signer,
            t_start,
            t_end,
            exit_code,
            outcome,
            verify_gone: verify.result,
            processes: log.seen.0,
            co_removed,
        },
        command,
        routing,
        wait_end,
        verify,
        warnings: log.warnings.0,
    })
}

// ---------------------------------------------------------------------------------------------------------
// Live host
// ---------------------------------------------------------------------------------------------------------

/// [`ProcessHost`] over `purge-win` (feature `run`): `CreateProcessW` in a Job object without breakaway,
/// the job's process list, `OpenMutexW`, Toolhelp32 and `QueryFullProcessImageNameW`.
///
/// Jobs are never killed: they are created without `KILL_ON_JOB_CLOSE`, so dropping the host leaves any
/// process still running alone.
#[derive(Debug)]
pub struct LiveHost {
    jobs: HashMap<u64, JobProcess>,
    next: u64,
    base: FileTime,
    started: Instant,
    hide_console: bool,
}

impl Default for LiveHost {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveHost {
    /// A host whose clock starts at the current wall-clock time and then advances monotonically.
    /// Console windows of console-subsystem commands are hidden.
    pub fn new() -> Self {
        let since_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let ticks = u64::try_from(since_unix.as_nanos() / 100).unwrap_or(u64::MAX);
        Self {
            jobs: HashMap::new(),
            next: 1,
            base: FileTime(FileTime::from_unix_secs(0).0.saturating_add(ticks)),
            started: Instant::now(),
            hide_console: true,
        }
    }

    /// Whether console-subsystem commands start without a console window (`CREATE_NO_WINDOW`).
    pub fn with_hidden_console(mut self, hide: bool) -> Self {
        self.hide_console = hide;
        self
    }

    fn job(&self, job: JobId) -> io::Result<&JobProcess> {
        self.jobs
            .get(&job.0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown job"))
    }
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

impl ProcessHost for LiveHost {
    fn spawn_in_job(&mut self, command_line: &str, context: SpawnContext<'_>) -> io::Result<JobId> {
        let process = JobProcess::spawn(
            command_line,
            &SpawnOptions {
                current_dir: context.current_dir,
                environment: context.environment,
                hide_console: self.hide_console,
                kill_on_drop: false,
            },
        )?;
        let id = self.next;
        self.next += 1;
        self.jobs.insert(id, process);
        Ok(JobId(id))
    }

    fn job_active_pids(&mut self, job: JobId) -> io::Result<Vec<u32>> {
        self.job(job)?.process_ids()
    }

    fn job_exit_code(&mut self, job: JobId) -> io::Result<Option<u32>> {
        self.job(job)?.exit_code()
    }

    fn process_info(&mut self, pid: u32) -> Option<ProcessSeen> {
        let path = winproc::process_image_path(pid).ok().flatten();
        let name = match &path {
            Some(p) => file_name(p),
            None => {
                winproc::snapshot_processes()
                    .ok()?
                    .into_iter()
                    .find(|e| e.pid == pid)?
                    .exe_file
            }
        };
        Some(ProcessSeen {
            pid,
            name,
            path: path.map(|p| p.to_string_lossy().into_owned()),
            start: None,
        })
    }

    fn running_processes(&mut self) -> io::Result<Vec<ProcessSeen>> {
        Ok(winproc::snapshot_processes()?
            .into_iter()
            .map(|e| ProcessSeen {
                pid: e.pid,
                path: winproc::process_image_path(e.pid)
                    .ok()
                    .flatten()
                    .map(|p| p.to_string_lossy().into_owned()),
                name: e.exe_file,
                start: None,
            })
            .collect())
    }

    fn mutex_exists(&mut self, name: &str) -> io::Result<bool> {
        winproc::mutex_exists(name)
    }

    fn now(&self) -> FileTime {
        let ticks = u64::try_from(self.started.elapsed().as_nanos() / 100).unwrap_or(u64::MAX);
        FileTime(self.base.0.saturating_add(ticks))
    }

    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_gone::tests::entry;
    use purge_model::{InstallerKind, View};
    use purge_source::fixture::Fixture;
    use purge_source::types::{KeyInfo, RegData, RegValue, SourceError, SourceResult};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// FileTime of the fake clock's zero.
    const BASE: u64 = 134_000_000_000_000_000;
    /// Ticks (100 ns) per millisecond, the unit of [`FileTime`].
    const TICKS_PER_MS: u64 = 10_000;

    fn secs(s: u64) -> u64 {
        s * 1000
    }

    /// A process of the scripted job: alive in `[start, end)` (milliseconds; `None` = forever).
    #[derive(Clone)]
    struct FakeProc {
        pid: u32,
        name: &'static str,
        start: u64,
        end: Option<u64>,
    }

    impl FakeProc {
        fn alive(&self, t: u64) -> bool {
            self.start <= t && self.end.is_none_or(|e| t < e)
        }
    }

    /// The environment and working directory of one spawn.
    type SpawnRecord = (Option<BTreeMap<String, String>>, Option<std::path::PathBuf>);

    /// A scripted host: the first process is the root; time only moves in `sleep`.
    struct FakeHost {
        clock: Arc<AtomicU64>,
        procs: Vec<FakeProc>,
        root_exit: u32,
        spawn_fails: bool,
        /// `[start, end)` intervals in which `Global\_MSIExecute` exists.
        msi: Vec<(u64, u64)>,
        running: Vec<ProcessSeen>,
        spawned: Vec<String>,
        /// The environment and working directory of each spawn.
        spawn_contexts: Vec<SpawnRecord>,
        polls: u32,
    }

    impl FakeHost {
        fn new(clock: &Arc<AtomicU64>, procs: Vec<FakeProc>, root_exit: u32) -> Self {
            Self {
                clock: clock.clone(),
                procs,
                root_exit,
                spawn_fails: false,
                msi: Vec::new(),
                running: Vec::new(),
                spawned: Vec::new(),
                spawn_contexts: Vec::new(),
                polls: 0,
            }
        }

        fn t(&self) -> u64 {
            self.clock.load(Ordering::SeqCst)
        }
    }

    impl ProcessHost for FakeHost {
        fn spawn_in_job(
            &mut self,
            command_line: &str,
            context: SpawnContext<'_>,
        ) -> io::Result<JobId> {
            self.spawned.push(command_line.to_owned());
            self.spawn_contexts.push((
                context.environment.cloned(),
                context.current_dir.map(Path::to_path_buf),
            ));
            if self.spawn_fails {
                return Err(io::Error::from_raw_os_error(2));
            }
            Ok(JobId(1))
        }

        fn job_active_pids(&mut self, job: JobId) -> io::Result<Vec<u32>> {
            assert_eq!(job, JobId(1));
            self.polls += 1;
            let t = self.t();
            Ok(self
                .procs
                .iter()
                .filter(|p| p.alive(t))
                .map(|p| p.pid)
                .collect())
        }

        fn job_exit_code(&mut self, _: JobId) -> io::Result<Option<u32>> {
            let t = self.t();
            Ok((!self.procs[0].alive(t)).then_some(self.root_exit))
        }

        fn process_info(&mut self, pid: u32) -> Option<ProcessSeen> {
            let p = self.procs.iter().find(|p| p.pid == pid)?;
            Some(ProcessSeen {
                pid,
                name: p.name.into(),
                path: Some(format!(r"C:\Users\u\AppData\Local\Temp\{}", p.name)),
                start: None,
            })
        }

        fn running_processes(&mut self) -> io::Result<Vec<ProcessSeen>> {
            Ok(self.running.clone())
        }

        fn mutex_exists(&mut self, name: &str) -> io::Result<bool> {
            assert_eq!(name, r"Global\_MSIExecute");
            let t = self.t();
            Ok(self.msi.iter().any(|&(a, b)| a <= t && t < b))
        }

        fn now(&self) -> FileTime {
            FileTime(BASE + self.t() * TICKS_PER_MS)
        }

        fn sleep(&mut self, d: Duration) {
            self.clock
                .fetch_add(u64::try_from(d.as_millis()).unwrap(), Ordering::SeqCst);
        }
    }

    /// A registry whose listed keys disappear at scripted times on the shared clock.
    struct ScriptedReg<'a> {
        inner: &'a Fixture,
        clock: Arc<AtomicU64>,
        gone_at: Vec<(String, Option<u64>)>,
    }

    impl ScriptedReg<'_> {
        fn gone(&self, key: &str) -> bool {
            let t = self.clock.load(Ordering::SeqCst);
            self.gone_at
                .iter()
                .any(|(k, at)| k.eq_ignore_ascii_case(key) && at.is_some_and(|at| t >= at))
        }
    }

    impl RegistrySource for ScriptedReg<'_> {
        fn key_info(&self, key: &str) -> SourceResult<KeyInfo> {
            if self.gone(key) {
                return Err(SourceError::NotFound);
            }
            self.inner.key_info(key)
        }
        fn subkeys(&self, key: &str) -> SourceResult<Vec<String>> {
            self.inner.subkeys(key)
        }
        fn values(&self, key: &str) -> SourceResult<Vec<RegValue>> {
            self.inner.values(key)
        }
        fn value(&self, key: &str, name: &str) -> SourceResult<RegData> {
            self.inner.value(key, name)
        }
        fn loaded_user_sids(&self) -> SourceResult<Vec<String>> {
            self.inner.loaded_user_sids()
        }
        fn current_control_set(&self) -> SourceResult<u32> {
            self.inner.current_control_set()
        }
    }

    const UNINS: &str = r"C:\Program Files\App\unins000.exe";

    fn inno_entry() -> InventoryEntry {
        let mut e = entry(View::K64, "App_is1", InstallerKind::Inno);
        e.uninstall_string = Some(format!("\"{UNINS}\""));
        e
    }

    /// A machine with the entry's ARP key and the uninstaller (signed, admin-only).
    fn machine(e: &InventoryEntry) -> Fixture {
        let mut f = Fixture::new();
        f.add_key(&e.key_path);
        f.add_file(UNINS, 100);
        f.set_signer(UNINS, "App Vendor Ltd");
        f.set_admin_only_roots(vec![r"C:\Program Files".into()]);
        f
    }

    struct Case {
        clock: Arc<AtomicU64>,
        host: FakeHost,
        fixture: Fixture,
        entry: InventoryEntry,
        arp_gone_at: Option<u64>,
        opts: RunOptions,
    }

    impl Case {
        /// Root `unins000.exe` alive for `root_ms`, exit code `code`, ARP key gone at `arp_gone_at`.
        fn new(root_ms: u64, code: u32, arp_gone_at: Option<u64>) -> Self {
            let clock = Arc::new(AtomicU64::new(0));
            let entry = inno_entry();
            Self {
                host: FakeHost::new(
                    &clock,
                    vec![FakeProc {
                        pid: 100,
                        name: "unins000.exe",
                        start: 0,
                        end: Some(root_ms),
                    }],
                    code,
                ),
                fixture: machine(&entry),
                clock,
                entry,
                arp_gone_at,
                opts: RunOptions::default(),
            }
        }

        fn run_with(
            &mut self,
            before: Option<&[InventoryEntry]>,
            extra_gone: &[(String, u64)],
        ) -> RunReport {
            let mut gone_at = vec![(self.entry.key_path.clone(), self.arp_gone_at)];
            gone_at.extend(extra_gone.iter().map(|(k, t)| (k.clone(), Some(*t))));
            let reg = ScriptedReg {
                inner: &self.fixture,
                clock: self.clock.clone(),
                gone_at,
            };
            let roots = [r"C:\Program Files\App".to_string()];
            let exes = [r"C:\Program Files\App\app.exe".to_string()];
            let req = RunRequest {
                entry: &self.entry,
                main_exes: &exes,
                roots: &roots,
                before,
                command: None,
            };
            run_uninstall(
                &mut self.host,
                &reg,
                &self.fixture,
                &self.fixture,
                &req,
                &self.opts,
            )
            .unwrap()
        }

        fn run(&mut self) -> RunReport {
            self.run_with(None, &[])
        }
    }

    fn ms_since_start(r: &RunReport) -> u64 {
        (r.doc.t_end.0 - r.doc.t_start.0) / TICKS_PER_MS
    }

    #[test]
    fn exit_codes_map_to_outcomes() {
        for (code, outcome) in [
            (0, RunOutcome::Success),
            (1605, RunOutcome::AlreadyGone),
            (1641, RunOutcome::SuccessReboot),
            (3010, RunOutcome::SuccessReboot),
            (1602, RunOutcome::Cancelled),
            (1603, RunOutcome::Failed),
            (1, RunOutcome::Failed),
        ] {
            let mut c = Case::new(secs(2), code, Some(secs(1)));
            let r = c.run();
            assert_eq!(r.doc.outcome, outcome, "{code}");
            assert_eq!(r.doc.exit_code, Some(code));
            assert_eq!(r.wait_end, WaitEnd::Settled);
            // Polls at 0,1,2,3 s: quiet at 2 and 3.
            assert_eq!(ms_since_start(&r), secs(3), "{code}");
            assert!(r.doc.verify_gone.is_passed(), "{code}");
        }
    }

    #[test]
    fn records_command_signer_and_routing() {
        let mut c = Case::new(secs(1), 0, Some(0));
        let r = c.run();
        let expected = format!("\"{UNINS}\" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART");
        assert_eq!(r.doc.cmd, expected);
        assert_eq!(c.host.spawned, vec![expected]);
        assert_eq!(r.doc.signer.as_deref(), Some("App Vendor Ltd"));
        assert_eq!(r.doc.program_id, c.entry.program_id);
        assert_eq!(r.doc.t_start, FileTime(BASE));
        assert_eq!(
            r.routing,
            Routing {
                ran_as: RanAs::Medium,
                should_run_medium: false
            }
        );
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        // The routing serialises with the documented spelling.
        assert_eq!(
            serde_json::to_value(r.routing).unwrap(),
            serde_json::json!({"ran_as": "medium", "should_run_medium": false})
        );

        // A per-user entry, an elevated engine, and an uninstaller in a user-writable folder.
        let mut c = Case::new(secs(1), 0, Some(0));
        c.fixture.system_mut().elevated = true;
        let r = c.run();
        assert_eq!(r.routing.ran_as, RanAs::Elevated);
        assert!(!r.routing.should_run_medium);
        let mut c = Case::new(secs(1), 0, Some(0));
        c.entry.writable_by = WritableBy::User;
        assert!(c.run().routing.should_run_medium);
        let mut c = Case::new(secs(1), 0, Some(0));
        c.fixture
            .set_admin_only_writable(r"C:\Program Files\App", false);
        assert!(c.run().routing.should_run_medium);
    }

    #[test]
    fn a_given_command_is_run_exactly_as_frozen() {
        let mut c = Case::new(secs(1), 0, Some(0));
        c.fixture.system_mut().env.insert(
            "X".into(),
            r"C:\Users\tester\AppData\Local\planted.exe".into(),
        );
        let frozen = QuietCommand {
            exe: UNINS.into(),
            args: "%X% /S".into(),
            generated: false,
            kind: InstallerKind::Inno,
        };
        let roots = [r"C:\Program Files\App".to_string()];
        let exes = [r"C:\Program Files\App\app.exe".to_string()];
        let req = RunRequest {
            entry: &c.entry,
            main_exes: &exes,
            roots: &roots,
            before: None,
            command: Some(&frozen),
        };
        let report = run_uninstall(
            &mut c.host,
            &c.fixture,
            &c.fixture,
            &c.fixture,
            &req,
            &c.opts,
        )
        .unwrap();
        let expected = format!("\"{UNINS}\" %X% /S");
        assert_eq!(c.host.spawned, vec![expected.clone()]);
        assert_eq!(report.doc.cmd, expected, "the shown command is the one run");
    }

    #[test]
    fn the_live_machine_path_keeps_the_expanded_system32() {
        // `%SystemRoot%\system32` in the registry's PATH arrives expanded and survives the filter.
        use purge_source::live::{LiveFileSystem, LiveSystem};
        let env = LiveSystem::new().machine_env().unwrap();
        let path = env.get("PATH").expect("a machine PATH");
        let system32 = format!(r"{}\system32", env.get("SYSTEMROOT").expect("SystemRoot"));
        let has_system32 = |p: &str| {
            p.split(';')
                .any(|e| e.trim_end_matches('\\').eq_ignore_ascii_case(&system32))
        };
        assert!(has_system32(path), "{path}");
        let kept = admin_only_path(path, &LiveFileSystem::new());
        assert!(has_system32(&kept), "{kept}");
        assert!(!kept.contains('%'), "{kept}");
    }

    #[test]
    fn an_elevated_run_gets_the_machine_environment_and_the_uninstaller_directory() {
        let mut c = Case::new(secs(1), 0, Some(0));
        c.fixture.add_dir(r"C:\Windows\system32");
        c.fixture
            .add_dir(r"C:\Windows\System32\WindowsPowerShell\v1.0");
        c.fixture.add_dir(r"C:\Tools\bin");
        c.fixture.add_dir(r"C:\Program Files\Vendor\bin");
        c.fixture
            .set_admin_only_roots(vec![r"C:\Program Files".into(), r"C:\Windows".into()]);
        let facts = c.fixture.system_mut();
        facts.elevated = true;
        // An admin-only dir, a user-writable dir, a missing dir, an empty entry, a relative entry and a
        // quoted admin-only dir: only the admin-only ones survive, in their order.
        facts.machine_env = [
            (
                "PATH",
                r#"C:\Windows\system32;C:\Tools\bin;;C:\Missing\bin;bin;"C:\Program Files\Vendor\bin";C:\Windows;C:\WINDOWS\System32\WindowsPowerShell\v1.0\"#,
            ),
            ("PROGRAMDATA", r"C:\ProgramData"),
            ("COMSPEC", r"C:\Windows\system32\cmd.exe"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        facts.env = [
            ("PATH", r"C:\Users\tester\bin"),
            ("PROGRAMDATA", r"C:\Users\tester\planted"),
            ("USERPROFILE", r"C:\Users\tester"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let frozen = QuietCommand {
            exe: UNINS.into(),
            args: "/S".into(),
            generated: false,
            kind: InstallerKind::Inno,
        };
        let roots = [r"C:\Program Files\App".to_string()];
        let exes = [r"C:\Program Files\App\app.exe".to_string()];
        let req = RunRequest {
            entry: &c.entry,
            main_exes: &exes,
            roots: &roots,
            before: None,
            command: Some(&frozen),
        };
        run_uninstall(
            &mut c.host,
            &c.fixture,
            &c.fixture,
            &c.fixture,
            &req,
            &c.opts,
        )
        .unwrap();
        let (environment, current_dir) = c.host.spawn_contexts.first().expect("a spawn");
        let environment = environment.as_ref().expect("a clean environment");
        assert_eq!(
            environment.get("PATH").map(String::as_str),
            Some(
                r#"C:\Windows\system32;"C:\Program Files\Vendor\bin";C:\Windows;C:\WINDOWS\System32\WindowsPowerShell\v1.0\"#
            ),
            "the user's PATH was inherited, or a writable or missing machine PATH entry kept"
        );
        assert_eq!(
            environment.get("PROGRAMDATA").map(String::as_str),
            Some(r"C:\ProgramData"),
            "a planted PROGRAMDATA was inherited"
        );
        assert_eq!(
            environment.get("USERPROFILE").map(String::as_str),
            Some(r"C:\Users\tester")
        );
        assert_eq!(
            current_dir.as_deref(),
            Some(std::path::Path::new(r"C:\Program Files\App")),
            "the working directory is the uninstaller's own"
        );
    }

    #[test]
    fn nsis_relaunch_child_is_awaited() {
        let mut c = Case::new(secs(1), 0, Some(secs(15)));
        // The NSIS stub exits at 1 s; its copy in %TEMP% runs inside the job until 20 s.
        c.host.procs.push(FakeProc {
            pid: 101,
            name: "Au_.exe",
            start: 500,
            end: Some(secs(20)),
        });
        let r = c.run();
        assert_eq!(r.wait_end, WaitEnd::Settled);
        assert_eq!(r.doc.outcome, RunOutcome::Success);
        assert_eq!(r.doc.exit_code, Some(0));
        assert_eq!(ms_since_start(&r), secs(21));
        let names: Vec<&str> = r.doc.processes.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["unins000.exe", "Au_.exe"]);
        assert!(r.doc.verify_gone.is_passed());
    }

    #[test]
    fn msi_mutex_delays_completion() {
        let mut c = Case::new(secs(2), 0, Some(secs(5)));
        c.host.msi = vec![(0, secs(30))];
        let r = c.run();
        assert_eq!(r.wait_end, WaitEnd::Settled);
        assert_eq!(ms_since_start(&r), secs(31));
        assert_eq!(r.doc.outcome, RunOutcome::Success);
    }

    #[test]
    fn two_consecutive_quiet_polls_are_needed() {
        let mut c = Case::new(secs(1), 0, Some(secs(1)));
        // Quiet at 1 s, busy at 2 s (an MSI transaction), quiet again at 3 and 4 s.
        c.host.msi = vec![(secs(2), secs(3))];
        let r = c.run();
        assert_eq!(ms_since_start(&r), secs(4));

        let mut c = Case::new(secs(1), 0, Some(secs(1)));
        c.opts.quiet_polls = 3;
        assert_eq!(ms_since_start(&c.run()), secs(3));
        let mut c = Case::new(secs(1), 0, Some(secs(1)));
        c.opts.quiet_polls = 0; // treated as 1
        assert_eq!(ms_since_start(&c.run()), secs(1));
    }

    #[test]
    fn arp_key_staying_ends_after_the_idle_grace() {
        let mut c = Case::new(secs(2), 0, None);
        let r = c.run();
        assert_eq!(r.wait_end, WaitEnd::ArpStayed);
        // Idle from 2 s; given up 180 s later. Not a timeout.
        assert_eq!(ms_since_start(&r), secs(182));
        assert_eq!(r.doc.outcome, RunOutcome::Success);
        assert_eq!(r.doc.exit_code, Some(0));
        assert!(!r.doc.verify_gone.passed && !r.doc.verify_gone.is_passed());
        assert!(!r.doc.verify_gone.arp_gone);
        assert_eq!(r.verify.arp, ExistsState::Present);

        // The grace restarts when the tree or MSI becomes busy again.
        let mut c = Case::new(secs(2), 0, None);
        c.host.msi = vec![(secs(100), secs(101))];
        assert_eq!(ms_since_start(&c.run()), secs(281));
    }

    #[test]
    fn timeout_kills_nothing_and_reports_timed_out() {
        let mut c = Case::new(u64::MAX, 0, None);
        c.host.procs[0].end = None;
        let r = c.run();
        assert_eq!(r.wait_end, WaitEnd::TimedOut);
        assert_eq!(r.doc.outcome, RunOutcome::TimedOut);
        assert_eq!(r.doc.exit_code, None);
        assert_eq!(ms_since_start(&r), secs(30 * 60));
        assert!(!r.doc.verify_gone.is_passed());
        // The root is still alive in the fake job: nothing terminated it.
        assert_eq!(c.host.job_active_pids(JobId(1)).unwrap(), vec![100]);

        // The root exited but its child keeps running: still a timeout, the root's code is kept.
        let mut c = Case::new(secs(1), 0, Some(secs(1)));
        c.opts.timeout = Duration::from_secs(60);
        c.host.procs.push(FakeProc {
            pid: 101,
            name: "child.exe",
            start: 0,
            end: None,
        });
        let r = c.run();
        assert_eq!(r.doc.outcome, RunOutcome::TimedOut);
        assert_eq!(r.doc.exit_code, Some(0));
        assert_eq!(ms_since_start(&r), secs(60));
    }

    #[test]
    fn spawn_failure_is_failed_without_exit_code() {
        let mut c = Case::new(secs(1), 0, None);
        c.host.spawn_fails = true;
        let r = c.run();
        assert_eq!(r.wait_end, WaitEnd::NotStarted);
        assert_eq!(r.doc.outcome, RunOutcome::Failed);
        assert_eq!(r.doc.exit_code, None);
        assert_eq!(c.host.polls, 0);
        assert!(!r.doc.verify_gone.is_passed());
        assert!(r.warnings.iter().any(|w| w.contains("cannot start")));
    }

    #[test]
    fn no_quiet_command_runs_nothing() {
        let mut c = Case::new(secs(1), 0, None);
        c.entry = entry(View::K64, "Mystery", InstallerKind::Unknown);
        c.entry.uninstall_string = Some(r"C:\Mystery\remove.exe".into());
        let reg = &c.fixture;
        let req = RunRequest {
            entry: &c.entry,
            main_exes: &[],
            roots: &[],
            before: None,
            command: None,
        };
        let err = run_uninstall(&mut c.host, reg, reg, reg, &req, &c.opts).unwrap_err();
        assert!(matches!(
            err,
            RunError::NoQuietCommand(QuietError::NoQuietForm(InstallerKind::Unknown))
        ));
        assert!(c.host.spawned.is_empty());
    }

    #[test]
    fn running_processes_under_roots_are_listed() {
        let mut c = Case::new(secs(1), 0, Some(0));
        let app = |pid, path: &str| ProcessSeen {
            pid,
            name: Path::new(path)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into(),
            path: Some(path.into()),
            start: None,
        };
        c.host.running = vec![
            app(7, r"C:\PROGRAM FILES\APP\app.exe"),
            app(8, r"C:\Program Files\AppOther\other.exe"),
            app(9, r"\\?\C:\Program Files\App\bin\helper.exe"),
            ProcessSeen {
                pid: 10,
                name: "System".into(),
                path: None,
                start: None,
            },
        ];
        let r = c.run();
        let pids: Vec<u32> = r.doc.processes.iter().map(|p| p.pid).collect();
        // Listed once each (before and after the run), then the uninstaller tree.
        assert_eq!(pids, [7, 9, 100]);
    }

    #[test]
    fn co_removed_entries_are_reported() {
        let mut c = Case::new(secs(2), 0, Some(secs(1)));
        let firefox = c.entry.clone();
        let mms = entry(View::K32, "MozillaMaintenanceService", InstallerKind::Nsis);
        let tb = entry(View::K64, "Mozilla Thunderbird", InstallerKind::Nsis);
        c.fixture.add_key(&mms.key_path);
        c.fixture.add_key(&tb.key_path);
        let before = vec![firefox, mms.clone(), tb];
        let r = c.run_with(Some(&before), &[(mms.key_path.clone(), secs(2))]);
        assert_eq!(r.doc.co_removed, vec![mms.program_id]);
        assert!(r.doc.verify_gone.is_passed());
    }

    #[test]
    fn path_prefix() {
        assert!(is_under(r"C:\App\x.exe", r"c:\app"));
        assert!(is_under(r"C:\App", r"C:\App\"));
        assert!(is_under(r"\\?\C:\App\x.exe", r"C:\App"));
        assert!(is_under("C:/App/x.exe", r"C:\App"));
        assert!(!is_under(r"C:\Apple\x.exe", r"C:\App"));
        assert!(!is_under(r"C:\x.exe", ""));
    }

    /// Live smoke test (harmless): a fake "uninstaller" that only exits with 1605 runs through the Live host.
    #[test]
    fn live_host_runs_a_harmless_command() {
        let mut e = entry(
            View::K64,
            "PurgeRunnerSmokeTest-7f3c",
            InstallerKind::Unknown,
        );
        e.quiet_uninstall_string = Some("cmd /c exit 1605".into());
        let f = Fixture::new(); // no ARP key: already gone
        let mut host = LiveHost::new();
        let opts = RunOptions {
            poll: Duration::from_millis(50),
            timeout: Duration::from_secs(120),
            ..RunOptions::default()
        };
        let req = RunRequest {
            entry: &e,
            main_exes: &[],
            roots: &[],
            before: None,
            command: None,
        };
        let r = run_uninstall(&mut host, &f, &f, &f, &req, &opts).unwrap();
        assert_eq!(r.doc.cmd, "cmd /c exit 1605");
        assert_eq!(r.wait_end, WaitEnd::Settled, "{:?}", r.warnings);
        assert_eq!(r.doc.exit_code, Some(1605));
        assert_eq!(r.doc.outcome, RunOutcome::AlreadyGone);
        assert!(r.doc.t_end >= r.doc.t_start);
        // The wall clock is roughly now (within a day).
        let now = FileTime::from_unix_secs(
            i64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
            .unwrap(),
        );
        assert!(r.doc.t_start.0.abs_diff(now.0) < 86_400 * 10_000_000);
    }
}
