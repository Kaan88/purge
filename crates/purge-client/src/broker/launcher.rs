//! The launcher of M3 design 3.3 step 1 and the client half of steps 3 and 4 (port of
//! `Broker/BrokerLauncher.cs` and `Broker/BrokerPipe.cs`).
//!
//! In order, and nothing written to the pipe before the last check passed:
//!
//! 1. The UI's own account pre-check: a standard user (no split token, not elevated) cannot elevate,
//!    so no prompt is shown ([`LaunchStatus::NotAdministrator`]).
//! 2. The broker must exist; its path is made absolute, so the image check compares against the file
//!    that was started.
//! 3. A pipe name of 128 random bits (`BCryptGenRandom` through `purge_win::os::random_u64`, 32
//!    lower-case hex digits), and the arguments `--pipe <name> --parent <pid> --parent-ctime
//!    <filetime>`: the broker holds this process as its parent and exits when it goes. With
//!    [`ConsentUi::Toolkit`], `--consent toolkit` is added ([`launch_with`]): the broker then draws
//!    its consent dialog with Purge's own toolkit. Without it the broker uses its own default, the
//!    TaskDialog.
//! 4. `ShellExecuteExW("runas")` on its own STA thread with no owner window (DECISIONS 2026-11-23 "UAC
//!    prompt owner"), keeping the process handle: the pid cannot be reused while it is held.
//! 5. Connect to `\\.\pipe\purge-<name>` with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` (the
//!    server may identify this client but never act as it), retrying for [`CONNECT_TIMEOUT`] while
//!    the pipe is missing or busy.
//! 6. [`super::check_server`]: the server pid, image and elevation.
//! 7. `engine.hello` within [`HELLO_TIMEOUT`]; only then is there a session.
//!
//! Every failure after step 4 terminates the broker on a best-effort basis (a medium process usually
//! may not; the broker then ends by itself when this process exits or after its idle time, and does
//! nothing meanwhile: it acts only for a client that passed its check and sent `engine.hello`).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use purge_win::launch::{LaunchedProcess, run_as};
use purge_win::os::{Win32Error, random_u64};
use purge_win::pipe_client::PipeClient;
use purge_win::process::ProcessHandle;
use purge_win::token::{ElevationType, current_process_facts};

use super::{BrokerClient, HandshakeError, ServerCheck, check_server};
use crate::engine::win32_text;
use crate::{CallId, ClientEvent, Sink};

/// How long the broker may take to create its pipe (design 3.3 step 3: retry for up to 10 s).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the broker may take to answer `engine.hello` once the pipe is open.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// The message of [`LaunchStatus::NotAdministrator`]; every route's bar shows it under its own
/// title.
pub const STANDARD_USER_MESSAGE: &str =
    "This needs an administrator account; this account is a standard user.";

const ERROR_CANCELLED: u32 = 1223;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PIPE_BUSY: u32 = 231;
const ERROR_SEM_TIMEOUT: u32 = 121;

/// How a launch ended without a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchStatus {
    /// The user said No at the Windows prompt (error 1223). Show the cancelled bar; nothing changed.
    Cancelled,
    /// The account cannot elevate (a standard user).
    NotAdministrator,
    /// The broker could not be started, exited before its pipe existed, or refused the hello.
    CannotStart,
    /// The pipe was served by something other than the broker that was launched.
    ServerCheckFailed,
    /// No pipe within [`CONNECT_TIMEOUT`], or no hello answer within [`HELLO_TIMEOUT`].
    TimedOut,
    /// The caller stopped the launch ([`Launch::stop`]).
    Stopped,
}

/// Why a launch made no session.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct LaunchFailure {
    /// What happened.
    pub status: LaunchStatus,
    /// One sentence for the UI; for [`LaunchStatus::Cancelled`] it feeds the cancelled bar.
    pub message: String,
    /// The Windows error behind it, or 0.
    pub win32_error: u32,
    /// The broker's exit code when it ended before its pipe existed.
    pub exit_code: Option<u32>,
}

impl LaunchFailure {
    fn new(status: LaunchStatus, message: impl Into<String>) -> LaunchFailure {
        LaunchFailure {
            status,
            message: message.into(),
            win32_error: 0,
            exit_code: None,
        }
    }
}

/// Who draws the broker's consent dialog (package BROKER-CONSENT-UI). The broker's own argument
/// `--consent` names the same two; the dialog says and approves the same whichever draws it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConsentUi {
    /// The Win32 TaskDialog: the default, and what a broker started without the argument shows.
    #[default]
    TaskDialog,
    /// Purge's own toolkit, with the TaskDialog behind it when its window cannot be shown.
    Toolkit,
}

impl ConsentUi {
    /// The name on Purge's and the broker's command lines.
    pub fn name(self) -> &'static str {
        match self {
            ConsentUi::TaskDialog => "taskdialog",
            ConsentUi::Toolkit => "toolkit",
        }
    }

    /// The choice `name` names, exactly as [`ConsentUi::name`] writes it.
    pub fn parse(name: &str) -> Option<ConsentUi> {
        [ConsentUi::TaskDialog, ConsentUi::Toolkit]
            .into_iter()
            .find(|c| c.name() == name)
    }
}

/// The broker's arguments (step 3). The default dialog adds nothing, so a broker that does not know
/// `--consent` starts as before.
pub(crate) fn arguments(name: &str, pid: u32, ctime: u64, consent: ConsentUi) -> String {
    let base = format!("--pipe {name} --parent {pid} --parent-ctime {ctime}");
    match consent {
        ConsentUi::TaskDialog => base,
        ConsentUi::Toolkit => format!("{base} --consent {}", consent.name()),
    }
}

/// A launch in progress. Its answer is a [`ClientEvent::BrokerLaunched`] with [`Launch::call`].
#[derive(Debug, Clone)]
pub struct Launch {
    /// The id the answer carries.
    pub call: CallId,
    stop: Arc<AtomicBool>,
}

impl Launch {
    /// Stops the launch at its next step ([`LaunchStatus::Stopped`]); a broker already started is
    /// ended. The Windows prompt itself cannot be taken down: the launch ends once it is answered.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// `purge-broker.exe` beside this program (the release layout). `None` when the UI's own path is
/// unknown.
pub fn broker_beside_app() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|d| d.join("purge-broker.exe")))
}

/// Maps a `ShellExecuteExW` failure. Error 1223 is the user saying No at the Windows prompt.
pub fn classify_shell_failure(error: u32) -> LaunchFailure {
    if error == ERROR_CANCELLED {
        return LaunchFailure::new(
            LaunchStatus::Cancelled,
            "You cancelled the Windows prompt. Nothing was changed.",
        );
    }
    LaunchFailure {
        win32_error: error,
        ..LaunchFailure::new(
            LaunchStatus::CannotStart,
            format!(
                "The administrator part could not start. {}",
                win32_text(error)
            ),
        )
    }
}

/// Starts `broker` elevated on a background thread. The session (or the failure) arrives as a
/// [`ClientEvent::BrokerLaunched`]; the session then delivers its own events through `sink`.
///
/// The thread is detached: it ends after this one launch, once the Windows prompt is answered and at
/// most [`CONNECT_TIMEOUT`] and [`HELLO_TIMEOUT`] later ([`Launch::stop`] ends it at its next step).
pub fn launch(broker: &Path, sink: Sink) -> Launch {
    launch_with(broker, ConsentUi::default(), sink)
}

/// [`launch`], naming who draws the broker's consent dialog.
pub fn launch_with(broker: &Path, consent: ConsentUi, sink: Sink) -> Launch {
    let launch = Launch {
        call: CallId::next(),
        stop: Arc::new(AtomicBool::new(false)),
    };
    let call = launch.call;
    let stop = launch.stop.clone();
    let broker = broker.to_path_buf();
    let worker_sink = sink.clone();
    let spawned = std::thread::Builder::new()
        .name("purge-broker-launcher".into())
        .spawn(move || {
            let result = run(&broker, consent, worker_sink.clone(), &stop);
            deliver(call, result, &worker_sink);
        });
    if let Err(e) = spawned {
        sink.send(ClientEvent::BrokerLaunched {
            call,
            result: Err(LaunchFailure::new(
                LaunchStatus::CannotStart,
                format!("The administrator part could not start. {e}"),
            )),
        });
    }
    launch
}

/// Sends the answer of launch `call`. A session is handed out with it
/// ([`BrokerClient::hand_over`]), so its [`ClientEvent::BrokerClosed`] can only come after this
/// [`ClientEvent::BrokerLaunched`]. A session whose link ended before is not handed out: the launch
/// fails instead, and the broker is ended.
pub(crate) fn deliver(call: CallId, result: Result<Arc<BrokerClient>, LaunchFailure>, sink: &Sink) {
    let session = match result {
        Ok(session) => session,
        Err(failure) => {
            sink.send(ClientEvent::BrokerLaunched {
                call,
                result: Err(failure),
            });
            return;
        }
    };
    let handed = session.clone();
    let refused = session.hand_over(|| {
        sink.send(ClientEvent::BrokerLaunched {
            call,
            result: Ok(handed),
        })
    });
    if let Err(e) = refused {
        let failure = match finish(Err(e), HELLO_TIMEOUT, || session.terminate()) {
            Ok(_) => unreachable!("finish of an error is an error"),
            Err(failure) => failure,
        };
        sink.send(ClientEvent::BrokerLaunched {
            call,
            result: Err(failure),
        });
    }
}

/// The account check of step 1: false only for a standard user (not elevated, and no limited half of
/// an administrator's split token). A token that cannot be read counts as a standard user, as in the
/// C#.
fn can_elevate() -> bool {
    match current_process_facts() {
        Ok(f) => f.elevated || f.elevation_type == ElevationType::Limited,
        Err(_) => false,
    }
}

fn stopped() -> LaunchFailure {
    LaunchFailure::new(LaunchStatus::Stopped, "The request was cancelled.")
}

fn run(
    broker: &Path,
    consent: ConsentUi,
    sink: Sink,
    stop: &AtomicBool,
) -> Result<Arc<BrokerClient>, LaunchFailure> {
    if !can_elevate() {
        return Err(LaunchFailure::new(
            LaunchStatus::NotAdministrator,
            STANDARD_USER_MESSAGE,
        ));
    }
    if broker.as_os_str().is_empty() || !broker.is_file() {
        return Err(LaunchFailure::new(
            LaunchStatus::CannotStart,
            format!("The administrator part is missing: {}.", broker.display()),
        ));
    }
    let broker = std::path::absolute(broker).map_err(|e| {
        LaunchFailure::new(
            LaunchStatus::CannotStart,
            format!("The administrator part could not start. {e}"),
        )
    })?;
    if stop.load(Ordering::SeqCst) {
        return Err(stopped());
    }
    let (pid, ctime) = identity().map_err(|e| {
        LaunchFailure::new(
            LaunchStatus::CannotStart,
            format!(
                "The administrator part could not start. {}",
                win32_text(e.code())
            ),
        )
    })?;
    let name = pipe_name().map_err(|e| {
        LaunchFailure::new(
            LaunchStatus::CannotStart,
            format!(
                "The administrator part could not start. {}",
                win32_text(e.code())
            ),
        )
    })?;
    let arguments = arguments(&name, pid, ctime, consent);
    let directory = broker
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| broker.clone());
    // `run_as` answers INVALID_DATA only for a start without a process handle; a process whose pid
    // could not be read was ended there, and its error is GetProcessId's.
    let process = run_as(&broker, &arguments, &directory).map_err(|e| {
        if e == Win32Error::INVALID_DATA {
            LaunchFailure::new(
                LaunchStatus::CannotStart,
                "Windows started the administrator part but returned no process handle.",
            )
        } else {
            classify_shell_failure(e.code())
        }
    })?;
    let path = PathBuf::from(format!(r"\\.\pipe\purge-{name}"));
    let pipe = connect(&process, &path, CONNECT_TIMEOUT, stop, |pipe, pid| {
        check_server(pipe, pid, &broker, true)
    })?;
    handshake(pipe, process, broker, sink, stop)
}

/// This process's pid and creation time (a FILETIME), which the broker checks to know its parent.
fn identity() -> Result<(u32, u64), Win32Error> {
    let me = ProcessHandle::current()?;
    Ok((std::process::id(), me.creation_time()?))
}

/// 128 random bits as 32 lower-case hex digits.
fn pipe_name() -> Result<String, Win32Error> {
    Ok(format!("{:016x}{:016x}", random_u64()?, random_u64()?))
}

/// What [`connect`] needs of the started broker; a test drives [`connect`] with its own.
pub(crate) trait BrokerProcess {
    /// The pid the server check expects.
    fn pid(&self) -> u32;
    /// The exit code once the process has ended; `None` while it runs.
    fn exit_code(&self) -> Option<u32>;
    /// Best effort: ends the process while it runs.
    fn terminate(&self);
}

impl BrokerProcess for LaunchedProcess {
    fn pid(&self) -> u32 {
        LaunchedProcess::pid(self)
    }

    fn exit_code(&self) -> Option<u32> {
        LaunchedProcess::exit_code(self)
    }

    fn terminate(&self) {
        LaunchedProcess::terminate(self)
    }
}

/// Steps 5 and 6: opens `path`, retrying for `timeout` while the pipe is missing or busy, then runs
/// `check` (the server check, given the pipe and the expected pid) before anything is written. Every
/// failure ends `process` (best effort), except that of a process that already exited.
pub(crate) fn connect<P: BrokerProcess>(
    process: &P,
    path: &Path,
    timeout: Duration,
    stop: &AtomicBool,
    check: impl Fn(&PipeClient, u32) -> ServerCheck,
) -> Result<PipeClient, LaunchFailure> {
    let pid = process.pid();
    let deadline = Instant::now() + timeout;
    loop {
        if stop.load(Ordering::SeqCst) {
            process.terminate();
            return Err(stopped());
        }
        match PipeClient::open(path) {
            Ok(pipe) => {
                let check = check(&pipe, pid);
                if !check.ok() {
                    drop(pipe);
                    process.terminate();
                    return Err(LaunchFailure::new(
                        LaunchStatus::ServerCheckFailed,
                        check.reason,
                    ));
                }
                return Ok(pipe);
            }
            Err(e) => {
                let error = e.code();
                if error != ERROR_PIPE_BUSY
                    && error != ERROR_FILE_NOT_FOUND
                    && error != ERROR_SEM_TIMEOUT
                {
                    process.terminate();
                    return Err(LaunchFailure {
                        win32_error: error,
                        ..LaunchFailure::new(
                            LaunchStatus::CannotStart,
                            format!(
                                "Purge could not connect to the administrator part. {}",
                                win32_text(error)
                            ),
                        )
                    });
                }
            }
        }
        if let Some(code) = process.exit_code() {
            return Err(LaunchFailure {
                exit_code: Some(code),
                ..LaunchFailure::new(
                    LaunchStatus::CannotStart,
                    format!("The administrator part could not start (exit code {code})."),
                )
            });
        }
        if Instant::now() >= deadline {
            process.terminate();
            return Err(LaunchFailure::new(
                LaunchStatus::TimedOut,
                format!(
                    "The administrator part did not start within {} seconds.",
                    timeout.as_secs()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn handshake(
    pipe: PipeClient,
    process: LaunchedProcess,
    broker: PathBuf,
    sink: Sink,
    stop: &AtomicBool,
) -> Result<Arc<BrokerClient>, LaunchFailure> {
    // The session holds the process handle; a failed handshake still ends the process.
    let process = Arc::new(process);
    let result = BrokerClient::over_pipe(pipe, process.clone(), broker, sink, HELLO_TIMEOUT, stop);
    finish(result, HELLO_TIMEOUT, || process.terminate())
}

/// The launch's answer to a handshake: a session, or the failure after `terminate` ended the
/// process (the link is already closed).
pub(crate) fn finish(
    result: Result<Arc<BrokerClient>, HandshakeError>,
    hello_timeout: Duration,
    terminate: impl FnOnce(),
) -> Result<Arc<BrokerClient>, LaunchFailure> {
    result.map_err(|e| {
        terminate();
        match e {
            HandshakeError::TimedOut => LaunchFailure::new(
                LaunchStatus::TimedOut,
                format!(
                    "The administrator part did not answer within {} seconds.",
                    hello_timeout.as_secs()
                ),
            ),
            HandshakeError::Refused(e) => LaunchFailure::new(
                LaunchStatus::CannotStart,
                format!("The administrator part did not accept Purge's connection. {e}"),
            ),
            HandshakeError::Stopped => stopped(),
        }
    })
}
