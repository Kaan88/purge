//! The elevated broker (ports of `Broker/*.cs` and of the broker half of
//! `Pipeline/UninstallPipeline.cs`).
//!
//! - [`launch`] is the launcher of M3 design 3.3: the UI's own account pre-check, the 128-bit pipe
//!   name, `ShellExecuteExW("runas")`, the connect with `SECURITY_IDENTIFICATION`, the server check
//!   ([`check_server`]) before a byte is written, and `engine.hello`. Nothing here runs at app start;
//!   the first click that needs the broker calls it.
//! - A [`BrokerClient`] is a session: it exists only once the broker answered `engine.hello`
//!   ([`BrokerClient::over`] and the launcher both go through the one handshake). The broker refuses a
//!   client whose first line is anything else (`serve.rs`, `accept`), so no caller sends a hello of its
//!   own, and none can forget it: a [`PipeCall::EngineHello`] is answered from the session.
//!
//! The C# client had one wrapper per page (`HistoryBroker`, `LeftoversBroker`,
//! `StoredLeftoversClient`, `BrokerUninstallClient`) that forwarded the progress of "the call in
//! flight" by method name. Here every notification that names a request (`params.request`: the
//! progress lines and `consent.shown`) goes to that request's [`CallId`], so one session serves every
//! page and the session hand-over between pages is just sharing the `Arc`.
//!
//! The consent requests (those of the method table with `consent: true`: `uninstall.run`,
//! `plan.execute`, `undo.run`, the three `journal.*` changes, `quarantine.purge`) call
//! [`Broker::allow_foreground`] before they are sent, so the broker's dialog can come to the front
//! (design 3.3; the C# pages each did it by hand). While a `plan.execute` with `delete_after` runs, it
//! is called again for every `exec.progress`, on the reader thread, so the permission for the second
//! dialog is given before the broker shows it.

mod check;
mod launcher;

use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use purge_rpc::EngineHello;
use purge_rpc::methods::{PipeCall, ServerNotification};
use purge_rpc::sets::PIPE_IN_LIMIT;
use purge_rpc::table::{CallSet, METHODS, Method};
use purge_win::launch::{LaunchedProcess, allow_set_foreground_window};
use purge_win::pipe_client::{PipeClient, PipeClientError};
use serde_json::Value;

use crate::link::{Call, Hooks, Link, decode};
use crate::{Answer, CallId, ClientError, ClientEvent, Sink};

pub use check::{ServerCheck, ServerCheckStatus, check_server};
pub use launcher::{
    CONNECT_TIMEOUT, HELLO_TIMEOUT, Launch, LaunchFailure, LaunchStatus, STANDARD_USER_MESSAGE,
    broker_beside_app, classify_shell_failure, launch,
};

/// The UI's view of a broker session. Every request returns at once; its answer is a
/// [`ClientEvent::Reply`] on the session's sink.
pub trait Broker: Send + Sync + fmt::Debug {
    /// The broker's answer to `engine.hello`.
    fn hello(&self) -> &EngineHello;

    /// False once the link ended; the next click that needs the broker launches a new one.
    fn is_live(&self) -> bool;

    /// Why the link ended; `None` while it is live.
    fn closed_reason(&self) -> Option<String>;

    /// Lets the broker's consent dialog come to the foreground (`AllowSetForegroundWindow`). A
    /// refusal is not an error; the UI then names the prompt in its waiting state.
    fn allow_foreground(&self);

    /// Sends one request.
    fn request(&self, request: PipeCall) -> CallId;

    /// Cancels a request in flight: sends `$/cancel` and answers it with [`ClientError::Cancelled`].
    /// The broker stops only what it can (a harvest, a scan); a running uninstaller, execute, undo,
    /// recovery or purge goes on, and the consent dialog only ends by its own Cancel.
    fn cancel(&self, call: CallId);

    /// Ends the session: the pipe closes and the broker exits (it also holds the UI as its parent).
    fn close(&self);
}

/// How long one request line may take to write before the link is given up (design T13, as the
/// broker's own writes).
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// A live broker session.
pub struct BrokerClient {
    link: Link,
    sink: Sink,
    hello: EngineHello,
    pid: u32,
    path: PathBuf,
    /// The handle `ShellExecuteExW` returned, held so the pid is not reused while the session lives.
    /// `None` for a session over streams given by a test.
    _process: Option<Arc<LaunchedProcess>>,
    /// `AllowSetForegroundWindow(pid)`; a test counts the calls instead.
    foreground: Foreground,
}

/// What [`Broker::allow_foreground`] does.
type Foreground = Arc<dyn Fn() + Send + Sync>;

impl fmt::Debug for BrokerClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrokerClient")
            .field("pid", &self.pid)
            .field("path", &self.path)
            .field("closed", &self.link.closed_reason())
            .finish_non_exhaustive()
    }
}

/// How a handshake ended without a session.
pub(crate) enum HandshakeError {
    /// The broker refused the hello, or the link ended, or the answer is not a hello.
    Refused(ClientError),
    /// No answer within the limit.
    TimedOut,
    /// The caller stopped the launch.
    Stopped,
}

impl BrokerClient {
    /// A session over an already checked, connected link (a test's scripted broker): sends
    /// `engine.hello`, waits up to `hello_timeout` for its answer, and only then returns the session.
    /// On a failure the link is closed. `shut_down` ends the transport (wakes the reader).
    pub fn over(
        input: Box<dyn Write + Send>,
        output: Box<dyn Read + Send>,
        shut_down: Box<dyn Fn() + Send + Sync>,
        sink: Sink,
        hello_timeout: Duration,
    ) -> Result<Arc<BrokerClient>, ClientError> {
        let stop = AtomicBool::new(false);
        BrokerClient::over_streams(input, output, shut_down, sink, hello_timeout, &stop).map_err(
            |e| match e {
                HandshakeError::Refused(e) => e,
                HandshakeError::TimedOut => ClientError::Link {
                    reason: "The administrator part did not answer.".into(),
                    not_sent: false,
                },
                HandshakeError::Stopped => ClientError::Cancelled,
            },
        )
    }

    /// [`BrokerClient::over`] with the handshake's own error.
    pub(crate) fn over_streams(
        input: Box<dyn Write + Send>,
        output: Box<dyn Read + Send>,
        shut_down: Box<dyn Fn() + Send + Sync>,
        sink: Sink,
        hello_timeout: Duration,
        stop: &AtomicBool,
    ) -> Result<Arc<BrokerClient>, HandshakeError> {
        BrokerClient::handshake(
            input,
            output,
            shut_down,
            None,
            std::process::id(),
            PathBuf::new(),
            sink,
            hello_timeout,
            stop,
        )
    }

    /// A session over the checked pipe `pipe` of process `process`.
    pub(crate) fn over_pipe(
        pipe: PipeClient,
        process: Arc<LaunchedProcess>,
        path: PathBuf,
        sink: Sink,
        hello_timeout: Duration,
        stop: &AtomicBool,
    ) -> Result<Arc<BrokerClient>, HandshakeError> {
        let pipe = Arc::new(pipe);
        let pid = process.pid();
        let shut = pipe.clone();
        BrokerClient::handshake(
            Box::new(PipeWriter(pipe.clone())),
            Box::new(PipeReader(pipe)),
            Box::new(move || shut.shut_down()),
            Some(process),
            pid,
            path,
            sink,
            hello_timeout,
            stop,
        )
    }

    /// The one way a session is made: the link, `engine.hello` as its first request, the answer.
    #[allow(clippy::too_many_arguments)]
    fn handshake(
        input: Box<dyn Write + Send>,
        output: Box<dyn Read + Send>,
        shut_down: Box<dyn Fn() + Send + Sync>,
        process: Option<Arc<LaunchedProcess>>,
        pid: u32,
        path: PathBuf,
        sink: Sink,
        hello_timeout: Duration,
        stop: &AtomicBool,
    ) -> Result<Arc<BrokerClient>, HandshakeError> {
        // Only a session that was handed out announces its end.
        let announced = Arc::new(AtomicBool::new(false));
        let hooks = Hooks {
            who: "The administrator part",
            out_limit: PIPE_IN_LIMIT,
            shut_down,
            unrouted: {
                let sink = sink.clone();
                Box::new(move |method, params| unrouted(&sink, method, params))
            },
            closed: {
                let sink = sink.clone();
                let announced = announced.clone();
                Box::new(move |reason| {
                    if announced.load(Ordering::SeqCst) {
                        sink.send(ClientEvent::BrokerClosed {
                            reason: reason.to_owned(),
                        });
                    }
                })
            },
            exit_text: Box::new(String::new),
        };
        let link = Link::new(input, output, hooks, "purge-broker-reader").map_err(|e| {
            HandshakeError::Refused(ClientError::Link {
                reason: e.to_string(),
                not_sent: true,
            })
        })?;
        let (tx, rx) = mpsc::channel();
        // `engine.hello` with no params member, as the broker's first line.
        link.start(
            CallId::next(),
            Method::EngineHello.name(),
            None,
            Box::new(HelloCall(Some(tx))),
            |_| {},
        );
        let deadline = Instant::now() + hello_timeout;
        let answer = loop {
            if stop.load(Ordering::SeqCst) {
                break Err(HandshakeError::Stopped);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break Err(HandshakeError::TimedOut);
            }
            match rx.recv_timeout(left.min(Duration::from_millis(50))) {
                Ok(Ok(hello)) => break Ok(hello),
                Ok(Err(e)) => break Err(HandshakeError::Refused(e)),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break Err(HandshakeError::Refused(ClientError::Link {
                        reason: "The administrator part ended.".into(),
                        not_sent: false,
                    }));
                }
            }
        };
        match answer {
            Ok(hello) => {
                announced.store(true, Ordering::SeqCst);
                if let Some(reason) = link.closed_reason() {
                    // Ended right after the hello: no session.
                    return Err(HandshakeError::Refused(ClientError::Link {
                        reason,
                        not_sent: false,
                    }));
                }
                Ok(Arc::new(BrokerClient {
                    link,
                    sink,
                    hello,
                    pid,
                    path,
                    _process: process,
                    foreground: Arc::new(move || {
                        let _ = allow_set_foreground_window(pid);
                    }),
                }))
            }
            Err(e) => {
                // No session is made, so nothing else would end this link.
                link.close("The administrator part link was closed.");
                Err(e)
            }
        }
    }

    /// A session whose foreground permission runs `f` (tests).
    #[cfg(test)]
    pub(crate) fn set_foreground(self: &mut Arc<Self>, f: Foreground) {
        if let Some(me) = Arc::get_mut(self) {
            me.foreground = f;
        }
    }

    /// The broker's pid.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The broker executable that was launched (empty for a test's session).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Notifications that name no request in flight: `baseline.changed`, and a `consent.shown` of a
/// request this client no longer waits for.
fn unrouted(sink: &Sink, method: &str, params: Value) {
    match ServerNotification::decode(method, params) {
        Ok(ServerNotification::BaselineChanged(changed)) => {
            sink.send(ClientEvent::BaselineChanged(changed))
        }
        Ok(ServerNotification::ConsentShown(shown)) => {
            sink.send(ClientEvent::ConsentShown { call: None, shown })
        }
        _ => {}
    }
}

impl Broker for BrokerClient {
    fn hello(&self) -> &EngineHello {
        &self.hello
    }

    fn is_live(&self) -> bool {
        self.link.closed_reason().is_none()
    }

    fn closed_reason(&self) -> Option<String> {
        self.link.closed_reason()
    }

    fn allow_foreground(&self) {
        (self.foreground)();
    }

    fn request(&self, request: PipeCall) -> CallId {
        let call = CallId::next();
        let method = request.method();
        if method == Method::EngineHello {
            // Answered when the session was made; the broker takes only one.
            self.sink.send(ClientEvent::Reply {
                call,
                result: Ok(Answer::BrokerHello(self.hello.clone())),
            });
            return call;
        }
        if METHODS.iter().any(|s| s.method == method && s.consent) {
            self.allow_foreground();
        }
        let exec_hook = match &request {
            PipeCall::PlanExecute(p) if p.delete_after => Some(self.foreground.clone()),
            _ => None,
        };
        let params = pipe_params(&request);
        let handler = BrokerCall {
            call,
            method,
            sink: self.sink.clone(),
            exec_hook,
        };
        self.link.start(
            call,
            method.name(),
            params.as_ref(),
            Box::new(handler),
            |_| {},
        );
        call
    }

    fn cancel(&self, call: CallId) {
        self.link.cancel(call);
    }

    fn close(&self) {
        self.link.close("The administrator part link was closed.");
    }
}

impl Drop for BrokerClient {
    fn drop(&mut self) {
        self.close();
    }
}

fn json<T: serde::Serialize>(value: &T) -> Option<Value> {
    serde_json::to_value(value).ok()
}

/// The params member of a request: none for the methods that take none (as the C# client wrote
/// `journal.pending` and `broker.shutdown`), else the params object.
fn pipe_params(request: &PipeCall) -> Option<Value> {
    match request {
        PipeCall::EngineHello(_) | PipeCall::JournalPending(_) | PipeCall::BrokerShutdown(_) => {
            None
        }
        PipeCall::UninstallPrepare(p) | PipeCall::LeftoversStored(p) => json(p),
        PipeCall::UninstallRun(p) => json(p),
        PipeCall::UninstallObserved(p) => json(p),
        PipeCall::LeftoversScan(p) => json(p),
        PipeCall::ScanCandidates(p) => json(p),
        PipeCall::CandidateExplain(p) => json(p),
        PipeCall::PlanCreate(p) => json(p),
        PipeCall::PlanExecute(p) => json(p),
        PipeCall::HistoryGet(p)
        | PipeCall::JournalResume(p)
        | PipeCall::JournalRollback(p)
        | PipeCall::JournalRetryHeld(p) => json(p),
        PipeCall::UndoRun(p) => json(p),
        PipeCall::QuarantineExpiring(p) => json(p),
        PipeCall::QuarantinePurge(p) => json(p),
    }
}

/// The typed answer of a broker request.
fn pipe_answer(method: Method, value: Value) -> Result<Answer, ClientError> {
    let name = method.name();
    Ok(match method {
        Method::EngineHello => Answer::BrokerHello(decode(name, value)?),
        Method::UninstallPrepare => Answer::Prepare(decode(name, value)?),
        Method::UninstallRun => Answer::Run(decode(name, value)?),
        Method::UninstallObserved => Answer::Observed(decode(name, value)?),
        Method::LeftoversStored => Answer::Stored(decode(name, value)?),
        Method::LeftoversScan => Answer::Scan(decode(name, value)?),
        Method::ScanCandidates => Answer::Candidates(decode(name, value)?),
        Method::CandidateExplain => Answer::Explanation(decode(name, value)?),
        Method::PlanCreate => Answer::Plan(decode(name, value)?),
        Method::PlanExecute => Answer::Exec(decode(name, value)?),
        Method::HistoryGet => Answer::HistoryDetail(decode(name, value)?),
        Method::UndoRun => Answer::Undo(decode(name, value)?),
        Method::JournalPending => Answer::Pending(decode(name, value)?),
        Method::JournalResume | Method::JournalRollback | Method::JournalRetryHeld => {
            Answer::Outcome(decode(name, value)?)
        }
        Method::QuarantineExpiring => Answer::Expiring(decode(name, value)?),
        Method::QuarantinePurge => Answer::Purge(decode(name, value)?),
        Method::BrokerShutdown => Answer::Shutdown(decode(name, value)?),
        other => {
            return Err(ClientError::NotAvailable(format!(
                "{} is not a request of the administrator part.",
                other.name()
            )));
        }
    })
}

/// One broker request: its progress and `consent.shown` go to its [`CallId`].
struct BrokerCall {
    call: CallId,
    method: Method,
    sink: Sink,
    /// Called for every `exec.progress` of a `plan.execute` with `delete_after`, first.
    exec_hook: Option<Foreground>,
}

impl Call for BrokerCall {
    fn notification(&mut self, method: &str, params: Value) -> bool {
        if method == "exec.progress" {
            if let Some(hook) = &self.exec_hook {
                hook();
            }
        }
        match ServerNotification::decode(method, params) {
            Ok(
                ServerNotification::UninstallProgress(progress)
                | ServerNotification::PrepareProgress(progress)
                | ServerNotification::ScanProgress(progress)
                | ServerNotification::ExecProgress(progress)
                | ServerNotification::UndoProgress(progress),
            ) => self.sink.send(ClientEvent::Progress {
                call: self.call,
                progress,
            }),
            Ok(ServerNotification::ConsentShown(shown)) => {
                self.sink.send(ClientEvent::ConsentShown {
                    call: Some(self.call),
                    shown,
                })
            }
            Ok(ServerNotification::BaselineChanged(changed)) => {
                self.sink.send(ClientEvent::BaselineChanged(changed))
            }
            _ => {}
        }
        false
    }

    fn reply(&mut self, result: Result<Value, ClientError>) -> bool {
        self.sink.send(ClientEvent::Reply {
            call: self.call,
            result: result.and_then(|v| pipe_answer(self.method, v)),
        });
        true
    }

    fn end(&mut self, error: ClientError) {
        self.sink.send(ClientEvent::Reply {
            call: self.call,
            result: Err(error),
        });
    }
}

/// The handshake's `engine.hello`: its answer goes to the waiting launcher.
struct HelloCall(Option<mpsc::Sender<Result<EngineHello, ClientError>>>);

impl HelloCall {
    fn send(&mut self, result: Result<EngineHello, ClientError>) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(result);
        }
    }
}

impl Call for HelloCall {
    fn notification(&mut self, _: &str, _: Value) -> bool {
        false
    }

    fn reply(&mut self, result: Result<Value, ClientError>) -> bool {
        self.send(result.and_then(|v| decode("engine.hello", v)));
        true
    }

    fn end(&mut self, error: ClientError) {
        self.send(Err(error));
    }
}

/// The reader thread's end of the pipe. A shut-down or closed link is the end of the stream.
struct PipeReader(Arc<PipeClient>);

impl Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0.read_with_timeout(buf, None) {
            Ok(n) => Ok(n),
            Err(PipeClientError::ShutDown | PipeClientError::Disconnected) => Ok(0),
            Err(e) => Err(io::Error::other(e)),
        }
    }
}

/// The writer's end of the pipe: each line within [`WRITE_TIMEOUT`].
struct PipeWriter(Arc<PipeClient>);

impl Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_all(buf)?;
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0
            .write_all_with_timeout(buf, WRITE_TIMEOUT)
            .map_err(io::Error::other)
    }

    /// Written bytes are in the pipe once the write returned.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
