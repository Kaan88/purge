//! The broker's serving loop (M3 design 3.3 steps 4 to 6, 3.6), generic over the transport
//! ([`Link`]), the consent dialog ([`Consent`]), the machine ([`Host`]) and the request handler
//! ([`Handler`]); the binary wires the real ones, the tests the fakes.
//!
//! **Accepting.** The loop waits for a client in slices of [`Limits::tick`], watching the parent and the
//! clock. A client is identified first ([`Link::identify`]: pid, creation time, image, account; nothing
//! is read from it before, review M3-R1 S1) and then has [`Limits::hello_wait`] to send `engine.hello`
//! as its first line (at most [`HELLO_LINE_CAP`] bytes). Anything else, at any step, is a refused
//! client: it is disconnected and nothing is answered to it. After [`Limits::max_failed`] refused
//! clients the broker ends. The client that passes is the only one ever served.
//!
//! **Serving.** A reader thread turns the pipe into lines; every line goes through
//! `purge_rpc::table::route` (the only path that does the table and set checks). This thread, the
//! supervisor, answers `engine.hello` and `broker.shutdown` itself and starts every other request on
//! a thread of its own, so it keeps reading, noticing `$/cancel`, a lost pipe or parent, and the clock:
//!
//! | Request | Rule |
//! |---|---|
//! | A program id of another hive than `HKLM` or the checked account's | `gone` (`program`), before the handler (review M3-R1 S5) |
//! | A mutating request (set `Execute`) while one runs | `busy` |
//! | A read or propose request while [`MAX_READS`] run | `busy` |
//! | A request id that is running | `-32600` |
//! | Any request after the broker decided to end | `runtime`, "the broker is closing" |
//! | `broker.shutdown` | `{exiting: true}` and the end when nothing runs, else `{exiting: false}` |
//!
//! **Ending** is `lifetime`'s table. A completed change (execute, undo, recovery, purge) with no
//! session left in the tables, and `broker.shutdown`, send their result, wait up to
//! [`Limits::close_wait`] for the client to close the pipe, and end. No request for [`Limits::idle`]
//! ends it. A lost parent or pipe sets the cancel flag of every cancellable request, closes an open
//! consent dialog as Cancel, lets every mutating request finish (its answer cannot be sent), gives a
//! read-only one [`Limits::read_grace`], and ends. At the end the local-baseline build is asked to stop
//! before its next part.
//!
//! **Timing** (`crate::timing`, design 9.1): [`run_timed`] takes the recorder; the loop marks
//! `pipe_connected`, and [`Ctx`] gives a request [`Ctx::mark`], [`Ctx::timings`] and the
//! `first_progress` and consent marks. Nothing here depends on a mark.

use std::collections::HashMap;
use std::io::{self, BufReader, Read};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use purge_engine::pipeline::Settings;
use purge_model::ProgramId;
use purge_rpc::error::{ErrorData, ErrorObject, INVALID_REQUEST, IdKind};
use purge_rpc::frame::{FrameError, FrameReader, FrameWriter, RequestId, Response};
use purge_rpc::methods::{
    BaselineChanged, ConfirmCode, ConsentShown, LeftoversScanParams, PipeCall, ServerNotification,
    ShutdownResult,
};
use purge_rpc::sets::{CapSet, OUT_LIMIT, PIPE_IN_LIMIT, Transport};
use purge_rpc::table::{Method, Routed, route, write_notification, write_response};
use purge_rpc::timing::TimingName;
use purge_rpc::{BaselineBuild, EngineHello};
use purge_win::pipe::ExpectedPeer;
use purge_win::taskdialog::{Outcome, Page};
use serde_json::Value;

use crate::baseline::{BuildHandle, in_progress};
use crate::consent::sheet::Sheet;
use crate::lifetime::{
    BUILD_GRACE, CLOSE_WAIT, Clock, Closer, Exit, ExitReason, HELLO_LINE_CAP, HELLO_WAIT,
    IDLE_LIMIT, MAX_FAILED_CLIENTS, Parent, READ_GRACE, idle_expired,
};
use crate::link::{Link, LinkError, Refusal};
use crate::session::{Tables, gone, program_hive_allowed};
use crate::timing::{RequestMarks, Timings};

/// Most non-mutating requests that run at once.
pub const MAX_READS: usize = 8;
/// How long one write to the client may take (design T13).
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The machine, for `engine.hello`.
pub trait Host: Send + Sync + 'static {
    /// The result of `engine.hello`; the serving loop sets `baseline_build` to the build's state.
    fn hello(&self) -> EngineHello;
}

/// The consent dialog. The broker holds one at a time: only a mutating request asks.
pub trait Consent: Send + Sync + 'static {
    /// Shows the dialog described by `pages` (`primary` is the id whose click approves) and waits for
    /// the answer. Arms `closer` with the way to close the window as soon as it is open
    /// ([`Closer::arm`]) and disarms it when it ends; the dialog closes as Cancel when the closer
    /// fires. `shown` is called once, when the window is up and can be answered (`consent.shown`),
    /// never when it could not be shown. An error means it could not be shown, and counts as Cancel.
    fn ask(
        &self,
        pages: &[Page],
        primary: i32,
        closer: &Closer,
        shown: &(dyn Fn() + Sync),
    ) -> io::Result<Outcome>;

    /// [`Consent::ask`] for a caller that also has the dialog as a [`Sheet`]: the same dialog in
    /// the form the toolkit window draws (`consent::toolkit`). Both say the same; an implementation
    /// shows one of them, and every rule of `ask` holds whichever it shows. By default the pages.
    fn ask_sheet(
        &self,
        sheet: &Sheet,
        pages: &[Page],
        primary: i32,
        closer: &Closer,
        shown: &(dyn Fn() + Sync),
    ) -> io::Result<Outcome> {
        let _ = sheet;
        self.ask(pages, primary, closer, shown)
    }
}

/// Runs the requests the serving loop does not answer itself: everything but `engine.hello` and
/// `broker.shutdown`. The tables are the broker's; a handler keeps nothing between calls that the
/// tables do not hold.
pub trait Handler: Send + Sync + 'static {
    /// What a session of this handler holds.
    type Session: Send + Sync + 'static;
    /// What a scan holds.
    type Scan: Send + Sync + 'static;
    /// What a plan holds.
    type Plan: Send + Sync + 'static;

    /// Runs one request and returns its result (the result type of the method) or its error. Called on
    /// a thread of its own. A mutating request is the only one of its kind running. Check
    /// [`Ctx::cancelled`] if the method is cancellable; a mutating request is finished even when the
    /// client is gone.
    fn call(&self, ctx: &Ctx<'_, Self>, call: PipeCall) -> Result<Value, ErrorObject>
    where
        Self: Sized;
}

/// A handler that implements nothing yet: every request is a `runtime` error. The binary uses it until
/// the methods of M3-BROKER-FLOW, -EXEC, -UNDO and -PURGE exist.
#[derive(Debug, Default, Clone, Copy)]
pub struct Unwired;

impl Handler for Unwired {
    type Session = ();
    type Scan = ();
    type Plan = ();

    fn call(&self, _: &Ctx<'_, Self>, call: PipeCall) -> Result<Value, ErrorObject> {
        Err(ErrorObject::runtime(format!(
            "{} is not implemented in this build",
            purge_rpc::table::CallSet::method(&call).name()
        )))
    }
}

/// The time limits of one broker. [`Limits::design`] is the design's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// How often the loop looks at the clock, the parent and the build.
    pub tick: Duration,
    /// No request for this long ends the broker.
    pub idle: Duration,
    /// After a result that ends the broker, how long to wait for the client to close the pipe.
    pub close_wait: Duration,
    /// How long an identified client has to send `engine.hello`.
    pub hello_wait: Duration,
    /// How long a read-only request may run on after the client is gone.
    pub read_grace: Duration,
    /// How long to wait at the end for the baseline build to leave its part.
    pub build_grace: Duration,
    /// Refused clients after which the broker ends.
    pub max_failed: usize,
}

impl Limits {
    /// The limits of the design.
    pub fn design() -> Limits {
        Limits {
            tick: Duration::from_millis(100),
            idle: IDLE_LIMIT,
            close_wait: CLOSE_WAIT,
            hello_wait: HELLO_WAIT,
            read_grace: READ_GRACE,
            build_grace: BUILD_GRACE,
            max_failed: MAX_FAILED_CLIENTS,
        }
    }
}

/// Everything [`run`] needs.
pub struct Wiring<L: Link, H: Handler> {
    /// The pipe.
    pub link: L,
    /// The request handler.
    pub handler: H,
    /// What the client must be (design 3.3 step 4); `user_sid` is also the checked account for the
    /// program ids of requests.
    pub expected: ExpectedPeer,
    /// The process `--parent` names, held.
    pub parent: Arc<dyn Parent>,
    /// The consent dialog.
    pub consent: Arc<dyn Consent>,
    /// The machine, for `engine.hello`.
    pub host: Arc<dyn Host>,
    /// The time.
    pub clock: Arc<dyn Clock>,
    /// The local-baseline build, when one was started.
    pub build: Option<Arc<dyn BuildHandle>>,
    /// The engine settings of the pipeline steps, with the build in `local_build`.
    pub settings: Settings,
    /// The time limits.
    pub limits: Limits,
}

enum Event {
    Line(Vec<u8>),
    /// The client closed, or a line was over the limit, or the read failed: the pipe is lost.
    ReaderEnded,
    JobDone {
        id: RequestId,
        completed_change: bool,
    },
    PipeBroken,
}

/// Writes whole lines to the client, one at a time.
trait Out: Send + Sync {
    fn write_line(&self, line: &[u8]) -> io::Result<()>;
}

struct LinkOut<L: Link> {
    link: Arc<L>,
    lock: Mutex<()>,
    broken: AtomicBool,
}

impl<L: Link> Out for LinkOut<L> {
    fn write_line(&self, line: &[u8]) -> io::Result<()> {
        let _one_at_a_time = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        if self.broken.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.link.write_all(line, WRITE_TIMEOUT).map_err(|e| {
            self.broken.store(true, Ordering::SeqCst);
            io::Error::from(e)
        })
    }
}

/// An `io::Write` over [`Out`]: `FrameWriter` hands it each line in one `write_all`.
struct Sink<'a>(&'a dyn Out);

impl io::Write for Sink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_line(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// An `io::Write` straight onto the link, for the answer to the first request.
struct LinkSink<'a, L: Link>(&'a L);

impl<L: Link> io::Write for LinkSink<'_, L> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_all(buf, WRITE_TIMEOUT)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// What the supervisor, the reader and the request threads share.
struct Shared<H: Handler> {
    tables: Tables<H::Session, H::Scan, H::Plan>,
    out: Box<dyn Out>,
    consent: Arc<dyn Consent>,
    closer: Closer,
    build: Option<Arc<dyn BuildHandle>>,
    settings: Settings,
    user_sid: String,
    /// The client or the parent is gone: nothing is sent, nothing is asked.
    lost: AtomicBool,
    /// Stops the reader.
    stop: AtomicBool,
    /// A write failed: the pipe is broken. Set before the event is sent, because the supervisor may be
    /// the one that found it and the channel may be full (review M3-R2 S1).
    broken: AtomicBool,
    events: SyncSender<Event>,
    /// The timing records (design 9.1); nothing depends on them.
    timings: Arc<Timings>,
}

impl<H: Handler> Shared<H> {
    fn mark_broken(&self) {
        // Never blocks: this is reached from `respond`, which the supervisor calls itself, so a
        // blocking send into a full channel would stop the only receiver. The supervisor reads
        // `broken` on every tick, so the event is only a way to wake it sooner.
        self.broken.store(true, Ordering::SeqCst);
        let _ = self.events.try_send(Event::PipeBroken);
    }

    fn respond(&self, id: RequestId, body: Result<Value, ErrorObject>) {
        if self.lost.load(Ordering::SeqCst) {
            return;
        }
        let mut writer = FrameWriter::new(Sink(&*self.out), OUT_LIMIT);
        if let Err(FrameError::Io(_)) =
            write_response(&mut writer, &Response { id: Some(id), body })
        {
            self.mark_broken();
        }
    }

    fn respond_response(&self, response: &Response) {
        if self.lost.load(Ordering::SeqCst) {
            return;
        }
        let mut writer = FrameWriter::new(Sink(&*self.out), OUT_LIMIT);
        if let Err(FrameError::Io(_)) = write_response(&mut writer, response) {
            self.mark_broken();
        }
    }

    fn notify(&self, notification: &ServerNotification) -> Result<(), FrameError> {
        if self.lost.load(Ordering::SeqCst) {
            return Err(FrameError::Io(io::ErrorKind::BrokenPipe.into()));
        }
        let mut writer = FrameWriter::new(Sink(&*self.out), OUT_LIMIT);
        let sent = write_notification(&mut writer, Transport::Pipe, notification);
        if let Err(FrameError::Io(_)) = &sent {
            self.mark_broken();
        }
        sent
    }

    fn build_state(&self) -> Option<BaselineBuild> {
        self.build.as_ref().map(|b| b.state())
    }
}

/// What a running request can ask of the broker.
pub struct Ctx<'a, H: Handler> {
    shared: &'a Shared<H>,
    request: RequestId,
    cancel: &'a AtomicBool,
    marks: &'a RequestMarks,
}

/// Whether a notification is a `*.progress` line (the request's first one is a timing mark).
fn is_progress(notification: &ServerNotification) -> bool {
    matches!(
        notification,
        ServerNotification::UninstallProgress(_)
            | ServerNotification::PrepareProgress(_)
            | ServerNotification::ScanProgress(_)
            | ServerNotification::ExecProgress(_)
            | ServerNotification::UndoProgress(_)
    )
}

impl<H: Handler> Ctx<'_, H> {
    /// The request being run: progress notifications carry it as `request`.
    pub fn request(&self) -> RequestId {
        self.request
    }

    /// Takes a timing mark of this request (`crate::timing`; once per name). Never fails and never
    /// changes the request.
    pub fn mark(&self, name: TimingName) {
        self.shared.timings.mark_request(self.marks, name);
    }

    /// The `timings` member of this request's result: the process marks and this request's so far.
    pub fn timings(&self) -> Option<purge_rpc::timing::Timings> {
        self.shared.timings.result_timings(self.marks)
    }

    /// The broker's tables.
    pub fn tables(&self) -> &Tables<H::Session, H::Scan, H::Plan> {
        &self.shared.tables
    }

    /// The account the client was checked as (`HKU:<sid>` ids of this account are served).
    pub fn user_sid(&self) -> &str {
        &self.shared.user_sid
    }

    /// The engine settings of the pipeline steps; `local_build` is the build this broker started.
    pub fn settings(&self) -> &Settings {
        &self.shared.settings
    }

    /// Sends a notification. An error means the client is gone or the line cannot be sent: stop
    /// sending, and finish a mutating request without it. The request's first `*.progress` line
    /// that was written is the `first_progress` mark.
    pub fn notify(&self, notification: &ServerNotification) -> Result<(), FrameError> {
        let sent = self.shared.notify(notification);
        if sent.is_ok() && is_progress(notification) {
            self.mark(TimingName::FirstProgress);
        }
        sent
    }

    /// Whether the request should stop: `$/cancel` named it (a cancellable request only), or the
    /// broker lost its parent or its pipe. A mutating request that is not cancellable ignores it.
    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst) || self.shared.lost.load(Ordering::SeqCst)
    }

    /// Whether the client or the parent is gone.
    pub fn lost(&self) -> bool {
        self.shared.lost.load(Ordering::SeqCst)
    }

    /// The local baseline build's state now.
    pub fn baseline(&self) -> BaselineBuild {
        self.shared
            .build_state()
            .unwrap_or_else(|| BaselineBuild::None {
                reason: "no build was started in this process".into(),
            })
    }

    /// Adds a scan to the table, remembering whether the local baseline was still building, so that
    /// `baseline.changed` offers it again when the build completes.
    pub fn add_scan(&self, scan: H::Scan) -> Result<purge_rpc::methods::ScanId, ErrorObject> {
        let building = self.shared.build_state().is_some_and(|s| in_progress(&s));
        self.shared.tables.add_scan(scan, building)
    }

    /// Shows the consent dialog and waits for the answer: [`Outcome::Approved`] only when the user
    /// approved. A dialog that cannot be shown, one whose broker is ending (parent or pipe lost),
    /// and one closed because of that, are [`Outcome::Declined`]. When the window is up the client is
    /// sent `consent.shown` with `code`; a client that cannot be written to is lost, which closes the
    /// dialog as Cancel. The request's first dialog is timed: `consent_shown` when it is up,
    /// `consent_answered` when it ended.
    pub fn consent(&self, pages: &[Page], primary: i32, code: ConfirmCode) -> Outcome {
        self.consent_with(None, pages, primary, code)
    }

    /// [`Ctx::consent`] for a dialog that is also there as a [`Sheet`] ([`Consent::ask_sheet`]).
    pub fn consent_sheet(
        &self,
        sheet: &Sheet,
        pages: &[Page],
        primary: i32,
        code: ConfirmCode,
    ) -> Outcome {
        self.consent_with(Some(sheet), pages, primary, code)
    }

    fn consent_with(
        &self,
        sheet: Option<&Sheet>,
        pages: &[Page],
        primary: i32,
        code: ConfirmCode,
    ) -> Outcome {
        if self.shared.closer.fired() || self.lost() {
            return Outcome::Declined;
        }
        let was_shown = AtomicBool::new(false);
        let shown = || {
            self.mark(TimingName::ConsentShown);
            was_shown.store(true, Ordering::SeqCst);
            let _ = self.notify(&ServerNotification::ConsentShown(ConsentShown {
                request: self.request,
                code,
            }));
        };
        let consent = &self.shared.consent;
        let closer = &self.shared.closer;
        let answer = match sheet {
            Some(sheet) => consent.ask_sheet(sheet, pages, primary, closer, &shown),
            None => consent.ask(pages, primary, closer, &shown),
        }
        .unwrap_or(Outcome::Declined);
        if was_shown.load(Ordering::SeqCst) {
            self.mark(TimingName::ConsentAnswered);
        }
        answer
    }
}

/// The program ids a request carries.
fn program_ids(call: &PipeCall) -> Vec<&ProgramId> {
    match call {
        PipeCall::UninstallPrepare(p) | PipeCall::LeftoversStored(p) => {
            p.program_ids.as_slice().iter().collect()
        }
        PipeCall::LeftoversScan(LeftoversScanParams::Stored(s)) => vec![&s.program_id],
        _ => Vec::new(),
    }
}

/// Whether a completed result of this method ends the broker when no session is left (design 3.6).
fn completes_change(method: Method) -> bool {
    matches!(
        method,
        Method::PlanExecute
            | Method::UndoRun
            | Method::JournalResume
            | Method::JournalRollback
            | Method::JournalRetryHeld
            | Method::QuarantinePurge
    )
}

fn hello_with_build(
    host: &dyn Host,
    build: Option<&Arc<dyn BuildHandle>>,
) -> (EngineHello, Option<BaselineBuild>) {
    let mut hello = host.hello();
    let state = build.map(|b| b.state());
    if let Some(state) = &state {
        hello.baseline.baseline_build = state.clone();
    }
    (hello, state)
}

/// Why waiting for a first line ended without one.
enum FirstLine {
    Refused(Refusal),
    End(ExitReason),
}

/// A client's first line, and what it sent after it.
fn read_first_line<L: Link>(
    link: &L,
    limits: &Limits,
    clock: &dyn Clock,
    parent: &dyn Parent,
) -> Result<(Vec<u8>, Vec<u8>), FirstLine> {
    let since = clock.now();
    let mut line: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if parent.exited() {
            return Err(FirstLine::End(ExitReason::ParentLost));
        }
        if clock.now().saturating_sub(since) >= limits.hello_wait {
            return Err(FirstLine::Refused(Refusal::HelloTimeout));
        }
        match link.read(&mut chunk, limits.tick) {
            Ok(0) | Err(LinkError::Disconnected) => return Err(FirstLine::Refused(Refusal::Gone)),
            Err(LinkError::TimedOut) => continue,
            Err(LinkError::Failed(why)) => return Err(FirstLine::End(ExitReason::LinkFailed(why))),
            Ok(n) => {
                line.extend_from_slice(&chunk[..n]);
                if let Some(end) = line.iter().position(|b| *b == b'\n') {
                    if end > HELLO_LINE_CAP {
                        return Err(FirstLine::Refused(Refusal::NotHello));
                    }
                    let rest = line.split_off(end + 1);
                    line.pop();
                    return Ok((line, rest));
                }
                if line.len() > HELLO_LINE_CAP {
                    return Err(FirstLine::Refused(Refusal::NotHello));
                }
            }
        }
    }
}

/// Accepts clients until one passes: identified, and `engine.hello` first. Its hello is answered here.
/// Returns what it sent after the hello line, the build state the hello carried and the time of the
/// hello (read before the answer, so the idle count starts no later than the client's next move).
/// The answered hello is the `pipe_connected` mark. `Err` is the end of the broker.
fn accept<L: Link>(
    w: &mut Wiring<L, impl Handler>,
    refusals: &mut Vec<Refusal>,
    timings: &Timings,
) -> Result<(Vec<u8>, Option<BaselineBuild>, Duration), ExitReason> {
    let started = w.clock.now();
    loop {
        if w.parent.exited() {
            return Err(ExitReason::ParentLost);
        }
        if idle_expired(w.clock.now(), started, w.limits.idle) {
            return Err(ExitReason::Idle);
        }
        let refusal = match w.link.wait_for_client(w.limits.tick) {
            Ok(false) => continue,
            Err(LinkError::TimedOut) => continue,
            Err(LinkError::Disconnected) => Refusal::Gone,
            Err(LinkError::Failed(why)) => return Err(ExitReason::LinkFailed(why)),
            Ok(true) => match w.link.identify(&w.expected) {
                Err(refusal) => refusal,
                Ok(()) => match read_first_line(&w.link, &w.limits, &*w.clock, &*w.parent) {
                    Err(FirstLine::End(reason)) => return Err(reason),
                    Err(FirstLine::Refused(refusal)) => refusal,
                    Ok((line, rest)) => match route::<PipeCall>(&line) {
                        Routed::Call {
                            id,
                            call: PipeCall::EngineHello(_),
                        } => {
                            let (hello, state) = hello_with_build(&*w.host, w.build.as_ref());
                            let at = w.clock.now();
                            let body = serde_json::to_value(&hello)
                                .map_err(|e| ErrorObject::runtime(e.to_string()));
                            let mut writer = FrameWriter::new(LinkSink(&w.link), OUT_LIMIT);
                            match write_response(&mut writer, &Response { id: Some(id), body }) {
                                Ok(()) => {
                                    timings.mark_process(TimingName::PipeConnected);
                                    return Ok((rest, state, at));
                                }
                                Err(_) => Refusal::Gone,
                            }
                        }
                        _ => Refusal::NotHello,
                    },
                },
            },
        };
        refusals.push(refusal);
        w.link.disconnect();
        if refusals.len() >= w.limits.max_failed {
            return Err(ExitReason::RefusedClients);
        }
    }
}

struct Job {
    cancel: Arc<AtomicBool>,
    mutating: bool,
    cancellable: bool,
}

struct Drain {
    reason: ExitReason,
    deadline: Duration,
}

/// Runs the broker: accepts and checks a client, serves it, and returns how the broker ended. The
/// caller reports a non-zero [`Exit::code`] and ends the process. The timing marks count from this
/// call; the binary uses [`run_timed`] with marks that count from the process creation.
pub fn run<L: Link, H: Handler>(w: Wiring<L, H>) -> Exit {
    run_timed(w, Arc::new(Timings::default()))
}

/// [`run`] with the broker's timing recorder (`crate::timing`; design 9.1).
pub fn run_timed<L: Link, H: Handler>(mut w: Wiring<L, H>, timings: Arc<Timings>) -> Exit {
    let mut refusals = Vec::new();
    let (rest, last_state, hello_at) = match accept(&mut w, &mut refusals, &timings) {
        Ok(ok) => ok,
        Err(reason) => {
            return finish(&w.build, &w.limits, reason, refusals);
        }
    };
    let Wiring {
        link,
        handler,
        expected,
        parent,
        consent,
        host,
        clock,
        build,
        settings,
        limits,
    } = w;
    let link = Arc::new(link);
    let (events, rx) = sync_channel::<Event>(256);
    let shared = Arc::new(Shared::<H> {
        tables: Tables::new(),
        out: Box::new(LinkOut {
            link: link.clone(),
            lock: Mutex::new(()),
            broken: AtomicBool::new(false),
        }),
        consent,
        closer: Closer::new(),
        build: build.clone(),
        settings,
        user_sid: expected.user_sid.clone(),
        lost: AtomicBool::new(false),
        stop: AtomicBool::new(false),
        broken: AtomicBool::new(false),
        events: events.clone(),
        timings,
    });
    let reader = {
        let shared = shared.clone();
        let link = link.clone();
        std::thread::Builder::new()
            .name("purge-broker-reader".into())
            .spawn(move || read_lines(&*link, rest, limits.tick, &shared.stop, &events))
    };
    if let Err(e) = reader {
        return finish(
            &build,
            &limits,
            ExitReason::LinkFailed(format!("the reader thread did not start: {e}")),
            refusals,
        );
    }
    let mut core = Core {
        shared,
        handler: Arc::new(handler),
        host,
        parent,
        clock,
        limits,
        jobs: HashMap::new(),
        last_state,
        drain: None,
    };
    let reason = core.serve(&rx, hello_at);
    finish(&build, &core.limits, reason, refusals)
}

/// Ends the run: stops the baseline build before its next part and gives it a short grace.
fn finish(
    build: &Option<Arc<dyn BuildHandle>>,
    limits: &Limits,
    reason: ExitReason,
    refusals: Vec<Refusal>,
) -> Exit {
    if let Some(build) = build {
        build.request_stop();
        let waited = std::time::Instant::now();
        while in_progress(&build.state()) && waited.elapsed() < limits.build_grace {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    Exit { reason, refusals }
}

/// The reader thread: lines from the pipe to the supervisor. A read that times out is a look at
/// the stop flag.
fn read_lines<L: Link>(
    link: &L,
    rest: Vec<u8>,
    tick: Duration,
    stop: &AtomicBool,
    events: &SyncSender<Event>,
) {
    struct Poll<'a, L: Link> {
        link: &'a L,
        pending: Vec<u8>,
        tick: Duration,
        stop: &'a AtomicBool,
    }
    impl<L: Link> Read for Poll<'_, L> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(buf.len());
                buf[..n].copy_from_slice(&self.pending[..n]);
                self.pending.drain(..n);
                return Ok(n);
            }
            loop {
                if self.stop.load(Ordering::SeqCst) {
                    return Err(io::ErrorKind::ConnectionAborted.into());
                }
                match self.link.read(buf, self.tick) {
                    Ok(n) => return Ok(n),
                    Err(LinkError::TimedOut) => continue,
                    Err(LinkError::Disconnected) => return Ok(0),
                    Err(e) => return Err(e.into()),
                }
            }
        }
    }
    let mut frames = FrameReader::new(
        BufReader::with_capacity(
            64 * 1024,
            Poll {
                link,
                pending: rest,
                tick,
                stop,
            },
        ),
        PIPE_IN_LIMIT,
    );
    loop {
        match frames.read_line() {
            Ok(Some(line)) => {
                if events.send(Event::Line(line.to_vec())).is_err() {
                    return;
                }
            }
            Ok(None) => break,
            Err(FrameError::Io(e)) if e.kind() == io::ErrorKind::ConnectionAborted => return,
            Err(_) => break,
        }
    }
    let _ = events.send(Event::ReaderEnded);
}

/// The supervisor's state.
struct Core<H: Handler> {
    shared: Arc<Shared<H>>,
    handler: Arc<H>,
    host: Arc<dyn Host>,
    parent: Arc<dyn Parent>,
    clock: Arc<dyn Clock>,
    limits: Limits,
    jobs: HashMap<RequestId, Job>,
    last_state: Option<BaselineBuild>,
    drain: Option<Drain>,
}

impl<H: Handler> Core<H> {
    fn serve(&mut self, rx: &Receiver<Event>, hello_at: Duration) -> ExitReason {
        let mut last_activity = hello_at;
        let mut lost: Option<ExitReason> = None;
        let mut lost_at = hello_at;
        let mut client_closed = false;
        loop {
            let event = rx.recv_timeout(self.limits.tick);
            let now = self.clock.now();
            match event {
                Ok(Event::Line(line)) => {
                    last_activity = now;
                    if lost.is_none() {
                        self.on_line(&line, now);
                    }
                }
                Ok(Event::ReaderEnded) => {
                    client_closed = true;
                    if self.drain.is_none() && lost.is_none() {
                        lost = Some(ExitReason::PipeLost);
                        lost_at = now;
                    }
                }
                Ok(Event::PipeBroken) => {
                    client_closed = true;
                    if self.drain.is_none() && lost.is_none() {
                        lost = Some(ExitReason::PipeLost);
                        lost_at = now;
                    }
                }
                Ok(Event::JobDone {
                    id,
                    completed_change,
                }) => {
                    self.jobs.remove(&id);
                    last_activity = now;
                    if completed_change
                        && self.drain.is_none()
                        && lost.is_none()
                        && self.shared.tables.sessions.is_empty()
                    {
                        self.drain = Some(Drain {
                            reason: ExitReason::CompletedChange,
                            deadline: now + self.limits.close_wait,
                        });
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return ExitReason::PipeLost,
            }
            // A failed write may not have reached the queue (`mark_broken` uses `try_send`): the flag
            // is the truth, read every tick.
            if self.shared.broken.load(Ordering::SeqCst) && self.drain.is_none() && lost.is_none() {
                lost = Some(ExitReason::PipeLost);
                lost_at = now;
            }
            if lost.is_none() && self.drain.is_none() && self.parent.exited() {
                lost = Some(ExitReason::ParentLost);
                lost_at = now;
            }
            if let Some(reason) = &lost {
                if !self.shared.lost.swap(true, Ordering::SeqCst) {
                    self.shared.closer.fire();
                    for job in self.jobs.values().filter(|j| j.cancellable) {
                        job.cancel.store(true, Ordering::SeqCst);
                    }
                }
                let mutating = self.jobs.values().any(|j| j.mutating);
                let reading = !self.jobs.is_empty() && !mutating;
                if !mutating && (!reading || now.saturating_sub(lost_at) >= self.limits.read_grace)
                {
                    self.shared.stop.store(true, Ordering::SeqCst);
                    return reason.clone();
                }
                continue;
            }
            if let Some(drain) = &self.drain {
                if client_closed || now >= drain.deadline {
                    self.shared.stop.store(true, Ordering::SeqCst);
                    return drain.reason.clone();
                }
                continue;
            }
            self.poll_baseline();
            if self.jobs.is_empty() && idle_expired(now, last_activity, self.limits.idle) {
                self.shared.stop.store(true, Ordering::SeqCst);
                return ExitReason::Idle;
            }
        }
    }

    /// `baseline.changed` when the build's state changed since the last one sent, with the scans made
    /// while it ran when it completed.
    fn poll_baseline(&mut self) {
        let Some(state) = self.shared.build_state() else {
            return;
        };
        if self.last_state.as_ref() == Some(&state) {
            return;
        }
        let rescan_offered = if matches!(state, BaselineBuild::Done { .. }) {
            self.shared.tables.scans_to_offer()
        } else {
            Vec::new()
        };
        let sent = self
            .shared
            .notify(&ServerNotification::BaselineChanged(BaselineChanged {
                build: state.clone(),
                rescan_offered,
            }));
        if sent.is_ok() {
            self.last_state = Some(state);
        }
    }

    fn on_line(&mut self, line: &[u8], now: Duration) {
        match route::<PipeCall>(line) {
            Routed::Reply(response) => self.shared.respond_response(&response),
            Routed::Ignored => {}
            Routed::Cancel { request } => {
                if let Some(job) = self.jobs.get(&request).filter(|j| j.cancellable) {
                    job.cancel.store(true, Ordering::SeqCst);
                }
            }
            Routed::Call { id, call } => self.dispatch(id, call, now),
        }
    }

    fn refuse(&self, id: RequestId, error: ErrorObject) {
        self.shared.respond(id, Err(error));
    }

    fn dispatch(&mut self, id: RequestId, call: PipeCall, now: Duration) {
        if self.drain.is_some() {
            return self.refuse(id, ErrorObject::runtime("the broker is closing"));
        }
        if self.jobs.contains_key(&id) {
            return self.refuse(
                id,
                ErrorObject::protocol(INVALID_REQUEST, "the request id is running"),
            );
        }
        match &call {
            PipeCall::EngineHello(_) => {
                let (hello, state) = hello_with_build(&*self.host, self.shared.build.as_ref());
                if state.is_some() {
                    self.last_state = state;
                }
                return self.shared.respond(
                    id,
                    serde_json::to_value(&hello).map_err(|e| ErrorObject::runtime(e.to_string())),
                );
            }
            PipeCall::BrokerShutdown(_) => {
                let exiting = self.jobs.is_empty();
                if exiting {
                    self.drain = Some(Drain {
                        reason: ExitReason::Shutdown,
                        deadline: now + self.limits.close_wait,
                    });
                }
                return self.shared.respond(
                    id,
                    serde_json::to_value(ShutdownResult { exiting })
                        .map_err(|e| ErrorObject::runtime(e.to_string())),
                );
            }
            _ => {}
        }
        let user_sid = &self.shared.user_sid;
        if program_ids(&call)
            .iter()
            .any(|p| !program_hive_allowed(p, user_sid))
        {
            return self.refuse(id, gone(IdKind::Program));
        }
        let method = purge_rpc::table::CallSet::method(&call);
        let spec = method.spec();
        let mutating = spec.set == CapSet::Execute;
        let busy = if mutating {
            self.jobs.values().any(|j| j.mutating)
        } else {
            self.jobs.values().filter(|j| !j.mutating).count() >= MAX_READS
        };
        if busy {
            return self.refuse(id, ErrorObject::server(ErrorData::Busy));
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let thread_cancel = cancel.clone();
        let shared = self.shared.clone();
        let handler = self.handler.clone();
        let started = std::thread::Builder::new()
            .name(format!("purge-broker-{}", spec.name))
            .spawn(move || {
                let marks = RequestMarks::new(id, spec.name);
                let ctx = Ctx {
                    shared: &shared,
                    request: id,
                    cancel: &thread_cancel,
                    marks: &marks,
                };
                let result =
                    std::panic::catch_unwind(AssertUnwindSafe(|| handler.call(&ctx, call)))
                        .unwrap_or_else(|_| {
                            Err(ErrorObject::runtime("the request failed internally"))
                        });
                // First the end of the job, then its answer: the client can only send its next
                // request after it has read the answer, so the supervisor has by then seen that no
                // request runs (a request sent at once is not `busy`).
                let completed_change = completes_change(method) && result.is_ok();
                let _ = shared.events.send(Event::JobDone {
                    id,
                    completed_change,
                });
                shared.respond(id, result);
            });
        match started {
            Ok(_) => {
                self.jobs.insert(
                    id,
                    Job {
                        cancel,
                        mutating,
                        cancellable: spec.cancellable,
                    },
                );
            }
            Err(e) => self.refuse(id, ErrorObject::runtime(format!("no thread for it: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests;
