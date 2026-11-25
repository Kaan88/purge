//! The medium engine: `purge-engine --stdio` as a child process (ports of `Stdio/EngineProcess.cs`,
//! `Stdio/StdioEngineClient.cs` and `IEngineClient.cs`).
//!
//! [`EngineClient::start`] starts the engine created suspended in a Job object with
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, resumed only once it is in the job, with two inherited pipes
//! (its stdin and stdout) and `NUL` as stderr, nothing else inherited (`purge_win::launch`).
//! Closing the client closes the job, which ends the engine and whatever it started, also when the UI
//! crashes. The protocol is newline-delimited JSON-RPC 2.0 ([`crate::link`]).
//!
//! The requests are [`StdioCall`] values. Three of them stream their data in notifications and end
//! only when every item their reply promised (`Started::count`) is in, whichever came first:
//! `programs.list` (`programs.batch` rows, `programs.patch` patches), `programs.sizes`
//! (`size.ready`, as [`ClientEvent::Sizes`]) and `programs.icons` (`icon.batch`, as
//! [`ClientEvent::Icons`]). `uninstall.run_user` reports `uninstall.progress` as
//! [`ClientEvent::Progress`]. A `programs.get` the engine answers with `gone` is `Program(None)`.

use std::fmt;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use purge_rpc::methods::{
    IconBatch, ProgramsBatch, ProgramsPatch, ServerNotification, SizeReady, Started, StdioCall,
};
use purge_rpc::sets::STDIO_IN_LIMIT;
use purge_rpc::table::{CallSet, Method};
use purge_win::launch::{JobChild, StdioJob};
use serde_json::Value;

use crate::link::{Call, Hooks, Link, decode, lock};
use crate::{Answer, CallId, ClientError, ClientEvent, ProgramIcon, ProgramList, Sink};

/// The UI's view of `purge-engine` (the real one over stdio, or [`crate::SampleEngine`]). Every
/// request returns at once; its answer is a [`ClientEvent::Reply`] on the client's sink.
pub trait Engine: Send + Sync + fmt::Debug {
    /// True for a real engine (scan, remove and undo work); false for sample data.
    fn is_live(&self) -> bool;

    /// True when the Uninstall click can start the flow: the engine is live, so it can route the
    /// program and the broker can be started. The sample engine answers false, and its page disables
    /// Uninstall with the reason.
    fn can_change_pc(&self) -> bool;

    /// Sends one request. A list of program ids is `NonEmpty`: the caller skips an empty one (the C#
    /// client answered those without asking).
    fn request(&self, request: StdioCall) -> CallId;

    /// Cancels a request in flight: sends `$/cancel` and answers it with
    /// [`ClientError::Cancelled`].
    fn cancel(&self, call: CallId);

    /// Why the link ended; `None` while it is live.
    fn closed_reason(&self) -> Option<String>;

    /// Ends the link (and the engine); every request in flight is answered with the link's error.
    fn close(&self);
}

/// Why the engine could not be started.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StartError {
    /// No file at the path.
    #[error("The engine was not found at {}.", .0)]
    NotFound(String),
    /// Windows refused to start it (not a program, access denied, ...).
    #[error("Windows could not start it: {0}")]
    Windows(String),
}

/// A Win32 error as one sentence: the system's text without the `(os error N)` suffix.
pub(crate) fn win32_text(code: u32) -> String {
    let text = std::io::Error::from_raw_os_error(code as i32).to_string();
    let text = match text.rfind(" (os error ") {
        Some(at) => text[..at].trim_end().to_owned(),
        None => text,
    };
    if text.ends_with('.') {
        text
    } else {
        format!("{text}.")
    }
}

/// The link to `purge-engine --stdio`.
pub struct EngineClient {
    link: Link,
    sink: Sink,
    /// The job; dropping it ends the engine. `None` for a client over plain streams (tests).
    child: Arc<Mutex<Option<JobChild>>>,
    /// The wire id of the last `programs.list`: its patches that come after the call ended are still
    /// delivered ([`ClientEvent::ProgramsPatched`]).
    last_list: Arc<AtomicU64>,
}

impl fmt::Debug for EngineClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EngineClient")
            .field("closed", &self.link.closed_reason())
            .finish_non_exhaustive()
    }
}

impl EngineClient {
    /// Starts `engine` with `arguments` (normally `--stdio`) in a kill-on-close job. Fails when the
    /// file is missing or Windows cannot start it.
    pub fn start(
        engine: &Path,
        arguments: &str,
        sink: Sink,
    ) -> Result<Arc<EngineClient>, StartError> {
        if !engine.is_file() {
            return Err(StartError::NotFound(engine.display().to_string()));
        }
        let job = StdioJob::spawn(engine, arguments)
            .map_err(|e| StartError::Windows(win32_text(e.code())))?;
        let StdioJob {
            stdin,
            stdout,
            child,
        } = job;
        let client = EngineClient::with(Box::new(stdin), Box::new(stdout), Some(child), sink)
            .map_err(|e| StartError::Windows(e.to_string()))?;
        Ok(Arc::new(client))
    }

    /// A client over two streams: `input` takes the requests, `output` gives the engine's lines. For
    /// tests and for an engine started elsewhere; closing it closes `input`.
    pub fn over(
        input: Box<dyn Write + Send>,
        output: Box<dyn Read + Send>,
        sink: Sink,
    ) -> std::io::Result<Arc<EngineClient>> {
        EngineClient::with(input, output, None, sink).map(Arc::new)
    }

    fn with(
        input: Box<dyn Write + Send>,
        output: Box<dyn Read + Send>,
        child: Option<JobChild>,
        sink: Sink,
    ) -> std::io::Result<EngineClient> {
        let child = Arc::new(Mutex::new(child));
        let last_list = Arc::new(AtomicU64::new(0));
        let hooks = Hooks {
            who: "The engine",
            out_limit: STDIO_IN_LIMIT,
            shut_down: {
                let child = child.clone();
                // Closing the job ends the engine; the reader then sees the end of its output.
                Box::new(move || drop(lock(&child).take()))
            },
            unrouted: {
                let sink = sink.clone();
                let last_list = last_list.clone();
                Box::new(move |method, params| {
                    late_patch(&sink, &last_list, method, params);
                })
            },
            closed: {
                let sink = sink.clone();
                Box::new(move |reason| {
                    sink.send(ClientEvent::EngineClosed {
                        reason: reason.to_owned(),
                    })
                })
            },
            exit_text: {
                let child = child.clone();
                Box::new(move || {
                    let code = lock(&child)
                        .as_ref()
                        .and_then(|c| c.exit_code(Some(Duration::from_millis(1500))));
                    code.map_or_else(String::new, |c| format!(" (exit code {c})"))
                })
            },
        };
        let link = Link::new(input, output, hooks, "purge-engine-reader")?;
        Ok(EngineClient {
            link,
            sink,
            child,
            last_list,
        })
    }

    /// The engine's pid, while its job is open.
    pub fn pid(&self) -> Option<u32> {
        lock(&self.child).as_ref().map(JobChild::pid)
    }
}

/// A `programs.patch` no request in flight claims: those of the last list, after it ended, go to the
/// page (the C# `ProgramsPatched` event). Other notifications (baseline, the broker's progress) are
/// not the stdio engine's.
fn late_patch(sink: &Sink, last_list: &AtomicU64, method: &str, params: Value) {
    if method != "programs.patch" {
        return;
    }
    let Ok(patch) = serde_json::from_value::<ProgramsPatch>(params) else {
        return;
    };
    let last = last_list.load(Ordering::SeqCst);
    if last != 0 && patch.request.0 == last {
        sink.send(ClientEvent::ProgramsPatched(patch.patches));
    }
}

impl Engine for EngineClient {
    fn is_live(&self) -> bool {
        true
    }

    fn can_change_pc(&self) -> bool {
        true
    }

    fn request(&self, request: StdioCall) -> CallId {
        let call = CallId::next();
        let method = request.method();
        let (params, handler): (Value, Box<dyn Call>) = match &request {
            StdioCall::ProgramsList(_) => (
                Value::Object(Default::default()),
                Box::new(ListCall::new(call, self.sink.clone())),
            ),
            StdioCall::ProgramsSizes(p) => {
                (json(p), Box::new(FeedCall::sizes(call, self.sink.clone())))
            }
            StdioCall::ProgramsIcons(p) => {
                (json(p), Box::new(FeedCall::icons(call, self.sink.clone())))
            }
            other => (
                params_of(other),
                Box::new(PlainCall::new(call, method, self.sink.clone())),
            ),
        };
        let last_list =
            matches!(request, StdioCall::ProgramsList(_)).then(|| self.last_list.clone());
        self.link
            .start(call, method.name(), Some(&params), handler, |id| {
                if let Some(last) = last_list {
                    last.store(id, Ordering::SeqCst);
                }
            });
        call
    }

    fn cancel(&self, call: CallId) {
        self.link.cancel(call);
    }

    fn closed_reason(&self) -> Option<String> {
        self.link.closed_reason()
    }

    fn close(&self) {
        self.link.close("The engine link was closed.");
    }
}

impl Drop for EngineClient {
    fn drop(&mut self) {
        self.close();
    }
}

fn json<T: serde::Serialize>(value: &T) -> Value {
    // The params types serialise to JSON objects without fail.
    serde_json::to_value(value).unwrap_or(Value::Null)
}

/// The params of a request, as the C# client wrote them: always an object (`{}` for none).
fn params_of(request: &StdioCall) -> Value {
    match request {
        StdioCall::EngineHello(p)
        | StdioCall::ProgramsList(p)
        | StdioCall::InventoryChanges(p)
        | StdioCall::HistoryIndex(p) => json(p),
        StdioCall::ProgramsGet(p) | StdioCall::UninstallRoute(p) => json(p),
        StdioCall::ProgramsIcons(p) => json(p),
        StdioCall::ProgramsSizes(p) | StdioCall::InventoryForget(p) => json(p),
        StdioCall::UninstallRunUser(p) => json(p),
    }
}

/// The answer of a request that has no feed.
fn answer(m: Method, result: Result<Value, ClientError>) -> Result<Answer, ClientError> {
    let method = m.name();
    if m == Method::ProgramsGet {
        return match result {
            Ok(v) => decode(method, v).map(|d| Answer::Program(Some(d))),
            Err(e) if e.kind() == Some("gone") => Ok(Answer::Program(None)),
            Err(e) => Err(e),
        };
    }
    let v = result?;
    Ok(match m {
        Method::EngineHello => Answer::MediumHello(decode(method, v)?),
        Method::InventoryChanges => Answer::InventoryChanges(decode(method, v)?),
        Method::InventoryForget => Answer::Done,
        Method::HistoryIndex => Answer::HistoryIndex(decode(method, v)?),
        Method::UninstallRoute => Answer::Route(decode(method, v)?),
        Method::UninstallRunUser => Answer::RunUser(decode(method, v)?),
        _ => {
            return Err(ClientError::BadReply(format!(
                "{method} has no plain answer"
            )));
        }
    })
}

/// A request answered by its reply alone; `*.progress` notifications go to the sink.
struct PlainCall {
    call: CallId,
    method: Method,
    sink: Sink,
}

impl PlainCall {
    fn new(call: CallId, method: Method, sink: Sink) -> PlainCall {
        PlainCall { call, method, sink }
    }
}

impl Call for PlainCall {
    fn notification(&mut self, method: &str, params: Value) -> bool {
        if method.ends_with(".progress") {
            if let Ok(progress) = serde_json::from_value(params) {
                self.sink.send(ClientEvent::Progress {
                    call: self.call,
                    progress,
                });
            }
        }
        false
    }

    fn reply(&mut self, result: Result<Value, ClientError>) -> bool {
        self.sink.send(ClientEvent::Reply {
            call: self.call,
            result: answer(self.method, result),
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

/// Counts the items of a request whose data follows its reply in notifications (or came before it).
#[derive(Default)]
struct Count {
    received: u64,
    expected: Option<u64>,
}

impl Count {
    fn complete(&self) -> bool {
        self.expected.is_some_and(|n| self.received >= n)
    }
}

/// `programs.list`: rows and patches gathered, then one answer.
struct ListCall {
    call: CallId,
    sink: Sink,
    list: ProgramList,
    count: Count,
}

impl ListCall {
    fn new(call: CallId, sink: Sink) -> ListCall {
        ListCall {
            call,
            sink,
            list: ProgramList::default(),
            count: Count::default(),
        }
    }

    fn finish_if_complete(&mut self) -> bool {
        if !self.count.complete() {
            return false;
        }
        self.sink.send(ClientEvent::Reply {
            call: self.call,
            result: Ok(Answer::Programs(std::mem::take(&mut self.list))),
        });
        true
    }
}

impl Call for ListCall {
    fn notification(&mut self, method: &str, params: Value) -> bool {
        match ServerNotification::decode(method, params) {
            Ok(ServerNotification::ProgramsBatch(ProgramsBatch { rows, .. })) => {
                self.count.received += rows.len() as u64;
                self.list.rows.extend(rows);
            }
            Ok(ServerNotification::ProgramsPatch(ProgramsPatch { patches, .. })) => {
                // After the reply, a patch also goes to the page, as one of a list that ended.
                if self.count.expected.is_some() {
                    self.sink
                        .send(ClientEvent::ProgramsPatched(patches.clone()));
                }
                self.list.patches.extend(patches);
            }
            _ => {}
        }
        self.finish_if_complete()
    }

    fn reply(&mut self, result: Result<Value, ClientError>) -> bool {
        match result.and_then(|v| decode::<Started>("programs.list", v)) {
            Ok(started) => {
                self.count.expected = Some(u64::from(started.count));
                self.finish_if_complete()
            }
            Err(e) => {
                self.end(e);
                true
            }
        }
    }

    fn end(&mut self, error: ClientError) {
        self.sink.send(ClientEvent::Reply {
            call: self.call,
            result: Err(error),
        });
    }
}

/// `programs.sizes` or `programs.icons`: each batch goes to the sink as it comes; the answer is
/// [`Answer::Done`] once every item is in.
struct FeedCall {
    call: CallId,
    sink: Sink,
    method: &'static str,
    count: Count,
}

impl FeedCall {
    fn sizes(call: CallId, sink: Sink) -> FeedCall {
        FeedCall {
            call,
            sink,
            method: "programs.sizes",
            count: Count::default(),
        }
    }

    fn icons(call: CallId, sink: Sink) -> FeedCall {
        FeedCall {
            call,
            sink,
            method: "programs.icons",
            count: Count::default(),
        }
    }

    fn finish_if_complete(&mut self) -> bool {
        if !self.count.complete() {
            return false;
        }
        self.sink.send(ClientEvent::Reply {
            call: self.call,
            result: Ok(Answer::Done),
        });
        true
    }
}

impl Call for FeedCall {
    fn notification(&mut self, method: &str, params: Value) -> bool {
        match (self.method, ServerNotification::decode(method, params)) {
            ("programs.sizes", Ok(ServerNotification::SizeReady(SizeReady { sizes, .. }))) => {
                self.count.received += sizes.len() as u64;
                self.sink.send(ClientEvent::Sizes {
                    call: self.call,
                    sizes,
                });
            }
            ("programs.icons", Ok(ServerNotification::IconBatch(IconBatch { icons, .. }))) => {
                self.count.received += icons.len() as u64;
                self.sink.send(ClientEvent::Icons {
                    call: self.call,
                    icons: icons.into_iter().map(ProgramIcon::from).collect(),
                });
            }
            _ => {}
        }
        self.finish_if_complete()
    }

    fn reply(&mut self, result: Result<Value, ClientError>) -> bool {
        match result.and_then(|v| decode::<Started>(self.method, v)) {
            Ok(started) => {
                self.count.expected = Some(u64::from(started.count));
                self.finish_if_complete()
            }
            Err(e) => {
                self.end(e);
                true
            }
        }
    }

    fn end(&mut self, error: ClientError) {
        self.sink.send(ClientEvent::Reply {
            call: self.call,
            result: Err(error),
        });
    }
}
