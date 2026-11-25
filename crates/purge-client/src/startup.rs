//! The start of the app (port of `EngineLink.cs`, ENGINE_PLAN.md A9.2): start the engine, send
//! `engine.hello` and `programs.list` on a background thread, and fall back to the sample engine with
//! a notice when the engine is missing, cannot start, ends early, answers with an error, or is too
//! slow ([`DEFAULT_TIMEOUT`] for hello and the list together).
//!
//! The answer is one [`ClientEvent::Startup`]. `inventory.changes` is sent before the list (the engine
//! answers it against the list of the last run, and stores the new list when the list ends); its
//! [`CallId`] is in [`StartupResult::changes`] and its reply comes through the sink like any other.
//!
//! While the start runs, the engine's events are held back: the UI sees nothing of an engine before
//! the [`ClientEvent::Startup`] that hands it over, and nothing at all of an engine that was replaced
//! by the sample. The held events (the `inventory.changes` reply, late patches) follow the
//! [`ClientEvent::Startup`] in their order.

use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use purge_rpc::methods::{MediumHello, NoParams, StdioCall};

use crate::engine::{Engine, EngineClient, StartError};
use crate::link::lock;
use crate::{Answer, CallId, ClientError, ClientEvent, ProgramList, SampleEngine, Sink};

/// How long the engine has to answer hello and the list before the sample data takes over.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// The sentence the fallback notice starts with.
pub const FALLBACK_NOTICE: &str = "Purge couldn't use its engine, so this list is sample data. ";

/// What the start of the app needs from the engine.
#[derive(Debug)]
pub struct StartupResult {
    /// The engine to use from now on (the sample engine when the real one could not be used).
    pub engine: Arc<dyn Engine>,
    /// Its hello.
    pub hello: MediumHello,
    /// The program list.
    pub list: ProgramList,
    /// The fallback notice; `None` when the engine answered (or sample data was asked for).
    pub error: Option<String>,
    /// Whether this process itself runs elevated (the "Administrator" chip).
    pub ui_elevated: bool,
    /// The `inventory.changes` request, sent before the list.
    pub changes: CallId,
}

/// Starts the real engine with the sink it is to use.
pub type OpenEngine = Box<dyn FnOnce(Sink) -> Result<Arc<dyn Engine>, StartError> + Send>;

/// A launch marker (the launch bench's `engine_ready` and `list_reply`).
pub type Mark = Box<dyn Fn() + Send>;

/// How to start.
pub struct Startup {
    open: Option<OpenEngine>,
    bench_rows: usize,
    timeout: Duration,
    engine_ready: Option<Mark>,
    list_reply: Option<Mark>,
}

impl Startup {
    /// `purge-engine --stdio` at `engine`.
    pub fn engine(engine: PathBuf) -> Startup {
        Startup::with_open(Box::new(move |sink| {
            EngineClient::start(&engine, "--stdio", sink).map(|e| e as Arc<dyn Engine>)
        }))
    }

    /// An engine started by `open` (tests, or another command line).
    pub fn with_open(open: OpenEngine) -> Startup {
        Startup {
            open: Some(open),
            bench_rows: 0,
            timeout: DEFAULT_TIMEOUT,
            engine_ready: None,
            list_reply: None,
        }
    }

    /// The sample engine only: no engine, no notice.
    pub fn sample() -> Startup {
        Startup {
            open: None,
            bench_rows: 0,
            timeout: DEFAULT_TIMEOUT,
            engine_ready: None,
            list_reply: None,
        }
    }

    /// The sample engine's bench rows ([`SampleEngine::with_bench_rows`]).
    pub fn bench_rows(mut self, rows: usize) -> Startup {
        self.bench_rows = rows;
        self
    }

    /// The limit for hello and the list.
    pub fn timeout(mut self, timeout: Duration) -> Startup {
        self.timeout = timeout;
        self
    }

    /// Called once hello is answered.
    pub fn on_engine_ready(mut self, mark: Mark) -> Startup {
        self.engine_ready = Some(mark);
        self
    }

    /// Called once the list is answered.
    pub fn on_list_reply(mut self, mark: Mark) -> Startup {
        self.list_reply = Some(mark);
        self
    }

    /// Runs the start on a background thread; the answer is a [`ClientEvent::Startup`] on `sink`.
    pub fn start(self, sink: Sink) {
        let fallback_sink = sink.clone();
        let spawned = std::thread::Builder::new()
            .name("purge-startup".into())
            .spawn(move || run(self, sink));
        if spawned.is_err() {
            // No thread: the sample data, answered here.
            let gate = Gate::new(fallback_sink);
            let sample: Arc<dyn Engine> = Arc::new(SampleEngine::new(gate.sink(Source::Sample)));
            let result = sample_result(
                &gate,
                sample,
                Some("Windows could not start a thread.".into()),
                &None,
                &None,
            );
            gate.open(result);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    Engine,
    Sample,
}

struct GateState {
    /// Until the Startup event is sent, events are held here.
    open: bool,
    /// The engine was replaced by the sample: its events are dropped.
    engine_dropped: bool,
    held: Vec<(Source, ClientEvent)>,
}

/// Holds the events of the start until the [`ClientEvent::Startup`] is sent.
struct Gate {
    ui: Sink,
    state: Mutex<GateState>,
    changed: Condvar,
}

impl Gate {
    fn new(ui: Sink) -> Arc<Gate> {
        Arc::new(Gate {
            ui,
            state: Mutex::new(GateState {
                open: false,
                engine_dropped: false,
                held: Vec::new(),
            }),
            changed: Condvar::new(),
        })
    }

    fn sink(self: &Arc<Gate>, source: Source) -> Sink {
        let gate = self.clone();
        Sink::from_fn(move |event| {
            let mut state = lock(&gate.state);
            if source == Source::Engine && state.engine_dropped {
                return;
            }
            if state.open {
                // Sent under the lock, so nothing overtakes the held events being flushed.
                gate.ui.send(event);
            } else {
                state.held.push((source, event));
                gate.changed.notify_all();
            }
        })
    }

    /// Waits until `call`'s reply is held, and takes it. `None` at the deadline.
    fn take_reply(
        &self,
        call: CallId,
        deadline: Option<Instant>,
    ) -> Option<Result<Answer, ClientError>> {
        let mut state = lock(&self.state);
        loop {
            let at = state
                .held
                .iter()
                .position(|(_, e)| matches!(e, ClientEvent::Reply { call: c, .. } if *c == call));
            if let Some(at) = at {
                if let (_, ClientEvent::Reply { result, .. }) = state.held.remove(at) {
                    return Some(result);
                }
            }
            let wait = match deadline {
                None => Duration::from_secs(3600),
                Some(d) => {
                    let left = d.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return None;
                    }
                    left
                }
            };
            state = self
                .changed
                .wait_timeout(state, wait)
                .map(|(s, _)| s)
                .unwrap_or_else(|p| p.into_inner().0);
        }
    }

    /// Drops the engine's events, held and to come.
    fn drop_engine(&self) {
        let mut state = lock(&self.state);
        state.engine_dropped = true;
        state.held.retain(|(s, _)| *s != Source::Engine);
    }

    /// Sends the Startup event, then the held events, and lets later events through.
    fn open(&self, result: StartupResult) {
        let mut state = lock(&self.state);
        self.ui.send(ClientEvent::Startup(Box::new(result)));
        for (_, event) in std::mem::take(&mut state.held) {
            self.ui.send(event);
        }
        state.open = true;
    }
}

fn describe(error: &str) -> String {
    if error.ends_with('.') {
        error.to_owned()
    } else {
        format!("{error}.")
    }
}

fn run(startup: Startup, ui: Sink) {
    let gate = Gate::new(ui);
    let Startup {
        open,
        bench_rows,
        timeout,
        engine_ready,
        list_reply,
    } = startup;
    let sample = |gate: &Arc<Gate>| -> Arc<dyn Engine> {
        Arc::new(SampleEngine::new(gate.sink(Source::Sample)).with_bench_rows(bench_rows))
    };
    let Some(open) = open else {
        let result = sample_result(&gate, sample(&gate), None, &engine_ready, &list_reply);
        gate.open(result);
        return;
    };
    let error = match open(gate.sink(Source::Engine)) {
        Err(e) => describe(&e.to_string()),
        Ok(engine) => match live(&gate, &engine, timeout, &engine_ready, &list_reply) {
            Ok(result) => {
                gate.open(result);
                return;
            }
            Err(error) => {
                gate.drop_engine();
                engine.close();
                error
            }
        },
    };
    let result = sample_result(
        &gate,
        sample(&gate),
        Some(error),
        &engine_ready,
        &list_reply,
    );
    gate.open(result);
}

fn mark(m: &Option<Mark>) {
    if let Some(m) = m {
        m();
    }
}

/// Hello and the list of the real engine within `timeout`.
fn live(
    gate: &Arc<Gate>,
    engine: &Arc<dyn Engine>,
    timeout: Duration,
    engine_ready: &Option<Mark>,
    list_reply: &Option<Mark>,
) -> Result<StartupResult, String> {
    let deadline = Instant::now() + timeout;
    let too_slow = || {
        format!(
            "The engine did not answer within {} seconds.",
            timeout.as_secs()
        )
    };
    let hello_call = engine.request(StdioCall::EngineHello(NoParams {}));
    let hello = match gate.take_reply(hello_call, Some(deadline)) {
        None => return Err(too_slow()),
        Some(Ok(Answer::MediumHello(h))) => h,
        Some(Ok(_)) => return Err("The engine's hello is not a hello.".into()),
        Some(Err(e)) => return Err(describe(&e.to_string())),
    };
    mark(engine_ready);
    // Written before the list request, so the engine answers it against the list of the last run.
    let changes = engine.request(StdioCall::InventoryChanges(NoParams {}));
    let list_call = engine.request(StdioCall::ProgramsList(NoParams {}));
    let list = match gate.take_reply(list_call, Some(deadline)) {
        None => return Err(too_slow()),
        Some(Ok(Answer::Programs(list))) => list,
        Some(Ok(_)) => return Err("The engine's list is not a list.".into()),
        Some(Err(e)) => return Err(describe(&e.to_string())),
    };
    mark(list_reply);
    Ok(StartupResult {
        engine: engine.clone(),
        hello,
        list,
        error: None,
        ui_elevated: crate::ui_elevated(),
        changes,
    })
}

/// The sample's hello and list (it always answers).
fn sample_result(
    gate: &Arc<Gate>,
    sample: Arc<dyn Engine>,
    error: Option<String>,
    engine_ready: &Option<Mark>,
    list_reply: &Option<Mark>,
) -> StartupResult {
    let hello_call = sample.request(StdioCall::EngineHello(NoParams {}));
    let hello = match gate.take_reply(hello_call, None) {
        Some(Ok(Answer::MediumHello(h))) => h,
        _ => SampleEngine::hello(),
    };
    mark(engine_ready);
    let changes = sample.request(StdioCall::InventoryChanges(NoParams {}));
    let list_call = sample.request(StdioCall::ProgramsList(NoParams {}));
    let list = match gate.take_reply(list_call, None) {
        Some(Ok(Answer::Programs(list))) => list,
        _ => ProgramList::default(),
    };
    mark(list_reply);
    StartupResult {
        engine: sample,
        hello,
        list,
        error: error.map(|e| format!("{FALLBACK_NOTICE}{e}")),
        ui_elevated: crate::ui_elevated(),
        changes,
    }
}

#[cfg(test)]
mod tests;
