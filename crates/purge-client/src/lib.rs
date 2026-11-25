//! The Rust UI's clients (docs/UI_RUST_PLAN.md, package UI-CLIENT): the engine over stdio, the
//! broker over its named pipe, and a sample engine. No UI code, no toolkit.
//!
//! | Module | What | Port of |
//! |---|---|---|
//! | [`engine`] | [`Engine`] and [`EngineClient`]: `purge-engine --stdio` in a kill-on-close job | `Stdio/*.cs`, `IEngineClient.cs` |
//! | [`broker`] | [`Broker`], [`BrokerClient`], [`launch`](broker::launch), the server check | `Broker/*.cs`, the broker half of `Pipeline/UninstallPipeline.cs` |
//! | [`sample`] | [`SampleEngine`] for `--sample` and as the fallback | `Fake/FakeEngineClient.cs` |
//! | [`sample_history`] | the sample's cleanups, for History and Quarantine under `--sample` | (new) |
//! | [`startup`] | the first `engine.hello` and `programs.list`, with the sample fallback | `EngineLink.cs` |
//! | [`fingerprint`] | whether the broker may hold a stored fingerprint | `Broker/FingerprintStore.cs` |
//!
//! # Delivery
//!
//! Nothing here blocks the caller. Every request returns a [`CallId`] at once; its answer, and the data
//! that streams in for it, arrive later as [`ClientEvent`]s through the [`Sink`] the client was made
//! with: a `std::sync::mpsc::Sender<ClientEvent>` plus a wake callback, called after each send so
//! the UI loop wakes. Events come from the clients' reader threads (or, for the sample engine, from
//! the calling thread, before the request returns).
//!
//! Wire types are `purge_rpc`'s: requests are [`purge_rpc::methods::StdioCall`] and
//! [`purge_rpc::methods::PipeCall`] values, answers are the result types, notifications are decoded
//! with [`purge_rpc::methods::ServerNotification`]. No DTO is copied here.

pub mod broker;
pub mod engine;
pub mod fingerprint;
mod icon;
mod link;
pub mod sample;
pub mod sample_history;
pub mod startup;
#[cfg(test)]
mod testing;

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::Sender;

use purge_rpc::EngineHello;
use purge_rpc::error::ErrorData;
use purge_rpc::methods::{
    BaselineChanged, CandidatesPage, ConsentShown, ExecResult, ExpiringList, Explanation,
    HistoryDetail, HistoryIndex, InventoryChanges, MediumHello, ObservedResult, OutcomeResult,
    PendingList, PlanCreated, PrepareResult, ProgramDetails, ProgramPatch, ProgramRow, ProgramSize,
    Progress, PurgeResult, RouteInfo, RunResult, RunUserResult, ScanResult, ShutdownResult,
    StoredResult, UndoResult,
};

pub use broker::{Broker, BrokerClient};
pub use engine::{Engine, EngineClient};
pub use icon::ProgramIcon;
pub use sample::SampleEngine;

/// The id of one request made through an [`Engine`] or a [`Broker`]: unique in the process, so the UI
/// can tell the answers of all its clients apart. Not the JSON-RPC id on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CallId(pub u64);

impl CallId {
    /// A fresh id.
    pub fn next() -> CallId {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        CallId(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// The callback that wakes the UI loop after an event was sent.
pub type Wake = Arc<dyn Fn() + Send + Sync>;

/// Where a client delivers its [`ClientEvent`]s. Cheap to clone.
#[derive(Clone)]
pub struct Sink(Arc<dyn Fn(ClientEvent) + Send + Sync>);

impl Sink {
    /// The UI's sink: each event is sent on `tx`, then `wake` is called. An event sent after the
    /// receiver is gone is dropped, and `wake` is not called.
    pub fn new(tx: Sender<ClientEvent>, wake: Wake) -> Sink {
        Sink(Arc::new(move |event| {
            if tx.send(event).is_ok() {
                wake();
            }
        }))
    }

    /// A sink that calls `f` for every event (tests, and the startup's own routing).
    pub fn from_fn(f: impl Fn(ClientEvent) + Send + Sync + 'static) -> Sink {
        Sink(Arc::new(f))
    }

    /// Delivers one event.
    pub fn send(&self, event: ClientEvent) {
        (self.0)(event)
    }
}

impl fmt::Debug for Sink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sink")
    }
}

/// What the engine's `programs.list` delivered: the rows of every `programs.batch`, and the
/// `programs.patch` patches that came before the call ended. Applying the patches to the rows is the
/// model's work (`ProgramEntries`); patches that come later arrive as
/// [`ClientEvent::ProgramsPatched`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgramList {
    /// The rows, in the order they arrived.
    pub rows: Vec<ProgramRow>,
    /// The patches, in the order they arrived.
    pub patches: Vec<ProgramPatch>,
}

/// The answer of one request, by method.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    /// `engine.hello` of the medium engine.
    MediumHello(MediumHello),
    /// `engine.hello` of the broker (answered when the session was made).
    BrokerHello(EngineHello),
    /// `programs.list`, with its rows and patches.
    Programs(ProgramList),
    /// `programs.get`; `None` when the engine no longer knows the program (`gone`).
    Program(Option<ProgramDetails>),
    /// A request whose data came as events and that returns nothing else: `programs.sizes`
    /// ([`ClientEvent::Sizes`]), `programs.icons` ([`ClientEvent::Icons`]), `inventory.forget`.
    Done,
    /// `inventory.changes`.
    InventoryChanges(InventoryChanges),
    /// `history.index`.
    HistoryIndex(HistoryIndex),
    /// `uninstall.route`.
    Route(RouteInfo),
    /// `uninstall.run_user`.
    RunUser(RunUserResult),
    /// `uninstall.prepare`.
    Prepare(PrepareResult),
    /// `uninstall.run`.
    Run(RunResult),
    /// `uninstall.observed`.
    Observed(ObservedResult),
    /// `leftovers.stored`.
    Stored(StoredResult),
    /// `leftovers.scan`.
    Scan(ScanResult),
    /// `scan.candidates`.
    Candidates(CandidatesPage),
    /// `candidate.explain`.
    Explanation(Explanation),
    /// `plan.create`.
    Plan(PlanCreated),
    /// `plan.execute`.
    Exec(ExecResult),
    /// `history.get`.
    HistoryDetail(HistoryDetail),
    /// `undo.run`.
    Undo(UndoResult),
    /// `journal.pending`.
    Pending(PendingList),
    /// `journal.resume`, `journal.rollback`, `journal.retry_held`.
    Outcome(OutcomeResult),
    /// `quarantine.expiring`.
    Expiring(ExpiringList),
    /// `quarantine.purge`.
    Purge(PurgeResult),
    /// `broker.shutdown`.
    Shutdown(ShutdownResult),
}

/// A JSON-RPC error the engine or the broker answered (`error.data.kind` says which).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcError {
    /// The JSON-RPC code.
    pub code: i32,
    /// `error.data.kind` (for example `runtime` or `gone`), when the server gave one.
    pub kind: Option<String>,
    /// A sentence for the UI: `error.data.message` when there is one, else `error.message`.
    pub message: String,
    /// The whole `error.data`, when it is one this client knows: the refusals of a `plan_refused`,
    /// `exit_code` and `forced_offered` of an `uninstall_failed`, the route of a `wrong_route`.
    pub data: Option<ErrorData>,
}

/// Why a request has no answer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ClientError {
    /// The server answered with an error.
    #[error("{}", .0.message)]
    Rpc(RpcError),
    /// The link ended, or could not be written to.
    #[error("{reason}")]
    Link {
        /// Why, in a sentence for the UI.
        reason: String,
        /// The request was never received by the server (the link had ended before, or the write
        /// failed), so the server did nothing for it. False: what it did is unknown.
        not_sent: bool,
    },
    /// The caller cancelled the request. For a method the server cannot stop (an uninstaller, an
    /// execute, an undo, a purge) only the wait ended; the server finishes its run.
    #[error("The request was cancelled.")]
    Cancelled,
    /// The answer is not of the method's result type.
    #[error("{0}")]
    BadReply(String),
    /// This client cannot do it (the sample engine, or a request sent to the wrong part).
    #[error("{0}")]
    NotAvailable(String),
}

impl ClientError {
    /// `error.data.kind` of an [`ClientError::Rpc`].
    pub fn kind(&self) -> Option<&str> {
        match self {
            ClientError::Rpc(e) => e.kind.as_deref(),
            _ => None,
        }
    }
}

/// What a client delivers through its [`Sink`].
#[derive(Debug)]
pub enum ClientEvent {
    /// The answer of a request. Exactly one per [`CallId`], always the last event of that call.
    Reply {
        /// The request.
        call: CallId,
        /// Its answer.
        result: Result<Answer, ClientError>,
    },
    /// A `*.progress` notification of a request in flight.
    Progress {
        /// The request.
        call: CallId,
        /// The progress line.
        progress: Progress,
    },
    /// One `size.ready` batch of a `programs.sizes` request (`bytes` is `None` when a size could not
    /// be measured).
    Sizes {
        /// The request.
        call: CallId,
        /// The sizes.
        sizes: Vec<ProgramSize>,
    },
    /// One `icon.batch` of a `programs.icons` request, decoded.
    Icons {
        /// The request.
        call: CallId,
        /// The icons.
        icons: Vec<ProgramIcon>,
    },
    /// `programs.patch` patches that came after the `programs.list` reply (the engine normally sends
    /// them before it). Patches that came while the list call was still open are also in its
    /// [`ProgramList`]; applying a patch twice changes nothing.
    ProgramsPatched(Vec<ProgramPatch>),
    /// The broker's consent dialog is up; the code is the one in its footer.
    ConsentShown {
        /// The request that opened it, when it is one of this client's.
        call: Option<CallId>,
        /// The notification.
        shown: ConsentShown,
    },
    /// `baseline.changed`, including the scans the broker offers again after a build.
    BaselineChanged(BaselineChanged),
    /// The engine link ended; every request in flight has had its [`ClientEvent::Reply`].
    EngineClosed {
        /// Why, in a sentence for the UI.
        reason: String,
    },
    /// The broker link of session `session` ended; every request in flight has had its
    /// [`ClientEvent::Reply`]. The next click that needs the broker launches a new one.
    ///
    /// Only a session that was handed out announces its end, and only after it was handed out: for a
    /// launch this event always comes after the [`ClientEvent::BrokerLaunched`] that carried the
    /// session, and a session whose link ended before that is never handed out (the launch fails).
    /// An event whose `session` is not the UI's current one is of an older session.
    BrokerClosed {
        /// [`Broker::session`] of the session that ended.
        session: u64,
        /// Why, in a sentence for the UI.
        reason: String,
    },
    /// The answer of [`broker::launch`].
    BrokerLaunched {
        /// The launch.
        call: CallId,
        /// The session, or why there is none.
        result: Result<Arc<BrokerClient>, broker::LaunchFailure>,
    },
    /// The answer of [`startup::start`].
    Startup(Box<startup::StartupResult>),
}

/// Whether this process runs elevated (started "as administrator", or UAC is off for an
/// administrator): the "Administrator" chip. False when the token cannot be read.
pub fn ui_elevated() -> bool {
    purge_win::token::current_process_facts().is_ok_and(|f| f.elevated)
}
