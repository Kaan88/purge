//! The method table (M3_DESIGN.md §6.3), routing and the [`Dispatcher`] trait.
//!
//! Every request method has one row: its name, its one [`CapSet`], the servers that implement it, and
//! whether it can be cancelled or ends in a consent dialog. A server answers a request only when the
//! method is in the table, served on its transport *and* in its transport's [`SetMask`]
//! (`Transport::mask`); anything else, unknown names included, answers `-32601`. A method that passes is
//! decoded by the transport's [`CallSet`] (`StdioCall`, `PipeCall`), which has a variant only for the
//! methods of that transport: the stdio call set has no variant that could carry an `Execute` or a
//! `Propose` method, so no stdio dispatcher can be handed one.
//!
//! Client notifications: only [`CANCEL`]. A notification with any other name, a request method's name
//! included, is dropped without effect: a request is never run from a notification.
//!
//! [`SetMask`]: crate::sets::SetMask

use std::io::{BufRead, Write};

use serde_json::Value;
use serde_json::value::RawValue;

use crate::error::ErrorObject;
use crate::frame::{
    FrameError, FrameReader, FrameWriter, Incoming, RequestId, Response, parse_incoming,
};
use crate::methods::{CancelParams, ServerNotification, decode_params};
use crate::sets::{CapSet, OUT_LIMIT, Transport};

/// The servers that implement a method or send a notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Served {
    /// The medium engine over stdio only.
    Stdio,
    /// The broker over its pipe only.
    Pipe,
    /// Both.
    Both,
}

impl Served {
    /// Whether a server of `transport` is one of them.
    pub const fn on(self, transport: Transport) -> bool {
        matches!(
            (self, transport),
            (Served::Both, _) | (Served::Stdio, Transport::Stdio) | (Served::Pipe, Transport::Pipe)
        )
    }
}

/// One row of the method table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodSpec {
    /// The method.
    pub method: Method,
    /// Its wire name.
    pub name: &'static str,
    /// Its one capability set.
    pub set: CapSet,
    /// The servers that implement it.
    pub served: Served,
    /// Whether `$/cancel` may stop it (harvest, scan, list). A running uninstaller, execute, undo,
    /// recovery or purge is not cancellable, and the consent dialog only by its own Cancel.
    pub cancellable: bool,
    /// Whether it ends in the broker's consent dialog (it sends `consent.shown`).
    pub consent: bool,
}

macro_rules! method_table {
    ($($(#[$doc:meta])* $variant:ident => $name:literal, $set:ident, $served:ident,
        cancel: $cancel:literal, consent: $consent:literal;)*) => {
        /// A request method of the engine API.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum Method {
            $($(#[$doc])* $variant,)*
        }

        /// The method table, one row per [`Method`] in declaration order.
        pub const METHODS: &[MethodSpec] = &[$(MethodSpec {
            method: Method::$variant,
            name: $name,
            set: CapSet::$set,
            served: Served::$served,
            cancellable: $cancel,
            consent: $consent,
        },)*];

        impl Method {
            /// Every method, in table order.
            pub const ALL: &[Method] = &[$(Method::$variant,)*];

            /// The wire name.
            pub const fn name(self) -> &'static str {
                match self {
                    $(Method::$variant => $name,)*
                }
            }
        }
    };
}

method_table! {
    /// `engine.hello`: what the engine is and what it can prove. The broker answers nothing before it.
    EngineHello => "engine.hello", Read, Both, cancel: false, consent: false;
    /// `programs.list` ⇢ `programs.batch`, `programs.patch`.
    ProgramsList => "programs.list", Read, Stdio, cancel: true, consent: false;
    /// `programs.get`: details-pane data of one program.
    ProgramsGet => "programs.get", Read, Stdio, cancel: false, consent: false;
    /// `programs.icons` ⇢ `icon.batch`.
    ProgramsIcons => "programs.icons", Read, Stdio, cancel: true, consent: false;
    /// `programs.sizes` ⇢ `size.ready`.
    ProgramsSizes => "programs.sizes", Read, Stdio, cancel: true, consent: false;
    /// `inventory.changes`: programs gone or new since the last stored list (display only).
    InventoryChanges => "inventory.changes", Read, Stdio, cancel: false, consent: false;
    /// `history.index`: session summaries and quarantine usage per volume.
    HistoryIndex => "history.index", Read, Stdio, cancel: false, consent: false;
    /// `uninstall.route`: where a program's uninstaller runs, and what it is.
    UninstallRoute => "uninstall.route", Read, Stdio, cancel: false, consent: false;
    /// `uninstall.run_user` ⇢ `uninstall.progress`: a medium-route uninstaller at the user's level.
    UninstallRunUser => "uninstall.run_user", UserRun, Stdio, cancel: false, consent: false;
    /// `uninstall.prepare` ⇢ `prepare.progress`: harvest in the broker.
    UninstallPrepare => "uninstall.prepare", Execute, Pipe, cancel: true, consent: false;
    /// `uninstall.run` ⇢ `uninstall.progress`: a broker-route uninstaller.
    UninstallRun => "uninstall.run", Execute, Pipe, cancel: false, consent: true;
    /// `uninstall.observed`: the broker's own verify-gone after a medium-route run.
    UninstallObserved => "uninstall.observed", Execute, Pipe, cancel: false, consent: false;
    /// `leftovers.stored`: which programs have a stored fingerprint.
    LeftoversStored => "leftovers.stored", Read, Pipe, cancel: false, consent: false;
    /// `leftovers.scan` ⇢ `scan.progress`.
    LeftoversScan => "leftovers.scan", Read, Pipe, cancel: true, consent: false;
    /// `scan.candidates`: one page of a scan's candidates.
    ScanCandidates => "scan.candidates", Read, Pipe, cancel: false, consent: false;
    /// `candidate.explain`: evidence lines and blockers of one candidate.
    CandidateExplain => "candidate.explain", Read, Pipe, cancel: false, consent: false;
    /// `plan.create`: a plan in broker memory from the broker's own scan.
    PlanCreate => "plan.create", Propose, Pipe, cancel: false, consent: false;
    /// `plan.execute` ⇢ `consent.shown`, `exec.progress`.
    PlanExecute => "plan.execute", Execute, Pipe, cancel: false, consent: true;
    /// `history.get`: one session's items with their state.
    HistoryGet => "history.get", Read, Pipe, cancel: false, consent: false;
    /// `undo.run` ⇢ `consent.shown`, `undo.progress`.
    UndoRun => "undo.run", Execute, Pipe, cancel: false, consent: true;
    /// `journal.pending`: interrupted sessions.
    JournalPending => "journal.pending", Read, Pipe, cancel: false, consent: false;
    /// `journal.resume` ⇢ `consent.shown`.
    JournalResume => "journal.resume", Execute, Pipe, cancel: false, consent: true;
    /// `journal.rollback` ⇢ `consent.shown`.
    JournalRollback => "journal.rollback", Execute, Pipe, cancel: false, consent: true;
    /// `journal.retry_held` ⇢ `consent.shown`.
    JournalRetryHeld => "journal.retry_held", Execute, Pipe, cancel: false, consent: true;
    /// `quarantine.expiring`: items past retention; with `include_not_due`, the quarantined items
    /// before it too.
    QuarantineExpiring => "quarantine.expiring", Read, Pipe, cancel: false, consent: false;
    /// `quarantine.purge` ⇢ `consent.shown`.
    QuarantinePurge => "quarantine.purge", Execute, Pipe, cancel: false, consent: true;
    /// `broker.shutdown`: the broker exits when nothing runs.
    BrokerShutdown => "broker.shutdown", Read, Pipe, cancel: false, consent: false;
}

impl Method {
    /// The method's row.
    pub fn spec(self) -> &'static MethodSpec {
        &METHODS[self as usize]
    }
}

/// The row of the method a server of `transport` answers by this name: `None` (answer `-32601`) for an
/// unknown name, a method another server implements, and a method outside the transport's sets.
pub fn lookup(transport: Transport, name: &str) -> Option<&'static MethodSpec> {
    METHODS.iter().find(|spec| {
        spec.name == name && spec.served.on(transport) && transport.mask().contains(spec.set)
    })
}

/// The one notification a client sends: stop a cancellable request.
pub const CANCEL: &str = "$/cancel";

/// One row of the notification table: a notification a server sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoticeSpec {
    /// The notification.
    pub notice: Notice,
    /// Its wire name.
    pub name: &'static str,
    /// The servers that send it.
    pub served: Served,
}

macro_rules! notice_table {
    ($($(#[$doc:meta])* $variant:ident => $name:literal, $served:ident;)*) => {
        /// A notification a server sends.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum Notice {
            $($(#[$doc])* $variant,)*
        }

        /// The notification table, one row per [`Notice`] in declaration order.
        pub const NOTICES: &[NoticeSpec] = &[$(NoticeSpec {
            notice: Notice::$variant,
            name: $name,
            served: Served::$served,
        },)*];

        impl Notice {
            /// Every notification, in table order.
            pub const ALL: &[Notice] = &[$(Notice::$variant,)*];

            /// The wire name.
            pub const fn name(self) -> &'static str {
                match self {
                    $(Notice::$variant => $name,)*
                }
            }
        }
    };
}

notice_table! {
    /// Raw ARP rows of a `programs.list`.
    ProgramsBatch => "programs.batch", Stdio;
    /// MSI, Burn and AppX details for rows already sent.
    ProgramsPatch => "programs.patch", Stdio;
    /// Icons of a `programs.icons`.
    IconBatch => "icon.batch", Stdio;
    /// Sizes of a `programs.sizes`.
    SizeReady => "size.ready", Stdio;
    /// Progress of an uninstaller.
    UninstallProgress => "uninstall.progress", Both;
    /// The local baseline's build state changed.
    BaselineChanged => "baseline.changed", Pipe;
    /// Progress of a harvest.
    PrepareProgress => "prepare.progress", Pipe;
    /// Progress of a scan.
    ScanProgress => "scan.progress", Pipe;
    /// The consent dialog is up.
    ConsentShown => "consent.shown", Pipe;
    /// Progress of an execute.
    ExecProgress => "exec.progress", Pipe;
    /// Progress of an undo.
    UndoProgress => "undo.progress", Pipe;
}

impl Notice {
    /// The notification's row.
    pub fn spec(self) -> &'static NoticeSpec {
        &NOTICES[self as usize]
    }
}

pub(crate) mod sealed {
    /// Keeps [`super::CallSet`] to the two call sets of this crate.
    pub trait Sealed {}
}

/// The requests one transport takes, decoded. Implemented by `StdioCall` and `PipeCall` only (the trait
/// is sealed): no other crate can define a call set that pairs a transport with another transport's
/// methods.
pub trait CallSet: sealed::Sealed + Sized {
    /// The transport whose methods these are.
    const TRANSPORT: Transport;

    /// Decodes the params of a method that passed [`lookup`]. `-32601` for a method this set has no
    /// variant for, `-32602` for params of the wrong form.
    fn decode(method: Method, params: Option<&RawValue>) -> Result<Self, ErrorObject>;

    /// The method of a decoded call.
    fn method(&self) -> Method;
}

/// What a server does with one line.
#[derive(Debug, Clone, PartialEq)]
pub enum Routed<C> {
    /// Run this request, then send exactly one response with its id.
    Call {
        /// The request id.
        id: RequestId,
        /// The decoded request.
        call: C,
    },
    /// `$/cancel` of the request with this id. Ignored when that request is not cancellable or done.
    Cancel {
        /// The request to stop.
        request: RequestId,
    },
    /// Send this error response now; nothing runs.
    Reply(Response),
    /// A notification that does nothing: no answer.
    Ignored,
}

/// Routes one line for the transport of `C`: envelope checks, the table and its mask, then the params.
pub fn route<C: CallSet>(line: &[u8]) -> Routed<C> {
    match parse_incoming(line) {
        Err(rejected) => Routed::Reply(rejected.response()),
        Ok(Incoming::Request { id, method, params }) => {
            let decoded = match lookup(C::TRANSPORT, &method) {
                None => Err(ErrorObject::method_not_found()),
                Some(spec) => C::decode(spec.method, params),
            };
            match decoded {
                Ok(call) => Routed::Call { id, call },
                Err(error) => Routed::Reply(Response {
                    id: Some(id),
                    body: Err(error),
                }),
            }
        }
        Ok(Incoming::Notification { method, params }) if method == CANCEL => {
            match decode_params::<CancelParams>(params) {
                Ok(cancel) => Routed::Cancel {
                    request: cancel.request,
                },
                Err(_) => Routed::Ignored,
            }
        }
        Ok(Incoming::Notification { .. }) => Routed::Ignored,
    }
}

/// Sends server notifications while a request runs.
pub trait Notify {
    /// Sends one notification. Errors when it is not sent on this transport or the transport failed.
    fn notify(&mut self, notification: &ServerNotification) -> Result<(), FrameError>;
}

/// Writes a notification to `writer` when `transport` carries it.
pub fn write_notification<W: Write>(
    writer: &mut FrameWriter<W>,
    transport: Transport,
    notification: &ServerNotification,
) -> Result<(), FrameError> {
    let notice = notification.notice();
    if !notice.spec().served.on(transport) {
        return Err(FrameError::NotOnTransport(notice.name()));
    }
    writer.send(notification)
}

/// Writes a response; one over the output limit is replaced by a `runtime` error with the same id.
pub fn write_response<W: Write>(
    writer: &mut FrameWriter<W>,
    response: &Response,
) -> Result<(), FrameError> {
    match writer.send(response) {
        Err(FrameError::OutOversize { limit, .. }) => writer.send(&Response {
            id: response.id,
            body: Err(ErrorObject::runtime(format!(
                "the result is over the {limit}-byte output limit"
            ))),
        }),
        other => other,
    }
}

/// A server's request handler for one transport.
pub trait Dispatcher {
    /// The requests of the transport: `StdioCall` or `PipeCall`.
    type Call: CallSet;

    /// Runs one request and returns its result (the result type of the method, see `methods`) or its
    /// error. Notifications go through `notify`.
    fn call(
        &mut self,
        id: RequestId,
        call: Self::Call,
        notify: &mut dyn Notify,
    ) -> Result<Value, ErrorObject>;

    /// `$/cancel` of a request. [`serve`] runs one request at a time, so it only sees a cancel between
    /// requests; a server that cancels for real reads on another thread and uses [`route`] itself.
    fn cancel(&mut self, request: RequestId) {
        let _ = request;
    }
}

struct WriterNotify<'a, W> {
    writer: &'a mut FrameWriter<W>,
    transport: Transport,
}

impl<W: Write> Notify for WriterNotify<'_, W> {
    fn notify(&mut self, notification: &ServerNotification) -> Result<(), FrameError> {
        write_notification(self.writer, self.transport, notification)
    }
}

/// Serves requests one at a time until the stream ends. Returns the error that closed the transport (an
/// oversize line, a truncated last line, a failed read or write).
pub fn serve<R: BufRead, W: Write, D: Dispatcher>(
    reader: R,
    writer: W,
    dispatcher: &mut D,
) -> Result<(), FrameError> {
    let transport = <D::Call as CallSet>::TRANSPORT;
    let mut reader = FrameReader::new(reader, transport.in_limit());
    let mut writer = FrameWriter::new(writer, OUT_LIMIT);
    while let Some(line) = reader.read_line()? {
        match route::<D::Call>(line) {
            Routed::Call { id, call } => {
                let body = dispatcher.call(
                    id,
                    call,
                    &mut WriterNotify {
                        writer: &mut writer,
                        transport,
                    },
                );
                write_response(&mut writer, &Response { id: Some(id), body })?;
            }
            Routed::Cancel { request } => dispatcher.cancel(request),
            Routed::Reply(response) => writer.send(&response)?,
            Routed::Ignored => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_rows_are_in_method_order_and_names_are_unique() {
        assert_eq!(METHODS.len(), Method::ALL.len());
        for (i, method) in Method::ALL.iter().enumerate() {
            assert_eq!(METHODS[i].method, *method);
            assert_eq!(method.spec().name, method.name());
        }
        let mut names: Vec<_> = METHODS.iter().map(|s| s.name).collect();
        names.extend(NOTICES.iter().map(|s| s.name));
        names.push(CANCEL);
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "a name is used twice");
        for (i, notice) in Notice::ALL.iter().enumerate() {
            assert_eq!(NOTICES[i].notice, *notice);
            assert_eq!(notice.spec().name, notice.name());
        }
    }

    #[test]
    fn every_method_is_reachable_on_some_transport() {
        for spec in METHODS {
            assert!(
                Transport::ALL
                    .iter()
                    .any(|t| lookup(*t, spec.name) == Some(spec)),
                "{} is served nowhere its set is allowed",
                spec.name
            );
        }
    }

    #[test]
    fn consent_methods_are_execute_and_never_cancellable() {
        for spec in METHODS {
            if spec.consent {
                assert_eq!(spec.set, CapSet::Execute, "{}", spec.name);
            }
            if spec.consent || spec.set == CapSet::UserRun {
                assert!(!spec.cancellable, "{}", spec.name);
            }
        }
        for name in [
            "uninstall.run",
            "uninstall.run_user",
            "plan.execute",
            "undo.run",
            "quarantine.purge",
        ] {
            let spec = METHODS.iter().find(|s| s.name == name).unwrap();
            assert!(!spec.cancellable, "{name}");
        }
    }
}
