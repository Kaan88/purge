//! One newline-delimited JSON-RPC 2.0 link (crates/purge-rpc, `frame.rs`), shared by the engine and
//! the broker clients: a writer, one reader thread, requests numbered from 1 that may overlap, the
//! notifications of a request routed to it by their `params.request`, `$/cancel`, and the end of the
//! link.
//!
//! The rules, as in the C# clients (`StdioEngineClient`, `BrokerRpcClient`):
//!
//! - A request made after the link ended fails at once, marked "not sent". A request whose write
//!   failed is "not sent" too, and the link ends: a part of the line may be in the pipe, so the stream
//!   is no longer framed.
//! - A line the server writes that is not JSON ends the link. A JSON line this client cannot read as
//!   a response or notification of the protocol is read leniently (an error whose `data` is of a newer
//!   kind is still an error and must not end the link), or ignored.
//! - When the link ends, every request in flight gets its answer (the link's error), then the
//!   `closed` callback runs once.
//! - A request is answered exactly once ([`Entry::done`]); its notifications before its answer.

use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use purge_rpc::error::ErrorObject;
use purge_rpc::frame::{
    FrameError, FrameReader, FrameWriter, NotificationLine, RequestId, RequestLine, ServerMessage,
    parse_server_line,
};
use purge_rpc::methods::CancelParams;
use purge_rpc::sets::OUT_LIMIT;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{CallId, ClientError, RpcError};

/// A lock that a panic elsewhere did not make unusable: the data under these locks stays consistent
/// at every await-free step, so a poisoned guard is taken as it is.
pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One request in flight, as the link drives it. Each method is called with the entry locked, at most
/// once after the request is done.
pub(crate) trait Call: Send {
    /// A notification whose `params.request` names this request. True when the request is now done
    /// (it delivered its answer).
    fn notification(&mut self, method: &str, params: Value) -> bool;
    /// The response. True when the request is now done.
    fn reply(&mut self, result: Result<Value, ClientError>) -> bool;
    /// The request ends without (more of) its answer: the link ended, the write failed, or the caller
    /// cancelled. Must deliver the answer.
    fn end(&mut self, error: ClientError);
}

struct Entry {
    call: Box<dyn Call>,
    done: bool,
}

impl Entry {
    fn end(&mut self, error: ClientError) {
        if !self.done {
            self.done = true;
            self.call.end(error);
        }
    }
}

struct Pending {
    call: CallId,
    entry: Arc<Mutex<Entry>>,
}

struct State {
    pending: HashMap<u64, Pending>,
    closed: Option<String>,
    next_id: u64,
}

/// The handler of notifications no request claims.
pub(crate) type Unrouted = Box<dyn Fn(&str, Value) + Send + Sync>;

/// What the two links differ in.
pub(crate) struct Hooks {
    /// "The engine" or "The administrator part": the subject of the link's sentences.
    pub who: &'static str,
    /// The longest request line the server reads (`sets::Transport::in_limit`); a longer request is
    /// refused here before anything is written.
    pub out_limit: usize,
    /// Wakes the reader and ends the transport (closes the pipe, or the engine's job).
    pub shut_down: Box<dyn Fn() + Send + Sync>,
    /// A notification no request in flight claims (no `params.request`, or one already answered).
    pub unrouted: Unrouted,
    /// Once, after the link ended and every request in flight was answered.
    pub closed: Box<dyn Fn(&str) + Send + Sync>,
    /// Text after "ended" in the reason, e.g. ` (exit code 3)`; called on the reader thread.
    pub exit_text: Box<dyn Fn() -> String + Send + Sync>,
}

struct Inner {
    hooks: Hooks,
    writer: Mutex<Option<FrameWriter<Box<dyn Write + Send>>>>,
    state: Mutex<State>,
}

/// The link. Cloning shares it.
#[derive(Clone)]
pub(crate) struct Link {
    inner: Arc<Inner>,
}

impl Link {
    /// A link over `output` (the server's lines in) and `input` (requests out); starts the reader
    /// thread.
    pub fn new(
        input: Box<dyn Write + Send>,
        output: Box<dyn Read + Send>,
        hooks: Hooks,
        thread_name: &str,
    ) -> io::Result<Link> {
        let limit = hooks.out_limit;
        let link = Link {
            inner: Arc::new(Inner {
                hooks,
                writer: Mutex::new(Some(FrameWriter::new(input, limit))),
                state: Mutex::new(State {
                    pending: HashMap::new(),
                    closed: None,
                    next_id: 1,
                }),
            }),
        };
        let reader = link.clone();
        std::thread::Builder::new()
            .name(thread_name.into())
            .spawn(move || reader.read_loop(output))?;
        Ok(link)
    }

    /// Why the link ended; `None` while it is live.
    pub fn closed_reason(&self) -> Option<String> {
        lock(&self.inner.state).closed.clone()
    }

    /// Sends `method` with `params` (`None`: no `params` member) as request `call`. `before_send`
    /// gets the wire id before the line is written. The answer goes through `entry`.
    pub fn start(
        &self,
        call: CallId,
        method: &str,
        params: Option<&Value>,
        handler: Box<dyn Call>,
        before_send: impl FnOnce(u64),
    ) {
        let entry = Arc::new(Mutex::new(Entry {
            call: handler,
            done: false,
        }));
        let id = {
            let mut state = lock(&self.inner.state);
            if let Some(reason) = state.closed.clone() {
                drop(state);
                lock(&entry).end(ClientError::Link {
                    reason,
                    not_sent: true,
                });
                return;
            }
            let id = state.next_id;
            state.next_id += 1;
            state.pending.insert(
                id,
                Pending {
                    call,
                    entry: entry.clone(),
                },
            );
            id
        };
        before_send(id);
        let line = RequestLine {
            id: RequestId(id),
            method,
            params,
        };
        if let Err(error) = self.write(&line) {
            // Never received as a request: no whole line of it reached the server.
            self.take(id);
            lock(&entry).end(error);
        }
    }

    /// Cancels request `call`: sends `$/cancel` and ends the call with [`ClientError::Cancelled`]. A
    /// call that is not in flight (answered already) is left alone.
    pub fn cancel(&self, call: CallId) {
        let found = {
            let mut state = lock(&self.inner.state);
            let id = state
                .pending
                .iter()
                .find(|(_, p)| p.call == call)
                .map(|(&id, _)| id);
            id.and_then(|id| state.pending.remove(&id).map(|p| (id, p.entry)))
        };
        let Some((id, entry)) = found else {
            return;
        };
        let cancel = NotificationLine {
            method: "$/cancel",
            params: &CancelParams {
                request: RequestId(id),
            },
        };
        // A failed write ends the link; the cancel itself is best effort.
        let _ = self.write(&cancel);
        lock(&entry).end(ClientError::Cancelled);
    }

    /// Ends the link with `reason` (the first reason wins): every request in flight is answered with
    /// it, the transport is shut down, then `closed` runs once.
    pub fn close(&self, reason: &str) {
        let (first, pending) = {
            let mut state = lock(&self.inner.state);
            let first = state.closed.is_none();
            if first {
                state.closed = Some(reason.to_owned());
            }
            let reason = state.closed.clone().unwrap_or_default();
            let pending: Vec<_> = state.pending.drain().map(|(_, p)| p.entry).collect();
            ((first, reason), pending)
        };
        let (first, reason) = first;
        for entry in pending {
            lock(&entry).end(ClientError::Link {
                reason: reason.clone(),
                not_sent: false,
            });
        }
        if first {
            // Closing our end of the requests: the engine sees the end of its input.
            lock(&self.inner.writer).take();
            (self.inner.hooks.shut_down)();
            (self.inner.hooks.closed)(&reason);
        }
    }

    fn take(&self, id: u64) -> Option<Arc<Mutex<Entry>>> {
        lock(&self.inner.state).pending.remove(&id).map(|p| p.entry)
    }

    fn get(&self, id: u64) -> Option<Arc<Mutex<Entry>>> {
        lock(&self.inner.state)
            .pending
            .get(&id)
            .map(|p| p.entry.clone())
    }

    /// Removes request `id` once it is done, if `entry` is still the one in the table.
    fn remove_done(&self, id: u64, entry: &Arc<Mutex<Entry>>) {
        let mut state = lock(&self.inner.state);
        if state
            .pending
            .get(&id)
            .is_some_and(|p| Arc::ptr_eq(&p.entry, entry))
        {
            state.pending.remove(&id);
        }
    }

    /// Writes one line. An oversize line writes nothing and leaves the link up; a failed write ends
    /// the link. Either way the request was not sent.
    fn write<T: serde::Serialize>(&self, line: &T) -> Result<(), ClientError> {
        let who = self.inner.hooks.who;
        let not_running = || {
            self.closed_reason()
                .unwrap_or_else(|| format!("{who} is not running."))
        };
        let result = {
            let mut writer = lock(&self.inner.writer);
            match writer.as_mut() {
                None => {
                    return Err(ClientError::Link {
                        reason: not_running(),
                        not_sent: true,
                    });
                }
                Some(w) => w.send(line),
            }
        };
        match result {
            Ok(()) => Ok(()),
            Err(FrameError::OutOversize { len, limit }) => Err(ClientError::Link {
                reason: format!(
                    "Purge's request of {len} bytes is over the {limit}-byte limit of {}.",
                    who.to_lowercase()
                ),
                not_sent: true,
            }),
            Err(_) => {
                let reason = not_running();
                self.close(&reason);
                Err(ClientError::Link {
                    reason: self.closed_reason().unwrap_or(reason),
                    not_sent: true,
                })
            }
        }
    }

    fn read_loop(self, output: Box<dyn Read + Send>) {
        let who = self.inner.hooks.who;
        let mut reader = FrameReader::new(BufReader::with_capacity(64 * 1024, output), OUT_LIMIT);
        let reason = loop {
            match reader.read_line() {
                Ok(Some(line)) => {
                    let line = line.strip_suffix(b"\r").unwrap_or(line);
                    if line.iter().all(u8::is_ascii_whitespace) {
                        continue;
                    }
                    if let Err(e) = self.dispatch(line) {
                        break format!("{who} sent a line that is not JSON-RPC: {e}");
                    }
                }
                Ok(None) | Err(FrameError::Truncated) | Err(FrameError::Io(_)) => {
                    break format!("{who} ended{}.", (self.inner.hooks.exit_text)());
                }
                Err(e) => break format!("{who} sent a line that is not JSON-RPC: {e}"),
            }
        };
        self.close(&reason);
    }

    /// One line from the server. `Err` only for a line that is not JSON, which ends the link.
    fn dispatch(&self, line: &[u8]) -> Result<(), String> {
        match parse_server_line(line) {
            Ok(ServerMessage::Response(response)) => {
                if let Some(RequestId(id)) = response.id {
                    let result = response.body.map_err(|e| self.rpc_error(&e));
                    self.reply(id, result);
                }
                Ok(())
            }
            Ok(ServerMessage::Notification { method, params }) => {
                self.notification(&method, params);
                Ok(())
            }
            Err(_) => {
                let value: Value = serde_json::from_slice(line).map_err(|e| e.to_string())?;
                self.lenient(value);
                Ok(())
            }
        }
    }

    /// A JSON line that is not exactly a message of the protocol: a response with an error of a kind
    /// this client does not know, or extra members. Read what can be read; ignore the rest.
    fn lenient(&self, value: Value) {
        let Value::Object(mut map) = value else {
            return;
        };
        if let Some(id) = map.get("id") {
            let Some(id) = id.as_u64() else {
                return;
            };
            let result = if let Some(error) = map.remove("error") {
                Err(self.lenient_error(&error))
            } else if let Some(result) = map.remove("result") {
                Ok(result)
            } else {
                Err(ClientError::BadReply(
                    "a response has neither result nor error".into(),
                ))
            };
            self.reply(id, result);
            return;
        }
        if let Some(Value::String(method)) = map.remove("method") {
            let params = map.remove("params").unwrap_or(Value::Null);
            self.notification(&method, params);
        }
    }

    fn reply(&self, id: u64, result: Result<Value, ClientError>) {
        let Some(entry) = self.get(id) else {
            return;
        };
        let done = {
            let mut e = lock(&entry);
            if e.done {
                true
            } else {
                let done = e.call.reply(result);
                e.done = done;
                done
            }
        };
        if done {
            self.remove_done(id, &entry);
        }
    }

    fn notification(&self, method: &str, params: Value) {
        let request = params.get("request").and_then(Value::as_u64);
        if let Some(id) = request {
            if let Some(entry) = self.get(id) {
                let mut e = lock(&entry);
                if !e.done {
                    let done = e.call.notification(method, params);
                    e.done = done;
                    drop(e);
                    if done {
                        self.remove_done(id, &entry);
                    }
                    return;
                }
            }
        }
        (self.inner.hooks.unrouted)(method, params);
    }

    /// The default sentence when an error names none.
    fn reported(&self) -> String {
        format!("{} reported an error.", self.inner.hooks.who)
    }

    fn rpc_error(&self, error: &ErrorObject) -> ClientError {
        use purge_rpc::error::ErrorData;
        let data_message = match &error.data {
            Some(ErrorData::Runtime { message } | ErrorData::StoreIntegrity { message }) => {
                Some(message.as_str())
            }
            _ => None,
        };
        let message = data_message
            .filter(|m| !m.is_empty())
            .or(Some(error.message.as_str()).filter(|m| !m.is_empty()))
            .map_or_else(|| self.reported(), str::to_owned);
        ClientError::Rpc(RpcError {
            code: error.code,
            kind: error.data.as_ref().map(|d| d.kind().to_owned()),
            message,
            data: error.data.clone(),
        })
    }

    /// An error object that is not one this client knows in full: its code, message and
    /// `data.kind`, as written.
    fn lenient_error(&self, error: &Value) -> ClientError {
        if let Ok(known) = serde_json::from_value::<ErrorObject>(error.clone()) {
            return self.rpc_error(&known);
        }
        let code = error
            .get("code")
            .and_then(Value::as_i64)
            .and_then(|c| i32::try_from(c).ok())
            .unwrap_or(0);
        let data = error.get("data");
        let message = text(data.and_then(|d| d.get("message")))
            .or(text(error.get("message")))
            .map_or_else(|| self.reported(), str::to_owned);
        ClientError::Rpc(RpcError {
            code,
            kind: text(data.and_then(|d| d.get("kind"))).map(str::to_owned),
            message,
            data: None,
        })
    }
}

/// A non-empty string member.
fn text(v: Option<&Value>) -> Option<&str> {
    v.and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// Reads a result as `T`; a result of another shape is [`ClientError::BadReply`].
pub(crate) fn decode<T: DeserializeOwned>(method: &str, value: Value) -> Result<T, ClientError> {
    let name = std::any::type_name::<T>().rsplit("::").next().unwrap_or("");
    serde_json::from_value(value)
        .map_err(|e| ClientError::BadReply(format!("the {method} result is not a {name}: {e}")))
}
