//! One newline-delimited JSON-RPC 2.0 link (crates/purge-rpc, `frame.rs`), shared by the engine and
//! the broker clients: a writer thread, a reader thread, requests numbered from 1 that may overlap,
//! the notifications of a request routed to it by their `params.request`, `$/cancel`, and the end of
//! the link.
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
//! - A request line is serialised and checked against the server's limit on the caller's thread (an
//!   oversize request is refused at once and the link stays up), then queued for the writer thread:
//!   no caller ever waits on the transport, so a server that stops reading cannot block the UI. A
//!   request the writer had not started when the link ended is answered "not sent".
//! - [`Link::close`] shuts the transport down first (the hook wakes a blocked read or write), then
//!   answers the requests in flight, then runs `closed`; it never waits for the writer.
//!
//! # Threads
//!
//! Both threads are detached; neither is joined, because `close` may run on either of them. The
//! reader ends when the transport ends: the server closes its end, or the `shut_down` hook wakes it.
//! The writer holds only a weak reference to the link and ends once its queue is dropped (by
//! `close`, or with the last [`Link`]) and its current write has returned, which the `shut_down`
//! hook makes happen at once. Each holds its end of the transport, so the transport is released
//! when both have ended.

use std::collections::{HashMap, HashSet};
use std::io::{self, BufReader, Read, Write};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use purge_rpc::error::ErrorObject;
use purge_rpc::frame::{
    FrameError, FrameReader, NotificationLine, RequestId, RequestLine, ServerMessage,
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
    /// Requests queued for the writer that it has not started to write: none of their bytes is in
    /// the transport.
    queued: HashSet<u64>,
    closed: Option<String>,
    next_id: u64,
}

/// A line for the writer thread.
enum Out {
    /// Request `id`'s line, written only while the request is still queued.
    Request { id: u64, line: Vec<u8> },
    /// A notification line (`$/cancel`).
    Notice(Vec<u8>),
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
    /// Wakes the reader and the writer and ends the transport (shuts the pipe down, or closes the
    /// engine's job). Called once, by the first [`Link::close`], before anything else it does.
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
    /// The writer thread's queue; `None` once the link is closed.
    queue: Mutex<Option<Sender<Out>>>,
    state: Mutex<State>,
}

/// The link. Cloning shares it.
#[derive(Clone)]
pub(crate) struct Link {
    inner: Arc<Inner>,
}

impl Link {
    /// A link over `output` (the server's lines in) and `input` (requests out); starts the writer
    /// thread `<name>-writer` and the reader thread `<name>-reader`.
    pub fn new(
        input: Box<dyn Write + Send>,
        output: Box<dyn Read + Send>,
        hooks: Hooks,
        name: &str,
    ) -> io::Result<Link> {
        let (tx, rx) = mpsc::channel();
        let link = Link {
            inner: Arc::new(Inner {
                hooks,
                queue: Mutex::new(Some(tx)),
                state: Mutex::new(State {
                    pending: HashMap::new(),
                    queued: HashSet::new(),
                    closed: None,
                    next_id: 1,
                }),
            }),
        };
        // The writer first: should the reader not start, dropping `link` drops the queue, and the
        // writer ends.
        let weak = Arc::downgrade(&link.inner);
        std::thread::Builder::new()
            .name(format!("{name}-writer"))
            .spawn(move || write_loop(weak, rx, input))?;
        let reader = link.clone();
        std::thread::Builder::new()
            .name(format!("{name}-reader"))
            .spawn(move || reader.read_loop(output))?;
        Ok(link)
    }

    /// Why the link ended; `None` while it is live.
    pub fn closed_reason(&self) -> Option<String> {
        lock(&self.inner.state).closed.clone()
    }

    /// Sends `method` with `params` (`None`: no `params` member) as request `call`. `before_send`
    /// gets the wire id before the line is queued. The answer goes through `handler`. Never waits for
    /// the transport.
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
            state.queued.insert(id);
            id
        };
        before_send(id);
        let line = RequestLine {
            id: RequestId(id),
            method,
            params,
        };
        match self.encode(&line) {
            Ok(line) => self.enqueue(Out::Request { id, line }),
            Err(error) => {
                // Refused before anything was written; the link stays up.
                self.take(id);
                lock(&self.inner.state).queued.remove(&id);
                lock(&entry).end(error);
            }
        }
    }

    /// Cancels request `call`: queues `$/cancel` and ends the call with [`ClientError::Cancelled`].
    /// A call that is not in flight (answered already) is left alone.
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
        // Best effort: the server ignores a cancel of an id it does not know.
        if let Ok(line) = self.encode(&cancel) {
            self.enqueue(Out::Notice(line));
        }
        lock(&entry).end(ClientError::Cancelled);
    }

    /// Ends the link with `reason` (the first reason wins): the transport is shut down, every request
    /// in flight is answered with it (those the writer had not started as "not sent"), then `closed`
    /// runs once. Never waits for a write in progress.
    pub fn close(&self, reason: &str) {
        let (first, reason, pending) = {
            let mut state = lock(&self.inner.state);
            let first = state.closed.is_none();
            if first {
                state.closed = Some(reason.to_owned());
            }
            let reason = state.closed.clone().unwrap_or_default();
            let queued = std::mem::take(&mut state.queued);
            let pending: Vec<_> = state
                .pending
                .drain()
                .map(|(id, p)| (p.entry, queued.contains(&id)))
                .collect();
            (first, reason, pending)
        };
        if first {
            // Before anything else: wakes a write blocked on a server that stopped reading, and the
            // reader.
            (self.inner.hooks.shut_down)();
            // The writer ends once out of its write, and closes our end of the requests.
            lock(&self.inner.queue).take();
        }
        for (entry, not_sent) in pending {
            lock(&entry).end(ClientError::Link {
                reason: reason.clone(),
                not_sent,
            });
        }
        if first {
            (self.inner.hooks.closed)(&reason);
        }
    }

    /// One line, serialised compactly with its newline. A line over the server's limit is refused:
    /// it is not sent, and the link stays up.
    fn encode<T: serde::Serialize>(&self, line: &T) -> Result<Vec<u8>, ClientError> {
        let who = self.inner.hooks.who;
        let limit = self.inner.hooks.out_limit;
        // Compact serde_json output never holds a raw newline: one in a string is escaped.
        let mut bytes = serde_json::to_vec(line).map_err(|e| ClientError::Link {
            reason: format!(
                "Purge could not write its request to {}: {e}",
                who.to_lowercase()
            ),
            not_sent: true,
        })?;
        if bytes.len() > limit {
            return Err(ClientError::Link {
                reason: format!(
                    "Purge's request of {} bytes is over the {limit}-byte limit of {}.",
                    bytes.len(),
                    who.to_lowercase()
                ),
                not_sent: true,
            });
        }
        bytes.push(b'\n');
        Ok(bytes)
    }

    /// Hands a line to the writer. After the link closed there is no writer and nothing to do: the
    /// request was answered by `close`.
    fn enqueue(&self, out: Out) {
        if let Some(queue) = lock(&self.inner.queue).as_ref() {
            let _ = queue.send(out);
        }
    }

    /// The writer is about to write request `id`: false when it must not (cancelled, refused, or the
    /// link ended).
    fn begin_write(&self, id: u64) -> bool {
        let mut state = lock(&self.inner.state);
        state.closed.is_none() && state.queued.remove(&id)
    }

    /// A write failed: the request being written (if any) was not received as a request, and the link
    /// ends (a part of the line may be in the transport, so the stream is no longer framed).
    fn write_failed(&self, id: Option<u64>) {
        let who = self.inner.hooks.who;
        let reason = self
            .closed_reason()
            .unwrap_or_else(|| format!("{who} is not running."));
        if let Some(entry) = id.and_then(|id| self.take(id)) {
            lock(&entry).end(ClientError::Link {
                reason: reason.clone(),
                not_sent: true,
            });
        }
        self.close(&reason);
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

    /// A known error object: the sentence is `data.message` when the kind has one (`runtime`,
    /// `store_integrity`), else `error.message`, else "... reported an error.".
    fn rpc_error(&self, error: &ErrorObject) -> ClientError {
        let data = error
            .data
            .as_ref()
            .and_then(|d| serde_json::to_value(d).ok());
        let message = text(data.as_ref().and_then(|d| d.get("message")))
            .or(Some(error.message.as_str()).filter(|m| !m.is_empty()))
            .map_or_else(|| self.reported(), str::to_owned);
        ClientError::Rpc(RpcError {
            code: error.code,
            kind: error.data.as_ref().map(|d| d.kind().to_owned()),
            message,
            data: error.data.clone(),
        })
    }

    /// An error object that is not one this client knows in full (a newer kind): its code,
    /// `error.message` and `data.kind`, as written (the C# client's lenient read).
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
        let message = text(error.get("message")).map_or_else(|| self.reported(), str::to_owned);
        ClientError::Rpc(RpcError {
            code,
            kind: text(data.and_then(|d| d.get("kind"))).map(str::to_owned),
            message,
            data: None,
        })
    }
}

/// The writer thread: writes each queued line in order until the queue is gone or a write fails.
fn write_loop(link: Weak<Inner>, queue: Receiver<Out>, mut input: Box<dyn Write + Send>) {
    while let Ok(out) = queue.recv() {
        let Some(inner) = link.upgrade() else {
            return;
        };
        let link = Link { inner };
        let (id, line) = match out {
            Out::Request { id, line } => {
                if !link.begin_write(id) {
                    continue;
                }
                (Some(id), line)
            }
            Out::Notice(line) => {
                if link.closed_reason().is_some() {
                    continue;
                }
                (None, line)
            }
        };
        if input.write_all(&line).and_then(|()| input.flush()).is_err() {
            link.write_failed(id);
            return;
        }
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

#[cfg(test)]
mod tests {
    //! The link alone: its size limits, and a writer that blocks (review of UI-CLIENT, S2).

    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::RecvTimeoutError;
    use std::sync::{Condvar, mpsc};
    use std::time::{Duration, Instant};

    use super::*;
    use crate::testing::{LIMIT, MemReader, MemWriter, mem_pipe};

    /// A call whose answer goes to a channel.
    struct TestCall(mpsc::Sender<Result<Value, ClientError>>);

    impl Call for TestCall {
        fn notification(&mut self, _: &str, _: Value) -> bool {
            false
        }

        fn reply(&mut self, result: Result<Value, ClientError>) -> bool {
            let _ = self.0.send(result);
            true
        }

        fn end(&mut self, error: ClientError) {
            let _ = self.0.send(Err(error));
        }
    }

    fn hooks(out_limit: usize, shut_down: Box<dyn Fn() + Send + Sync>) -> Hooks {
        Hooks {
            who: "The engine",
            out_limit,
            shut_down,
            unrouted: Box::new(|_, _| {}),
            closed: Box::new(|_| {}),
            exit_text: Box::new(String::new),
        }
    }

    fn request(link: &Link, params: Option<&Value>) -> mpsc::Receiver<Result<Value, ClientError>> {
        let (tx, rx) = mpsc::channel();
        link.start(
            CallId::next(),
            "engine.hello",
            params,
            Box::new(TestCall(tx)),
            |_| {},
        );
        rx
    }

    /// A link over in-memory pipes: the link, the server's view of the requests, and the server's
    /// output.
    fn mem_link(out_limit: usize) -> (Link, MemReader, MemWriter) {
        let (to_server, from_client) = mem_pipe();
        let (to_client, from_server) = mem_pipe();
        let link = Link::new(
            Box::new(to_server),
            Box::new(from_server),
            hooks(out_limit, Box::new(|| {})),
            "purge-test",
        )
        .unwrap();
        (link, from_client, to_client)
    }

    #[test]
    fn a_request_over_the_servers_limit_is_refused_and_the_link_stays_up() {
        let (link, mut server_in, mut server_out) = mem_link(64);
        let big = Value::String("x".repeat(100));
        let answer = request(&link, Some(&big)).recv_timeout(LIMIT).unwrap();
        let Err(ClientError::Link { reason, not_sent }) = answer else {
            panic!("{answer:?}")
        };
        assert!(not_sent);
        assert!(reason.contains("over the 64-byte limit"), "{reason}");
        assert!(link.closed_reason().is_none());
        // Nothing of it was written: the next line the server reads is the next request.
        let small = request(&link, None);
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        while byte[0] != b'\n' {
            assert_eq!(server_in.read(&mut byte).unwrap(), 1);
            line.push(byte[0]);
        }
        let sent: Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(sent["id"], 2);
        server_out
            .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n")
            .unwrap();
        assert_eq!(small.recv_timeout(LIMIT).unwrap(), Ok(serde_json::json!({})));
    }

    #[test]
    fn a_server_line_over_the_read_limit_ends_the_link() {
        let (link, _server_in, mut server_out) = mem_link(1024);
        let open = request(&link, None);
        let mut line = vec![b' '; OUT_LIMIT + 1];
        line.push(b'\n');
        server_out.write_all(&line).unwrap();
        let Err(ClientError::Link { reason, not_sent }) = open.recv_timeout(LIMIT).unwrap() else {
            panic!()
        };
        assert!(
            reason.starts_with("The engine sent a line that is not JSON-RPC: "),
            "{reason}"
        );
        assert!(!not_sent);
        assert!(link.closed_reason().is_some());
    }

    /// A transport whose writes block until `shut_down` is called, as a server that stopped reading.
    #[derive(Clone, Default)]
    struct Stuck(Arc<(Mutex<bool>, Condvar)>);

    impl Stuck {
        fn shut_down(&self) {
            *lock(&self.0.0) = true;
            self.0.1.notify_all();
        }
    }

    impl Write for Stuck {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            let mut down = lock(&self.0.0);
            while !*down {
                down = self.0.1.wait(down).unwrap_or_else(PoisonError::into_inner);
            }
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn requests_and_close_never_wait_for_a_blocked_write() {
        let stuck = Stuck::default();
        let shut = stuck.clone();
        let shut_down = Arc::new(AtomicBool::new(false));
        let s = shut_down.clone();
        let (_to_client, from_server) = mem_pipe();
        let link = Link::new(
            Box::new(stuck),
            Box::new(from_server),
            hooks(
                1024,
                Box::new(move || {
                    s.store(true, Ordering::SeqCst);
                    shut.shut_down();
                }),
            ),
            "purge-test",
        )
        .unwrap();
        let started = Instant::now();
        let first = request(&link, None);
        // The writer is now inside the first write, which does not return.
        std::thread::sleep(Duration::from_millis(100));
        let second = request(&link, None);
        assert!(started.elapsed() < Duration::from_secs(2), "a request waited");
        assert_eq!(
            first.recv_timeout(Duration::from_millis(100)),
            Err(RecvTimeoutError::Timeout)
        );
        let closing = Instant::now();
        link.close("The engine link was closed.");
        assert!(closing.elapsed() < Duration::from_secs(2), "close waited");
        assert!(shut_down.load(Ordering::SeqCst));
        // The first was being written: what the server got of it is unknown. The second never left
        // the queue.
        let Err(ClientError::Link { not_sent, .. }) = first.recv_timeout(LIMIT).unwrap() else {
            panic!()
        };
        assert!(!not_sent);
        let Err(ClientError::Link { not_sent, .. }) = second.recv_timeout(LIMIT).unwrap() else {
            panic!()
        };
        assert!(not_sent);
    }
}
