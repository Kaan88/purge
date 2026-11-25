//! Test helpers: an in-memory byte pipe, the scripted engine (port of `ScriptedEngine.cs`), the event
//! collector, and fixtures.

use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::engine::EngineClient;
use crate::{Answer, CallId, ClientError, ClientEvent, Sink};

/// The write end of an in-memory pipe; dropping it is the end of the stream.
pub struct MemWriter(Sender<Vec<u8>>);

/// The read end of an in-memory pipe.
pub struct MemReader {
    rx: Receiver<Vec<u8>>,
    buf: VecDeque<u8>,
}

/// A one-way in-memory pipe.
pub fn mem_pipe() -> (MemWriter, MemReader) {
    let (tx, rx) = mpsc::channel();
    (
        MemWriter(tx),
        MemReader {
            rx,
            buf: VecDeque::new(),
        },
    )
}

impl Write for MemWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .send(buf.to_vec())
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for MemReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.buf.is_empty() {
            match self.rx.recv() {
                Ok(chunk) => self.buf.extend(chunk),
                Err(_) => return Ok(0),
            }
        }
        let n = out.len().min(self.buf.len());
        for (slot, byte) in out.iter_mut().zip(self.buf.drain(..n)) {
            *slot = byte;
        }
        Ok(n)
    }
}

/// The events of one client, as a test reads them.
pub struct Events {
    rx: Receiver<ClientEvent>,
    /// Events read while looking for another.
    pub seen: Vec<ClientEvent>,
}

/// A sink and its events.
pub fn events() -> (Sink, Events) {
    let (tx, rx) = mpsc::channel();
    (
        Sink::new(tx, Arc::new(|| {})),
        Events {
            rx,
            seen: Vec::new(),
        },
    )
}

pub const LIMIT: Duration = Duration::from_secs(10);

impl Events {
    /// The next event that `pick` accepts, within [`LIMIT`]; others go to `seen`.
    pub fn find<T>(&mut self, mut pick: impl FnMut(&ClientEvent) -> Option<T>) -> T {
        if let Some(at) = self.seen.iter().position(|e| pick(e).is_some()) {
            let e = self.seen.remove(at);
            return pick(&e).unwrap();
        }
        let deadline = Instant::now() + LIMIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let event = self.rx.recv_timeout(left).expect("no such event in time");
            if let Some(v) = pick(&event) {
                return v;
            }
            self.seen.push(event);
        }
    }

    /// The next [`ClientEvent::Startup`]; the events before it go to `seen`.
    pub fn startup(&mut self) -> crate::startup::StartupResult {
        let deadline = Instant::now() + LIMIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left).expect("no startup in time") {
                ClientEvent::Startup(result) => return *result,
                other => self.seen.push(other),
            }
        }
    }

    /// The reply of `call`.
    pub fn reply(&mut self, call: CallId) -> Result<Answer, ClientError> {
        self.find(|e| match e {
            ClientEvent::Reply { call: c, result } if *c == call => Some(result.clone()),
            _ => None,
        })
    }

    /// Whether `call` has a reply within `wait`.
    pub fn replied_within(&mut self, call: CallId, wait: Duration) -> bool {
        let is = |e: &ClientEvent| matches!(e, ClientEvent::Reply { call: c, .. } if *c == call);
        if self.seen.iter().any(is) {
            return true;
        }
        let deadline = Instant::now() + wait;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(e) => {
                    let hit = is(&e);
                    self.seen.push(e);
                    if hit {
                        return true;
                    }
                }
                Err(_) => return false,
            }
        }
    }

    /// Everything that arrives within `wait`, into `seen`.
    pub fn drain_for(&mut self, wait: Duration) {
        let deadline = Instant::now() + wait;
        while let Ok(e) = self
            .rx
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            self.seen.push(e);
        }
    }
}

/// A fixture of `crates/purge-rpc/fixtures`, as one line.
pub fn fixture(name: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../purge-rpc/fixtures")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let value: Value = serde_json::from_str(&text).unwrap();
    value.to_string()
}

/// The `engine.hello` result of the medium engine.
pub fn hello_result() -> String {
    fixture("stdio.engine.hello.result.json")
}

/// The recorded `programs.batch` params with `request` as its request id.
pub fn batch_params(request: u64) -> String {
    let mut v: Value = serde_json::from_str(&fixture("notification.programs.batch.json")).unwrap();
    v["request"] = request.into();
    v.to_string()
}

/// The recorded `programs.patch` params with `request` as its request id.
pub fn patch_params(request: u64) -> String {
    let mut v: Value = serde_json::from_str(&fixture("notification.programs.patch.json")).unwrap();
    v["request"] = request.into();
    v.to_string()
}

pub fn id_of(line: &str) -> u64 {
    serde_json::from_str::<Value>(line).unwrap()["id"]
        .as_u64()
        .unwrap_or(0)
}

pub fn method_of(line: &str) -> String {
    serde_json::from_str::<Value>(line).unwrap()["method"]
        .as_str()
        .unwrap_or("")
        .to_owned()
}

/// The server's half of a scripted link: lines out to the client.
#[derive(Clone)]
pub struct Peer {
    out: Arc<Mutex<Option<Box<dyn Write + Send>>>>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Peer {
    pub fn send(&self, line: &str) {
        if let Some(w) = self.out.lock().unwrap().as_mut() {
            let _ = w.write_all(format!("{line}\n").as_bytes());
            let _ = w.flush();
        }
    }

    /// The server ends: the client's reader sees the end of the stream.
    pub fn end(&self) {
        self.out.lock().unwrap().take();
    }

    /// The request lines so far.
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    /// Waits until `n` request lines arrived.
    pub fn wait_requests(&self, n: usize) -> Vec<String> {
        let deadline = Instant::now() + LIMIT;
        loop {
            let r = self.requests();
            if r.len() >= n || Instant::now() > deadline {
                return r;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A peer that reads lines from `input` on a thread and answers through `on_line`.
    pub fn serve(
        input: impl Read + Send + 'static,
        out: Box<dyn Write + Send>,
        on_line: impl Fn(&str, &Peer) + Send + 'static,
    ) -> Peer {
        let peer = Peer {
            out: Arc::new(Mutex::new(Some(out))),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        let p = peer.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(input).lines() {
                let Ok(line) = line else { break };
                p.requests.lock().unwrap().push(line.clone());
                on_line(&line, &p);
                if p.out.lock().unwrap().is_none() {
                    // Ended: let go of the input too (a pipe server closes its handle).
                    break;
                }
            }
        });
        peer
    }
}

/// An engine played by a test over in-memory pipes.
pub struct ScriptedEngine {
    pub client: Arc<EngineClient>,
    pub peer: Peer,
    pub events: Events,
}

impl ScriptedEngine {
    pub fn new(on_line: impl Fn(&str, &Peer) + Send + 'static) -> ScriptedEngine {
        let (sink, events) = events();
        let (client, peer) = ScriptedEngine::with_sink(on_line, sink);
        ScriptedEngine {
            client,
            peer,
            events,
        }
    }

    /// The client and the peer, delivering to `sink`.
    pub fn with_sink(
        on_line: impl Fn(&str, &Peer) + Send + 'static,
        sink: Sink,
    ) -> (Arc<EngineClient>, Peer) {
        let (to_engine, engine_in) = mem_pipe();
        let (engine_out, from_engine) = mem_pipe();
        let peer = Peer::serve(engine_in, Box::new(engine_out), on_line);
        let client = EngineClient::over(Box::new(to_engine), Box::new(from_engine), sink).unwrap();
        (client, peer)
    }

    /// The healthy engine: answers hello, then `programs.list` with its count and a batch.
    pub fn healthy() -> ScriptedEngine {
        ScriptedEngine::new(healthy)
    }
}

/// The healthy engine's answers.
pub fn healthy(line: &str, peer: &Peer) {
    let id = id_of(line);
    match method_of(line).as_str() {
        "engine.hello" => peer.send(&format!(
            r#"{{"jsonrpc":"2.0","id":{id},"result":{}}}"#,
            hello_result()
        )),
        "programs.list" => {
            peer.send(&format!(
                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"count":1}}}}"#
            ));
            peer.send(&format!(
                r#"{{"jsonrpc":"2.0","method":"programs.batch","params":{}}}"#,
                batch_params(id)
            ));
        }
        "inventory.changes" => peer.send(&format!(
            r#"{{"jsonrpc":"2.0","id":{id},"result":{}}}"#,
            fixture("stdio.inventory.changes.result.json")
        )),
        _ => {}
    }
}
