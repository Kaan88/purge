//! Fakes for the tests of the serving loop (`cfg(test)` only): an in-memory transport, a fake clock and
//! parent, a scripted consent dialog, a fake baseline build and a handler whose requests the test
//! controls.

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use purge_engine::pipeline::Settings;
use purge_model::BaselineTrust;
use purge_rpc::error::{ErrorData, ErrorObject};
use purge_rpc::methods::PipeCall;
use purge_rpc::{BaselineBuild, BaselineStatus, EngineHello};
use purge_win::pipe::ExpectedPeer;
use purge_win::taskdialog::{Outcome, Page};
use serde_json::{Value, json};

use crate::baseline::BuildHandle;
use crate::lifetime::{Clock, Closer, Exit, Parent};
use crate::link::{Link, LinkError, Refusal};
use crate::serve::{Consent, Ctx, Handler, Host, Limits, Wiring, run};

/// A one-shot flag with a wait.
#[derive(Default)]
pub struct Gate {
    open: Mutex<bool>,
    cv: Condvar,
}

impl Gate {
    pub fn open(&self) {
        *self.open.lock().unwrap() = true;
        self.cv.notify_all();
    }

    pub fn is_open(&self) -> bool {
        *self.open.lock().unwrap()
    }

    pub fn wait(&self, timeout: Duration) -> bool {
        let guard = self.open.lock().unwrap();
        let (guard, _) = self
            .cv
            .wait_timeout_while(guard, timeout, |open| !*open)
            .unwrap();
        *guard
    }
}

/// How long a test waits for something that should happen.
pub const SECS: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------------------------------
// The in-memory transport.

#[derive(Default)]
struct ConnInner {
    to_server: VecDeque<u8>,
    from_server: VecDeque<u8>,
    client_closed: bool,
    server_disconnected: bool,
    fail_writes: bool,
}

/// One connection, seen from both ends.
pub struct Conn {
    identity: Result<(), Refusal>,
    inner: Mutex<ConnInner>,
    cv: Condvar,
}

/// The client end of a [`Conn`].
#[derive(Clone)]
pub struct Client(Arc<Conn>);

impl Client {
    pub fn send(&self, text: &str) {
        let mut g = self.0.inner.lock().unwrap();
        g.to_server.extend(text.as_bytes());
        self.0.cv.notify_all();
    }

    pub fn send_line(&self, line: &str) {
        self.send(&format!("{line}\n"));
    }

    pub fn send_bytes(&self, bytes: &[u8]) {
        let mut g = self.0.inner.lock().unwrap();
        g.to_server.extend(bytes);
        self.0.cv.notify_all();
    }

    /// The next line the broker wrote, or `None` after `timeout`.
    pub fn recv(&self, timeout: Duration) -> Option<Value> {
        let deadline = Instant::now() + timeout;
        let mut g = self.0.inner.lock().unwrap();
        loop {
            if let Some(end) = g.from_server.iter().position(|b| *b == b'\n') {
                let line: Vec<u8> = g.from_server.drain(..=end).collect();
                return Some(serde_json::from_slice(&line[..line.len() - 1]).unwrap());
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            g = self.0.cv.wait_timeout(g, left).unwrap().0;
        }
    }

    pub fn reply(&self) -> Value {
        self.recv(SECS).expect("the broker answered")
    }

    /// Asserts nothing is written within a short time.
    pub fn silent(&self) {
        assert_eq!(self.recv(Duration::from_millis(150)), None);
    }

    pub fn close(&self) {
        let mut g = self.0.inner.lock().unwrap();
        g.client_closed = true;
        self.0.cv.notify_all();
    }

    /// Makes every further write of the broker fail, as a broken pipe does.
    pub fn break_writes(&self) {
        self.0.inner.lock().unwrap().fail_writes = true;
    }

    /// Whether the broker disconnected this client.
    pub fn disconnected(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut g = self.0.inner.lock().unwrap();
        while !g.server_disconnected {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            g = self.0.cv.wait_timeout(g, left).unwrap().0;
        }
        true
    }
}

#[derive(Default)]
struct Net {
    queue: Mutex<VecDeque<Arc<Conn>>>,
    cv: Condvar,
}

/// The pipe's name, from which clients connect.
#[derive(Clone, Default)]
pub struct MemNet(Arc<Net>);

impl MemNet {
    /// A client that identifies as `identity`.
    pub fn connect(&self, identity: Result<(), Refusal>) -> Client {
        let conn = Arc::new(Conn {
            identity,
            inner: Mutex::new(ConnInner::default()),
            cv: Condvar::new(),
        });
        self.0.queue.lock().unwrap().push_back(conn.clone());
        self.0.cv.notify_all();
        Client(conn)
    }

    pub fn link(&self) -> MemLink {
        MemLink {
            net: self.clone(),
            current: Mutex::new(None),
        }
    }
}

pub struct MemLink {
    net: MemNet,
    current: Mutex<Option<Arc<Conn>>>,
}

impl MemLink {
    fn conn(&self) -> Result<Arc<Conn>, LinkError> {
        self.current
            .lock()
            .unwrap()
            .clone()
            .ok_or(LinkError::Disconnected)
    }
}

impl Link for MemLink {
    fn wait_for_client(&mut self, timeout: Duration) -> Result<bool, LinkError> {
        let mut queue = self.net.0.queue.lock().unwrap();
        if queue.is_empty() {
            queue = self.net.0.cv.wait_timeout(queue, timeout).unwrap().0;
        }
        let Some(conn) = queue.pop_front() else {
            return Ok(false);
        };
        {
            let g = conn.inner.lock().unwrap();
            if g.client_closed && g.to_server.is_empty() {
                return Err(LinkError::Disconnected);
            }
        }
        *self.current.lock().unwrap() = Some(conn);
        Ok(true)
    }

    fn identify(&self, _expected: &ExpectedPeer) -> Result<(), Refusal> {
        self.conn().map_err(|_| Refusal::Gone)?.identity.clone()
    }

    fn read(&self, buf: &mut [u8], timeout: Duration) -> Result<usize, LinkError> {
        let conn = self.conn()?;
        let deadline = Instant::now() + timeout;
        let mut g = conn.inner.lock().unwrap();
        loop {
            if g.server_disconnected {
                return Err(LinkError::Disconnected);
            }
            if !g.to_server.is_empty() {
                let n = buf.len().min(g.to_server.len());
                for slot in buf.iter_mut().take(n) {
                    *slot = g.to_server.pop_front().unwrap();
                }
                return Ok(n);
            }
            if g.client_closed {
                return Ok(0);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(LinkError::TimedOut);
            }
            g = conn.cv.wait_timeout(g, left).unwrap().0;
        }
    }

    fn write_all(&self, buf: &[u8], _timeout: Duration) -> Result<(), LinkError> {
        let conn = self.conn()?;
        let mut g = conn.inner.lock().unwrap();
        if g.client_closed || g.fail_writes || g.server_disconnected {
            return Err(LinkError::Disconnected);
        }
        g.from_server.extend(buf);
        conn.cv.notify_all();
        Ok(())
    }

    fn disconnect(&mut self) {
        if let Some(conn) = self.current.lock().unwrap().take() {
            conn.inner.lock().unwrap().server_disconnected = true;
            conn.cv.notify_all();
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Clock, parent, host, build.

#[derive(Default)]
pub struct FakeClock(AtomicU64);

impl FakeClock {
    pub fn advance(&self, by: Duration) {
        self.0.fetch_add(by.as_millis() as u64, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.0.load(Ordering::SeqCst))
    }
}

#[derive(Default)]
pub struct FakeParent(AtomicBool);

impl FakeParent {
    pub fn exit(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

impl Parent for FakeParent {
    fn exited(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

pub struct FakeHost;

impl Host for FakeHost {
    fn hello(&self) -> EngineHello {
        EngineHello {
            version: "0.0.0-test".into(),
            elevated: true,
            user_sid: ME.into(),
            shell_sid: None,
            edition: "Professional".into(),
            build: 26100,
            ubr: 1,
            policy_version: "test".into(),
            baseline: BaselineStatus {
                baseline_available: false,
                baseline_trust: BaselineTrust::None,
                baseline_view: None,
                baseline_build: BaselineBuild::None {
                    reason: "fake host".into(),
                },
            },
        }
    }
}

pub struct FakeBuild {
    state: Mutex<BaselineBuild>,
    pub stopped: AtomicBool,
}

impl FakeBuild {
    pub fn new(state: BaselineBuild) -> Arc<FakeBuild> {
        Arc::new(FakeBuild {
            state: Mutex::new(state),
            stopped: AtomicBool::new(false),
        })
    }

    pub fn set(&self, state: BaselineBuild) {
        *self.state.lock().unwrap() = state;
    }
}

impl BuildHandle for FakeBuild {
    fn state(&self) -> BaselineBuild {
        self.state.lock().unwrap().clone()
    }

    fn request_stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.set(BaselineBuild::Failed {
            reason: "stopped".into(),
        });
    }
}

// ---------------------------------------------------------------------------------------------------
// Consent.

#[derive(Default)]
struct ConsentState {
    open: bool,
    answer: Option<Outcome>,
    closed_by_broker: bool,
    pages: Vec<Page>,
}

/// A consent dialog the test answers (`cfg(test)` only).
#[derive(Default)]
pub struct ScriptedConsent {
    state: Mutex<ConsentState>,
    cv: Condvar,
}

impl ScriptedConsent {
    pub fn wait_open(&self, timeout: Duration) -> bool {
        let g = self.state.lock().unwrap();
        let (g, _) = self.cv.wait_timeout_while(g, timeout, |s| !s.open).unwrap();
        g.open
    }

    pub fn answer(&self, outcome: Outcome) {
        self.state.lock().unwrap().answer = Some(outcome);
        self.cv.notify_all();
    }

    pub fn closed_by_broker(&self) -> bool {
        self.state.lock().unwrap().closed_by_broker
    }

    pub fn pages(&self) -> Vec<Page> {
        self.state.lock().unwrap().pages.clone()
    }
}

impl Consent for Arc<ScriptedConsent> {
    fn ask(&self, pages: &[Page], _primary: i32, closer: &Closer) -> io::Result<Outcome> {
        {
            let mut g = self.state.lock().unwrap();
            g.open = true;
            g.answer = None;
            g.pages = pages.to_vec();
            self.cv.notify_all();
        }
        let this = self.clone();
        closer.arm(move || {
            let mut g = this.state.lock().unwrap();
            g.closed_by_broker = true;
            g.answer = Some(Outcome::Declined);
            this.cv.notify_all();
        });
        let g = self.state.lock().unwrap();
        let (mut g, _) = self
            .cv
            .wait_timeout_while(g, SECS, |s| s.answer.is_none())
            .unwrap();
        g.open = false;
        let outcome = g.answer.take().unwrap_or(Outcome::Declined);
        drop(g);
        closer.disarm();
        Ok(outcome)
    }
}

// ---------------------------------------------------------------------------------------------------
// The handler.

/// What the test handler records and waits for.
#[derive(Default)]
pub struct Probe {
    /// `uninstall.run` waits for this.
    pub run_gate: Gate,
    pub run_started: Gate,
    pub run_finished: Gate,
    /// `leftovers.scan` started, saw `cancelled()`.
    pub scan_started: Gate,
    pub scan_saw_cancel: Gate,
    /// `leftovers.stored` ran (the handler was reached).
    pub stored_calls: AtomicU64,
    /// What `plan.execute` got from the consent dialog.
    pub consent_outcome: Mutex<Option<Outcome>>,
    /// `journal.pending` ignores `cancelled()` and waits for this (a read that does not cooperate).
    pub stubborn_gate: Gate,
    pub stubborn_started: Gate,
    /// Whether a notification sent from a request after the client was lost failed.
    pub notify_failed: AtomicBool,
}

/// A handler for the test table of methods.
#[derive(Clone)]
pub struct TestHandler(pub Arc<Probe>);

pub fn id_text(prefix: &str, n: u64) -> String {
    format!("{prefix}-{n:016x}")
}

impl Handler for TestHandler {
    type Session = String;
    type Scan = String;
    type Plan = String;

    fn call(&self, ctx: &Ctx<'_, Self>, call: PipeCall) -> Result<Value, ErrorObject> {
        let p = &self.0;
        match call {
            PipeCall::UninstallPrepare(_) => {
                let id = ctx.tables().sessions.insert("session".into())?;
                Ok(json!({ "session_id": id.to_string() }))
            }
            PipeCall::UninstallRun(_) => {
                p.run_started.open();
                p.run_gate.wait(SECS);
                if ctx
                    .notify(&purge_rpc::methods::ServerNotification::UninstallProgress(
                        purge_rpc::methods::Progress {
                            request: ctx.request(),
                            program_id: None,
                            phase: "working".into(),
                            done: 1,
                            total: None,
                        },
                    ))
                    .is_err()
                {
                    p.notify_failed.store(true, Ordering::SeqCst);
                }
                p.run_finished.open();
                Ok(json!({ "outcome": "complete" }))
            }
            PipeCall::UninstallObserved(_) => Ok(json!({})),
            PipeCall::LeftoversScan(_) => {
                p.scan_started.open();
                let start = Instant::now();
                while !ctx.cancelled() && start.elapsed() < SECS {
                    std::thread::sleep(Duration::from_millis(2));
                }
                if ctx.cancelled() {
                    p.scan_saw_cancel.open();
                }
                let id = ctx.add_scan("scan".into())?;
                Ok(json!({ "scan_id": id.to_string() }))
            }
            PipeCall::LeftoversStored(_) => {
                p.stored_calls.fetch_add(1, Ordering::SeqCst);
                Ok(json!({}))
            }
            PipeCall::ScanCandidates(c) => {
                let scan = ctx.tables().scans.get(c.scan_id)?;
                Ok(json!({ "scan": scan.scan }))
            }
            PipeCall::PlanCreate(_) => {
                let id = ctx.tables().plans.insert("plan".into())?;
                Ok(json!({ "plan_id": id.to_string() }))
            }
            PipeCall::PlanExecute(e) => {
                let _plan = ctx.tables().plans.take(e.plan_id)?;
                let outcome = ctx.consent(&[Page::default()], 100);
                *p.consent_outcome.lock().unwrap() = Some(outcome);
                match outcome {
                    Outcome::Approved => {
                        if let Some(id) = ctx.tables().sessions.ids().first() {
                            ctx.tables().sessions.remove(*id);
                        }
                        Ok(json!({ "outcome": "complete" }))
                    }
                    Outcome::Declined => Err(ErrorObject::server(ErrorData::ConsentDeclined)),
                }
            }
            PipeCall::QuarantinePurge(_) => Ok(json!({ "purged": 0, "kept": 0 })),
            PipeCall::JournalPending(_) => {
                p.stubborn_started.open();
                p.stubborn_gate.wait(SECS);
                Ok(json!({ "sessions": [] }))
            }
            other => Err(ErrorObject::runtime(format!("{other:?} is not scripted"))),
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// The harness.

/// The checked account of the harness.
pub const ME: &str = "S-1-5-21-1-2-3-1001";

pub fn expected() -> ExpectedPeer {
    ExpectedPeer {
        pid: 4242,
        creation_time: 7,
        image: r"C:\Program Files\Purge\Purge.exe".into(),
        user_sid: ME.into(),
    }
}

/// Limits for tests: a short real tick; every other limit is the design's and runs on the fake clock.
pub fn test_limits() -> Limits {
    Limits {
        tick: Duration::from_millis(5),
        build_grace: Duration::from_millis(100),
        ..Limits::design()
    }
}

pub const HELLO: &str = r#"{"jsonrpc":"2.0","id":1,"method":"engine.hello"}"#;

/// One broker running in a thread over the in-memory transport.
pub struct Harness {
    pub net: MemNet,
    pub clock: Arc<FakeClock>,
    pub parent: Arc<FakeParent>,
    pub build: Arc<FakeBuild>,
    pub consent: Arc<ScriptedConsent>,
    pub probe: Arc<Probe>,
    join: Option<JoinHandle<Exit>>,
}

impl Harness {
    pub fn start() -> Harness {
        Harness::start_with(test_limits())
    }

    pub fn start_with(limits: Limits) -> Harness {
        let net = MemNet::default();
        let clock = Arc::new(FakeClock::default());
        let parent = Arc::new(FakeParent::default());
        let build = FakeBuild::new(BaselineBuild::None {
            reason: "test".into(),
        });
        let consent = Arc::new(ScriptedConsent::default());
        let probe = Arc::new(Probe::default());
        let wiring = Wiring {
            link: net.link(),
            handler: TestHandler(probe.clone()),
            expected: expected(),
            parent: parent.clone(),
            consent: Arc::new(consent.clone()),
            host: Arc::new(FakeHost),
            clock: clock.clone(),
            build: Some(build.clone() as Arc<dyn BuildHandle>),
            settings: Settings::default(),
            limits,
        };
        let join = std::thread::spawn(move || run(wiring));
        Harness {
            net,
            clock,
            parent,
            build,
            consent,
            probe,
            join: Some(join),
        }
    }

    /// Connects an identified client and completes the hello.
    pub fn client(&self) -> Client {
        let c = self.net.connect(Ok(()));
        c.send_line(HELLO);
        let hello = c.reply();
        assert_eq!(hello["id"], 1, "{hello}");
        assert_eq!(hello["result"]["elevated"], true, "{hello}");
        c
    }

    /// Moves the fake clock on after a moment in which the broker's loop settles: it reads the clock
    /// when it handles an event, so an advance made at once could be taken as the time of that event.
    pub fn advance(&self, by: Duration) {
        std::thread::sleep(Duration::from_millis(80));
        self.clock.advance(by);
    }

    /// The broker's end, within `timeout`.
    pub fn exit(&mut self, timeout: Duration) -> Exit {
        let join = self.join.take().expect("the broker was running");
        let deadline = Instant::now() + timeout;
        while !join.is_finished() {
            assert!(Instant::now() < deadline, "the broker did not end");
            std::thread::sleep(Duration::from_millis(2));
        }
        join.join().unwrap()
    }

    /// Whether the broker has ended.
    pub fn ended(&self) -> bool {
        self.join.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Waits a moment and says the broker is still running.
    pub fn still_running(&self) -> bool {
        std::thread::sleep(Duration::from_millis(100));
        !self.ended()
    }
}

/// A request line.
pub fn request(id: u64, method: &str, params: &Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string()
}

pub fn kind(reply: &Value) -> &str {
    reply["error"]["data"]["kind"]
        .as_str()
        .unwrap_or_else(|| panic!("no error kind in {reply}"))
}
