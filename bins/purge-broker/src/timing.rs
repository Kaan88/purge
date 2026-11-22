//! The broker's timing records (M3 design 9.1, gate G12; the wire types are `purge_rpc::timing`).
//!
//! | Mark | Taken | Where |
//! |---|---|---|
//! | `broker_start` | `main` passed the DLL-search and working-directory restriction | `main.rs` |
//! | `pipe_connected` | the client passed the pipe checks and its `engine.hello` was answered | `serve::accept` |
//! | `harvest_start`, `harvest_complete` | entry of `uninstall.prepare`; its result is built (every program harvested, fingerprints stored, sessions open) | `uninstall::prepare` |
//! | `scan_start`, `scan_complete` | entry of `leftovers.scan`; the scan is built and counted | `scan::handle` |
//! | `first_progress` | the request's first `*.progress` line was written to the pipe (after the write returned) | `serve::Ctx::notify` |
//! | `plan_ready` | `plan.create` froze the plan | `plan::create` |
//! | `consent_shown`, `consent_answered` | the request's first consent dialog is up; it ended | `serve::Ctx::consent` |
//! | `execute_start`, `execute_complete` | the approved plan goes to the executor; the executor returned a run | `execute::execute_plan` |
//!
//! Each mark is taken once per request (a request mark) or once per process (`broker_start`,
//! `pipe_connected`). Its `ms` counts from the broker process's creation (`GetProcessTimes`): the
//! offset to the creation time is read once from the wall clock when the [`ProcessTimer`] is made, and
//! every reading after that adds [`Instant`] time, so the marks of one process never go back. Its
//! `wall_unix_ms` is the wall clock at the mark, for lining marks up with other machines' records.
//!
//! **Nothing depends on a mark.** A clock that cannot be read, a timer that panics, a sink that
//! fails: the mark is left out and the request goes on as if there were no timing at all. A request
//! with no marks answers without the `timings` member.
//!
//! **Where marks go.** Into the request's [`RequestMarks`] (the `timings` member of the four timed
//! results, [`Timings::result_timings`]) and, once a sink is attached, to the sink one line each. The
//! binary attaches a [`ChannelSink`] that writes each line to the Application event log (source `Purge`,
//! id `purge_rpc::timing::TIMING_EVENT_ID`, information) on a thread of its own, so a slow event log
//! never holds a request; `main` flushes it for at most [`FLUSH_WAIT`] before the process ends.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use purge_rpc::frame::RequestId;
use purge_rpc::timing::{TIMING_LINE_KIND, TimingLine, TimingMark, TimingName, Timings as Wire};

/// How long `main` waits at the end for the sink to write what it was given.
pub const FLUSH_WAIT: Duration = Duration::from_secs(1);
/// Lines the sink holds before it drops new ones (it never blocks a request).
pub const SINK_QUEUE: usize = 256;
/// Milliseconds between 1601-01-01 and 1970-01-01.
const UNIX_EPOCH_FILETIME_MS: u64 = 11_644_473_600_000;

/// One reading of the clocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// Milliseconds since the process was created, monotonic.
    pub ms: u64,
    /// The wall clock, milliseconds since the Unix epoch.
    pub wall_unix_ms: u64,
}

/// The clocks the marks read; the binary's is [`ProcessTimer`].
pub trait Timer: Send + Sync + 'static {
    /// The time now, or `None` when a clock cannot be read (the mark is then left out).
    fn now(&self) -> Option<Stamp>;
    /// When the process was created, milliseconds since the Unix epoch, when known.
    fn process_created_unix_ms(&self) -> Option<u64>;
}

/// The wall clock in milliseconds since the Unix epoch.
fn wall_unix_ms() -> Option<u64> {
    let since = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    u64::try_from(since.as_millis()).ok()
}

/// A `FILETIME` value (100 ns since 1601) in milliseconds since the Unix epoch.
pub fn filetime_to_unix_ms(filetime: u64) -> Option<u64> {
    (filetime / 10_000).checked_sub(UNIX_EPOCH_FILETIME_MS)
}

/// [`Instant`] time anchored at the process creation time.
#[derive(Debug)]
pub struct ProcessTimer {
    origin: Instant,
    /// Milliseconds from the process creation to `origin`.
    origin_ms: u64,
    created_unix_ms: Option<u64>,
}

impl ProcessTimer {
    /// A timer whose `ms` counts from `created_filetime`, the process creation time (`FILETIME`).
    /// Without it, or when the wall clock cannot be read now, the marks count from this call and
    /// [`Timer::process_created_unix_ms`] is `None`.
    pub fn new(created_filetime: Option<u64>) -> ProcessTimer {
        let origin = Instant::now();
        let anchored = created_filetime
            .and_then(filetime_to_unix_ms)
            .zip(wall_unix_ms())
            .map(|(created, now)| (created, now.saturating_sub(created)));
        ProcessTimer {
            origin,
            origin_ms: anchored.map_or(0, |(_, offset)| offset),
            created_unix_ms: anchored.map(|(created, _)| created),
        }
    }

    /// The timer of this process: [`ProcessTimer::new`] with its creation time, when it can be read.
    pub fn of_this_process() -> ProcessTimer {
        let created = purge_win::process::ProcessHandle::current()
            .and_then(|p| p.creation_time())
            .ok();
        ProcessTimer::new(created)
    }
}

impl Timer for ProcessTimer {
    fn now(&self) -> Option<Stamp> {
        let elapsed = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        Some(Stamp {
            ms: self.origin_ms.saturating_add(elapsed),
            wall_unix_ms: wall_unix_ms()?,
        })
    }

    fn process_created_unix_ms(&self) -> Option<u64> {
        self.created_unix_ms
    }
}

/// Where the lines of the marks go once attached ([`Timings::attach`]).
pub trait TimingSink: Send + Sync + 'static {
    /// Takes one line. Must not block for long: it runs on the request's thread.
    fn record(&self, line: TimingLine);
    /// Waits up to `wait` for the lines taken so far to be written.
    fn flush(&self, _wait: Duration) {}
}

/// The marks of one request.
#[derive(Debug)]
pub struct RequestMarks {
    request: RequestId,
    method: &'static str,
    marks: Mutex<Vec<TimingMark>>,
}

impl RequestMarks {
    /// No marks yet for `request` of `method`.
    pub fn new(request: RequestId, method: &'static str) -> RequestMarks {
        RequestMarks {
            request,
            method,
            marks: Mutex::new(Vec::new()),
        }
    }

    /// The marks taken, in order.
    pub fn marks(&self) -> Vec<TimingMark> {
        self.marks.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// The broker's recorder: the timer, the process marks and the sink.
pub struct Timings {
    timer: Box<dyn Timer>,
    pid: u32,
    process: Mutex<Vec<TimingMark>>,
    sink: OnceLock<Arc<dyn TimingSink>>,
}

impl std::fmt::Debug for Timings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Timings")
            .field("pid", &self.pid)
            .field("process", &self.process)
            .finish_non_exhaustive()
    }
}

impl Default for Timings {
    /// A recorder over a [`ProcessTimer`] that counts from now, with no sink.
    fn default() -> Self {
        Timings::new(ProcessTimer::new(None), std::process::id())
    }
}

impl Timings {
    /// A recorder over `timer`; `pid` goes on every sink line.
    pub fn new(timer: impl Timer, pid: u32) -> Timings {
        Timings {
            timer: Box::new(timer),
            pid,
            process: Mutex::new(Vec::new()),
            sink: OnceLock::new(),
        }
    }

    /// Reads the timer; a panic or a clock that cannot be read is `None`.
    fn stamp(&self, mark: TimingName) -> Option<TimingMark> {
        let stamp = catch_unwind(AssertUnwindSafe(|| self.timer.now())).ok()??;
        Some(TimingMark {
            mark,
            ms: stamp.ms,
            wall_unix_ms: stamp.wall_unix_ms,
        })
    }

    fn created(&self) -> Option<u64> {
        catch_unwind(AssertUnwindSafe(|| self.timer.process_created_unix_ms()))
            .ok()
            .flatten()
    }

    fn emit(&self, mark: TimingMark, request: Option<&RequestMarks>) {
        let Some(sink) = self.sink.get() else {
            return;
        };
        let line = TimingLine {
            kind: TIMING_LINE_KIND.to_owned(),
            pid: self.pid,
            process_created_unix_ms: self.created(),
            request: request.map(|r| r.request),
            method: request.map(|r| r.method.to_owned()),
            mark,
        };
        let _ = catch_unwind(AssertUnwindSafe(|| sink.record(line)));
    }

    /// Takes a process mark (once: a second one of the same name is ignored).
    pub fn mark_process(&self, name: TimingName) {
        let taken = {
            let mut marks = self.process.lock().unwrap_or_else(|e| e.into_inner());
            if marks.iter().any(|m| m.mark == name) {
                return;
            }
            let Some(mark) = self.stamp(name) else {
                return;
            };
            marks.push(mark);
            mark
        };
        self.emit(taken, None);
    }

    /// Takes a mark of `request` (once: a second one of the same name is ignored).
    pub fn mark_request(&self, request: &RequestMarks, name: TimingName) {
        let taken = {
            let mut marks = request.marks.lock().unwrap_or_else(|e| e.into_inner());
            if marks.iter().any(|m| m.mark == name) {
                return;
            }
            let Some(mark) = self.stamp(name) else {
                return;
            };
            marks.push(mark);
            mark
        };
        self.emit(taken, Some(request));
    }

    /// The `timings` member of a result: the process marks, then the request's. `None` when there is
    /// no mark at all.
    pub fn result_timings(&self, request: &RequestMarks) -> Option<Wire> {
        let mut marks = self
            .process
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        marks.extend(request.marks());
        if marks.is_empty() {
            return None;
        }
        Some(Wire {
            process_created_unix_ms: self.created(),
            marks,
        })
    }

    /// The process marks taken so far.
    pub fn process_marks(&self) -> Vec<TimingMark> {
        self.process
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Sends every later mark to `sink`, and the process marks taken so far at once. Called once,
    /// before any request runs; a second sink is ignored.
    pub fn attach(&self, sink: Arc<dyn TimingSink>) {
        if self.sink.set(sink).is_err() {
            return;
        }
        for mark in self.process_marks() {
            self.emit(mark, None);
        }
    }

    /// Waits up to `wait` for the sink to write what it was given.
    pub fn flush(&self, wait: Duration) {
        if let Some(sink) = self.sink.get() {
            let _ = catch_unwind(AssertUnwindSafe(|| sink.flush(wait)));
        }
    }
}

enum Job {
    Line(TimingLine),
    Flush(SyncSender<()>),
}

/// A sink that hands each line, as one JSON object, to `write` on a thread of its own. A full queue
/// drops the line; a line that cannot be serialised is dropped.
pub struct ChannelSink {
    jobs: SyncSender<Job>,
}

impl ChannelSink {
    /// Starts the writer thread. `None` when the thread cannot start (then there is no sink).
    pub fn start(write: impl Fn(&str) + Send + 'static) -> Option<Arc<ChannelSink>> {
        let (jobs, rx) = sync_channel::<Job>(SINK_QUEUE);
        std::thread::Builder::new()
            .name("purge-broker-timing".into())
            .spawn(move || write_lines(&rx, &write))
            .ok()?;
        Some(Arc::new(ChannelSink { jobs }))
    }
}

fn write_lines(rx: &Receiver<Job>, write: &dyn Fn(&str)) {
    while let Ok(job) = rx.recv() {
        match job {
            Job::Line(line) => {
                if let Ok(text) = serde_json::to_string(&line) {
                    let _ = catch_unwind(AssertUnwindSafe(|| write(&text)));
                }
            }
            Job::Flush(done) => {
                let _ = done.send(());
            }
        }
    }
}

impl TimingSink for ChannelSink {
    fn record(&self, line: TimingLine) {
        // A full queue or a writer that ended drops the line: a request never waits for the log.
        let _ = self.jobs.try_send(Job::Line(line));
    }

    fn flush(&self, wait: Duration) {
        let (done, rx) = sync_channel(1);
        let deadline = Instant::now() + wait;
        // The queue may be full: retry the hand-over until the deadline rather than block on it.
        let mut job = Job::Flush(done);
        loop {
            match self.jobs.try_send(job) {
                Ok(()) => break,
                Err(TrySendError::Disconnected(_)) => return,
                Err(TrySendError::Full(back)) => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    job = back;
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }
        let _ = rx.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A timer that steps one millisecond per reading, and fails or panics when told to.
    #[derive(Debug, Default)]
    pub(crate) struct Steps {
        ms: std::sync::atomic::AtomicU64,
        pub(crate) fail: std::sync::atomic::AtomicBool,
        pub(crate) panic: std::sync::atomic::AtomicBool,
    }

    impl Timer for Arc<Steps> {
        fn now(&self) -> Option<Stamp> {
            use std::sync::atomic::Ordering::SeqCst;
            assert!(!self.panic.load(SeqCst), "the timer panics");
            if self.fail.load(SeqCst) {
                return None;
            }
            let ms = self.ms.fetch_add(1, SeqCst);
            Some(Stamp {
                ms,
                wall_unix_ms: 1_000 + ms,
            })
        }

        fn process_created_unix_ms(&self) -> Option<u64> {
            assert!(!self.panic.load(std::sync::atomic::Ordering::SeqCst));
            Some(1_000)
        }
    }

    #[derive(Default)]
    struct Collect(Mutex<Vec<TimingLine>>);

    impl TimingSink for Collect {
        fn record(&self, line: TimingLine) {
            self.0.lock().unwrap().push(line);
        }
    }

    #[test]
    fn the_filetime_of_the_unix_epoch_is_zero_and_earlier_is_none() {
        assert_eq!(filetime_to_unix_ms(116_444_736_000_000_000), Some(0));
        assert_eq!(
            filetime_to_unix_ms(116_444_736_000_000_000 + 12_340_000),
            Some(1_234)
        );
        assert_eq!(filetime_to_unix_ms(1), None);
    }

    #[test]
    fn the_process_timer_counts_from_the_creation_and_never_goes_back() {
        let now = wall_unix_ms().unwrap();
        // Created 5 s ago, in FILETIME.
        let created = (now - 5_000 + UNIX_EPOCH_FILETIME_MS) * 10_000;
        let timer = ProcessTimer::new(Some(created));
        assert_eq!(timer.process_created_unix_ms(), Some(now - 5_000));
        let first = timer.now().unwrap();
        assert!((5_000..6_000).contains(&first.ms), "{first:?}");
        let mut last = first.ms;
        for _ in 0..200 {
            let next = timer.now().unwrap().ms;
            assert!(next >= last);
            last = next;
        }
        // No creation time: the marks count from the timer's start.
        let bare = ProcessTimer::new(None);
        assert_eq!(bare.process_created_unix_ms(), None);
        assert!(bare.now().unwrap().ms < 1_000);
        // A creation time in the future (a clock set back) counts from zero, not from a wrap.
        let ahead = ProcessTimer::new(Some((now + 60_000 + UNIX_EPOCH_FILETIME_MS) * 10_000));
        assert!(ahead.now().unwrap().ms < 1_000);
    }

    #[test]
    fn marks_are_taken_once_in_order_and_the_result_puts_the_process_first() {
        let steps = Arc::new(Steps::default());
        let timings = Timings::new(steps.clone(), 7);
        let sink = Arc::new(Collect::default());
        timings.mark_process(TimingName::BrokerStart);
        timings.attach(sink.clone());
        timings.mark_process(TimingName::PipeConnected);
        timings.mark_process(TimingName::PipeConnected);
        let request = RequestMarks::new(RequestId(4), "leftovers.scan");
        timings.mark_request(&request, TimingName::ScanStart);
        timings.mark_request(&request, TimingName::FirstProgress);
        timings.mark_request(&request, TimingName::FirstProgress);
        timings.mark_request(&request, TimingName::ScanComplete);

        let wire = timings.result_timings(&request).unwrap();
        assert_eq!(wire.process_created_unix_ms, Some(1_000));
        let names: Vec<TimingName> = wire.marks.iter().map(|m| m.mark).collect();
        assert_eq!(
            names,
            [
                TimingName::BrokerStart,
                TimingName::PipeConnected,
                TimingName::ScanStart,
                TimingName::FirstProgress,
                TimingName::ScanComplete
            ]
        );
        assert!(wire.marks.windows(2).all(|w| w[0].ms <= w[1].ms));

        // The sink got the process mark taken before it was attached, then every later one, once.
        let lines = sink.0.lock().unwrap().clone();
        let got: Vec<(TimingName, Option<u64>)> = lines
            .iter()
            .map(|l| (l.mark.mark, l.request.map(|r| r.0)))
            .collect();
        assert_eq!(
            got,
            [
                (TimingName::BrokerStart, None),
                (TimingName::PipeConnected, None),
                (TimingName::ScanStart, Some(4)),
                (TimingName::FirstProgress, Some(4)),
                (TimingName::ScanComplete, Some(4)),
            ]
        );
        assert!(
            lines
                .iter()
                .all(|l| l.pid == 7 && l.kind == TIMING_LINE_KIND)
        );
        assert_eq!(lines[2].method.as_deref(), Some("leftovers.scan"));
    }

    #[test]
    fn a_failing_or_panicking_timer_leaves_marks_out_and_nothing_else() {
        use std::sync::atomic::Ordering::SeqCst;
        let steps = Arc::new(Steps::default());
        let timings = Timings::new(steps.clone(), 7);
        let request = RequestMarks::new(RequestId(2), "uninstall.prepare");
        steps.fail.store(true, SeqCst);
        timings.mark_process(TimingName::BrokerStart);
        timings.mark_request(&request, TimingName::HarvestStart);
        assert_eq!(timings.result_timings(&request), None);
        steps.fail.store(false, SeqCst);
        steps.panic.store(true, SeqCst);
        timings.mark_request(&request, TimingName::HarvestStart);
        assert_eq!(timings.result_timings(&request), None);
        steps.panic.store(false, SeqCst);
        // The clock works again: the mark that failed can still be taken.
        timings.mark_request(&request, TimingName::HarvestStart);
        assert_eq!(timings.result_timings(&request).unwrap().marks.len(), 1);
    }

    #[test]
    fn a_panicking_sink_does_not_reach_the_caller() {
        struct Boom;
        impl TimingSink for Boom {
            fn record(&self, _: TimingLine) {
                panic!("the sink fails");
            }
            fn flush(&self, _: Duration) {
                panic!("the sink fails");
            }
        }
        let timings = Timings::new(Arc::new(Steps::default()), 7);
        timings.attach(Arc::new(Boom));
        let request = RequestMarks::new(RequestId(2), "plan.create");
        timings.mark_request(&request, TimingName::PlanReady);
        timings.flush(Duration::from_millis(10));
        assert_eq!(timings.result_timings(&request).unwrap().marks.len(), 1);
    }

    #[test]
    fn the_channel_sink_writes_json_lines_in_order_and_flushes() {
        let written = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = {
            let written = written.clone();
            ChannelSink::start(move |line| written.lock().unwrap().push(line.to_owned())).unwrap()
        };
        let timings = Timings::new(Arc::new(Steps::default()), 9);
        timings.mark_process(TimingName::BrokerStart);
        timings.attach(sink);
        let request = RequestMarks::new(RequestId(6), "plan.execute");
        timings.mark_request(&request, TimingName::ExecuteStart);
        timings.mark_request(&request, TimingName::ExecuteComplete);
        timings.flush(Duration::from_secs(5));
        let lines = written.lock().unwrap().clone();
        assert_eq!(lines.len(), 3, "{lines:?}");
        let read: Vec<TimingLine> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(read[0].mark.mark, TimingName::BrokerStart);
        assert_eq!(read[2].mark.mark, TimingName::ExecuteComplete);
        assert_eq!(read[2].request, Some(RequestId(6)));
        assert!(read.windows(2).all(|w| w[0].mark.ms <= w[1].mark.ms));
    }
}
