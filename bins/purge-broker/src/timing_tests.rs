//! The timing marks as the serving loop takes them (design 9.1, `crate::timing`): `pipe_connected` after
//! the hello, `first_progress` only once a progress line was written, and a timer that fails or panics
//! changes no answer. The marks of the real methods are checked in `exec_tests`
//! (`the_flow_results_carry_their_timing_marks_in_order`).

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use purge_engine::pipeline::Settings;
use purge_rpc::error::ErrorObject;
use purge_rpc::methods::{PipeCall, Progress, ServerNotification};
use purge_rpc::timing::{TimingName, Timings as Wire};
use serde_json::{Value, json};

use crate::baseline::BuildHandle;
use crate::lifetime::Exit;
use crate::serve::{Ctx, Handler, Wiring, run_timed};
use crate::testkit::{
    Client, FakeBuild, FakeClock, FakeHost, FakeParent, Gate, HELLO, MemNet, SECS, ScriptedConsent,
    expected, id_text, request, test_limits,
};
use crate::timing::Timings;
use crate::timing::tests::Steps;

/// What the probe handler saw around its progress line.
#[derive(Default)]
struct Seen {
    before: Mutex<Option<Wire>>,
    after: Mutex<Option<Wire>>,
    sent: Mutex<Option<bool>>,
    done: Gate,
}

/// `leftovers.scan` and `uninstall.run` take a start mark, send one progress line and report the
/// request's timings before and after it.
struct ProgressProbe(Arc<Seen>);

impl Handler for ProgressProbe {
    type Session = ();
    type Scan = ();
    type Plan = ();

    fn call(&self, ctx: &Ctx<'_, Self>, call: PipeCall) -> Result<Value, ErrorObject> {
        let progress = Progress {
            request: ctx.request(),
            program_id: None,
            phase: "scan".into(),
            done: 1,
            total: None,
        };
        let note = match call {
            PipeCall::LeftoversScan(_) => ServerNotification::ScanProgress(progress),
            PipeCall::UninstallRun(_) => ServerNotification::UninstallProgress(progress),
            other => return Err(ErrorObject::runtime(format!("{other:?} is not scripted"))),
        };
        ctx.mark(TimingName::ScanStart);
        *self.0.before.lock().unwrap() = ctx.timings();
        // A notification that is not progress is no `first_progress`.
        let _ = ctx.notify(&ServerNotification::BaselineChanged(
            purge_rpc::methods::BaselineChanged {
                build: purge_rpc::BaselineBuild::None {
                    reason: "test".into(),
                },
                rescan_offered: vec![],
            },
        ));
        let sent = ctx.notify(&note).is_ok();
        *self.0.sent.lock().unwrap() = Some(sent);
        *self.0.after.lock().unwrap() = ctx.timings();
        ctx.mark(TimingName::ScanComplete);
        self.0.done.open();
        Ok(json!({ "timings": ctx.timings() }))
    }
}

struct Probe {
    net: MemNet,
    seen: Arc<Seen>,
    join: Option<JoinHandle<Exit>>,
}

impl Probe {
    fn start(timings: Timings) -> Probe {
        let net = MemNet::default();
        let seen = Arc::new(Seen::default());
        let wiring = Wiring {
            link: net.link(),
            handler: ProgressProbe(seen.clone()),
            expected: expected(),
            parent: Arc::new(FakeParent::default()),
            consent: Arc::new(Arc::new(ScriptedConsent::default())),
            host: Arc::new(FakeHost),
            clock: Arc::new(FakeClock::default()),
            build: Some(FakeBuild::new(purge_rpc::BaselineBuild::None {
                reason: "test".into(),
            }) as Arc<dyn BuildHandle>),
            settings: Settings::default(),
            limits: test_limits(),
        };
        let timings = Arc::new(timings);
        let join = std::thread::spawn(move || run_timed(wiring, timings));
        Probe {
            net,
            seen,
            join: Some(join),
        }
    }

    fn client(&self) -> Client {
        let c = self.net.connect(Ok(()));
        c.send_line(HELLO);
        let hello = c.reply();
        assert_eq!(hello["result"]["elevated"], true, "{hello}");
        c
    }
}

impl Probe {
    /// Closes the client and waits for the broker to end on the lost pipe.
    fn finish(mut self, c: &Client) {
        c.close();
        let join = self.join.take().expect("the broker was running");
        let deadline = std::time::Instant::now() + SECS;
        while !join.is_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "the broker did not end"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        join.join().unwrap();
    }
}

fn names(timings: &Wire) -> Vec<TimingName> {
    timings.marks.iter().map(|m| m.mark).collect()
}

/// The answer to request `id`, and the methods of the notifications before it.
fn answer(c: &Client, id: u64) -> (Value, Vec<String>) {
    let mut notes = Vec::new();
    loop {
        let line = c.recv(SECS).expect("an answer");
        if line.get("id").and_then(Value::as_u64) == Some(id) {
            return (line, notes);
        }
        notes.push(line["method"].as_str().unwrap_or_default().to_owned());
    }
}

#[test]
fn first_progress_is_taken_once_the_progress_line_was_written() {
    let probe = Probe::start(Timings::new(Arc::new(Steps::default()), 7));
    let c = probe.client();
    c.send_line(&request(
        2,
        "leftovers.scan",
        &json!({ "session_id": id_text("u", 1) }),
    ));
    let (reply, notes) = answer(&c, 2);
    assert_eq!(notes, ["baseline.changed", "scan.progress"]);

    let before = probe.seen.before.lock().unwrap().clone().unwrap();
    let after = probe.seen.after.lock().unwrap().clone().unwrap();
    assert_eq!(
        names(&before),
        [TimingName::PipeConnected, TimingName::ScanStart],
        "no first_progress before the line, and none for a notification that is not progress"
    );
    assert_eq!(
        names(&after),
        [
            TimingName::PipeConnected,
            TimingName::ScanStart,
            TimingName::FirstProgress
        ]
    );
    let wire: Wire = serde_json::from_value(reply["result"]["timings"].clone()).unwrap();
    assert_eq!(
        names(&wire),
        [
            TimingName::PipeConnected,
            TimingName::ScanStart,
            TimingName::FirstProgress,
            TimingName::ScanComplete
        ]
    );
    assert!(
        wire.marks.windows(2).all(|w| w[0].ms < w[1].ms),
        "the marks are in order: {wire:?}"
    );
    probe.finish(&c);
}

#[test]
fn a_progress_line_that_could_not_be_written_is_no_first_progress() {
    let probe = Probe::start(Timings::new(Arc::new(Steps::default()), 7));
    let c = probe.client();
    c.break_writes();
    c.send_line(&request(
        2,
        "uninstall.run",
        &json!({ "session_id": id_text("u", 1), "quiet": false }),
    ));
    assert!(probe.seen.done.wait(SECS), "the request ran");
    assert_eq!(*probe.seen.sent.lock().unwrap(), Some(false));
    let after = probe.seen.after.lock().unwrap().clone().unwrap();
    assert!(
        !names(&after).contains(&TimingName::FirstProgress),
        "{after:?}"
    );
    probe.finish(&c);
}

#[test]
fn a_timer_that_fails_or_panics_changes_no_answer() {
    for panics in [false, true] {
        let steps = Arc::new(Steps::default());
        if panics {
            steps.panic.store(true, Ordering::SeqCst);
        } else {
            steps.fail.store(true, Ordering::SeqCst);
        }
        let probe = Probe::start(Timings::new(steps, 7));
        let c = probe.client();
        c.send_line(&request(
            2,
            "leftovers.scan",
            &json!({ "session_id": id_text("u", 1) }),
        ));
        let (reply, notes) = answer(&c, 2);
        assert_eq!(notes, ["baseline.changed", "scan.progress"]);
        assert!(reply.get("error").is_none(), "{reply}");
        assert_eq!(reply["result"]["timings"], Value::Null, "{reply}");
        assert_eq!(*probe.seen.sent.lock().unwrap(), Some(true));
        // The broker goes on serving.
        c.send_line(&request(
            3,
            "leftovers.scan",
            &json!({ "session_id": id_text("u", 2) }),
        ));
        assert!(answer(&c, 3).0.get("result").is_some());
        probe.finish(&c);
    }
}
