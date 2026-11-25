//! The broker client over real named pipes served by this test process (ports of
//! `BrokerClientTests.cs`, `BrokerHelloTests.cs`, `BrokerPipeTests.cs`, `LeftoversBrokerTests.cs` and
//! the broker half of `UninstallClientTests.cs`). The real elevated broker is a VM test; the real
//! broker pipe server, unelevated, is the `pipe_harness` test below (ignored: it needs the example
//! built first).

use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use purge_rpc::error::ErrorData;
use purge_rpc::methods::{NoParams, PipeCall};
use purge_win::pipe::{PipeOptions, PipeServer};
use purge_win::pipe_client::PipeClient;
use serde_json::Value;

use super::*;
use crate::testing::{Events, LIMIT, Peer, events, fixture, id_of, method_of};

fn random_name() -> String {
    let a = purge_win::os::random_u64().unwrap();
    let b = purge_win::os::random_u64().unwrap();
    format!("{a:016x}{b:016x}")
}

/// The server end of a test pipe, shared by the peer's reader and writer.
struct ServerIo(Arc<PipeServer>);

impl Read for ServerIo {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // A client that left is the end of the stream.
        Ok((&*self.0).read(buf).unwrap_or(0))
    }
}

impl Write for ServerIo {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A connected pipe: this process's server, and the client end the launcher would open.
fn connect() -> (PipeServer, PipeClient) {
    let me = purge_win::sid::current_user_sid().unwrap();
    let mut server = PipeServer::create(
        &random_name(),
        &me,
        PipeOptions {
            read_timeout: Some(Duration::from_secs(30)),
            write_timeout: Duration::from_secs(10),
            buffer_size: 4096,
        },
    )
    .unwrap();
    let client = PipeClient::open(Path::new(server.path())).unwrap();
    server.wait_for_client(Some(LIMIT)).unwrap();
    (server, client)
}

/// A broker played over a real pipe by `on_line`.
fn peer(on_line: impl Fn(&str, &Peer) + Send + 'static) -> (Peer, PipeClient) {
    let (server, client) = connect();
    let server = Arc::new(server);
    let peer = Peer::serve(
        ServerIo(server.clone()),
        Box::new(ServerIo(server)),
        on_line,
    );
    (peer, client)
}

/// A session over `client` with the launcher's pipe wiring, through the one handshake, not handed
/// out yet.
fn pending_session(
    client: PipeClient,
    sink: Sink,
    hello_timeout: Duration,
) -> Result<Arc<BrokerClient>, HandshakeError> {
    let stop = AtomicBool::new(false);
    BrokerClient::pipe_session(
        client,
        None,
        std::process::id(),
        std::path::PathBuf::new(),
        sink,
        hello_timeout,
        &stop,
    )
}

/// [`pending_session`], handed out.
fn session_over(
    client: PipeClient,
    sink: Sink,
    hello_timeout: Duration,
) -> Result<Arc<BrokerClient>, HandshakeError> {
    let session = pending_session(client, sink, hello_timeout)?;
    session.hand_over(|| {})?;
    Ok(session)
}

fn send_result(peer: &Peer, id: u64, result: &str) {
    peer.send(&format!(
        r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#
    ));
}

fn send_error(peer: &Peer, id: u64, error: &str) {
    peer.send(&format!(r#"{{"jsonrpc":"2.0","id":{id},"error":{error}}}"#));
}

fn notify(peer: &Peer, method: &str, params: &str) {
    peer.send(&format!(
        r#"{{"jsonrpc":"2.0","method":"{method}","params":{params}}}"#
    ));
}

/// The broker's `engine.hello` result.
fn hello_result() -> String {
    fixture("pipe.engine.hello.result.json")
}

#[derive(Clone, Copy, Default)]
struct HelloFirst {
    refuse_hello: bool,
    drop_at_hello: bool,
    silent_at_hello: bool,
}

/// Like `serve.rs`: drops a client whose first line is not `engine.hello`; after the hello it answers
/// each method with its recorded pipe fixture. `refused` turns true when it dropped a client.
fn hello_first(how: HelloFirst) -> (Peer, PipeClient, Arc<AtomicBool>) {
    let refused = Arc::new(AtomicBool::new(false));
    let saw_hello = Arc::new(AtomicBool::new(false));
    let r = refused.clone();
    let (peer, client) = peer(move |line, p| {
        let id = id_of(line);
        let method = method_of(line);
        if !saw_hello.load(Ordering::SeqCst) {
            if method != "engine.hello" {
                r.store(true, Ordering::SeqCst);
                p.end();
                return;
            }
            saw_hello.store(true, Ordering::SeqCst);
            if how.drop_at_hello {
                p.end();
            } else if how.refuse_hello {
                send_error(p, id, &fixture("error.runtime.json"));
            } else if !how.silent_at_hello {
                send_result(p, id, &hello_result());
            }
            return;
        }
        let name = format!(
            "{}/../purge-rpc/fixtures/pipe.{method}.result.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let result = if Path::new(&name).exists() {
            fixture(&format!("pipe.{method}.result.json"))
        } else {
            "{}".into()
        };
        send_result(p, id, &result);
    });
    (peer, client, refused)
}

fn parsed(lines: &[String]) -> Vec<Value> {
    lines
        .iter()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn session(how: HelloFirst) -> (Peer, Arc<BrokerClient>, Events, Arc<AtomicBool>) {
    let (peer, client, refused) = hello_first(how);
    let (sink, events) = events();
    let session = session_over(client, sink, LIMIT).unwrap_or_else(|_| panic!("no session"));
    (peer, session, events, refused)
}

fn params<T: serde::de::DeserializeOwned>(name: &str) -> T {
    serde_json::from_str(&fixture(name)).unwrap()
}

#[test]
fn framing_round_trip_reads_the_result_and_notifications() {
    let (peer, client) = peer(|line, p| {
        let id = id_of(line);
        match method_of(line).as_str() {
            "engine.hello" => {
                send_result(p, id, &hello_result());
                notify(
                    p,
                    "baseline.changed",
                    &fixture("notification.baseline.changed.json"),
                );
            }
            "broker.shutdown" => send_result(p, id, r#"{"exiting":true}"#),
            _ => {}
        }
    });
    let (sink, mut events) = events();
    let Ok(session) = session_over(client, sink, LIMIT) else {
        panic!()
    };
    assert_eq!(session.hello().version, "0.1.0");
    assert!(session.hello().elevated);
    let changed = events.find(|e| match e {
        ClientEvent::BaselineChanged(c) => Some(c.clone()),
        _ => None,
    });
    let expected: purge_rpc::methods::BaselineChanged =
        params("notification.baseline.changed.json");
    assert_eq!(changed, expected);

    let call = session.request(PipeCall::BrokerShutdown(NoParams {}));
    let Ok(Answer::Shutdown(shutdown)) = events.reply(call) else {
        panic!()
    };
    assert!(shutdown.exiting);

    let requests = parsed(&peer.requests());
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["jsonrpc"], "2.0");
    assert_eq!(requests[0]["id"], 1);
    assert_eq!(requests[0]["method"], "engine.hello");
    assert!(
        requests[0].get("params").is_none(),
        "the hello has no params member"
    );
    assert_eq!(requests[1]["id"], 2);
    assert_eq!(requests[1]["method"], "broker.shutdown");
    assert!(session.is_live());
    // A hello asked again is the session's, not a second line.
    let call = session.request(PipeCall::EngineHello(NoParams {}));
    assert!(matches!(events.reply(call), Ok(Answer::BrokerHello(_))));
    assert_eq!(peer.requests().len(), 2);
}

#[test]
fn cancelling_sends_cancel_and_ends_the_call() {
    let cancelled = Arc::new(std::sync::Mutex::new(None));
    let c = cancelled.clone();
    let (_peer, client) = peer(move |line, p| {
        let id = id_of(line);
        match method_of(line).as_str() {
            "$/cancel" => {
                let v: Value = serde_json::from_str(line).unwrap();
                *c.lock().unwrap() = v["params"]["request"].as_u64();
                assert!(v.get("id").is_none());
            }
            "engine.hello" => send_result(p, id, &hello_result()),
            // Never answers a scan.
            _ => {}
        }
    });
    let (sink, mut events) = events();
    let Ok(session) = session_over(client, sink, LIMIT) else {
        panic!()
    };
    let call = session.request(PipeCall::LeftoversScan(params(
        "pipe.leftovers.scan.params.json",
    )));
    std::thread::sleep(Duration::from_millis(100));
    session.cancel(call);
    assert_eq!(events.reply(call), Err(ClientError::Cancelled));
    let deadline = std::time::Instant::now() + LIMIT;
    while cancelled.lock().unwrap().is_none() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(*cancelled.lock().unwrap(), Some(2));
    assert!(
        session.is_live(),
        "cancelling one request does not end the link"
    );
}

#[test]
fn an_error_response_names_its_kind() {
    let (_peer, client) = peer(|line, p| {
        send_error(
            p,
            id_of(line),
            r#"{"code":-32000,"message":"the request failed","data":{"kind":"runtime","message":"the harvest store could not be opened"}}"#,
        )
    });
    let (sink, _events) = events();
    let Err(HandshakeError::Refused(ClientError::Rpc(error))) = session_over(client, sink, LIMIT)
    else {
        panic!()
    };
    assert_eq!(error.code, -32000);
    assert_eq!(error.kind.as_deref(), Some("runtime"));
    assert_eq!(error.message, "the harvest store could not be opened");
}

#[test]
fn a_server_that_ends_fails_the_open_request() {
    let (_peer, client) = peer(|line, p| match method_of(line).as_str() {
        "engine.hello" => send_result(p, id_of(line), &hello_result()),
        _ => p.end(),
    });
    let (sink, mut events) = events();
    let Ok(session) = session_over(client, sink, LIMIT) else {
        panic!()
    };
    let call = session.request(PipeCall::JournalPending(NoParams {}));
    let Err(ClientError::Link { reason, not_sent }) = events.reply(call) else {
        panic!()
    };
    assert!(reason.contains("ended"), "{reason}");
    assert!(
        !not_sent,
        "the request went out before the link ended: what it did is unknown"
    );
    assert!(!session.is_live());
    let closed = events.find(|e| match e {
        ClientEvent::BrokerClosed { reason, session: s } if *s == session.session() => {
            Some(reason.clone())
        }
        _ => None,
    });
    assert_eq!(closed, "The administrator part ended.");
    // Later calls fail at once, and say nothing was sent.
    let later = session.request(PipeCall::JournalPending(NoParams {}));
    let Err(ClientError::Link { not_sent, .. }) = events.reply(later) else {
        panic!()
    };
    assert!(not_sent);
}

#[test]
fn server_check_refuses_a_pipe_served_by_another_process_or_image() {
    let (_server, client) = connect();
    let image = std::env::current_exe().unwrap();
    let me = std::process::id();
    let other_pid = check_server(&client, me + 1, &image, false);
    assert_eq!(other_pid.status, ServerCheckStatus::PidMismatch);
    assert!(other_pid.reason.contains("not the administrator part"));
    let mut other = image.clone().into_os_string();
    other.push(".other");
    let other_image = check_server(&client, me, Path::new(&other), false);
    assert_eq!(other_image.status, ServerCheckStatus::ImageMismatch);
    // Case does not matter, as on NTFS.
    let upper = image.to_string_lossy().to_uppercase();
    assert!(check_server(&client, me, Path::new(&upper), false).ok());
    let own = check_server(&client, me, &image, false);
    assert_eq!(own.status, ServerCheckStatus::Ok);
    // This test process is not the administrator part: elevation decides.
    let elevated = check_server(&client, me, &image, true);
    if crate::ui_elevated() {
        assert!(elevated.ok());
    } else {
        assert_eq!(elevated.status, ServerCheckStatus::NotElevated);
    }
}

#[test]
fn a_cancelled_uac_prompt_maps_to_the_cancelled_result() {
    let cancelled = classify_shell_failure(1223);
    assert_eq!(cancelled.status, LaunchStatus::Cancelled);
    assert!(cancelled.message.to_lowercase().contains("cancelled"));
    let failed = classify_shell_failure(5);
    assert_eq!(failed.status, LaunchStatus::CannotStart);
    assert_eq!(failed.win32_error, 5);
    assert!(
        failed
            .message
            .starts_with("The administrator part could not start. ")
    );
}

#[test]
fn a_missing_broker_is_cannot_start() {
    let (sink, mut events) = events();
    let missing = std::env::temp_dir()
        .join("purge-no-such-broker")
        .join("purge-broker.exe");
    let launch = launch(&missing, sink);
    let result = events.find(|e| match e {
        ClientEvent::BrokerLaunched { call, result } if *call == launch.call => {
            Some(result.clone().map(|_| ()))
        }
        _ => None,
    });
    let failure = result.unwrap_err();
    // A standard user is told so before anything else; an administrator account learns the file is
    // missing.
    if failure.status == LaunchStatus::NotAdministrator {
        assert_eq!(failure.message, STANDARD_USER_MESSAGE);
    } else {
        assert_eq!(failure.status, LaunchStatus::CannotStart);
        assert!(
            failure
                .message
                .starts_with("The administrator part is missing: ")
        );
    }
}

#[test]
fn history_and_vault_calls_reach_a_broker_that_wants_hello_first() {
    let (peer, session, mut events, refused) = session(HelloFirst::default());
    let calls = [
        PipeCall::HistoryGet(params("pipe.history.get.params.json")),
        PipeCall::JournalPending(NoParams {}),
        PipeCall::JournalResume(params("pipe.journal.resume.params.json")),
        PipeCall::JournalRollback(params("pipe.journal.rollback.params.json")),
        PipeCall::UndoRun(params("pipe.undo.run.params.json")),
        PipeCall::QuarantineExpiring(params("pipe.quarantine.expiring.params.json")),
        PipeCall::QuarantinePurge(params("pipe.quarantine.purge.params.json")),
        PipeCall::UninstallPrepare(params("pipe.uninstall.prepare.params.json")),
        PipeCall::LeftoversStored(params("pipe.leftovers.stored.params.json")),
        PipeCall::LeftoversScan(params("pipe.leftovers.scan.params.stored.json")),
        PipeCall::ScanCandidates(params("pipe.scan.candidates.params.json")),
    ];
    for request in calls.clone() {
        let call = session.request(request);
        let answer = events.reply(call);
        assert!(answer.is_ok(), "{answer:?}");
    }
    assert!(!refused.load(Ordering::SeqCst));
    let requests = parsed(&peer.requests());
    let methods: Vec<&str> = requests
        .iter()
        .map(|r| r["method"].as_str().unwrap())
        .collect();
    assert_eq!(
        methods,
        [
            "engine.hello",
            "history.get",
            "journal.pending",
            "journal.resume",
            "journal.rollback",
            "undo.run",
            "quarantine.expiring",
            "quarantine.purge",
            "uninstall.prepare",
            "leftovers.stored",
            "leftovers.scan",
            "scan.candidates",
        ]
    );
    // Params as the fixtures have them; none for journal.pending.
    assert!(requests[2].get("params").is_none());
    let purge: Value = serde_json::from_str(&fixture("pipe.quarantine.purge.params.json")).unwrap();
    assert_eq!(requests[7]["params"], purge);
}

#[test]
fn a_refused_or_dropped_hello_makes_no_session() {
    let (_p, client, _) = hello_first(HelloFirst {
        refuse_hello: true,
        ..HelloFirst::default()
    });
    let (sink, _e) = events();
    assert!(matches!(
        session_over(client, sink, LIMIT),
        Err(HandshakeError::Refused(ClientError::Rpc(_)))
    ));
    let (_p, client, _) = hello_first(HelloFirst {
        drop_at_hello: true,
        ..HelloFirst::default()
    });
    let (sink, mut events) = events();
    assert!(matches!(
        session_over(client, sink, LIMIT),
        Err(HandshakeError::Refused(ClientError::Link { .. }))
    ));
    // A link that made no session announces no end.
    events.drain_for(Duration::from_millis(200));
    assert!(
        !events
            .seen
            .iter()
            .any(|e| matches!(e, ClientEvent::BrokerClosed { .. }))
    );
}

/// The launcher's handshake answer against the scripted broker, counting the terminations.
fn handshake(how: HelloFirst, hello_timeout: Duration) -> (Result<(), LaunchFailure>, usize, Peer) {
    let (peer, client, _) = hello_first(how);
    let (sink, _e) = events();
    let terminated = AtomicUsize::new(0);
    let result = launcher::finish(
        session_over(client, sink, hello_timeout),
        hello_timeout,
        || {
            terminated.fetch_add(1, Ordering::SeqCst);
        },
    );
    (result.map(|_| ()), terminated.load(Ordering::SeqCst), peer)
}

#[test]
fn the_handshake_makes_a_session_once_hello_is_answered() {
    let (result, terminated, _) = handshake(HelloFirst::default(), LIMIT);
    assert!(result.is_ok());
    assert_eq!(terminated, 0);
}

#[test]
fn a_refused_or_dropped_hello_is_cannot_start_and_ends_the_process() {
    for how in [
        HelloFirst {
            refuse_hello: true,
            ..HelloFirst::default()
        },
        HelloFirst {
            drop_at_hello: true,
            ..HelloFirst::default()
        },
    ] {
        let (result, terminated, _) = handshake(how, LIMIT);
        let failure = result.unwrap_err();
        assert_eq!(failure.status, LaunchStatus::CannotStart);
        assert!(
            failure.message.contains("did not accept"),
            "{}",
            failure.message
        );
        assert_eq!(terminated, 1);
    }
}

#[test]
fn a_hello_never_answered_is_timed_out_and_ends_the_process() {
    let (result, terminated, peer) = handshake(
        HelloFirst {
            silent_at_hello: true,
            ..HelloFirst::default()
        },
        Duration::from_millis(200),
    );
    let failure = result.unwrap_err();
    assert_eq!(failure.status, LaunchStatus::TimedOut);
    assert!(failure.message.contains("did not answer"));
    assert_eq!(terminated, 1);
    let methods: Vec<String> = peer.requests().iter().map(|l| method_of(l)).collect();
    assert_eq!(methods, ["engine.hello"]);
}

#[test]
fn the_callers_stop_ends_the_handshake_and_the_process() {
    let (_peer, client, _) = hello_first(HelloFirst {
        silent_at_hello: true,
        ..HelloFirst::default()
    });
    let (sink, _e) = events();
    let pipe = Arc::new(client);
    let shut = pipe.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        s.store(true, Ordering::SeqCst);
    });
    let result = BrokerClient::over_streams(
        Box::new(PipeWriter(pipe.clone())),
        Box::new(PipeReader(pipe)),
        Box::new(move || shut.shut_down()),
        sink,
        LIMIT,
        &stop,
    );
    let terminated = AtomicUsize::new(0);
    let failure = launcher::finish(result, LIMIT, || {
        terminated.fetch_add(1, Ordering::SeqCst);
    })
    .unwrap_err();
    assert_eq!(failure.status, LaunchStatus::Stopped);
    assert_eq!(terminated.load(Ordering::SeqCst), 1);
}

#[test]
fn consent_codes_progress_and_refusals_reach_their_call() {
    let (peer, client) = peer(|line, p| {
        let id = id_of(line);
        match method_of(line).as_str() {
            "engine.hello" => send_result(p, id, &hello_result()),
            "plan.create" => send_error(p, id, &fixture("error.plan_refused.json")),
            "uninstall.run" => {
                notify(
                    p,
                    "consent.shown",
                    &format!(r#"{{"request":{id},"code":"A1B2-C3D4"}}"#),
                );
                notify(
                    p,
                    "uninstall.progress",
                    &format!(r#"{{"request":{id},"phase":"wait","done":1,"total":2}}"#),
                );
                send_error(p, id, &fixture("error.uninstall_failed.json"));
            }
            "undo.run" => {
                notify(
                    p,
                    "consent.shown",
                    &format!(r#"{{"request":{id},"code":"E5F6-A7B8"}}"#),
                );
                send_result(p, id, &fixture("pipe.undo.run.result.json"));
                // Late: the call has ended, so no call claims it.
                notify(
                    p,
                    "consent.shown",
                    &format!(r#"{{"request":{id},"code":"0A0B-0C0D"}}"#),
                );
            }
            _ => {}
        }
    });
    let (sink, mut events) = events();
    let Ok(mut session) = session_over(client, sink, LIMIT) else {
        panic!()
    };
    let foreground = Arc::new(AtomicUsize::new(0));
    let f = foreground.clone();
    session.set_foreground(Arc::new(move || {
        f.fetch_add(1, Ordering::SeqCst);
    }));

    let call = session.request(PipeCall::PlanCreate(params("pipe.plan.create.params.json")));
    let Err(ClientError::Rpc(refused)) = events.reply(call) else {
        panic!()
    };
    assert_eq!(refused.kind.as_deref(), Some("plan_refused"));
    let Some(ErrorData::PlanRefused { refusals }) = refused.data else {
        panic!()
    };
    assert_eq!(refusals.len(), 2);
    assert_eq!(
        foreground.load(Ordering::SeqCst),
        0,
        "plan.create shows no dialog"
    );

    let run = session.request(PipeCall::UninstallRun(params(
        "pipe.uninstall.run.params.json",
    )));
    let Err(ClientError::Rpc(failed)) = events.reply(run) else {
        panic!()
    };
    let Some(ErrorData::UninstallFailed {
        exit_code,
        forced_offered,
        ..
    }) = failed.data
    else {
        panic!()
    };
    assert_eq!((exit_code, forced_offered), (Some(1603), true));
    assert_eq!(
        foreground.load(Ordering::SeqCst),
        1,
        "uninstall.run asks for consent"
    );

    let undo = session.request(PipeCall::UndoRun(params("pipe.undo.run.params.json")));
    assert!(matches!(events.reply(undo), Ok(Answer::Undo(_))));
    events.drain_for(Duration::from_millis(200));
    let shown: Vec<(Option<CallId>, String)> = events
        .seen
        .iter()
        .filter_map(|e| match e {
            ClientEvent::ConsentShown { call, shown } => Some((*call, shown.code.to_string())),
            _ => None,
        })
        .collect();
    assert_eq!(
        shown,
        [
            (Some(run), "A1B2-C3D4".to_owned()),
            (Some(undo), "E5F6-A7B8".to_owned()),
            (None, "0A0B-0C0D".to_owned()),
        ]
    );
    assert!(
        events
            .seen
            .iter()
            .any(|e| matches!(e, ClientEvent::Progress { call, progress } if *call == run && progress.phase == "wait"))
    );
    let _ = peer;
}

#[test]
fn delete_after_is_one_flag_on_plan_execute_and_allows_the_second_dialog() {
    let (peer, client) = peer(|line, p| {
        let id = id_of(line);
        match method_of(line).as_str() {
            "engine.hello" => send_result(p, id, &hello_result()),
            "plan.execute" => {
                let asked = line.contains(r#""delete_after":true"#);
                notify(
                    p,
                    "consent.shown",
                    &format!(r#"{{"request":{id},"code":"A1B2-C3D4"}}"#),
                );
                let mut result: Value =
                    serde_json::from_str(&fixture("pipe.plan.execute.result.json")).unwrap();
                if asked {
                    notify(
                        p,
                        "exec.progress",
                        &format!(r#"{{"request":{id},"phase":"delete_after","done":1,"total":1}}"#),
                    );
                    notify(
                        p,
                        "consent.shown",
                        &format!(r#"{{"request":{id},"code":"E5F6-A7B8"}}"#),
                    );
                } else {
                    result.as_object_mut().unwrap().remove("delete_after");
                }
                send_result(p, id, &result.to_string());
            }
            _ => {}
        }
    });
    let (sink, mut events) = events();
    let Ok(mut session) = session_over(client, sink, LIMIT) else {
        panic!()
    };
    let foreground = Arc::new(AtomicUsize::new(0));
    let f = foreground.clone();
    session.set_foreground(Arc::new(move || {
        f.fetch_add(1, Ordering::SeqCst);
    }));

    let mut plain: purge_rpc::methods::PlanExecuteParams = params("pipe.plan.execute.params.json");
    plain.delete_after = false;
    let call = session.request(PipeCall::PlanExecute(plain));
    let Ok(Answer::Exec(result)) = events.reply(call) else {
        panic!()
    };
    assert!(result.delete_after.is_none());
    assert_eq!(
        foreground.load(Ordering::SeqCst),
        1,
        "once, before the request"
    );

    let call = session.request(PipeCall::PlanExecute(params(
        "pipe.plan.execute.params.json",
    )));
    let Ok(Answer::Exec(result)) = events.reply(call) else {
        panic!()
    };
    assert!(result.delete_after.is_some());
    // Before the request, and again when the delete step was announced (on the reader thread).
    assert_eq!(foreground.load(Ordering::SeqCst), 3);

    let requests = parsed(&peer.requests());
    assert_eq!(requests[1]["params"]["delete_after"], false);
    assert_eq!(requests[2]["params"]["delete_after"], true);
    assert_eq!(requests[2]["params"]["restore_point"], "high_risk");
    let phases: Vec<String> = events
        .seen
        .iter()
        .filter_map(|e| match e {
            ClientEvent::Progress { progress, .. } => Some(progress.phase.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(phases, ["delete_after"]);
}

#[test]
fn a_write_goes_out_while_the_reader_waits_in_a_pending_read() {
    // Review M3-R2 B2: the server sends nothing before it has the hello line, while the client's
    // reader thread is already inside a read.
    let (_peer, client) = peer(|line, p| {
        std::thread::sleep(Duration::from_millis(300));
        send_result(p, id_of(line), &hello_result());
    });
    let (sink, _e) = events();
    assert!(session_over(client, sink, Duration::from_secs(5)).is_ok());
}

/// The real broker pipe server (`serve::run`, its client check and its `engine.hello` gate), run
/// unelevated by the `pipe_harness` example, expecting this test process as its client.
#[test]
#[ignore = "needs `cargo build -p purge-broker --example pipe_harness` in this CARGO_TARGET_DIR first"]
fn hello_completes_against_the_real_broker_pipe_server() {
    use std::io::BufRead;
    use std::process::{Command, Stdio};
    let target = std::env::var_os("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"));
    // Absolute, as the launcher makes it: GetFullPathNameW also turns `/` into `\`, and the image
    // check compares names as they are.
    let exe = std::path::absolute(target.join(r"debug\examples\pipe_harness.exe")).unwrap();
    assert!(exe.is_file(), "{} is not built", exe.display());
    let me = purge_win::process::ProcessHandle::current().unwrap();
    let image = std::env::current_exe().unwrap();
    let mut child = Command::new(&exe)
        .arg(random_name())
        .arg(std::process::id().to_string())
        .arg(me.creation_time().unwrap().to_string())
        .arg(&image)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let path = line
        .trim()
        .strip_prefix("READY ")
        .expect("READY line")
        .to_owned();
    let client = PipeClient::open(Path::new(&path)).unwrap();
    let check = check_server(&client, child.id(), &exe, false);
    assert!(check.ok(), "{:?}: {}", check.status, check.reason);
    // A pid that is not the harness's fails the check and nothing is written.
    assert_eq!(
        check_server(&client, child.id() + 4, &exe, false).status,
        ServerCheckStatus::PidMismatch
    );
    std::thread::sleep(Duration::from_millis(300));
    let (sink, _e) = events();
    let session = session_over(client, sink, LIMIT).unwrap_or_else(|_| panic!("no session"));
    assert!(session.is_live());
    assert!(
        child.try_wait().unwrap().is_none(),
        "the broker pipe server must still serve"
    );
    session.close();
    let _ = child.kill();
}

#[test]
fn close_ends_the_pipe_while_the_session_is_still_held() {
    // Review S1: the broker must see the pipe end (and take its consent dialog down) when the UI
    // closes the session, even while a page still holds the session.
    let (server, client) = connect();
    let server = Arc::new(server);
    let (tx, rx) = std::sync::mpsc::channel();
    let s = server.clone();
    std::thread::spawn(move || {
        use std::io::BufRead;
        let mut reader = io::BufReader::new(ServerIo(s.clone()));
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let answer = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":{}}}\n",
            id_of(line.trim()),
            hello_result()
        );
        ServerIo(s).write_all(answer.as_bytes()).unwrap();
        // The next read is the end of the stream once the client's handle is closed.
        let mut rest = String::new();
        let _ = tx.send(reader.read_line(&mut rest).unwrap_or(0));
    });
    let (sink, _events) = events();
    let session = session_over(client, sink, LIMIT).unwrap_or_else(|_| panic!("no session"));
    let held = session.clone();
    session.close();
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(5)),
        Ok(0),
        "the server did not see the pipe end"
    );
    assert!(!held.is_live());
}

/// A broker that answers the hello and ends at the next request.
fn ends_after_hello() -> (Peer, PipeClient) {
    peer(|line, p| match method_of(line).as_str() {
        "engine.hello" => send_result(p, id_of(line), &hello_result()),
        _ => p.end(),
    })
}

#[test]
fn a_session_whose_link_ended_before_the_launch_answer_is_not_handed_out() {
    // Review S3: no BrokerClosed may come for a session the UI never got.
    let (_peer, client) = ends_after_hello();
    let (sink, mut events) = events();
    let session = pending_session(client, sink.clone(), LIMIT).unwrap_or_else(|_| panic!());
    let call = session.request(PipeCall::JournalPending(NoParams {}));
    assert!(events.reply(call).is_err());
    assert!(!session.is_live());
    let launch = CallId::next();
    launcher::deliver(launch, Ok(session), &sink);
    let failure = events.find(|e| match e {
        ClientEvent::BrokerLaunched { call, result } if *call == launch => {
            Some(result.clone().map(|_| ()))
        }
        _ => None,
    });
    assert_eq!(failure.unwrap_err().status, LaunchStatus::CannotStart);
    events.drain_for(Duration::from_millis(200));
    assert!(
        !events
            .seen
            .iter()
            .any(|e| matches!(e, ClientEvent::BrokerClosed { .. }))
    );
}

#[test]
fn a_launched_session_announces_its_end_after_the_launch_answer() {
    let (_peer, client) = ends_after_hello();
    let (sink, mut events) = events();
    let session = pending_session(client, sink.clone(), LIMIT).unwrap_or_else(|_| panic!());
    let id = session.session();
    assert_ne!(id, 0);
    let launch = CallId::next();
    launcher::deliver(launch, Ok(session.clone()), &sink);
    let call = session.request(PipeCall::JournalPending(NoParams {}));
    assert!(events.reply(call).is_err());
    events.drain_for(Duration::from_millis(200));
    let launched = events
        .seen
        .iter()
        .position(
            |e| matches!(e, ClientEvent::BrokerLaunched { call, result: Ok(_) } if *call == launch),
        )
        .expect("launched");
    let closed = events
        .seen
        .iter()
        .position(|e| matches!(e, ClientEvent::BrokerClosed { session, .. } if *session == id))
        .expect("closed, naming its session");
    assert!(launched < closed);
}

/// A started broker for [`launcher::connect`]: a pid, an exit code, the terminations.
struct FakeProcess {
    pid: u32,
    exit_code: Option<u32>,
    terminated: AtomicUsize,
}

impl FakeProcess {
    fn running() -> FakeProcess {
        FakeProcess {
            pid: 4242,
            exit_code: None,
            terminated: AtomicUsize::new(0),
        }
    }

    fn terminations(&self) -> usize {
        self.terminated.load(Ordering::SeqCst)
    }
}

impl launcher::BrokerProcess for FakeProcess {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn exit_code(&self) -> Option<u32> {
        self.exit_code
    }

    fn terminate(&self) {
        self.terminated.fetch_add(1, Ordering::SeqCst);
    }
}

fn pipe_path(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!(r"\\.\pipe\purge-{name}"))
}

fn options() -> PipeOptions {
    PipeOptions {
        read_timeout: Some(Duration::from_secs(10)),
        write_timeout: Duration::from_secs(10),
        buffer_size: 4096,
    }
}

fn passes(_: &PipeClient, _: u32) -> ServerCheck {
    ServerCheck {
        status: ServerCheckStatus::Ok,
        reason: String::new(),
    }
}

#[test]
fn connect_retries_until_the_pipe_exists_then_checks_the_expected_pid() {
    let name = random_name();
    let n = name.clone();
    let server = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        let me = purge_win::sid::current_user_sid().unwrap();
        let mut server = PipeServer::create(&n, &me, options()).unwrap();
        server.wait_for_client(Some(LIMIT)).unwrap();
        server
    });
    let process = FakeProcess::running();
    let checked = std::sync::Mutex::new(None);
    let stop = AtomicBool::new(false);
    let pipe = launcher::connect(&process, &pipe_path(&name), LIMIT, &stop, |pipe, pid| {
        *checked.lock().unwrap() = Some(pid);
        passes(pipe, pid)
    });
    assert!(pipe.is_ok(), "{:?}", pipe.err());
    assert_eq!(*checked.lock().unwrap(), Some(4242));
    assert_eq!(process.terminations(), 0);
    drop(server.join().unwrap());
}

#[test]
fn connect_reports_the_exit_code_of_a_broker_that_ended_before_its_pipe() {
    let process = FakeProcess {
        exit_code: Some(3),
        ..FakeProcess::running()
    };
    let stop = AtomicBool::new(false);
    let failure =
        launcher::connect(&process, &pipe_path(&random_name()), LIMIT, &stop, passes).unwrap_err();
    assert_eq!(failure.status, LaunchStatus::CannotStart);
    assert_eq!(failure.exit_code, Some(3));
    assert!(
        failure.message.contains("exit code 3"),
        "{}",
        failure.message
    );
}

#[test]
fn connect_times_out_and_ends_the_broker() {
    let process = FakeProcess::running();
    let stop = AtomicBool::new(false);
    let failure = launcher::connect(
        &process,
        &pipe_path(&random_name()),
        Duration::from_millis(300),
        &stop,
        passes,
    )
    .unwrap_err();
    assert_eq!(failure.status, LaunchStatus::TimedOut);
    assert_eq!(process.terminations(), 1);
}

#[test]
fn a_stopped_connect_ends_the_broker() {
    let process = FakeProcess::running();
    let stop = AtomicBool::new(true);
    let failure =
        launcher::connect(&process, &pipe_path(&random_name()), LIMIT, &stop, passes).unwrap_err();
    assert_eq!(failure.status, LaunchStatus::Stopped);
    assert_eq!(process.terminations(), 1);
}

#[test]
fn a_failed_server_check_writes_nothing_and_ends_the_broker() {
    let name = random_name();
    let me = purge_win::sid::current_user_sid().unwrap();
    let mut server = PipeServer::create(&name, &me, options()).unwrap();
    let process = FakeProcess::running();
    let stop = AtomicBool::new(false);
    let failure = launcher::connect(&process, &pipe_path(&name), LIMIT, &stop, |_, _| {
        ServerCheck {
            status: ServerCheckStatus::PidMismatch,
            reason: "not ours".into(),
        }
    })
    .unwrap_err();
    assert_eq!(failure.status, LaunchStatus::ServerCheckFailed);
    assert_eq!(failure.message, "not ours");
    assert_eq!(process.terminations(), 1);
    // The client connected and left without a byte.
    let _ = server.wait_for_client(Some(Duration::from_secs(1)));
    let mut buf = [0u8; 16];
    assert_eq!(ServerIo(Arc::new(server)).read(&mut buf).unwrap(), 0);
}

#[test]
fn a_pipe_that_refuses_this_client_ends_the_broker() {
    // Review S4: an open error other than missing or busy (here access denied: the pipe admits only
    // SYSTEM) ends the launch at once, and the broker with it.
    let name = random_name();
    let _server = PipeServer::create(&name, "S-1-5-18", options()).unwrap();
    let process = FakeProcess::running();
    let stop = AtomicBool::new(false);
    let failure = launcher::connect(&process, &pipe_path(&name), LIMIT, &stop, passes).unwrap_err();
    assert_eq!(failure.status, LaunchStatus::CannotStart);
    assert_eq!(failure.win32_error, 5);
    assert_eq!(process.terminations(), 1);
}
