//! The broker's client check over a real named pipe, unelevated (M3 design 3.3, threats T2 and T5).
//!
//! The test process is the UI: its pid, creation time and image are what the broker expects, or one of
//! them is made wrong. A refused client is disconnected and gets no byte; three of them end the
//! broker. What needs a real elevation (the broker as a high-integrity process, a medium client, UAC)
//! is on the VM (`docs/m3-notes/broker-core.md`).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::channel;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use purge_broker::lifetime::{Exit, ExitReason, SystemClock};
use purge_broker::link::Refusal;
use purge_broker::serve::{Consent, Host, Limits, Unwired, Wiring, run};
use purge_broker::wire::{PipeLink, ProcessParent};
use purge_engine::pipeline::Settings;
use purge_model::BaselineTrust;
use purge_rpc::{BaselineBuild, BaselineStatus, EngineHello};
use purge_win::pipe::{ExpectedPeer, PipeError};
use purge_win::process::ProcessHandle;
use purge_win::taskdialog::{Outcome, Page};

const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;
const ERROR_PIPE_BUSY: i32 = 231;
const HELLO: &str = r#"{"jsonrpc":"2.0","id":1,"method":"engine.hello"}"#;

struct NoConsent;

impl Consent for NoConsent {
    fn ask(
        &self,
        _: &[Page],
        _: i32,
        _: &purge_broker::lifetime::Closer,
        _: &(dyn Fn(purge_rpc::methods::ConsentRenderer) + Sync),
    ) -> std::io::Result<Outcome> {
        Ok(Outcome::Declined)
    }
}

struct TestHost;

impl Host for TestHost {
    fn hello(&self) -> EngineHello {
        EngineHello {
            version: "test".into(),
            elevated: false,
            user_sid: me(),
            shell_sid: None,
            edition: "Test".into(),
            build: 1,
            ubr: 0,
            policy_version: "test".into(),
            baseline: BaselineStatus {
                baseline_available: false,
                baseline_trust: BaselineTrust::None,
                baseline_view: None,
                baseline_build: BaselineBuild::None {
                    reason: "test".into(),
                },
            },
        }
    }
}

fn me() -> String {
    purge_win::sid::current_user_sid().unwrap()
}

fn random_name() -> String {
    use std::hash::{BuildHasher, Hasher};
    let mut out = String::new();
    for i in 0..2u64 {
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(i);
        h.write_u32(std::process::id());
        h.write_u128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        );
        out.push_str(&format!("{:016x}", h.finish()));
    }
    out
}

/// What this process is, as the broker would be told by `--parent`.
fn expected_self() -> ExpectedPeer {
    ExpectedPeer {
        pid: std::process::id(),
        creation_time: ProcessHandle::current().unwrap().creation_time().unwrap(),
        image: std::env::current_exe().unwrap(),
        user_sid: me(),
    }
}

/// A broker over a fresh pipe in a thread; this process is its parent.
struct Broker {
    path: String,
    join: Option<JoinHandle<Exit>>,
}

impl Broker {
    fn start(expected: ExpectedPeer, max_failed: usize) -> Broker {
        let link = PipeLink::create(&random_name(), &me()).unwrap();
        let path = link.path().to_owned();
        let me = ProcessHandle::current().unwrap();
        let parent = ProcessParent::open(std::process::id(), me.creation_time().unwrap()).unwrap();
        let wiring = Wiring {
            link,
            handler: Unwired,
            expected,
            parent: Arc::new(parent),
            consent: Arc::new(NoConsent),
            host: Arc::new(TestHost),
            clock: Arc::new(SystemClock::new()),
            build: None,
            settings: Settings::default(),
            limits: Limits {
                tick: Duration::from_millis(20),
                hello_wait: Duration::from_secs(5),
                build_grace: Duration::from_millis(50),
                max_failed,
                ..Limits::design()
            },
        };
        Broker {
            path,
            join: Some(std::thread::spawn(move || run(wiring))),
        }
    }

    fn exit(&mut self) -> Exit {
        let join = self.join.take().unwrap();
        let t = Instant::now();
        while !join.is_finished() {
            assert!(
                t.elapsed() < Duration::from_secs(20),
                "the broker did not end"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        join.join().unwrap()
    }
}

/// Opens the client end as the UI does: identification level, static tracking. A pipe that is busy
/// (between a refused client and the next wait) is retried for up to ten seconds.
fn connect(path: &str) -> File {
    let t = Instant::now();
    loop {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(path)
        {
            Ok(f) => return f,
            Err(e)
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY)
                    && t.elapsed() < Duration::from_secs(10) =>
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("{e}"),
        }
    }
}

/// The bytes the server sends until it ends the connection, or `None` after `limit`.
fn read_all(mut f: File, limit: Duration) -> Option<Vec<u8>> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match f.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
        let _ = tx.send(out);
    });
    rx.recv_timeout(limit).ok()
}

/// Row: a client that fails the check gets no byte; the refusal is the one named; one refusal ends a
/// broker built for one.
fn refused_with(expected: ExpectedPeer, want: Refusal) {
    let mut broker = Broker::start(expected, 1);
    let mut client = connect(&broker.path);
    let _ = client.write_all(format!("{HELLO}\n").as_bytes());
    let got =
        read_all(client, Duration::from_secs(10)).expect("the broker disconnected the client");
    assert!(
        got.is_empty(),
        "answered a refused client: {:?}",
        String::from_utf8_lossy(&got)
    );
    let exit = broker.exit();
    assert_eq!(exit.refusals, [want]);
    assert_eq!((exit.code(), exit.reason), (25, ExitReason::RefusedClients));
}

#[test]
fn a_client_with_another_pid_is_refused() {
    let me = expected_self();
    refused_with(
        ExpectedPeer {
            pid: me.pid + 4,
            ..me
        },
        Refusal::Pid,
    );
}

#[test]
fn a_client_created_at_another_time_is_refused() {
    let me = expected_self();
    refused_with(
        ExpectedPeer {
            creation_time: me.creation_time + 1,
            ..me
        },
        Refusal::CreationTime,
    );
}

#[test]
fn a_client_with_another_image_is_refused() {
    // A copy of Purge.exe elsewhere: the image is not `<own directory>\Purge.exe`.
    let me = expected_self();
    refused_with(
        ExpectedPeer {
            image: me.image.with_file_name("Purge.exe"),
            ..me
        },
        Refusal::Image,
    );
}

#[test]
fn a_client_of_another_account_is_refused() {
    let me = expected_self();
    refused_with(
        ExpectedPeer {
            user_sid: "S-1-5-18".into(),
            ..me
        },
        Refusal::Account,
    );
}

/// A client that did not open at identification level with static tracking has no security context
/// before its first write: it is refused as unidentified, or (if this Windows identifies it anyway)
/// as the process that is not the parent. Either way it gets nothing.
#[test]
fn a_client_that_cannot_be_identified_before_its_first_write_is_refused() {
    let mut broker = Broker::start(expected_self(), 1);
    let mut child: Child = Command::new("cmd.exe")
        .raw_arg(format!("/d /c \"(echo hi& set /p x=)>{}\"", broker.path))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let exit = broker.exit();
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(exit.reason, ExitReason::RefusedClients);
    println!("dynamic-tracking client refused as: {:?}", exit.refusals);
    assert!(
        matches!(
            exit.refusals.as_slice(),
            [Refusal::Unidentified(_)] | [Refusal::Pid]
        ),
        "{:?}",
        exit.refusals
    );
}

/// The UI's own order (review M3-R1 S1): identified before it wrote a byte, then `engine.hello`
/// after a pause. If this Windows needed the first write, the client would be refused here.
#[test]
fn an_identification_level_client_is_identified_before_it_writes_and_is_served() {
    let mut broker = Broker::start(expected_self(), 3);
    let mut client = connect(&broker.path);
    std::thread::sleep(Duration::from_millis(300));
    client.write_all(format!("{HELLO}\n").as_bytes()).unwrap();
    let mut buf = [0u8; 4096];
    let n = client.read(&mut buf).unwrap();
    let hello: serde_json::Value = serde_json::from_slice(&buf[..n - 1]).unwrap();
    assert_eq!(hello["id"], 1);
    assert_eq!(hello["result"]["user_sid"], me());
    // Shutdown: nothing runs, so it is accepted, and the broker ends once the client closes.
    client
        .write_all(br#"{"jsonrpc":"2.0","id":2,"method":"broker.shutdown"}"#)
        .unwrap();
    client.write_all(b"\n").unwrap();
    let n = client.read(&mut buf).unwrap();
    let bye: serde_json::Value = serde_json::from_slice(&buf[..n - 1]).unwrap();
    assert_eq!(bye["result"]["exiting"], true);
    drop(client);
    let exit = broker.exit();
    assert_eq!((exit.code(), exit.reason), (0, ExitReason::Shutdown));
    assert!(exit.refusals.is_empty());
}

/// Row: after three failed clients the broker exits; the same instance serves each in turn.
#[test]
fn three_refused_clients_in_a_row_end_the_broker() {
    let me = expected_self();
    let wrong = ExpectedPeer {
        pid: me.pid + 4,
        ..me
    };
    let mut broker = Broker::start(wrong, 3);
    for _ in 0..3 {
        let mut c = connect(&broker.path);
        let _ = c.write_all(format!("{HELLO}\n").as_bytes());
        assert!(read_all(c, Duration::from_secs(10)).unwrap().is_empty());
    }
    let exit = broker.exit();
    assert_eq!(exit.refusals, vec![Refusal::Pid; 3]);
    assert_eq!(exit.code(), 25);
}

/// Row (design 3.3 step 2): a pipe name that exists already is not taken over.
#[test]
fn a_name_that_exists_is_taken_and_the_broker_would_exit() {
    let first = PipeLink::create(&random_name(), &me()).unwrap();
    let name = first.path().rsplit('-').next().unwrap().to_owned();
    assert_eq!(
        PipeLink::create(&name, &me()).err(),
        Some(PipeError::NameTaken)
    );
}

/// Row: the parent is the process `--parent` names, as created at `--parent-ctime`.
#[test]
fn the_parent_must_be_the_process_that_was_named() {
    let me = ProcessHandle::current().unwrap();
    let ctime = me.creation_time().unwrap();
    assert!(ProcessParent::open(std::process::id(), ctime).is_ok());
    assert!(ProcessParent::open(std::process::id(), ctime + 1).is_err());
    assert!(ProcessParent::open(u32::MAX - 3, ctime).is_err());
}

/// Parent loss over the real process handle: the parent is a child process; when it ends, so does
/// the broker.
#[test]
fn the_broker_ends_when_the_parent_process_ends() {
    let mut child = Command::new("cmd.exe")
        .raw_arg("/d /c \"set /p x=\"")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    let handle = ProcessHandle::open(child.id()).unwrap();
    let parent = ProcessParent::open(child.id(), handle.creation_time().unwrap()).unwrap();
    let link = PipeLink::create(&random_name(), &me()).unwrap();
    let wiring = Wiring {
        link,
        handler: Unwired,
        expected: expected_self(),
        parent: Arc::new(parent),
        consent: Arc::new(NoConsent),
        host: Arc::new(TestHost),
        clock: Arc::new(SystemClock::new()),
        build: None,
        settings: Settings::default(),
        limits: Limits {
            tick: Duration::from_millis(20),
            ..Limits::design()
        },
    };
    let join = std::thread::spawn(move || run(wiring));
    std::thread::sleep(Duration::from_millis(200));
    assert!(!join.is_finished());
    let _ = child.stdin.take().unwrap().write_all(b"\r\n");
    let _ = child.wait();
    let t = Instant::now();
    while !join.is_finished() {
        assert!(t.elapsed() < Duration::from_secs(10));
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(join.join().unwrap().reason, ExitReason::ParentLost);
}
