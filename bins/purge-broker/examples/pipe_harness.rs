//! A test-only harness: the broker's real pipe server (`serve::run`, the real client check, the real
//! `engine.hello` gate) over a fresh named pipe, unelevated, for the C# client tests
//! (`ui/Purge.Client.Tests/BrokerPipeTests.cs`). It is an example target: no release build contains it, and
//! `purge-broker.exe` itself has no way to skip its elevation start check.
//!
//! `pipe_harness <pipe-name> <client-pid> <client-ctime> <client-image>`: the client is the process the
//! broker expects (its pid, FILETIME creation time and image). The harness prints `READY <pipe path>`
//! once the pipe exists, then serves until the client leaves or the client process ends.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use purge_broker::lifetime::SystemClock;
use purge_broker::serve::{Consent, Host, Limits, Unwired, Wiring, run};
use purge_broker::wire::{PipeLink, ProcessParent};
use purge_engine::pipeline::Settings;
use purge_model::BaselineTrust;
use purge_rpc::{BaselineBuild, BaselineStatus, EngineHello};
use purge_win::pipe::ExpectedPeer;
use purge_win::taskdialog::{Outcome, Page};

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

struct HarnessHost {
    user_sid: String,
}

impl Host for HarnessHost {
    fn hello(&self) -> EngineHello {
        EngineHello {
            version: "0.1.0".into(),
            elevated: false,
            user_sid: self.user_sid.clone(),
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, name, pid, ctime, image] = args.as_slice() else {
        eprintln!("usage: pipe_harness <pipe-name> <client-pid> <client-ctime> <client-image>");
        std::process::exit(2);
    };
    let pid: u32 = pid.parse().expect("client pid");
    let creation_time: u64 = ctime.parse().expect("client ctime");
    let user_sid = purge_win::sid::current_user_sid().expect("user sid");

    let link = PipeLink::create(name, &user_sid).expect("create the pipe");
    let path = link.path().to_owned();
    let parent = ProcessParent::open(pid, creation_time).expect("open the client process");
    let wiring = Wiring {
        link,
        handler: Unwired,
        expected: ExpectedPeer {
            pid,
            creation_time,
            image: PathBuf::from(image),
            user_sid: user_sid.clone(),
        },
        parent: Arc::new(parent),
        consent: Arc::new(NoConsent),
        host: Arc::new(HarnessHost { user_sid }),
        clock: Arc::new(SystemClock::new()),
        build: None,
        settings: Settings::default(),
        limits: Limits {
            tick: Duration::from_millis(20),
            hello_wait: Duration::from_secs(30),
            build_grace: Duration::from_millis(50),
            max_failed: 1,
            ..Limits::design()
        },
    };
    println!("READY {path}");
    std::io::stdout().flush().expect("flush");
    let exit = run(wiring);
    eprintln!(
        "pipe_harness ended: code {} reason {:?}",
        exit.code(),
        exit.reason
    );
}
