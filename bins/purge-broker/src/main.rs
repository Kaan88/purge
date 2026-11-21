//! `purge-broker` entry point (M3 design 3.3, 3.4, package M3-BROKER-CORE).
//!
//! Order: the DLL search is restricted to System32; the start checks run (elevation first, then the
//! directories); the command line is read; the parent process is opened and its creation time
//! compared; the pipe is created (first instance only: a name that exists ends the broker); the
//! standard handles are closed; the local-baseline build starts on its own thread; and the serving
//! loop runs until it ends. The handler is [`purge_broker::broker::BrokerHandler`]: the flow over the live
//! machine (M3-BROKER-FLOW), `plan.execute` (M3-EXEC), history, undo and recovery (M3-UNDO) and the purge
//! of expired quarantine (M3-PURGE).

use std::process::ExitCode;
use std::sync::Arc;

use purge_broker::baseline::{BuildHandle, LiveHost};
use purge_broker::broker::BrokerHandler;
use purge_broker::exec_live::LiveExec;
use purge_broker::lifetime::{SystemClock, codes};
use purge_broker::live::LiveBackend;
use purge_broker::purge::Purger;
use purge_broker::serve::{Limits, Wiring, run};
use purge_broker::undo::UndoMethods;
use purge_broker::uninstall::{Flow, LiveMachine};
use purge_broker::wire::{PipeLink, ProcessParent, TaskDialogConsent};
use purge_broker::{args, start};
use purge_engine::pipeline::{self, Sources};
use purge_source::live::{Live, LiveLocal};
use purge_win::pipe::{ExpectedPeer, PipeError};

/// Reports a failure that is not a start failure: the event log (id = exit code) and stderr.
fn fail(code: u8, line: &str) -> ExitCode {
    start::report_exit(code, line);
    ExitCode::from(code)
}

fn main() -> ExitCode {
    if let Err(failure) = start::restrict_dll_search() {
        failure.report();
        return ExitCode::from(failure.exit_code());
    }
    let started = match start::check() {
        Ok(started) => started,
        Err(failure) => {
            failure.report();
            return ExitCode::from(failure.exit_code());
        }
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match args::parse(&argv) {
        Ok(args) => args,
        Err(why) => {
            return fail(
                codes::BAD_ARGUMENTS,
                &format!("purge-broker did not start: {why}; {}", args::USAGE),
            );
        }
    };
    let parent = match ProcessParent::open(args.parent_pid, args.parent_ctime) {
        Ok(parent) => parent,
        Err(why) => {
            return fail(
                codes::PARENT_MISMATCH,
                &format!("purge-broker did not start: the parent is not as claimed: {why}"),
            );
        }
    };
    let user_sid = match purge_win::sid::current_user_sid() {
        Ok(sid) => sid,
        Err(e) => {
            return fail(
                codes::PIPE_TAKEN,
                &format!("purge-broker did not start: the account's SID: {e}"),
            );
        }
    };
    let link = match PipeLink::create(&args.pipe_name, &user_sid) {
        Ok(link) => link,
        Err(e) => {
            let why = match e {
                PipeError::NameTaken => "the pipe name exists already".to_owned(),
                other => other.to_string(),
            };
            return fail(
                codes::PIPE_TAKEN,
                &format!("purge-broker did not start: {why}"),
            );
        }
    };
    purge_win::os::close_std_handles();

    let expected = ExpectedPeer {
        pid: args.parent_pid,
        creation_time: args.parent_ctime,
        image: started.client_image.clone(),
        user_sid,
    };
    let mut settings = started.engine_settings();
    let live = Live::new();
    let local = LiveLocal::new();
    let sources = Sources {
        reg: &live.registry,
        fs: &live.fs,
        sys: &live.system,
    };
    std::thread::scope(|scope| {
        let build = pipeline::start_local_build(scope, sources, &settings, &local, || {
            purge_win::sxs::find_base().map_err(|e| e.to_string())
        });
        settings.local_build = build.clone();
        let exit = run(Wiring {
            link,
            handler: BrokerHandler::new(
                Flow::new(Arc::new(LiveMachine::new(started.store.clone()))),
                Purger::from_store(started.store.clone()),
                UndoMethods::new(LiveBackend::new(
                    started.store.clone(),
                    settings.purge_dirs.clone(),
                )),
                Arc::new(LiveExec::new(started.store, settings.purge_dirs.clone())),
            ),
            expected,
            parent: Arc::new(parent),
            consent: Arc::new(TaskDialogConsent),
            host: Arc::new(LiveHost::new(settings.clone())),
            clock: Arc::new(SystemClock::new()),
            build: build.map(|b| Arc::new(b) as Arc<dyn BuildHandle>),
            settings: settings.clone(),
            limits: Limits::design(),
        });
        if exit.code() != 0 {
            start::report_exit(exit.code(), &exit.line());
        }
        // The process ends here, not when the scope joins: a build still in its current part is not
        // waited for, and leaves no partial cache (its parts are renamed into place).
        std::process::exit(i32::from(exit.code()));
    });
    ExitCode::SUCCESS
}
