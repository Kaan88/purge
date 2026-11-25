// Built for the Windows subsystem (M3-R2 S7, ruling on flagged point 4): a console binary gets a
// console window from `runas`, and the start-up show command applies to the process's first window,
// which is the consent TaskDialog. Failures still reach the UI through the exit code and the event
// log; stderr is written only while it is still open, and `close_std_handles` clears it afterwards.
#![windows_subsystem = "windows"]

//! `purge-broker` entry point (M3 design 3.3, 3.4, package M3-BROKER-CORE).
//!
//! Order: the DLL search is restricted to System32; the start checks run (elevation first, then the
//! directories); the command line is read; the parent process is opened and its creation time
//! compared; the pipe is created (first instance only: a name that exists ends the broker); the
//! standard handles are closed; the timing lines start going to the event log (`purge_broker::timing`,
//! the `broker_start` mark was taken right after the DLL-search and working-directory restriction);
//! the local-baseline build starts on its own thread; and the serving loop runs until it ends. The
//! timing lines are flushed for at most `FLUSH_WAIT` before the process ends. With `--consent toolkit`
//! the serving loop runs on a second thread and this one is the consent window's
//! (`serve_beside_the_window`); otherwise everything is as it was. The handler is [`purge_broker::broker::BrokerHandler`]: the flow over the live
//! machine (M3-BROKER-FLOW), `plan.execute` (M3-EXEC), history, undo and recovery (M3-UNDO) and the purge
//! of expired quarantine (M3-PURGE).

use std::process::ExitCode;
use std::sync::Arc;

use purge_broker::args::ConsentUi;
use purge_broker::baseline::{BuildHandle, LiveHost};
use purge_broker::broker::BrokerHandler;
use purge_broker::consent::toolkit::ToolkitConsent;
use purge_broker::exec_live::LiveExec;
use purge_broker::lifetime::{SystemClock, codes};
use purge_broker::live::LiveBackend;
use purge_broker::purge::Purger;
use purge_broker::serve::Consent;
use purge_broker::serve::{Limits, Wiring, run_timed};
use purge_broker::timing::{ChannelSink, FLUSH_WAIT, ProcessTimer, Timings};
use purge_broker::undo::UndoMethods;
use purge_broker::uninstall::{Flow, LiveMachine};
use purge_broker::wire::{PipeLink, ProcessParent, TaskDialogConsent};
use purge_broker::{args, start};
use purge_engine::pipeline::{self, Sources};
use purge_exec::storage::StorageRoots;
use purge_rpc::timing::{TIMING_EVENT_ID, TimingName};
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
    if let Err(failure) = start::restrict_working_directory() {
        failure.report();
        return ExitCode::from(failure.exit_code());
    }
    // Timing (design 9.1): marks count from the process creation; nothing depends on them. The
    // event-log sink is attached once the pipe exists, so a refused start writes no timing line.
    let timings = Arc::new(Timings::new(
        ProcessTimer::of_this_process(),
        std::process::id(),
    ));
    timings.mark_process(TimingName::BrokerStart);
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
    if let Some(sink) = ChannelSink::start(|line| {
        let _ = purge_win::eventlog::report_info(start::EVENT_SOURCE, TIMING_EVENT_ID, line);
    }) {
        timings.attach(sink);
    }

    let parts = Parts {
        link,
        parent,
        parent_pid: args.parent_pid,
        parent_ctime: args.parent_ctime,
        user_sid,
        started,
        timings,
    };
    match args.consent {
        ConsentUi::TaskDialog => serve(parts, Arc::new(TaskDialogConsent)),
        ConsentUi::Toolkit => serve_beside_the_window(parts),
    }
}

/// What `main` made before the pipe is served.
struct Parts {
    link: PipeLink,
    parent: ProcessParent,
    parent_pid: u32,
    parent_ctime: u64,
    user_sid: String,
    started: start::Started<StorageRoots>,
    timings: Arc<Timings>,
}

/// `--consent toolkit`: the toolkit's window loop must run on the thread the process started on
/// (`consent::toolkit::service`), so the pipe is served from a second thread and this one becomes the
/// window's. It makes no window until a dialog is asked for. If the second thread cannot be started,
/// the pipe is served here with the TaskDialog, as without the argument.
fn serve_beside_the_window(parts: Parts) -> ! {
    type Job = Box<dyn FnOnce() + Send>;
    let (hand, taken) = std::sync::mpsc::channel::<Job>();
    let spawned = std::thread::Builder::new()
        .name("purge-broker-serve".into())
        .spawn(move || {
            if let Ok(job) = taken.recv() {
                job();
            }
        });
    if spawned.is_err() {
        serve(parts, Arc::new(TaskDialogConsent));
    }
    let (consent, window) = ToolkitConsent::new();
    let job: Job = Box::new(move || serve(parts, Arc::new(consent)));
    if hand.send(job).is_ok() {
        window.run();
    }
    // The window's loop ended or never began (the dialogs are TaskDialogs from here on), or the
    // serving thread is gone. The serving thread ends the process; this one has nothing left to do.
    loop {
        std::thread::park();
    }
}

/// Serves the pipe until the broker ends, and ends the process.
fn serve(parts: Parts, consent: Arc<dyn Consent>) -> ! {
    let expected = ExpectedPeer {
        pid: parts.parent_pid,
        creation_time: parts.parent_ctime,
        image: parts.started.client_image.clone(),
        user_sid: parts.user_sid,
    };
    // The MSI table cache and the local baseline cache are the store's checked `fp\msitables` and
    // `baseline`, never the directories by path.
    let mut settings = parts.started.broker_settings();
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
        let exit = run_timed(
            Wiring {
                link: parts.link,
                handler: BrokerHandler::new(
                    Flow::new(Arc::new(LiveMachine::new(parts.started.store.clone()))),
                    Purger::from_store(parts.started.store.clone()),
                    UndoMethods::new(LiveBackend::new(
                        parts.started.store.clone(),
                        settings.purge_dirs.clone(),
                    )),
                    Arc::new(LiveExec::new(
                        parts.started.store,
                        settings.purge_dirs.clone(),
                    )),
                ),
                expected,
                parent: Arc::new(parts.parent),
                consent,
                host: Arc::new(LiveHost::new(settings.clone())),
                clock: Arc::new(SystemClock::new()),
                build: build.map(|b| Arc::new(b) as Arc<dyn BuildHandle>),
                settings: settings.clone(),
                limits: Limits::design(),
            },
            parts.timings.clone(),
        );
        parts.timings.flush(FLUSH_WAIT);
        if exit.code() != 0 {
            start::report_exit(exit.code(), &exit.line());
        }
        // The process ends here, not when the scope joins: a build still in its current part is not
        // waited for, and leaves no partial cache (its parts are renamed into place).
        std::process::exit(i32::from(exit.code()))
    })
}
