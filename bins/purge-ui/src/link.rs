//! The window's link to the engine and the broker (UI-WIRE): it starts the engine
//! (`purge_client::startup`), routes each [`ClientEvent`] to the model that waits for it, and turns
//! the models' requests into `purge-client` calls, keeping which call is whose.
//!
//! Everything here runs on the window's thread. The clients deliver their events from their own
//! threads into a channel; the [`Sink`]'s wake sends the host one message, and the window then
//! calls [`Link::pump`], which empties the channel and sends what the models asked for until both
//! are quiet.
//!
//! **The seam for the other pages (UI-PAGES).** A page's model gets its engine calls the way the
//! Programs page does: a request enum drained in [`Link::pump`], each call kept in `pending` with
//! what its answer is for, and its answer routed back by [`CallId`]. The one broker session is
//! [`BrokerHub`]: a page launches it for itself ([`BrokerHub::launch`]), takes it
//! ([`BrokerHub::session`]), hands it on ([`BrokerHub::hand_over`], as the removed-program check
//! hands its scan's session to the Leftovers page) and ends it ([`BrokerHub::close`]). Only one
//! page owns it at a time.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Mutex};

use purge_client::broker::{self, ConsentUi, Launch, LaunchFailure, LaunchStatus};
use purge_client::startup::{Startup, StartupResult};
use purge_client::{Answer, Broker, BrokerClient, CallId, ClientError, ClientEvent, Engine, Sink};
use purge_model::ProgramId;
use purge_rpc::error::ErrorObject;
use purge_rpc::methods::{
    IconsParams, LeftoversScanParams, NoParams, NonEmpty, PipeCall, ProgramParams, ProgramsParams,
    ScanStoredParams, StdioCall,
};
use purge_ui_model::CallError;
use purge_ui_model::pipeline::{LaunchResult, LaunchState, RemovedRequest};
use purge_ui_model::programs::page::{IconWanted, ProgramsRequest};
use purge_ui_model::programs::{EngineState, ProgramEntry, ProgramIcon};

mod flow;
// ---- UI-PAGES2: the History and Quarantine pages (`pages2`) ----
mod pages2;

use crate::icons::{self, Atlas};
use crate::markers;
use crate::model::{Mode, Model};

/// How the window starts.
#[derive(Debug, Clone)]
pub enum Source {
    /// `purge-engine.exe --stdio` at this path (beside `Purge.exe`).
    Engine(PathBuf),
    /// The sample engine (`--sample`, the scripted walk), with this many bench rows (0: its own).
    Sample { bench_rows: usize },
}

impl Source {
    /// The engine beside this exe.
    pub fn beside_exe() -> Source {
        let exe = std::env::current_exe().ok();
        let dir = exe
            .as_deref()
            .and_then(Path::parent)
            .unwrap_or(Path::new("."));
        Source::Engine(dir.join("purge-engine.exe"))
    }
}

/// `purge-client`'s failure as the models tell failures apart.
pub fn call_error(e: ClientError) -> CallError {
    match e {
        ClientError::Rpc(r) => CallError::Rpc(ErrorObject {
            code: r.code,
            message: r.message,
            data: r.data,
        }),
        ClientError::Link { reason, not_sent } => CallError::link(reason, not_sent),
        ClientError::Cancelled => CallError::Cancelled,
        ClientError::BadReply(m) | ClientError::NotAvailable(m) => CallError::Other(m),
    }
}

/// A broker launch's failure as the models see it.
fn launch_result(f: LaunchFailure) -> Result<LaunchResult, CallError> {
    let state = match f.status {
        // Purge stopped the launch itself (Stop on the check): the answer of a cancel.
        LaunchStatus::Stopped => return Err(CallError::Cancelled),
        LaunchStatus::Cancelled => LaunchState::Cancelled,
        LaunchStatus::NotAdministrator => LaunchState::NotAdministrator,
        LaunchStatus::CannotStart => LaunchState::CannotStart,
        LaunchStatus::ServerCheckFailed | LaunchStatus::TimedOut => LaunchState::Failed,
    };
    Ok(LaunchResult {
        state,
        message: f.message,
        exit_code: f.exit_code,
        declined_explanation: false,
    })
}

// ---- the broker session --------------------------------------------------------------------

/// "The administrator part is in use by the Uninstall pipeline page.": the holder by its
/// page's name.
pub fn in_use(holder: Owner) -> String {
    format!(
        "The administrator part is in use by the {} page.",
        holder.page_name()
    )
}

/// Who holds the one broker session. The broker serves one client at a time, so the pages take
/// turns.
// Every page takes the broker through `launch_for` (link/flow.rs).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Owner {
    /// The Programs page's check of a program removed outside Purge.
    Removed,
    /// The Uninstall page.
    Pipeline,
    /// The Leftovers page (it also gets the removed check's session with its scan).
    Leftovers,
    /// The History page (undo).
    History,
    /// The Quarantine page (purge).
    Vault,
}

impl Owner {
    /// The name of the page, as the rail shows it.
    pub fn page_name(self) -> &'static str {
        use crate::model::Page;
        match self {
            Owner::Removed => Page::Programs,
            Owner::Pipeline => Page::Pipeline,
            Owner::Leftovers => Page::Leftovers,
            Owner::History => Page::History,
            Owner::Vault => Page::Quarantine,
        }
        .title()
    }
}

/// The one broker session, and the launch of it while one runs. The session is a
/// [`BrokerClient`], or with sample data the [`crate::sample_broker::SampleBroker`].
#[derive(Default)]
pub struct BrokerHub {
    session: Option<(Owner, Arc<dyn Broker>)>,
    launching: Option<(Owner, Launch)>,
    /// Who draws the broker's consent dialog: every launch passes it on (`--broker-consent`; the
    /// TaskDialog unless that names the toolkit).
    pub consent: ConsentUi,
}

impl BrokerHub {
    /// Starts the elevated broker for `owner` (the Windows prompt shows); the answer comes as a
    /// [`ClientEvent::BrokerLaunched`] with the returned call. `Err` with the sentence to show when
    /// another page holds a live broker or there is no broker beside the app. Another page's
    /// session that is no longer live is dropped, never a reason to refuse.
    pub fn launch(&mut self, owner: Owner, sink: Sink) -> Result<CallId, String> {
        // The caller (`launch_now`) has dropped another page's dead session already and told
        // that page; the only session that can have died since is `owner`'s own, which it is
        // replacing. Another page's, dropped here, would go untold (review N10).
        let dropped = self.drop_dead();
        debug_assert!(
            dropped.is_none_or(|o| o == owner),
            "{dropped:?}'s dead session was dropped without telling its page"
        );
        if let Some((other, _)) = self.session.as_ref().filter(|(o, _)| *o != owner) {
            return Err(in_use(*other));
        }
        if self.launching.is_some() {
            return Err("The administrator part is starting.".into());
        }
        let Some(path) = broker::broker_beside_app().filter(|p| p.is_file()) else {
            return Err("purge-broker.exe is not beside Purge.exe.".into());
        };
        let launch = broker::launch_with(&path, self.consent, sink);
        let call = launch.call;
        self.launching = Some((owner, launch));
        Ok(call)
    }

    /// Stops `owner`'s launch: its answer comes back as stopped.
    pub fn stop_launch(&mut self, owner: Owner) -> bool {
        match &self.launching {
            Some((o, l)) if *o == owner => {
                l.stop();
                true
            }
            _ => false,
        }
    }

    /// The launch `call` ended: whose it was. A started session goes to that owner.
    fn launched(
        &mut self,
        call: CallId,
        result: &Result<Arc<BrokerClient>, LaunchFailure>,
    ) -> Option<Owner> {
        let owner = match &self.launching {
            Some((o, l)) if l.call == call => *o,
            _ => return None,
        };
        self.launching = None;
        if let Ok(client) = result {
            let client: Arc<dyn Broker> = client.clone();
            self.session = Some((owner, client));
        }
        Some(owner)
    }

    /// Drops a session whose link has ended (its `BrokerClosed` may not have come yet): whose it
    /// was, so that page can be told.
    pub fn drop_dead(&mut self) -> Option<Owner> {
        if self.session.as_ref().is_some_and(|(_, c)| !c.is_live())
            && let Some((owner, c)) = self.session.take()
        {
            c.close();
            return Some(owner);
        }
        None
    }

    /// Gives `owner` a session made without a launch (the sample broker). A session another
    /// page held is ended first.
    pub fn adopt(&mut self, owner: Owner, session: Arc<dyn Broker>) {
        if let Some((_, old)) = self.session.replace((owner, session)) {
            old.close();
        }
    }

    /// Who holds a live session, if any page does.
    pub fn holder(&self) -> Option<Owner> {
        self.session
            .as_ref()
            .filter(|(_, c)| c.is_live())
            .map(|(o, _)| *o)
    }

    /// The live session, when `owner` holds it.
    pub fn session(&self, owner: Owner) -> Option<&Arc<dyn Broker>> {
        self.session
            .as_ref()
            .filter(|(o, c)| *o == owner && c.is_live())
            .map(|(_, c)| c)
    }

    /// Hands the session from `from` to `to` (the link stays open). False when `from` does not
    /// hold one.
    pub fn hand_over(&mut self, from: Owner, to: Owner) -> bool {
        match &mut self.session {
            Some((o, _)) if *o == from => {
                *o = to;
                true
            }
            _ => false,
        }
    }

    /// Ends `owner`'s session (the broker exits).
    pub fn close(&mut self, owner: Owner) {
        if self.session.as_ref().is_some_and(|(o, _)| *o == owner)
            && let Some((_, c)) = self.session.take()
        {
            c.close();
        }
    }

    /// The broker link of session `session` ended: whoever held it holds nothing any more. An
    /// older session's end (a page took a new one since) changes nothing.
    fn closed(&mut self, session: u64) -> Option<Owner> {
        match &self.session {
            Some((o, c)) if c.session() == session || !c.is_live() => {
                let owner = *o;
                self.session = None;
                Some(owner)
            }
            _ => None,
        }
    }
}

impl Drop for BrokerHub {
    fn drop(&mut self) {
        if let Some((_, l)) = &self.launching {
            l.stop();
        }
        if let Some((_, c)) = self.session.take() {
            c.close();
        }
    }
}

// ---- the link ------------------------------------------------------------------------------

/// What a call in flight is for.
#[derive(Debug)]
enum Pending {
    List,
    Changes,
    Details(ProgramId),
    Sizes(u64),
    Icons(u64),
    Forget,
    CheckStored,
    CheckScan,
    /// A call of the Uninstall or the Leftovers page (UI-FLOW, `link/flow.rs`).
    Flow(flow::Call),
}

/// The icons of the current enrichment still to fetch.
#[derive(Default)]
struct IconLoad {
    generation: u64,
    stamps: HashMap<ProgramId, i64>,
    chunks: VecDeque<Vec<ProgramId>>,
    in_flight: Option<CallId>,
}

pub struct Link {
    rx: Receiver<ClientEvent>,
    sink: Sink,
    engine: Option<Arc<dyn Engine>>,
    /// Where the data comes from: `Starting` until the startup has answered. Only `Sample` (an
    /// explicit `--sample`) plays the made-up broker; `Fallback` refuses every change.
    pub mode: Mode,
    /// `--sample` was asked for (the startup's answer then is `Sample`, not `Fallback`).
    sample_asked: bool,
    pending: HashMap<CallId, Pending>,
    icons: IconLoad,
    atlas: Atlas,
    /// The broker call of the removed-program check in flight.
    check_call: Option<CallId>,
    pub broker: BrokerHub,
    /// What the uninstall flow last told the Programs page and itself (`link/flow.rs`).
    flow: flow::Seen,
    /// UI-PAGES2: the History and Quarantine pages' calls.
    pages: pages2::Pages,
}

impl Link {
    /// A link whose clients wake the window with `wake`.
    pub fn new(wake: impl Fn() + Send + 'static) -> Link {
        let (tx, rx) = channel();
        // The host's proxy may not be shareable across threads: one at a time is enough.
        let wake = Mutex::new(wake);
        let sink = Sink::new(
            tx,
            Arc::new(move || {
                if let Ok(w) = wake.lock() {
                    w();
                }
            }),
        );
        Link {
            rx,
            sink,
            engine: None,
            mode: Mode::Starting,
            sample_asked: false,
            pending: HashMap::new(),
            icons: IconLoad::default(),
            atlas: Atlas::open(None),
            check_call: None,
            broker: BrokerHub::default(),
            flow: flow::Seen::default(),
            pages: pages2::Pages::default(),
        }
    }

    /// Starts the engine (or the sample) on a background thread; its answer arrives through
    /// [`Link::pump`].
    pub fn start(&mut self, source: &Source) {
        self.sample_asked = matches!(source, Source::Sample { .. });
        let startup = match source {
            Source::Engine(path) => Startup::engine(path.clone()),
            Source::Sample { bench_rows } => Startup::sample().bench_rows(*bench_rows),
        };
        startup
            .on_engine_ready(Box::new(|| {
                markers::mark("engine_ready");
            }))
            .on_list_reply(Box::new(|| {
                markers::mark("list_reply");
            }))
            .start(self.sink.clone());
    }

    /// Empties the channel into the models and sends what they asked for, until both are quiet.
    /// True when anything changed (the window draws again).
    pub fn pump(&mut self, model: &mut Model) -> bool {
        let mut changed = false;
        for _ in 0..10_000 {
            let mut busy = false;
            while let Ok(event) = self.rx.try_recv() {
                self.on_event(model, event);
                busy = true;
            }
            let requests = std::mem::take(&mut model.programs.out);
            for r in requests {
                self.send(model, r);
                busy = true;
            }
            busy |= self.flow_pump(model);
            // UI-PAGES2.
            busy |= self.pages_pump(model);
            if !busy {
                break;
            }
            changed = true;
        }
        changed
    }

    // ---- events ------------------------------------------------------------------------------

    fn on_event(&mut self, model: &mut Model, event: ClientEvent) {
        let pr = &mut model.programs;
        match event {
            ClientEvent::Startup(s) => self.on_startup(model, *s),
            ClientEvent::Reply { call, result } => self.on_reply(model, call, result),
            ClientEvent::Sizes { call, sizes } => {
                if let Some(Pending::Sizes(generation)) = self.pending.get(&call) {
                    let r = pr.page.on_sizes(*generation, &sizes);
                    pr.take(r);
                }
            }
            ClientEvent::Icons { call, icons } => {
                if let Some(Pending::Icons(generation)) = self.pending.get(&call) {
                    let generation = *generation;
                    for icon in icons {
                        if let Some(bgra) = &icon.bgra
                            && let Some(stamp) = self.icons.stamps.get(&icon.program_id)
                        {
                            self.atlas
                                .put(&icons::key_of(&icon.program_id), *stamp, icon.px, bgra);
                        }
                        pr.set_icon(
                            generation,
                            ProgramIcon {
                                program_id: icon.program_id,
                                px: icon.px,
                                bgra: icon.bgra,
                            },
                        );
                    }
                    pr.sync();
                }
            }
            ClientEvent::Progress { call, progress } => {
                // UI-PAGES2.
                if self.pages_progress(model, call, &progress) {
                    return;
                }
                let pr = &mut model.programs;
                if self.check_call == Some(call) {
                    pr.page.on_check_progress(&progress.phase);
                    pr.sync();
                }
                if let Some(Pending::Flow(what)) = self.pending.get(&call) {
                    let what = *what;
                    self.flow_progress(model, what, &progress);
                }
            }
            ClientEvent::ProgramsPatched(patches) => {
                let r = pr.page.on_late_patches(&patches);
                pr.take(r);
            }
            ClientEvent::EngineClosed { reason } => {
                pr.page
                    .show_engine_notice(&format!("Purge's engine stopped: {reason}"));
                let r = pr.page.set_engine(EngineState::default());
                pr.take(r);
            }
            ClientEvent::BrokerClosed { session, .. } => {
                if let Some(owner) = self.broker.closed(session) {
                    self.flow_broker_closed(model, owner);
                }
            }
            ClientEvent::BrokerLaunched { call, result } => {
                if let Some(owner) = self.broker.launched(call, &result) {
                    let answer = match result {
                        Ok(_) => Ok(LaunchResult::started()),
                        Err(f) => launch_result(f),
                    };
                    self.on_launched(model, owner, answer);
                }
            }
            ClientEvent::ConsentShown { call, shown } => {
                if let Some(Pending::Flow(what)) = call.and_then(|c| self.pending.get(&c)) {
                    let what = *what;
                    self.flow_consent(model, what, &shown);
                }
            }
            ClientEvent::BaselineChanged(changed) => {
                model.flow.leftovers.on_baseline_changed(&changed);
            }
        }
    }

    fn on_startup(&mut self, model: &mut Model, s: StartupResult) {
        let live = s.error.is_none() && s.engine.is_live();
        self.mode = match &s.error {
            _ if live => Mode::Live,
            None if self.sample_asked => Mode::Sample,
            Some(notice) => Mode::Fallback(notice.clone()),
            None => Mode::Fallback(purge_client::startup::FALLBACK_NOTICE.trim_end().to_owned()),
        };
        let can_change_pc = live && s.engine.can_change_pc();
        self.engine = Some(s.engine.clone());
        self.pending.insert(s.changes, Pending::Changes);
        // A live engine's icons are kept between runs; the sample's are not.
        self.atlas = Atlas::open(if live { icons::default_file() } else { None });
        model.mode = self.mode.clone();
        if live {
            model.settings.facts.engine = Some(s.hello.hello.version.clone());
            model.settings.facts.policy = Some(s.hello.hello.policy_version.clone());
        }
        let pr = &mut model.programs;
        let r = pr.page.set_engine(EngineState {
            live,
            can_change_pc,
        });
        pr.take(r);
        let r = pr
            .page
            .on_list(Ok(ProgramEntry::from_list(&s.list.rows, &s.list.patches)));
        pr.take(r);
        pr.loaded = true;
        if let Some(notice) = &s.error {
            pr.page.show_engine_notice(notice);
            pr.sync();
        }
    }

    fn on_reply(&mut self, model: &mut Model, call: CallId, result: Result<Answer, ClientError>) {
        if self.icons.in_flight == Some(call) {
            self.icons.in_flight = None;
        }
        if self.check_call == Some(call) {
            self.check_call = None;
        }
        // UI-PAGES2.
        let Some(result) = self.pages_reply(model, call, result) else {
            return;
        };
        let Some(what) = self.pending.remove(&call) else {
            return;
        };
        if let Pending::Flow(what) = what {
            return self.flow_reply(model, what, result);
        }
        let pr = &mut model.programs;
        let r = match (what, result) {
            (Pending::List, Ok(Answer::Programs(l))) => pr
                .page
                .on_list(Ok(ProgramEntry::from_list(&l.rows, &l.patches))),
            (Pending::List, r) => pr.page.on_list(Err(failure(r))),
            (Pending::Changes, Ok(Answer::InventoryChanges(c))) => pr.page.on_changes(Some(c)),
            (Pending::Changes, _) => pr.page.on_changes(None),
            (Pending::Details(id), Ok(Answer::Program(d))) => pr.page.on_details(&id, Ok(d)),
            (Pending::Details(id), r) => pr.page.on_details(&id, Err(failure(r))),
            (Pending::Sizes(g), Ok(_)) => pr.page.on_sizes_done(g, Ok(())),
            (Pending::Sizes(g), Err(e)) => pr.page.on_sizes_done(g, Err(call_error(e))),
            (Pending::Icons(g), _) => {
                // A failed chunk leaves its rows with their tiles; the next chunk still goes.
                if g == self.icons.generation {
                    self.next_icons();
                }
                vec![]
            }
            // A failed forget is asked again by the next session's changes.
            (Pending::Forget, _) => vec![],
            (Pending::CheckStored, Ok(Answer::Stored(s))) => pr.page.on_check_stored(Ok(s.stored)),
            (Pending::CheckStored, r) => pr.page.on_check_stored(Err(failure(r))),
            (Pending::CheckScan, Ok(Answer::Scan(s))) => pr.page.on_check_scan(Ok(s)),
            (Pending::CheckScan, r) => pr.page.on_check_scan(Err(failure(r))),
            (Pending::Flow(_), _) => vec![],
        };
        pr.take(r);
    }

    // ---- requests ----------------------------------------------------------------------------

    fn engine_call(&mut self, call: StdioCall, what: Pending) -> Option<CallId> {
        let engine = self.engine.as_ref()?;
        let id = engine.request(call);
        self.pending.insert(id, what);
        Some(id)
    }

    fn send(&mut self, model: &mut Model, request: ProgramsRequest) {
        let pr = &mut model.programs;
        match request {
            ProgramsRequest::List => {
                self.engine_call(StdioCall::ProgramsList(NoParams {}), Pending::List);
            }
            ProgramsRequest::Details { program_id } => {
                let call = StdioCall::ProgramsGet(ProgramParams {
                    program_id: program_id.clone(),
                });
                self.engine_call(call, Pending::Details(program_id));
            }
            ProgramsRequest::Sizes {
                generation,
                program_ids,
            } => match NonEmpty::new(program_ids) {
                Some(program_ids) => {
                    let call = StdioCall::ProgramsSizes(ProgramsParams { program_ids });
                    self.engine_call(call, Pending::Sizes(generation));
                }
                None => {
                    let r = pr.page.on_sizes_done(generation, Ok(()));
                    pr.take(r);
                }
            },
            ProgramsRequest::Icons { generation, wanted } => {
                self.start_icons(model, generation, wanted);
            }
            ProgramsRequest::Forecasts { .. } => {
                // The engine has no `programs.forecast` yet: it knows no forecast for any program,
                // so every row and details pane says "Not known yet" (an error would leave the
                // pane "Checking..." for good).
                let r = pr.page.on_forecasts(Ok(Vec::new()));
                pr.take(r);
            }
            ProgramsRequest::Forget { program_ids } => {
                if let Some(program_ids) = NonEmpty::new(program_ids) {
                    let call = StdioCall::InventoryForget(ProgramsParams { program_ids });
                    self.engine_call(call, Pending::Forget);
                }
            }
            ProgramsRequest::Check(check) => self.check(model, check),
            ProgramsRequest::OpenLeftovers(outcome) => self.show_stored(model, outcome),
            ProgramsRequest::CloseCheckSession => self.broker.close(Owner::Removed),
            // The Uninstall page reads whether a check runs each time it is drawn or acted on.
            ProgramsRequest::CheckRunningChanged => {}
            ProgramsRequest::Uninstall { targets } => {
                model.open_uninstall(targets);
            }
            ProgramsRequest::OpenFolder { path } => {
                if !open_folder(Path::new(&path)) {
                    pr.page.folder_missing();
                    pr.sync();
                }
            }
            ProgramsRequest::OpenWeb { url } => open_url(&url),
            ProgramsRequest::ScrollIntoView(id) => pr.scroll_to = Some(id),
        }
    }

    /// An icon request: the atlas's icons at once, the rest from the engine in chunks, one after
    /// another. A newer generation replaces what is left of an older one.
    fn start_icons(&mut self, model: &mut Model, generation: u64, wanted: Vec<IconWanted>) {
        if let Some(old) = self.icons.in_flight.take()
            && let Some(engine) = &self.engine
        {
            engine.cancel(old);
        }
        self.icons = IconLoad {
            generation,
            ..IconLoad::default()
        };
        let pr = &mut model.programs;
        let mut misses = Vec::new();
        for w in wanted {
            let stamp = icons::stamp(w.version.as_deref(), w.install_time);
            match self.atlas.get(&icons::key_of(&w.program_id), stamp) {
                Some(hit) => pr.set_icon(
                    generation,
                    ProgramIcon {
                        program_id: w.program_id.clone(),
                        px: hit.px,
                        bgra: Some(hit.bgra.clone()),
                    },
                ),
                None => misses.push(w.program_id.clone()),
            }
            self.icons.stamps.insert(w.program_id, stamp);
        }
        pr.sync();
        self.icons.chunks = misses.chunks(icons::CHUNK).map(<[_]>::to_vec).collect();
        self.next_icons();
    }

    fn next_icons(&mut self) {
        let Some(chunk) = self.icons.chunks.pop_front() else {
            // Done: what was fetched is kept for the next start.
            self.atlas.save();
            return;
        };
        let Some(program_ids) = NonEmpty::new(chunk) else {
            return self.next_icons();
        };
        let call = StdioCall::ProgramsIcons(IconsParams {
            program_ids,
            px: icons::PX,
        });
        let generation = self.icons.generation;
        self.icons.in_flight = self.engine_call(call, Pending::Icons(generation));
    }

    /// A request of the removed-program check.
    fn check(&mut self, model: &mut Model, check: RemovedRequest) {
        let pr = &mut model.programs;
        let broker_call = |link: &mut Link, call: PipeCall, what: Pending| -> bool {
            let Some(session) = link.broker.session(Owner::Removed).cloned() else {
                return false;
            };
            let id = session.request(call);
            link.pending.insert(id, what);
            link.check_call = Some(id);
            true
        };
        match check {
            // Through the first-elevation explanation, as every launch (`link/flow.rs`).
            RemovedRequest::Launch => self.launch_for(model, Owner::Removed, false),
            RemovedRequest::Stored { program_ids } => {
                let sent = NonEmpty::new(program_ids).is_some_and(|program_ids| {
                    broker_call(
                        self,
                        PipeCall::LeftoversStored(ProgramsParams { program_ids }),
                        Pending::CheckStored,
                    )
                });
                if !sent {
                    let r = pr.page.on_check_stored(Err(no_session()));
                    pr.take(r);
                }
            }
            RemovedRequest::ScanStored { program_id } => {
                let call = PipeCall::LeftoversScan(LeftoversScanParams::Stored(ScanStoredParams {
                    program_id,
                }));
                if !broker_call(self, call, Pending::CheckScan) {
                    let r = pr.page.on_check_scan(Err(no_session()));
                    pr.take(r);
                }
            }
            RemovedRequest::Cancel => {
                if !self.broker.stop_launch(Owner::Removed)
                    && let Some(call) = self.check_call
                    && let Some(session) = self.broker.session(Owner::Removed)
                {
                    session.cancel(call);
                }
            }
            RemovedRequest::CloseBroker => self.broker.close(Owner::Removed),
            // The model shows the bar; the window has nothing to undo.
            RemovedRequest::AdminPromptCancelled { .. } => {}
            // The model hands this over as `OpenLeftovers`, never as a request.
            RemovedRequest::Completed(_) => {}
        }
    }
}

/// The answer of a call that was not the one asked for, or its failure.
fn failure(result: Result<Answer, ClientError>) -> CallError {
    match result {
        Err(e) => call_error(e),
        Ok(other) => CallError::Other(format!("An answer of another kind came: {other:?}")),
    }
}

fn no_session() -> CallError {
    CallError::link("The administrator part is not running.", true)
}

/// Opens `dir` in File Explorer; false when it is not a folder on this PC.
fn open_folder(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Explorer reads its own command line: the path is quoted as one argument, as the WinUI
        // app passed it.
        let _ = std::process::Command::new("explorer.exe")
            .raw_arg(format!("\"{}\"", dir.display()))
            .spawn();
    }
    true
}

/// Opens `url` in the default browser.
fn open_url(url: &str) {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
        let (verb, file) = (wide("open"), wide(url));
        // SAFETY: both strings are NUL-terminated and live across the call; the other pointers
        // are null, which the function accepts.
        unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            );
        }
    }
    #[cfg(not(windows))]
    let _ = url;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::tests::sample_programs;
    use crate::prefs::Prefs;

    #[test]
    fn a_client_error_keeps_its_kind_and_whether_it_was_sent() {
        let e = call_error(ClientError::Link {
            reason: "gone".into(),
            not_sent: true,
        });
        assert_eq!(e, CallError::link("gone", true));
        assert_eq!(call_error(ClientError::Cancelled), CallError::Cancelled);
        assert_eq!(
            call_error(ClientError::NotAvailable("no".into())),
            CallError::Other("no".into())
        );
    }

    #[test]
    fn the_sample_start_fills_the_programs_page() {
        let mut link = Link::new(|| {});
        let mut model = Model::new(Prefs::default(), sample_programs(), true);
        model.programs = crate::model::Programs::new(crate::model::tests::clock(), |_| false);
        link.start(&Source::Sample { bench_rows: 0 });
        let t0 = std::time::Instant::now();
        while link.mode == Mode::Starting && t0.elapsed().as_secs() < 10 {
            link.pump(&mut model);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(link.mode, Mode::Sample);
        assert!(model.sample());
        assert!(!model.programs.rows.is_empty());
        assert!(
            model.programs.view.notice.is_none(),
            "sample data asked for: no notice"
        );
        let r = model.programs.page.on_first_frame();
        model.programs.take(r);
        link.pump(&mut model);
        let t0 = std::time::Instant::now();
        while model.programs.all.iter().all(|p| p.icon.is_none()) && t0.elapsed().as_secs() < 10 {
            link.pump(&mut model);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(model.programs.all.iter().all(|p| p.junk == "Not known yet"));
        assert!(
            model.programs.all.iter().any(|p| p.icon.is_some()),
            "the sample's icons reach the rows"
        );
    }

    #[test]
    fn a_missing_engine_falls_back_to_the_sample_with_the_notice() {
        let mut link = Link::new(|| {});
        let mut model = Model::new(Prefs::default(), sample_programs(), false);
        model.programs = crate::model::Programs::new(crate::model::tests::clock(), |_| false);
        link.start(&Source::Engine(PathBuf::from(
            r"Z:\no\such\purge-engine.exe",
        )));
        let t0 = std::time::Instant::now();
        while link.mode == Mode::Starting && t0.elapsed().as_secs() < 30 {
            link.pump(&mut model);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(matches!(link.mode, Mode::Fallback(_)), "{:?}", link.mode);
        assert!(
            !model.sample(),
            "a failed engine never plays the pretend flow"
        );
        let notice = model
            .programs
            .view
            .notice
            .as_ref()
            .expect("the fallback notice");
        assert!(
            notice
                .message
                .starts_with(purge_client::startup::FALLBACK_NOTICE),
            "{}",
            notice.message
        );

        // Review SF5: History and Quarantine never list the sample engine's made-up cleanups;
        // they say why their lists are empty.
        let notice = purge_client::startup::FALLBACK_NOTICE.trim_end();
        model.page = crate::model::Page::History;
        let t0 = std::time::Instant::now();
        while model
            .history
            .page
            .state_panel()
            .is_some_and(|(_, d, _)| d.is_empty())
            && t0.elapsed().as_secs() < 10
        {
            link.pump(&mut model);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(model.history.page.sessions().is_empty());
        let (_, detail, _) = model.history.page.state_panel().expect("History's panel");
        assert!(detail.contains(notice), "{detail}");

        model.page = crate::model::Page::Quarantine;
        let t0 = std::time::Instant::now();
        while model.quarantine.page.error().is_none() && t0.elapsed().as_secs() < 10 {
            link.pump(&mut model);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(model.quarantine.page.batches().is_empty());
        let error = model.quarantine.page.error().unwrap_or_default();
        assert!(error.contains(notice), "{error}");
    }
}
