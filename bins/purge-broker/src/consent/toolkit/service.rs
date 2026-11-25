//! The toolkit dialog as the broker's [`Consent`]: [`ToolkitConsent`] on the request's thread, and
//! [`UiThread`], which the process's first thread runs for as long as the broker lives.
//!
//! **Threads.** The toolkit's window loop must be on the thread the process started on, and can be
//! made once. So with the toolkit dialog chosen, `main` serves the pipe from a second thread and gives
//! its own to [`UiThread::run`], which sleeps until the first dialog is asked for and only then makes
//! the loop and the window. A broker that never asks never makes either.
//!
//! **One answer, and only from a dialog that was up.** A request puts one job at the desk and waits.
//! The window takes the job, says when it is on screen, and says how it ended; an answer is taken only
//! from the job that is at the desk, only once it was on screen, and only once. Everything else is
//! Cancel or the TaskDialog:
//!
//! | What happens | The request gets |
//! |---|---|
//! | The loop or the window cannot be made, the window does not come up within [`SHOW_WAIT`], or the window's thread died before the dialog was on screen | the TaskDialog, for this dialog and (when the thread died) every later one |
//! | The parent is gone or the pipe broke ([`Closer`]), before or while the dialog is up | [`Outcome::Declined`] at once; the window is told to take the dialog down |
//! | The window's thread died while the dialog was up | [`Outcome::Declined`] |
//! | The user answered | that answer |
//!
//! The request never waits on the window to learn that the broker is ending: the closer wakes the
//! request itself. Nor does it wait on a window that died: that is a flag of its own, set without the
//! lock (a panic may come while the window's thread holds it) and looked at four times a second by
//! every wait.

use std::cell::Cell;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use mdshared_ui::gfx::Gfx;
use mdshared_ui::host::{self, Config, Proxy};
use mdshared_ui::platform;
use purge_win::taskdialog::{Outcome, Page};

use super::super::sheet::Sheet;
use super::app::{ConsentApp, Desk, Msg, opening_size, work_height};
use super::draw::{MIN_HEIGHT, WIDTH};
use super::look::Look;
use crate::lifetime::Closer;
use crate::serve::Consent;
use crate::wire::TaskDialogConsent;

/// How long a request waits for the toolkit window to show its dialog before it asks with the
/// TaskDialog instead.
pub const SHOW_WAIT: Duration = Duration::from_secs(10);

/// How long a wait sleeps at most before it looks again at whether the window died.
const LOOK_AGAIN: Duration = Duration::from_millis(250);

/// Where the window's thread is.
enum Ui {
    /// Not asked for yet: [`UiThread::run`] sleeps.
    Idle,
    /// Asked for; the loop is being made.
    Starting,
    /// The loop runs.
    Running(Proxy<Msg>),
    /// The loop ended or its thread died: the TaskDialog from here on. ([`Core::dead`] says so
    /// first; this follows when the lock can be had.)
    Dead,
}

/// How far the job at the desk is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Waiting for the window to take it.
    Posted,
    /// The window has it, and has not shown it yet.
    Taken,
    /// On screen.
    Shown,
    /// Answered.
    Done(Outcome),
    /// No longer wanted: the request has gone on without it.
    Dropped,
}

struct Job {
    id: u64,
    sheet: Arc<Sheet>,
    phase: Phase,
}

struct State {
    ui: Ui,
    next: u64,
    job: Option<Job>,
}

/// What the request's thread and the window's thread share.
pub(super) struct Core {
    state: Mutex<State>,
    changed: Condvar,
    /// The window's thread is gone. Set without the lock.
    dead: AtomicBool,
}

impl Core {
    pub(super) fn new() -> Core {
        Core {
            state: Mutex::new(State {
                ui: Ui::Idle,
                next: 1,
                job: None,
            }),
            changed: Condvar::new(),
            dead: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The window's thread is gone, or never came to be. Callable from a panic on that thread,
    /// whatever it holds: the flag needs no lock, and the state follows only if the lock is free.
    pub(super) fn died(&self) {
        self.dead.store(true, Ordering::SeqCst);
        if let Ok(mut state) = self.state.try_lock() {
            state.ui = Ui::Dead;
        }
        self.changed.notify_all();
    }

    /// Whether the window's thread is gone.
    fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    /// The request no longer wants job `id`: it is dropped unless it is answered already, and the
    /// window is told to take it down.
    fn drop_job(&self, id: u64) {
        let mut guard = self.lock();
        let state = &mut *guard;
        let Some(job) = state.job.as_mut().filter(|j| j.id == id) else {
            return;
        };
        if matches!(job.phase, Phase::Done(_) | Phase::Dropped) {
            return;
        }
        job.phase = Phase::Dropped;
        if let Ui::Running(proxy) = &state.ui {
            proxy.send(Msg::Close(id));
        }
        drop(guard);
        self.changed.notify_all();
    }

    /// Job `id` leaves the desk: what the window says of it from now on is nobody's.
    fn clear(&self, id: u64) {
        let mut state = self.lock();
        if state.job.as_ref().is_some_and(|j| j.id == id) {
            state.job = None;
        }
    }

    /// Posts a job and wakes the window. `None` when there is no window to ask.
    fn post(&self, sheet: Arc<Sheet>) -> Option<u64> {
        let mut guard = self.lock();
        let state = &mut *guard;
        if self.is_dead() || matches!(state.ui, Ui::Dead) {
            state.ui = Ui::Dead;
            return None;
        }
        let id = state.next;
        state.next += 1;
        state.job = Some(Job {
            id,
            sheet,
            phase: Phase::Posted,
        });
        // A window that is starting takes whatever waits when it starts; one that runs is told.
        let sent = match &state.ui {
            Ui::Running(proxy) => proxy.send(Msg::Show(id)),
            _ => true,
        };
        if matches!(state.ui, Ui::Idle) {
            state.ui = Ui::Starting;
        }
        if !sent {
            // The loop has ended without a word.
            state.ui = Ui::Dead;
            state.job = None;
        }
        drop(guard);
        self.changed.notify_all();
        sent.then_some(id)
    }

    /// Waits until `done` says so or `until` passes; answers what `done` found, `None` on the time.
    /// `done` is asked again at every change and at least every [`LOOK_AGAIN`], so that it sees
    /// [`Core::is_dead`] turn without being told.
    fn wait<T>(
        &self,
        until: Option<Instant>,
        mut done: impl FnMut(&State) -> Option<T>,
    ) -> Option<T> {
        let mut state = self.lock();
        loop {
            if let Some(found) = done(&state) {
                return Some(found);
            }
            let nap = match until {
                None => LOOK_AGAIN,
                Some(at) => {
                    let left = at.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return None;
                    }
                    left.min(LOOK_AGAIN)
                }
            };
            state = self
                .changed
                .wait_timeout(state, nap)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    fn phase_of(state: &State, id: u64) -> Phase {
        state
            .job
            .as_ref()
            .filter(|j| j.id == id)
            .map_or(Phase::Dropped, |j| j.phase)
    }

    /// Asks with the toolkit window. `Err(())`: it could not show the dialog, and nothing was
    /// shown or answered; the caller asks another way.
    fn ask(
        self: &Arc<Core>,
        sheet: &Sheet,
        closer: &Closer,
        shown: &(dyn Fn() + Sync),
    ) -> Result<Outcome, ()> {
        let Some(id) = self.post(Arc::new(sheet.clone())) else {
            return Err(());
        };
        let core = self.clone();
        closer.arm(move || core.drop_job(id));

        /// How the wait for the window ended.
        enum Up {
            Shown,
            Closed,
            Failed,
        }
        let up = self
            .wait(
                Some(Instant::now() + SHOW_WAIT),
                |state| match Core::phase_of(state, id) {
                    Phase::Shown | Phase::Done(_) => Some(Up::Shown),
                    Phase::Dropped => Some(Up::Closed),
                    Phase::Posted | Phase::Taken => self.is_dead().then_some(Up::Failed),
                },
            )
            .unwrap_or(Up::Failed);
        let outcome = match up {
            Up::Failed => {
                // Not on screen and never will be for this request: whatever the window does with
                // the job now is ignored.
                self.drop_job(id);
                closer.disarm();
                self.clear(id);
                return Err(());
            }
            Up::Closed => Outcome::Declined,
            Up::Shown => {
                shown();
                self.wait(None, |state| match Core::phase_of(state, id) {
                    Phase::Done(outcome) => Some(outcome),
                    Phase::Dropped => Some(Outcome::Declined),
                    _ => self.is_dead().then_some(Outcome::Declined),
                })
                .unwrap_or(Outcome::Declined)
            }
        };
        closer.disarm();
        // The job leaves the desk: an answer that arrives now is nobody's.
        self.drop_job(id);
        self.clear(id);
        Ok(outcome)
    }
}

impl Desk for Arc<Core> {
    fn started(&self, proxy: Proxy<Msg>) {
        let mut state = self.lock();
        if !self.is_dead() && !matches!(state.ui, Ui::Dead) {
            state.ui = Ui::Running(proxy);
        }
    }

    fn take(&self, id: Option<u64>) -> Option<(u64, Arc<Sheet>)> {
        if self.is_dead() {
            return None;
        }
        let mut state = self.lock();
        let job = state
            .job
            .as_mut()
            .filter(|j| j.phase == Phase::Posted && id.is_none_or(|id| id == j.id))?;
        job.phase = Phase::Taken;
        Some((job.id, job.sheet.clone()))
    }

    fn shown(&self, id: u64) {
        if self.is_dead() {
            return;
        }
        let mut state = self.lock();
        if let Some(job) = state
            .job
            .as_mut()
            .filter(|j| j.id == id && j.phase == Phase::Taken)
        {
            job.phase = Phase::Shown;
        }
        drop(state);
        self.changed.notify_all();
    }

    /// The only place an answer enters: for the job at the desk, once, only while it is on
    /// screen, and never from a window that was declared dead.
    fn answered(&self, id: u64, outcome: Outcome) {
        if self.is_dead() {
            return;
        }
        let mut state = self.lock();
        if let Some(job) = state
            .job
            .as_mut()
            .filter(|j| j.id == id && j.phase == Phase::Shown)
        {
            job.phase = Phase::Done(outcome);
        }
        drop(state);
        self.changed.notify_all();
    }
}

/// The broker's consent dialog drawn by the toolkit, with the TaskDialog behind it.
#[derive(Clone)]
pub struct ToolkitConsent {
    core: Arc<Core>,
    fallback: TaskDialogConsent,
}

/// The window's side of a [`ToolkitConsent`]: run it on the thread the process started on.
pub struct UiThread {
    core: Arc<Core>,
}

thread_local! {
    /// This thread runs the window: a panic on it ends the toolkit dialog for the process.
    static IS_UI: Cell<bool> = const { Cell::new(false) };
}

impl ToolkitConsent {
    /// The consent to wire into the broker, and what its first thread must run.
    pub fn new() -> (ToolkitConsent, UiThread) {
        let core = Arc::new(Core::new());
        (
            ToolkitConsent {
                core: core.clone(),
                fallback: TaskDialogConsent,
            },
            UiThread { core },
        )
    }
}

impl Consent for ToolkitConsent {
    /// Without a sheet there is nothing for the toolkit to draw: the TaskDialog.
    fn ask(
        &self,
        pages: &[Page],
        primary: i32,
        closer: &Closer,
        shown: &(dyn Fn() + Sync),
    ) -> io::Result<Outcome> {
        self.fallback.ask(pages, primary, closer, shown)
    }

    fn ask_sheet(
        &self,
        sheet: &Sheet,
        pages: &[Page],
        primary: i32,
        closer: &Closer,
        shown: &(dyn Fn() + Sync),
    ) -> io::Result<Outcome> {
        match self.core.ask(sheet, closer, shown) {
            Ok(outcome) => Ok(outcome),
            Err(()) => self.fallback.ask(pages, primary, closer, shown),
        }
    }
}

impl UiThread {
    /// Sleeps until the first dialog is asked for, then makes the window and runs its loop for as
    /// long as the process lives. Returns only when the loop could not be made or ended: the
    /// broker then asks with the TaskDialog, and this thread has nothing left to do.
    ///
    /// Call it on the thread the process started on.
    pub fn run(self) {
        let core = self.core;
        let first = core.wait(None, |state| match state.ui {
            Ui::Idle => None,
            _ => Some(state.job.as_ref().map(|j| j.sheet.clone())),
        });
        IS_UI.with(|f| f.set(true));
        // A panic on this thread, wherever the loop is in its work, ends the toolkit dialog at
        // once: the request waiting on it is answered Cancel (or asks with the TaskDialog when
        // nothing was on screen yet), and no later request waits on a window that is gone.
        let hooked = core.clone();
        let before = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if IS_UI.with(Cell::get) {
                hooked.died();
            }
            before(info);
        }));
        let size = {
            let scale = platform::system_scale();
            let mut gfx = Gfx::new();
            match first.flatten() {
                Some(sheet) => opening_size(&mut gfx, &sheet, scale, work_height(scale)),
                None => (WIDTH, MIN_HEIGHT),
            }
        };
        let look = Look::system(platform::system_high_contrast());
        let config = Config::new(super::super::text::TITLE)
            .size(size.0, size.1)
            .min_size(WIDTH, MIN_HEIGHT)
            .app_id("Purge")
            .dark(look.pal.dark);
        let app = ConsentApp::new(core.clone(), None);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = host::run(config, app);
        }));
        core.died();
    }
}

/// One dialog of a [`rehearse`].
pub struct Trial {
    /// What the report calls it.
    pub name: String,
    /// The dialog as the toolkit window draws it.
    pub sheet: Sheet,
    /// The same dialog as TaskDialog pages, for the fall back.
    pub pages: Vec<Page>,
    /// The id of the button that approves on the pages.
    pub primary: i32,
    /// Fire the dialog's [`Closer`] this long after it was asked for, as the broker does when its
    /// parent is gone or its pipe broke. `None`: the dialog waits for its answer.
    pub close_after: Option<Duration>,
}

/// Asks `trials` one after another through a real [`ToolkitConsent`], with the threads the broker
/// has under `--consent toolkit`: the calling thread, which must be the one the process started
/// on, becomes the window's, and a second one asks. `report` is told `shown: <name>` when a dialog
/// is on screen and `outcome: <name>: <answer>` when it ended; `gap` is waited between two
/// dialogs. The process ends after the last one.
///
/// For the preview harness (`examples/consent_preview.rs --service`): the broker's own path from
/// [`Consent::ask_sheet`] to the window and back, with no pipe and nothing to run. It is here
/// because a [`Closer`] can be made and fired only inside this crate.
pub fn rehearse(
    trials: Vec<Trial>,
    gap: Duration,
    report: impl Fn(&str) + Send + Sync + 'static,
) -> ! {
    let (consent, window) = ToolkitConsent::new();
    let asking = std::thread::Builder::new()
        .name("consent-rehearsal".into())
        .spawn(move || {
            for (i, trial) in trials.iter().enumerate() {
                if i > 0 {
                    std::thread::sleep(gap);
                }
                let closer = Arc::new(Closer::new());
                if let Some(after) = trial.close_after {
                    let closer = closer.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(after);
                        closer.fire();
                    });
                }
                let name = &trial.name;
                let answer =
                    consent.ask_sheet(&trial.sheet, &trial.pages, trial.primary, &closer, &|| {
                        report(&format!("shown: {name}"))
                    });
                report(&match answer {
                    Ok(outcome) => format!("outcome: {name}: {outcome:?}"),
                    Err(e) => format!("outcome: {name}: not shown ({e})"),
                });
            }
            std::process::exit(0);
        });
    if asking.is_ok() {
        window.run();
    }
    // The window's loop ended or never began; the asking thread ends the process.
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::thread;

    use super::super::super::sheet::Block;
    use super::super::super::view::Icon;
    use super::*;

    fn sheet() -> Sheet {
        Sheet {
            title: "Purge security prompt".into(),
            icon: Icon::Shield,
            instruction: "Move 2 leftovers to quarantine?".into(),
            blocks: vec![Block::Summary("2 items".into())],
            verification: None,
            approve: "Move 2 items to quarantine".into(),
            footer: "Code A1B2-C3D4".into(),
        }
    }

    /// Waits, for at most ten seconds, until `done` says so.
    fn until(done: impl Fn() -> bool) {
        let end = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < end, "waited ten seconds");
            thread::sleep(Duration::from_millis(2));
        }
    }

    /// A window's thread played by the test: waits for a job to be posted, and takes it.
    fn take(core: &Arc<Core>) -> u64 {
        core.wait(Some(Instant::now() + Duration::from_secs(10)), |s| {
            s.job
                .as_ref()
                .filter(|j| j.phase == Phase::Posted)
                .map(|j| j.id)
        })
        .expect("a job is posted");
        Desk::take(core, None).expect("the job is handed out").0
    }

    fn ask(
        core: &Arc<Core>,
        closer: &Arc<Closer>,
    ) -> (thread::JoinHandle<Result<Outcome, ()>>, Arc<AtomicU32>) {
        let shown = Arc::new(AtomicU32::new(0));
        let (core, closer, count) = (core.clone(), closer.clone(), shown.clone());
        let handle = thread::spawn(move || {
            core.ask(&sheet(), &closer, &|| {
                count.fetch_add(1, Ordering::SeqCst);
            })
        });
        (handle, shown)
    }

    #[test]
    fn an_answer_is_taken_only_from_a_dialog_that_is_on_screen() {
        let core = Arc::new(Core::new());
        let closer = Arc::new(Closer::new());
        let (request, shown) = ask(&core, &closer);
        let id = take(&core);
        // Not on screen yet: an approval now is nobody's.
        core.answered(id, Outcome::Approved);
        assert_eq!(Core::phase_of(&core.lock(), id), Phase::Taken);
        // Another job's id is nobody's either.
        core.shown(id + 1);
        core.answered(id + 1, Outcome::Approved);
        core.shown(id);
        core.answered(id, Outcome::Approved);
        // The first answer stands.
        core.answered(id, Outcome::Declined);
        assert_eq!(request.join().unwrap(), Ok(Outcome::Approved));
        assert_eq!(shown.load(Ordering::SeqCst), 1);
        // The job has left the desk: nothing is handed out or answered twice.
        assert!(Desk::take(&core, Some(id)).is_none());
        core.answered(id, Outcome::Approved);
        assert!(core.lock().job.is_none());
    }

    #[test]
    fn the_closer_declines_at_once_before_and_after_the_dialog_is_up() {
        // While the window has not even taken the job.
        let core = Arc::new(Core::new());
        let closer = Arc::new(Closer::new());
        let (request, shown) = ask(&core, &closer);
        until(|| core.lock().job.is_some());
        closer.fire();
        assert_eq!(request.join().unwrap(), Ok(Outcome::Declined));
        assert_eq!(shown.load(Ordering::SeqCst), 0);
        // A window that comes late finds nothing to show, and its answer is ignored.
        assert!(Desk::take(&core, None).is_none());

        // While the dialog is up: declined without a word from the window, and an approval that
        // races the close loses.
        let core = Arc::new(Core::new());
        let closer = Arc::new(Closer::new());
        let (request, shown) = ask(&core, &closer);
        let id = take(&core);
        core.shown(id);
        until(|| shown.load(Ordering::SeqCst) == 1);
        closer.fire();
        core.answered(id, Outcome::Approved);
        assert_eq!(request.join().unwrap(), Ok(Outcome::Declined));

        // A closer that fired before the request: declined, nothing shown.
        let core = Arc::new(Core::new());
        let closer = Arc::new(Closer::new());
        closer.fire();
        let (request, shown) = ask(&core, &closer);
        assert_eq!(request.join().unwrap(), Ok(Outcome::Declined));
        assert_eq!(shown.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_window_that_dies_falls_back_before_the_dialog_is_up_and_declines_after() {
        // Before it is on screen: the caller asks another way.
        let core = Arc::new(Core::new());
        let closer = Arc::new(Closer::new());
        let (request, shown) = ask(&core, &closer);
        let id = take(&core);
        core.died();
        assert_eq!(request.join().unwrap(), Err(()));
        assert_eq!(shown.load(Ordering::SeqCst), 0);
        // What the dead window says afterwards is ignored, and every later request fails fast.
        core.shown(id);
        core.answered(id, Outcome::Approved);
        let (request, _) = ask(&core, &closer);
        assert_eq!(request.join().unwrap(), Err(()));
        assert!(core.lock().job.is_none());

        // While it is on screen: Cancel, never the TaskDialog over a dialog the user saw.
        let core = Arc::new(Core::new());
        let (request, shown) = ask(&core, &closer);
        let id = take(&core);
        core.shown(id);
        until(|| shown.load(Ordering::SeqCst) == 1);
        core.died();
        assert_eq!(request.join().unwrap(), Ok(Outcome::Declined));
    }

    #[test]
    fn the_first_request_wakes_the_window_and_later_ones_get_new_ids() {
        let core = Arc::new(Core::new());
        assert!(matches!(core.lock().ui, Ui::Idle));
        assert!(!core.is_dead());
        let closer = Arc::new(Closer::new());
        let (first, _) = ask(&core, &closer);
        let a = take(&core);
        assert!(matches!(core.lock().ui, Ui::Starting));
        core.shown(a);
        core.answered(a, Outcome::Declined);
        assert_eq!(first.join().unwrap(), Ok(Outcome::Declined));
        let (second, _) = ask(&core, &closer);
        let b = take(&core);
        assert_ne!(a, b);
        // The first dialog's id cannot answer the second.
        core.shown(a);
        core.answered(a, Outcome::Approved);
        assert_eq!(Core::phase_of(&core.lock(), b), Phase::Taken);
        core.shown(b);
        core.answered(b, Outcome::Approved);
        assert_eq!(second.join().unwrap(), Ok(Outcome::Approved));
    }
}
