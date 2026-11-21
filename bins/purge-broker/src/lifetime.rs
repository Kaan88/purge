//! When the broker ends (M3 design 3.3 step 5, 3.6): the clock, the parent, the exit reasons and codes,
//! the limits, and the closer that ends an open consent dialog as Cancel.
//!
//! | Event | Reason | Process exit code |
//! |---|---|---|
//! | `broker.shutdown` with nothing running | [`ExitReason::Shutdown`] | 0 |
//! | Execute, undo, recovery or purge completed, no other session open | [`ExitReason::CompletedChange`] | 0 |
//! | No request for [`IDLE_LIMIT`] | [`ExitReason::Idle`] | 0 |
//! | The parent process has exited | [`ExitReason::ParentLost`] | 0 |
//! | The pipe broke (client closed, a write failed, an oversize line) | [`ExitReason::PipeLost`] | 0 |
//! | [`MAX_FAILED_CLIENTS`] clients refused | [`ExitReason::RefusedClients`] | 25 |
//! | The pipe itself failed | [`ExitReason::LinkFailed`] | 27 |
//!
//! Before the pipe exists the process can also end with [`codes::BAD_ARGUMENTS`], [`codes::PIPE_TAKEN`] or
//! [`codes::PARENT_MISMATCH`]; with the start failures of `start` (20 to 22) these are the codes the UI
//! names in "The administrator part could not start". Parent or pipe loss, idle and the orderly ends
//! exit with 0: they are the design, not failures, and write nothing to the event log.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::link::Refusal;

/// No request for this long ends the broker (design 3.6).
pub const IDLE_LIMIT: Duration = Duration::from_secs(10 * 60);
/// After a completed change or `broker.shutdown`, how long the broker waits for the client to close the
/// pipe before it exits (design 3.6).
pub const CLOSE_WAIT: Duration = Duration::from_secs(5);
/// Refused clients after which the broker exits (design 3.3 step 5).
pub const MAX_FAILED_CLIENTS: usize = 3;
/// How long an identified client has to send its `engine.hello`.
pub const HELLO_WAIT: Duration = Duration::from_secs(30);
/// The longest first line (`engine.hello`) read from a client; a longer one refuses the client.
pub const HELLO_LINE_CAP: usize = 4096;
/// How long a non-mutating request may keep running after the client is gone before the broker exits
/// anyway: it has no side effect to finish.
pub const READ_GRACE: Duration = Duration::from_secs(10);
/// How long the broker waits, at exit, for the local-baseline build to leave its current part.
/// Cache parts are written to a temporary name and renamed, so a build still running when the process
/// ends never leaves a partial cache file.
pub const BUILD_GRACE: Duration = Duration::from_secs(3);

/// Process exit codes of the broker that are not start failures (`start::StartFailure`, 20 to 22).
pub mod codes {
    /// The command line is not `--pipe <name> --parent <pid> --parent-ctime <filetime>`.
    pub const BAD_ARGUMENTS: u8 = 23;
    /// The pipe name exists already (another process created it first), or the pipe could not be made.
    pub const PIPE_TAKEN: u8 = 24;
    /// Three clients were refused.
    pub const REFUSED_CLIENTS: u8 = 25;
    /// `--parent` names no process, or one created at another time than `--parent-ctime`.
    pub const PARENT_MISMATCH: u8 = 26;
    /// The pipe failed while waiting for or reading from a client.
    pub const LINK_FAILED: u8 = 27;
}

/// Time as the broker reads it, so idle and close timeouts are tested with a fake.
pub trait Clock: Send + Sync + 'static {
    /// The time since some fixed start. Never goes back.
    fn now(&self) -> Duration;
}

/// The system's monotonic clock.
#[derive(Debug)]
pub struct SystemClock(Instant);

impl SystemClock {
    /// A clock that starts now.
    pub fn new() -> SystemClock {
        SystemClock(Instant::now())
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

/// The process the broker was started for (`--parent`). The broker holds it from its start, so the pid
/// cannot be reused while it is held.
pub trait Parent: Send + Sync + 'static {
    /// True once the process has exited. A handle that cannot be read counts as exited.
    fn exited(&self) -> bool;
}

/// Why the broker ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitReason {
    /// `broker.shutdown` with nothing running.
    Shutdown,
    /// A change (execute, undo, recovery, purge) completed with no other session open.
    CompletedChange,
    /// No request for [`IDLE_LIMIT`].
    Idle,
    /// The parent process exited.
    ParentLost,
    /// The pipe broke.
    PipeLost,
    /// [`MAX_FAILED_CLIENTS`] clients were refused.
    RefusedClients,
    /// The pipe failed (not a client's doing).
    LinkFailed(String),
}

impl ExitReason {
    /// The process exit code (see the module table).
    pub fn code(&self) -> u8 {
        match self {
            ExitReason::RefusedClients => codes::REFUSED_CLIENTS,
            ExitReason::LinkFailed(_) => codes::LINK_FAILED,
            _ => 0,
        }
    }
}

/// How a run of the broker ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    /// Why.
    pub reason: ExitReason,
    /// Every client refused before the end, in order.
    pub refusals: Vec<Refusal>,
}

impl Exit {
    /// The process exit code.
    pub fn code(&self) -> u8 {
        self.reason.code()
    }

    /// The line for the event log when [`Exit::code`] is not 0.
    pub fn line(&self) -> String {
        let refusals: Vec<String> = self.refusals.iter().map(ToString::to_string).collect();
        format!(
            "purge-broker ended: {:?} (exit code {}); refused clients: [{}]",
            self.reason,
            self.code(),
            refusals.join("; ")
        )
    }
}

/// Whether the broker has had no request for `limit` at `now`.
pub fn idle_expired(now: Duration, last_activity: Duration, limit: Duration) -> bool {
    now.saturating_sub(last_activity) >= limit
}

/// Ends the consent dialog that is open, as Cancel, from another thread (parent or pipe lost, design
/// 3.6). The dialog's owner [`Closer::arm`]s it with the way to close its window; whoever ends the
/// broker [`Closer::fire`]s it. A dialog armed after the fire is closed at once, and none opens after
/// it ([`Closer::fired`]).
pub struct Closer {
    state: Mutex<CloserState>,
}

enum CloserState {
    Idle,
    Armed(Box<dyn Fn() + Send>),
    Fired,
}

impl Closer {
    pub(crate) fn new() -> Closer {
        Closer {
            state: Mutex::new(CloserState::Idle),
        }
    }

    /// Registers how to close the dialog that just opened. Closes it at once when the closer has
    /// fired already.
    pub fn arm(&self, close: impl Fn() + Send + 'static) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(*state, CloserState::Fired) {
            drop(state);
            close();
        } else {
            *state = CloserState::Armed(Box::new(close));
        }
    }

    /// Forgets the registered way to close: the dialog has ended.
    pub fn disarm(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(*state, CloserState::Armed(_)) {
            *state = CloserState::Idle;
        }
    }

    /// Whether the broker is ending: no dialog may open.
    pub fn fired(&self) -> bool {
        matches!(
            *self.state.lock().unwrap_or_else(|e| e.into_inner()),
            CloserState::Fired
        )
    }

    pub(crate) fn fire(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let was = std::mem::replace(&mut *state, CloserState::Fired);
        drop(state);
        if let CloserState::Armed(close) = was {
            close();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[test]
    fn idle_is_ten_minutes_without_a_request() {
        let s = Duration::from_secs;
        assert!(!idle_expired(s(599), s(0), IDLE_LIMIT));
        assert!(idle_expired(s(600), s(0), IDLE_LIMIT));
        assert!(!idle_expired(s(699), s(100), IDLE_LIMIT));
        assert!(
            !idle_expired(s(0), s(5), IDLE_LIMIT),
            "a clock never goes back"
        );
    }

    #[test]
    fn exit_codes() {
        for ok in [
            ExitReason::Shutdown,
            ExitReason::CompletedChange,
            ExitReason::Idle,
            ExitReason::ParentLost,
            ExitReason::PipeLost,
        ] {
            assert_eq!(ok.code(), 0);
        }
        assert_eq!(ExitReason::RefusedClients.code(), 25);
        assert_eq!(ExitReason::LinkFailed("x".into()).code(), 27);
        let all = [
            codes::BAD_ARGUMENTS,
            codes::PIPE_TAKEN,
            codes::REFUSED_CLIENTS,
            codes::PARENT_MISMATCH,
            codes::LINK_FAILED,
        ];
        // Distinct from each other and from the start failures 20 to 22 and the stub's 1.
        for (i, a) in all.iter().enumerate() {
            assert!(*a > 22);
            assert!(all[i + 1..].iter().all(|b| a != b));
        }
    }

    #[test]
    fn closer_closes_an_armed_dialog_once_and_late_arming_at_once() {
        let n = Arc::new(AtomicU32::new(0));
        let closer = Closer::new();
        let c = n.clone();
        closer.arm(move || {
            c.fetch_add(1, Ordering::SeqCst);
        });
        closer.disarm();
        closer.fire();
        assert_eq!(
            n.load(Ordering::SeqCst),
            0,
            "a disarmed dialog is not closed"
        );
        assert!(closer.fired());
        let c = n.clone();
        closer.arm(move || {
            c.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(
            n.load(Ordering::SeqCst),
            1,
            "armed after the fire: closed now"
        );

        let n2 = Arc::new(AtomicU32::new(0));
        let closer = Closer::new();
        let c = n2.clone();
        closer.arm(move || {
            c.fetch_add(1, Ordering::SeqCst);
        });
        closer.fire();
        closer.fire();
        assert_eq!(n2.load(Ordering::SeqCst), 1);
    }
}
