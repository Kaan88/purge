//! The local baseline in the broker (M3 design 3.6, DECISIONS 2026-11-21 W4): the engine's background
//! build is started when the broker starts (`pipeline::start_local_build`: it checks, then builds the
//! missing parts, on its own thread), a scan never waits for it, `engine.hello` carries its state and
//! `baseline.changed` reports each change, with the scans worth making again when it completes.
//!
//! [`BuildHandle`] is what the serving loop needs of the build, so the loop is tested with a fake;
//! `LocalBuild` is the real one. [`LiveHost`] answers `engine.hello` from the live machine with the
//! engine's own `pipeline::hello`, over the checked settings of the start checks.
//!
//! At exit the loop asks the build to stop before its next part ([`BuildHandle::request_stop`]) and
//! waits a short grace. A part being built is not interrupted, and a process that ends in the middle of
//! one leaves nothing partial: parts are written to a temporary name and renamed.

use purge_engine::pipeline::{LocalBuild, Settings, Sources, hello};
use purge_rpc::{BaselineBuild, EngineHello};
use purge_source::live::Live;

use crate::serve::Host;

/// The local-baseline build, as the serving loop sees it.
pub trait BuildHandle: Send + Sync + 'static {
    /// The state now.
    fn state(&self) -> BaselineBuild;
    /// Asks the build to stop before it starts its next part.
    fn request_stop(&self);
}

impl BuildHandle for LocalBuild {
    fn state(&self) -> BaselineBuild {
        LocalBuild::state(self)
    }

    fn request_stop(&self) {
        LocalBuild::request_stop(self);
    }
}

/// Whether a state is one in which the build still runs (`Checking` or `Building`).
pub fn in_progress(state: &BaselineBuild) -> bool {
    matches!(
        state,
        BaselineBuild::Checking | BaselineBuild::Building { .. }
    )
}

/// `engine.hello` from the live machine.
pub struct LiveHost {
    settings: Settings,
}

impl LiveHost {
    /// A host over the settings of the start checks (`Started::engine_settings`), with the build the
    /// broker started in `settings.local_build`.
    pub fn new(settings: Settings) -> LiveHost {
        LiveHost { settings }
    }
}

impl Host for LiveHost {
    fn hello(&self) -> EngineHello {
        let live = Live::new();
        let sources = Sources {
            reg: &live.registry,
            fs: &live.fs,
            sys: &live.system,
        };
        hello(sources, &self.settings, &mut Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_checking_and_building_are_in_progress() {
        assert!(in_progress(&BaselineBuild::Checking));
        assert!(in_progress(&BaselineBuild::Building {
            parts: vec!["S1".into()],
            scan_waiting: false
        }));
        for done in [
            BaselineBuild::None { reason: "x".into() },
            BaselineBuild::Done { rescan: true },
            BaselineBuild::Failed { reason: "x".into() },
        ] {
            assert!(!in_progress(&done));
        }
    }
}
