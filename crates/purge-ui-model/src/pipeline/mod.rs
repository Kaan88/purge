//! The Uninstall pipeline's models (package UI-MODEL-A): the pipeline itself
//! ([`uninstall::UninstallController`], the port of `ui/Purge.Client/Pipeline/UninstallPipeline.cs`), the
//! queue of an "Uninstall N" click ([`queue::UninstallQueue`]), the Uninstall page's view state
//! ([`page::UninstallPage`], the logic of `UninstallView.xaml.cs`) and the "removed outside Purge" check
//! ([`removed`], `RemovedLeftovers.cs`).
//!
//! Every model is a plain state machine: a method takes a user action or a call's result and returns the
//! requests the UI sends through `purge-client`; the UI then reads the view state again. Nothing here
//! blocks, spawns, or touches a link: the UI owns the broker and engine clients and correlates each
//! request with its answer. At most one call of a model is in flight at a time (the WinUI controllers
//! awaited each one), and an answer the model is not waiting for is ignored.

pub mod page;
pub mod queue;
pub mod removed;
#[cfg(test)]
mod rig;
pub mod strings;
pub mod uninstall;

use purge_model::ProgramId;

pub use crate::call_error::CallError;
pub use page::{PageEnv, PageRequest, UninstallPage, UninstallPageView};
pub use queue::UninstallQueue;
pub use removed::{
    RemovedCheckState, RemovedGroup, RemovedLeftovers, RemovedNotice, RemovedRequest,
    StoredScanOutcome,
};
pub use uninstall::{
    PipelineRequest, StepState, UninstallAnswer, UninstallConfirmation, UninstallController,
    UninstallNotice, UninstallOutcome, UninstallStep,
};

/// What the Uninstall click asked for: one program (the queue runs one after the other).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UninstallTarget {
    /// The program.
    pub program_id: ProgramId,
    /// Its display name (may be empty).
    pub program_name: String,
}

impl UninstallTarget {
    /// A target.
    pub fn new(program_id: ProgramId, program_name: impl Into<String>) -> Self {
        Self {
            program_id,
            program_name: program_name.into(),
        }
    }
}

/// Why a model shows a bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NoticeKind {
    /// Informational.
    Info,
    /// A warning.
    Warning,
    /// An error; in the pipeline it blocks the run.
    Error,
}

/// How the elevated broker's start went, as the models see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LaunchState {
    /// The broker runs and its link is checked; the UI holds it.
    Started,
    /// "Not now" at Purge's explanation, or No at the Windows prompt.
    Cancelled,
    /// The account is not an administrator.
    NotAdministrator,
    /// The broker could not be started, or exited before its pipe.
    CannotStart,
    /// The start timed out, or the server check failed.
    Failed,
}

/// The answer to a launch request: the broker's start as the models see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchResult {
    /// How it went. With [`LaunchState::Started`] the UI holds the live broker link.
    pub state: LaunchState,
    /// The launcher's sentence (empty when started).
    pub message: String,
    /// The broker's exit code, when it exited before its pipe.
    pub exit_code: Option<u32>,
    /// With [`LaunchState::Cancelled`]: the user chose "Not now" at Purge's explanation, so the Windows
    /// prompt was never shown.
    pub declined_explanation: bool,
}

impl LaunchResult {
    /// A started broker.
    pub fn started() -> Self {
        Self::of(LaunchState::Started, "")
    }

    /// A launch that came to `state` with the launcher's sentence.
    pub fn of(state: LaunchState, message: impl Into<String>) -> Self {
        Self {
            state,
            message: message.into(),
            exit_code: None,
            declined_explanation: false,
        }
    }
}
