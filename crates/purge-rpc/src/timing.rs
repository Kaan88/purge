//! The broker's timing records (M3_DESIGN.md §9.1, gate G12): when the steps of the elevated flow
//! happened, for measurement only.
//!
//! The broker records each [`TimingName`] once per request (the process marks once per process) as a
//! [`TimingMark`]: milliseconds since the broker **process was created** on a monotonic clock, and the
//! wall clock. The marks reach the gate two ways:
//!
//! - the optional `timings` member ([`Timings`]) of the results of `uninstall.prepare`, `leftovers.scan`,
//!   `plan.create` and `plan.execute`: the process marks and the marks of that request. A client ignores
//!   it; a result without it is as valid (results do not refuse unknown members, and this one is
//!   optional both ways);
//! - one Application event-log line per mark ([`TimingLine`], source `Purge`, event id
//!   [`TIMING_EVENT_ID`], information), so the rig collects them with no client involved.
//!
//! Timing never changes an answer: a mark the clock cannot give is left out, and nothing about a
//! request depends on its marks.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::frame::RequestId;

/// The event id of a timing line in the Application log (source `Purge`). The broker's failure events
/// use the exit codes (20 to 27) as ids; timing lines are information events.
pub const TIMING_EVENT_ID: u32 = 100;

/// The `kind` member of every [`TimingLine`], so a reader can tell it from any other text.
pub const TIMING_LINE_KIND: &str = "purge.broker.timing/1";

/// A step of the elevated flow the broker times.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TimingName {
    /// `main` passed the DLL-search and working-directory restriction (process mark).
    BrokerStart,
    /// The client passed the pipe checks and its `engine.hello` was answered (process mark).
    PipeConnected,
    /// `uninstall.prepare` began.
    HarvestStart,
    /// `uninstall.prepare` harvested every program, stored each fingerprint and opened the sessions.
    HarvestComplete,
    /// `leftovers.scan` began.
    ScanStart,
    /// The first `*.progress` line of the request was written to the pipe.
    FirstProgress,
    /// `leftovers.scan` built its scan and counted the bands.
    ScanComplete,
    /// `plan.create` bound and froze the plan.
    PlanReady,
    /// The consent dialog was up and could be answered.
    ConsentShown,
    /// The consent dialog ended (any answer).
    ConsentAnswered,
    /// `plan.execute` handed the approved plan to the executor.
    ExecuteStart,
    /// The executor returned its run.
    ExecuteComplete,
}

impl TimingName {
    /// Whether the mark belongs to the process, not to a request.
    pub const fn is_process_mark(self) -> bool {
        matches!(self, TimingName::BrokerStart | TimingName::PipeConnected)
    }
}

/// One mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TimingMark {
    /// The step.
    pub mark: TimingName,
    /// Milliseconds since the broker process was created, on a monotonic clock.
    pub ms: u64,
    /// The wall clock at the mark, milliseconds since the Unix epoch (UTC).
    pub wall_unix_ms: u64,
}

/// The `timings` member of a result: for measurement only (M3_DESIGN.md §9.1); a client ignores it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Timings {
    /// When the broker process was created (`GetProcessTimes`), milliseconds since the Unix epoch;
    /// absent when it could not be read (the marks then count from the broker's own start).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_created_unix_ms: Option<u64>,
    /// The process marks, then the marks of this request, in the order they were taken.
    pub marks: Vec<TimingMark>,
}

/// One event-log line of the broker's timing channel: one mark, with what a reader needs to group it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimingLine {
    /// Always [`TIMING_LINE_KIND`].
    pub kind: String,
    /// The broker's process id.
    pub pid: u32,
    /// As [`Timings::process_created_unix_ms`]; with `pid` it names one broker process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_created_unix_ms: Option<u64>,
    /// The request, for a request mark.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<RequestId>,
    /// The request's method, for a request mark.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The mark itself.
    #[serde(flatten)]
    pub mark: TimingMark,
}
