//! Expected leftovers per program (the port of `ui/Purge.Client/Model/Forecast.cs`, the forecast part).
//!
//! These are UI-side shapes for `programs.forecast`, a method the engine does not have yet (an engine
//! question in `ui/README.md`): the live engine answers none, and the sample engine answers from
//! `sample-forecast.json`. They are not wire types of `purge-rpc` for that reason. A program with no
//! answer is "not known yet", never "clean".

use purge_model::ProgramId;
use serde::{Deserialize, Serialize};

/// How much a program is expected to leave behind after its own uninstaller ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum ForecastVerdict {
    /// Not known.
    #[default]
    Unknown,
    /// Nothing expected.
    Clean,
    /// Some leftovers.
    Some,
    /// Large leftovers.
    Large,
}

/// What one line of "What Purge expects" says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ForecastLineKind {
    /// Removed by its uninstaller.
    Removed,
    /// Stays behind.
    Stays,
    /// User data that stays.
    UserData,
}

/// One line of "What Purge expects" in the details pane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForecastLine {
    /// What the line says.
    pub kind: ForecastLineKind,
    /// The text.
    pub text: String,
    /// A detail beside it.
    #[serde(default)]
    pub detail: Option<String>,
}

/// The expected leftovers of one program, from what Purge recorded at install time and knowledge packs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeftoverForecast {
    /// The program.
    pub program_id: ProgramId,
    /// The verdict.
    pub verdict: ForecastVerdict,
    /// Bytes expected to stay; `None` when the size is not known.
    #[serde(default)]
    pub estimate_bytes: Option<i64>,
    /// What stays, e.g. "profile and cache".
    #[serde(default)]
    pub what: Option<String>,
    /// Whether what stays holds user data.
    pub holds_user_data: bool,
    /// The details pane's lines.
    pub lines: Vec<ForecastLine>,
}
