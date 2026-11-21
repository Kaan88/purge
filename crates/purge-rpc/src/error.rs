//! Outcomes and errors (M3_DESIGN.md §6.4).
//!
//! A result that did something carries an [`Outcome`]; that is not an error. A request that failed answers
//! a JSON-RPC error: the protocol codes of JSON-RPC 2.0 for a line, an envelope, a method or params the
//! server cannot take, and [`SERVER_ERROR`] with an [`ErrorData`] for everything the engine refuses. The
//! client switches on `error.data.kind`, never on the message.

use purge_model::exec::session::SessionId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::methods::{CandidateRef, Route};

/// The line is not JSON.
pub const PARSE_ERROR: i32 = -32700;
/// The line is JSON but not a request this protocol takes: a batch array, a bad envelope, an id that is
/// not an unsigned integer.
pub const INVALID_REQUEST: i32 = -32600;
/// The method is unknown, or not in the sets of this transport. Both answer the same.
pub const METHOD_NOT_FOUND: i32 = -32601;
/// The params do not fit the method: a missing or unknown field, a value of the wrong form.
pub const INVALID_PARAMS: i32 = -32602;
/// The server failed to write its own answer (an answer over the output limit).
pub const INTERNAL_ERROR: i32 = -32603;
/// Every error the engine itself decides; `data` says which.
pub const SERVER_ERROR: i32 = -32000;

/// What a run did. Carried by results; not an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Everything was done.
    Complete,
    /// Some items are held or failed; the result names them and what holds them.
    Partial,
    /// An undo restored what it could and lists conflicts.
    UndoConflicts,
    /// The session was not recorded completely; History offers recovery. Wins over the two above.
    NotClosed,
}

impl Outcome {
    /// The exit code of the CLI verb this outcome mirrors (`cli.rs`).
    pub const fn cli_exit(self) -> u8 {
        match self {
            Outcome::Complete => 0,
            Outcome::Partial => 10,
            Outcome::UndoConflicts => 11,
            Outcome::NotClosed => 12,
        }
    }
}

/// Which kind of id a [`ErrorData::Gone`] error is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IdKind {
    /// An uninstall session (`session_id`).
    UninstallSession,
    /// A scan (`scan_id`).
    Scan,
    /// A plan (`plan_id`).
    Plan,
    /// A candidate of a scan.
    Candidate,
    /// An executor session (`session`).
    Session,
    /// An expired quarantine entry.
    Expiry,
    /// A program id.
    Program,
}

/// One reason `plan.create` refused a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Refusal {
    /// The item refused; `None` when the reason is about the plan as a whole.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_id: Option<CandidateRef>,
    /// Why, in words for the user.
    pub reason: String,
}

/// `error.data` of a [`SERVER_ERROR`]: the kind, and what the client needs to show it. Serialised as an
/// object tagged by `"kind"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ErrorData {
    /// Cancel in the consent dialog; nothing was done.
    ConsentDeclined,
    /// `bind` refused the plan.
    PlanRefused {
        /// The items and reasons.
        refusals: Vec<Refusal>,
    },
    /// An interrupted session comes first.
    NeedsRecovery {
        /// The interrupted sessions.
        sessions: Vec<SessionId>,
    },
    /// The store or a journal failed its check.
    StoreIntegrity {
        /// What failed.
        message: String,
    },
    /// The uninstaller failed.
    UninstallFailed {
        /// Its exit code, when it ran.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<u32>,
        /// Whether a forced-mode scan is offered.
        forced_offered: bool,
    },
    /// The client runs as another account than the broker (design 3.5).
    OtherAccount,
    /// The broker's token is not elevated.
    NotElevated,
    /// The broker's own directory failed the start checks (design 3.4).
    InstallUntrusted,
    /// The program belongs to the other route.
    WrongRoute {
        /// The route it belongs to.
        route: Route,
    },
    /// A mutating request is running.
    Busy,
    /// An unknown or expired id.
    Gone {
        /// Which kind of id.
        id: IdKind,
    },
    /// The quarantine cap would be passed.
    CapExceeded {
        /// The volume's root, for display.
        volume: String,
        /// Bytes the quarantine holds on it now.
        used: u64,
        /// Bytes the plan would add.
        needed: u64,
        /// The cap.
        cap: u64,
    },
    /// Anything else.
    Runtime {
        /// What happened.
        message: String,
    },
}

impl ErrorData {
    /// The exit code of the CLI verb this kind mirrors, when there is one.
    pub const fn cli_exit(&self) -> Option<u8> {
        match self {
            ErrorData::PlanRefused { .. } => Some(6),
            ErrorData::NeedsRecovery { .. } => Some(8),
            ErrorData::StoreIntegrity { .. } => Some(9),
            ErrorData::UninstallFailed { .. } => Some(4),
            ErrorData::OtherAccount | ErrorData::NotElevated | ErrorData::InstallUntrusted => {
                Some(7)
            }
            ErrorData::Runtime { .. } => Some(3),
            ErrorData::ConsentDeclined
            | ErrorData::WrongRoute { .. }
            | ErrorData::Busy
            | ErrorData::Gone { .. }
            | ErrorData::CapExceeded { .. } => None,
        }
    }

    /// The `kind` string of the variant.
    pub fn kind(&self) -> &'static str {
        match self {
            ErrorData::ConsentDeclined => "consent_declined",
            ErrorData::PlanRefused { .. } => "plan_refused",
            ErrorData::NeedsRecovery { .. } => "needs_recovery",
            ErrorData::StoreIntegrity { .. } => "store_integrity",
            ErrorData::UninstallFailed { .. } => "uninstall_failed",
            ErrorData::OtherAccount => "other_account",
            ErrorData::NotElevated => "not_elevated",
            ErrorData::InstallUntrusted => "install_untrusted",
            ErrorData::WrongRoute { .. } => "wrong_route",
            ErrorData::Busy => "busy",
            ErrorData::Gone { .. } => "gone",
            ErrorData::CapExceeded { .. } => "cap_exceeded",
            ErrorData::Runtime { .. } => "runtime",
        }
    }
}

/// The `error` member of a JSON-RPC response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ErrorObject {
    /// A JSON-RPC code: one of the protocol codes, or [`SERVER_ERROR`].
    pub code: i32,
    /// A short text for logs. The client does not parse it.
    pub message: String,
    /// The kind and its details; present exactly when `code` is [`SERVER_ERROR`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<ErrorData>,
}

impl ErrorObject {
    /// A protocol error without data.
    pub fn protocol(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// `-32601`: an unknown method, or one outside the transport's sets.
    pub fn method_not_found() -> Self {
        Self::protocol(METHOD_NOT_FOUND, "method not found")
    }

    /// `-32602` with what is wrong with the params.
    pub fn invalid_params(message: impl Into<String>) -> Self {
        Self::protocol(INVALID_PARAMS, message)
    }

    /// An engine error of one kind. The message is the kind; details are in `data`.
    pub fn server(data: ErrorData) -> Self {
        Self {
            code: SERVER_ERROR,
            message: data.kind().to_owned(),
            data: Some(data),
        }
    }

    /// A [`ErrorData::Runtime`] error with a message.
    pub fn runtime(message: impl Into<String>) -> Self {
        Self::server(ErrorData::Runtime {
            message: message.into(),
        })
    }
}

impl From<ErrorData> for ErrorObject {
    fn from(data: ErrorData) -> Self {
        Self::server(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_serialise_as_their_names() {
        let all = [
            ErrorData::ConsentDeclined,
            ErrorData::PlanRefused { refusals: vec![] },
            ErrorData::NeedsRecovery { sessions: vec![] },
            ErrorData::StoreIntegrity {
                message: String::new(),
            },
            ErrorData::UninstallFailed {
                exit_code: None,
                forced_offered: true,
            },
            ErrorData::OtherAccount,
            ErrorData::NotElevated,
            ErrorData::InstallUntrusted,
            ErrorData::WrongRoute {
                route: Route::Medium,
            },
            ErrorData::Busy,
            ErrorData::Gone { id: IdKind::Plan },
            ErrorData::CapExceeded {
                volume: "C:\\".into(),
                used: 1,
                needed: 2,
                cap: 3,
            },
            ErrorData::Runtime {
                message: String::new(),
            },
        ];
        for data in all {
            let json = serde_json::to_value(&data).unwrap();
            assert_eq!(json["kind"], data.kind());
            let object = ErrorObject::server(data.clone());
            assert_eq!(object.code, SERVER_ERROR);
            assert_eq!(object.message, data.kind());
        }
    }

    #[test]
    fn exits_mirror_the_cli() {
        assert_eq!(Outcome::Complete.cli_exit(), 0);
        assert_eq!(Outcome::Partial.cli_exit(), 10);
        assert_eq!(Outcome::UndoConflicts.cli_exit(), 11);
        assert_eq!(Outcome::NotClosed.cli_exit(), 12);
        assert_eq!(ErrorData::Busy.cli_exit(), None);
        assert_eq!(ErrorData::OtherAccount.cli_exit(), Some(7));
        assert_eq!(
            ErrorData::PlanRefused { refusals: vec![] }.cli_exit(),
            Some(6)
        );
    }
}
