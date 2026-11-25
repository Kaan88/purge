//! What the Leftovers, History and Quarantine models share about a broker call: how one ended
//! ([`CallError`]), how a broker launch ended ([`BrokerLaunch`]) and the reconcile-alert sentences
//! (the port of `Rpc/ReconcileAlert.cs`). The models never hold a broker: the UI does, and tells
//! the model how each call it sent ended.

use purge_rpc::error::{ErrorData, ErrorObject};
use purge_rpc::methods::{Alert, ConflictRow};

/// How a broker (or engine) call failed, as the UI hands it to a model. The port of the C#
/// `BrokerRpcException` (an `error` answer), `BrokerLinkException` (the link broke) and
/// `OperationCanceledException` (the call was cancelled).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// The broker answered with an error: switch on `error.data.kind`, never on the message.
    Rpc(ErrorObject),
    /// The link to the broker broke: it could not be written to, or it ended.
    Link {
        /// Why, in a sentence for the UI.
        message: String,
        /// The request never went out (the link had ended before, or writing it failed), so the
        /// broker did nothing for it. False: it may have been received, and what it did is unknown.
        not_sent: bool,
    },
    /// The call was cancelled before it answered.
    Cancelled,
    /// Anything else the client could not turn into an answer (an answer that would not read): its
    /// message. Treated like an error answer without a kind.
    Other(String),
}

/// The message of an error answer when the broker sent none (`BrokerRpcClient.cs`).
const NO_MESSAGE: &str = "The administrator part reported an error.";

impl CallError {
    /// An error answer of this kind, for tests and for clients that build one.
    pub fn rpc(data: ErrorData, message: impl Into<String>) -> Self {
        CallError::Rpc(ErrorObject {
            code: purge_rpc::error::SERVER_ERROR,
            message: message.into(),
            data: Some(data),
        })
    }

    /// A broken link.
    pub fn link(message: impl Into<String>, not_sent: bool) -> Self {
        CallError::Link {
            message: message.into(),
            not_sent,
        }
    }

    /// `error.data.kind` of an error answer; `None` for every other failure or an answer without one.
    pub fn kind(&self) -> Option<&'static str> {
        match self {
            CallError::Rpc(ErrorObject { data: Some(d), .. }) => Some(d.kind()),
            _ => None,
        }
    }

    /// `error.data` of an error answer.
    pub fn data(&self) -> Option<&ErrorData> {
        match self {
            CallError::Rpc(e) => e.data.as_ref(),
            _ => None,
        }
    }

    /// Whether this is an error answer (`BrokerRpcException`), as opposed to a broken link or a cancel.
    pub fn is_rpc(&self) -> bool {
        matches!(self, CallError::Rpc(_) | CallError::Other(_))
    }

    /// Whether the link broke (`BrokerLinkException`).
    pub fn is_link(&self) -> bool {
        matches!(self, CallError::Link { .. })
    }

    /// The text the C# exception carried: the answer's message, the link's reason.
    pub fn message(&self) -> &str {
        match self {
            CallError::Rpc(e) if e.message.is_empty() => NO_MESSAGE,
            CallError::Rpc(e) => &e.message,
            CallError::Link { message, .. } => message,
            CallError::Cancelled => "The operation was canceled.",
            CallError::Other(message) => message,
        }
    }
}

/// How a broker launch for a page ended (the UI maps its launcher onto this): the port of
/// `HistoryBrokerLaunch`, `VaultBrokerLaunch` and `LeftoversBrokerLaunch`. The broker itself stays
/// with the UI; the model only learns whether one is live now.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BrokerLaunch {
    /// A broker was started and is now the page's link.
    pub started: bool,
    /// The user said No at the Windows prompt or "Not now" at the explanation.
    pub cancelled: bool,
    /// Why it was not started, for the bar.
    pub message: String,
    /// With `cancelled`: it was "Not now", so no Windows prompt was shown.
    pub declined_explanation: bool,
}

impl BrokerLaunch {
    /// A broker was started.
    pub fn started() -> Self {
        Self {
            started: true,
            ..Self::default()
        }
    }

    /// The Windows prompt was cancelled (`message` may say so).
    pub fn cancelled(message: impl Into<String>) -> Self {
        Self {
            cancelled: true,
            message: message.into(),
            ..Self::default()
        }
    }

    /// "Not now" at the first-elevation explanation: no Windows prompt was shown.
    pub fn declined() -> Self {
        Self {
            cancelled: true,
            declined_explanation: true,
            ..Self::default()
        }
    }

    /// The launch failed for this reason.
    pub fn failed(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            ..Self::default()
        }
    }
}

/// The one sentence for a reconcile alert (review M3-R2 S5), shared by the Leftovers "Put back"
/// result, the History page and the vault, so all say the same thing.
pub fn alert_text(alert: &Alert) -> String {
    if alert.moved_back {
        format!(
            "Purge found another file in quarantine and put it back at {}.",
            alert.original_path
        )
    } else {
        format!(
            "Purge found another file in quarantine and kept it there: {}.",
            alert.original_path
        )
    }
}

/// The line for one conflict of an undo. An item whose kept data was deleted (after its retention,
/// or before it with "Delete now") is said in words; every other conflict keeps its kind.
pub fn conflict_text(conflict: &ConflictRow) -> String {
    let kind = conflict_kind(&conflict.conflict);
    if kind == "Expired" {
        format!(
            "{}: what Purge kept of it was deleted, so it cannot be put back",
            conflict.display_name
        )
    } else {
        format!("{}: {}", conflict.display_name, kind)
    }
}

/// The wire `kind` of an undo conflict (`DestinationExists`, `Expired`, ...).
fn conflict_kind(conflict: &purge_model::exec::journal::UndoConflict) -> String {
    serde_json::to_value(conflict)
        .ok()
        .and_then(|v| v.get("kind").and_then(|k| k.as_str()).map(str::to_owned))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_model::exec::journal::UndoConflict;
    use purge_model::exec::op::OpId;

    #[test]
    fn conflicts_keep_their_kind_and_an_expired_one_is_said_in_words() {
        let row = |conflict| ConflictRow {
            op: OpId(1),
            display_name: r"C:\Program Files\Git".into(),
            conflict,
        };
        assert_eq!(
            conflict_text(&row(UndoConflict::DestinationExists)),
            r"C:\Program Files\Git: DestinationExists"
        );
        assert_eq!(
            conflict_text(&row(UndoConflict::Expired)),
            r"C:\Program Files\Git: what Purge kept of it was deleted, so it cannot be put back"
        );
    }

    #[test]
    fn an_error_answer_reads_its_kind_and_message() {
        let e = CallError::rpc(ErrorData::Busy, "");
        assert_eq!(e.kind(), Some("busy"));
        assert_eq!(e.message(), NO_MESSAGE);
        assert!(CallError::link("gone", true).is_link());
        assert_eq!(CallError::Cancelled.kind(), None);
    }
}
