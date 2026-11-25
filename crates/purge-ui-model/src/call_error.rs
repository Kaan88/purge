//! How an engine or broker call ended without an answer, as every model needs to tell it apart. One
//! type for all the models (the Programs and Uninstall models and the Leftovers, History and
//! Quarantine models had a near-copy each); the UI maps `purge-client`'s `ClientError` onto it.
//!
//! The port of the C# `BrokerRpcException` (an `error` answer), `BrokerLinkException` (the link
//! broke) and `OperationCanceledException` (the call was cancelled).

use purge_rpc::error::{ErrorData, ErrorObject};

/// Why a call to the engine or the broker failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// The server answered with an error: switch on `error.data.kind`, never on the message.
    Rpc(ErrorObject),
    /// The link broke: it could not be written to, or it ended.
    Link {
        /// Why, in a sentence for the UI.
        message: String,
        /// The request never went out (the link had ended before, or writing it failed), so the
        /// server did nothing for it. False: it may have been received, and what it did is unknown.
        not_sent: bool,
    },
    /// The call was cancelled before it answered.
    Cancelled,
    /// Anything else the client could not turn into an answer (an answer that would not read, a
    /// call this client cannot make): its message. Treated like an error answer without a kind.
    Other(String),
}

/// The message of an error answer when the server sent none (`BrokerRpcClient.cs`).
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

    /// `error.data.kind` of an error answer (e.g. `gone` or `wrong_route`); `None` for every other
    /// failure or an answer without one.
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

    /// The error's text: the answer's message, the link's reason, the failure's sentence.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_error_answer_reads_its_kind_and_message() {
        let e = CallError::rpc(ErrorData::Busy, "");
        assert_eq!(e.kind(), Some("busy"));
        assert_eq!(e.message(), NO_MESSAGE);
        assert!(e.is_rpc());
        assert!(CallError::link("gone", true).is_link());
        assert_eq!(CallError::link("gone", true).message(), "gone");
        assert_eq!(CallError::Cancelled.kind(), None);
        assert!(!CallError::Cancelled.is_rpc());
    }
}
