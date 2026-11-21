//! The transport the broker serves over (M3 design 3.3), as a trait: the binary wires the named
//! pipe ([`crate::wire::PipeLink`]); the library tests use an in-memory one.
//!
//! One [`Link`] is one pipe with one instance. It accepts a client, says who the client is, and moves
//! bytes. A refused client is disconnected and the same link accepts the next one, so the name is
//! never free for another process while the broker runs. A client that passed is the only one ever
//! served: when it is gone the broker ends (design 3.6), so the link is shared by `&` from then on.

use std::time::Duration;

use purge_win::pipe::ExpectedPeer;

/// A transport failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// The operation did not finish within its timeout (nothing was lost).
    TimedOut,
    /// The client closed its end, or the pipe is not connected.
    Disconnected,
    /// Anything else.
    Failed(String),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkError::TimedOut => f.write_str("the pipe operation timed out"),
            LinkError::Disconnected => f.write_str("the pipe client disconnected"),
            LinkError::Failed(why) => write!(f, "the pipe failed: {why}"),
        }
    }
}

impl std::error::Error for LinkError {}

impl From<LinkError> for std::io::Error {
    fn from(e: LinkError) -> Self {
        let kind = match e {
            LinkError::TimedOut => std::io::ErrorKind::TimedOut,
            LinkError::Disconnected => std::io::ErrorKind::BrokenPipe,
            LinkError::Failed(_) => std::io::ErrorKind::Other,
        };
        std::io::Error::new(kind, e)
    }
}

/// Why a client was refused, in the order the checks run (design 3.3 step 4). The client is
/// disconnected and nothing is answered to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The client cannot be identified before its first write (it did not open with identification
    /// level and static tracking, as the UI does), or not at all.
    Unidentified(String),
    /// The pipe's client pid is not `--parent`.
    Pid,
    /// The client process was created at another time than `--parent-ctime`.
    CreationTime,
    /// The client process has exited.
    Exited,
    /// The client's image is not `<own directory>\Purge.exe`.
    Image,
    /// The client runs as another account (`other_account`, design 3.5).
    Account,
    /// The client's token is not its process's token.
    Token,
    /// The client connected and closed before it could be identified.
    Gone,
    /// The client sent no `engine.hello` first: another request, a line that is not a request, or a
    /// line over the first-line cap.
    NotHello,
    /// The client was identified and did not send its `engine.hello` in time.
    HelloTimeout,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Unidentified(why) => write!(f, "client not identified: {why}"),
            Refusal::Pid => f.write_str("client pid is not the parent"),
            Refusal::CreationTime => f.write_str("client creation time differs"),
            Refusal::Exited => f.write_str("client process has exited"),
            Refusal::Image => f.write_str("client image is not Purge.exe in the install directory"),
            Refusal::Account => f.write_str("client runs as another account (other_account)"),
            Refusal::Token => f.write_str("client token differs from its process's token"),
            Refusal::Gone => f.write_str("client closed before it was identified"),
            Refusal::NotHello => f.write_str("client's first request is not engine.hello"),
            Refusal::HelloTimeout => f.write_str("client sent no engine.hello in time"),
        }
    }
}

/// The pipe, as the broker uses it.
pub trait Link: Send + Sync + 'static {
    /// Waits up to `timeout` for a client: `Ok(true)` when one is connected, `Ok(false)` on timeout.
    /// A client that connected and closed first is [`LinkError::Disconnected`] and the link is ready
    /// to wait again.
    fn wait_for_client(&mut self, timeout: Duration) -> Result<bool, LinkError>;

    /// Identifies the connected client and compares it with `expected` (pid, creation time, image,
    /// account). Reads nothing from the client first: a client that cannot be identified before its
    /// first write is [`Refusal::Unidentified`].
    fn identify(&self, expected: &ExpectedPeer) -> Result<(), Refusal>;

    /// Reads up to `buf.len()` bytes, waiting up to `timeout`. `Ok(0)` is end of stream.
    fn read(&self, buf: &mut [u8], timeout: Duration) -> Result<usize, LinkError>;

    /// Writes all of `buf` within `timeout` in total. After an error the stream is not framed any
    /// more: the caller stops writing.
    fn write_all(&self, buf: &[u8], timeout: Duration) -> Result<(), LinkError>;

    /// Disconnects the client, discarding unread data; the link can wait again.
    fn disconnect(&mut self);
}
