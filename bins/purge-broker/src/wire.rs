//! What the binary wires into the generic broker: the named pipe ([`PipeLink`]), the TaskDialog
//! ([`TaskDialogConsent`]) and the parent process handle ([`ProcessParent`]). The library does not
//! know them; `serve::run` takes the traits.

use std::io;
use std::time::Duration;

use purge_rpc::methods::ConsentRenderer;
use purge_win::pipe::{ExpectedPeer, PeerMismatch, PipeError, PipeOptions, PipeServer};
use purge_win::process::ProcessHandle;
use purge_win::taskdialog::{Dialog, Outcome, Page};

use crate::lifetime::{Closer, Parent};
use crate::link::{Link, LinkError, Refusal};
use crate::serve::Consent;

/// The pipe `\\.\pipe\purge-<name>`: first instance only, one instance, the broker's user and SYSTEM
/// (`purge_win::pipe`).
pub struct PipeLink {
    server: PipeServer,
}

impl PipeLink {
    /// Creates the pipe. [`PipeError::NameTaken`] when the name exists already (design 3.3 step 2:
    /// the broker then exits).
    pub fn create(name: &str, user_sid: &str) -> Result<PipeLink, PipeError> {
        Ok(PipeLink {
            server: PipeServer::create(name, user_sid, PipeOptions::default())?,
        })
    }

    /// The pipe's path.
    pub fn path(&self) -> &str {
        self.server.path()
    }
}

fn failed(e: PipeError) -> LinkError {
    match e {
        PipeError::TimedOut => LinkError::TimedOut,
        PipeError::Disconnected | PipeError::NotConnected => LinkError::Disconnected,
        other => LinkError::Failed(other.to_string()),
    }
}

impl Link for PipeLink {
    fn wait_for_client(&mut self, timeout: Duration) -> Result<bool, LinkError> {
        match self.server.wait_for_client(Some(timeout)) {
            Ok(()) => Ok(true),
            Err(PipeError::TimedOut) => Ok(false),
            Err(e) => Err(failed(e)),
        }
    }

    /// Identification before any read (review M3-R1 S1): the UI opens with identification level and
    /// static tracking, which the server can identify at once. A client that cannot be identified
    /// before its first write, and any other failure to identify, is a refused client.
    fn identify(&self, expected: &ExpectedPeer) -> Result<(), Refusal> {
        let peer = self.server.peer().map_err(|e| match e {
            PipeError::ReadFirst => {
                Refusal::Unidentified("not identifiable before its first write".into())
            }
            PipeError::NotConnected | PipeError::Disconnected => Refusal::Gone,
            other => Refusal::Unidentified(other.to_string()),
        })?;
        peer.check(expected).map_err(|m| match m {
            PeerMismatch::Pid => Refusal::Pid,
            PeerMismatch::CreationTime => Refusal::CreationTime,
            PeerMismatch::Exited => Refusal::Exited,
            PeerMismatch::Image => Refusal::Image,
            PeerMismatch::Account => Refusal::Account,
            PeerMismatch::Token => Refusal::Token,
        })
    }

    fn read(&self, buf: &mut [u8], timeout: Duration) -> Result<usize, LinkError> {
        self.server
            .read_with_timeout(buf, Some(timeout))
            .map_err(failed)
    }

    fn write_all(&self, buf: &[u8], timeout: Duration) -> Result<(), LinkError> {
        self.server
            .write_all_with_timeout(buf, timeout)
            .map_err(failed)
    }

    fn disconnect(&mut self) {
        let _ = self.server.disconnect();
    }
}

/// How long the broker waits for the window to come up before it stops waiting to say so. The dialog
/// itself keeps running; `consent.shown` is then simply not sent.
const CREATE_WAIT: Duration = Duration::from_secs(30);

/// The consent dialog: `purge_win::taskdialog` on its own thread, closed as Cancel through the
/// [`Closer`] when the parent or the pipe is lost.
#[derive(Debug, Default, Clone, Copy)]
pub struct TaskDialogConsent;

impl Consent for TaskDialogConsent {
    fn ask(
        &self,
        pages: &[Page],
        primary: i32,
        closer: &Closer,
        shown: &(dyn Fn(ConsentRenderer) + Sync),
    ) -> io::Result<Outcome> {
        let dialog = Dialog::open(pages, primary)?;
        let handle = dialog.close_handle();
        closer.arm(move || handle.close());
        if dialog.wait_created(CREATE_WAIT) {
            shown(ConsentRenderer::TaskDialog);
        }
        let outcome = dialog.wait();
        closer.disarm();
        outcome
    }
}

/// The process `--parent` names, held from the broker's start.
pub struct ProcessParent(ProcessHandle);

impl ProcessParent {
    /// Opens process `pid` and checks that it was created at `creation_time` (a `FILETIME`): a pid
    /// that names another process, or none, is an error.
    pub fn open(pid: u32, creation_time: u64) -> Result<ProcessParent, String> {
        let process = ProcessHandle::open(pid).map_err(|e| format!("process {pid}: {e}"))?;
        let created = process
            .creation_time()
            .map_err(|e| format!("process {pid}: {e}"))?;
        if created != creation_time {
            return Err(format!(
                "process {pid} was created at {created}, not at {creation_time}"
            ));
        }
        if process.has_exited().unwrap_or(true) {
            return Err(format!("process {pid} has exited"));
        }
        Ok(ProcessParent(process))
    }
}

impl Parent for ProcessParent {
    fn exited(&self) -> bool {
        self.0.has_exited().unwrap_or(true)
    }
}
