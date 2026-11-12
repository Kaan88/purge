//! Shell-link reads on a dedicated COM thread (ENGINE_PLAN.md §3.2, §5.6 FS-SHORTCUTS).
//!
//! `purge_win::shelllink::read_shell_link` loads a `.lnk` through `IShellLinkW`, which needs COM on the
//! calling thread. Scanner threads must not have their COM state changed (a thread already in the
//! multithreaded apartment, or a thread pool another library initialised, would otherwise mix models), so
//! every read is sent to one worker thread that does nothing else. The worker enters a single-threaded
//! apartment for each read through `purge-win` and leaves it again; it is started on the first read and
//! ends when the owning [`ShortcutWorker`] is dropped.
//!
//! A panic inside a read is caught on the worker and reported as an error for that read only; if the
//! worker thread is gone anyway, the next read starts a new one.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Mutex, PoisonError};

use purge_win::shelllink::{ShellLinkInfo, read_shell_link};

use super::errors::{ERROR_WORKER_GONE, map_io};
use crate::types::{SourceError, SourceResult};

/// One read request: the path and where to send the answer.
struct Job {
    path: PathBuf,
    reply: Sender<SourceResult<ShellLinkInfo>>,
}

/// The handle to the shortcut thread, started lazily.
#[derive(Debug, Default)]
pub(crate) struct ShortcutWorker {
    tx: Mutex<Option<Sender<Job>>>,
}

impl ShortcutWorker {
    /// Reads `path` on the worker thread and waits for the answer.
    pub(crate) fn read(&self, path: PathBuf) -> SourceResult<ShellLinkInfo> {
        let (reply, answer) = mpsc::channel();
        let mut job = Job { path, reply };
        // One retry: a worker that died (only possible if the thread itself failed) is replaced once.
        for _ in 0..2 {
            let tx = self.sender()?;
            match tx.send(job) {
                Ok(()) => {
                    return answer
                        .recv()
                        .unwrap_or(Err(SourceError::Other(ERROR_WORKER_GONE)));
                }
                Err(mpsc::SendError(back)) => {
                    job = back;
                    *self.tx.lock().unwrap_or_else(PoisonError::into_inner) = None;
                }
            }
        }
        Err(SourceError::Other(ERROR_WORKER_GONE))
    }

    /// The sender to the running worker, starting it when needed.
    fn sender(&self) -> SourceResult<Sender<Job>> {
        let mut guard = self.tx.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(tx) = guard.as_ref() {
            return Ok(tx.clone());
        }
        let (tx, rx) = mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name("purge-source-shelllink".into())
            .spawn(move || serve(rx))
            .map_err(|e| map_io(&e))?;
        *guard = Some(tx.clone());
        Ok(tx)
    }
}

/// The worker loop: one read at a time until every sender is dropped.
fn serve(rx: Receiver<Job>) {
    for job in rx {
        let result = catch_unwind(AssertUnwindSafe(|| read_shell_link(&job.path)))
            .unwrap_or_else(|_| Err(std::io::Error::other("shell link read panicked")))
            .map_err(|e| map_io(&e));
        // The caller may have given up waiting; nothing to do then.
        let _ = job.reply.send(result);
    }
}
