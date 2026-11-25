//! The client's half of M3 design 3.3 step 3 (port of `Broker/BrokerServerCheck.cs`): before the UI
//! writes a byte, the server end of the pipe must be the process `ShellExecuteExW` returned, its image
//! must be the broker that was started, and its token must be elevated.
//!
//! The broker sends nothing to a client it refuses, so this check is the UI's own guarantee that it
//! talks to the administrator part and not to a squatter that won the pipe name: a process of the
//! same user that created `\\.\pipe\purge-<name>` first would otherwise get the user's `engine.hello`
//! and could answer anything. The pid is compared with the pid of the process handle the launcher
//! holds, so the pid cannot have been reused; the image and the token are read from the process the
//! pid names, opened with `PROCESS_QUERY_LIMITED_INFORMATION` only (what a medium process may open of
//! an elevated one).

use std::path::Path;

use purge_win::pipe::same_path;
use purge_win::pipe_client::PipeClient;
use purge_win::process::QueryProcessHandle;
use purge_win::token::Token;

use crate::engine::win32_text;

/// What the client found at the other end of the pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerCheckStatus {
    /// The server is the process the launcher started, from the expected image, running elevated.
    Ok,
    /// `GetNamedPipeServerProcessId` named another process than the one `ShellExecuteExW` returned.
    PidMismatch,
    /// The server process's image is not the broker executable that was launched.
    ImageMismatch,
    /// The server process's token is not elevated.
    NotElevated,
    /// The server process could not be queried (ended, or access refused).
    CannotQuery,
}

/// The answer of [`check_server`]; `reason` is a sentence for the UI (empty when it passed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCheck {
    /// What was found.
    pub status: ServerCheckStatus,
    /// Why it failed.
    pub reason: String,
}

impl ServerCheck {
    /// True when the check passed.
    pub fn ok(&self) -> bool {
        self.status == ServerCheckStatus::Ok
    }

    fn fail(status: ServerCheckStatus, reason: impl Into<String>) -> ServerCheck {
        ServerCheck {
            status,
            reason: reason.into(),
        }
    }
}

const NOT_OURS: &str = "The program on Purge's pipe is not the administrator part Purge started.";

/// Checks the server behind `pipe` (a connected client end, before anything was written).
/// `require_elevation` is false only for tests that cannot be elevated; the launcher always passes
/// true.
pub fn check_server(
    pipe: &PipeClient,
    expected_pid: u32,
    expected_image: &Path,
    require_elevation: bool,
) -> ServerCheck {
    let server_pid = match pipe.server_process_id() {
        Ok(pid) => pid,
        Err(e) => {
            return ServerCheck::fail(
                ServerCheckStatus::CannotQuery,
                format!(
                    "Purge could not tell which program is on its pipe: {}",
                    win32_text(e.code())
                ),
            );
        }
    };
    if server_pid != expected_pid {
        return ServerCheck::fail(ServerCheckStatus::PidMismatch, NOT_OURS);
    }
    let process = match QueryProcessHandle::open(server_pid) {
        Ok(p) => p,
        Err(e) => {
            return ServerCheck::fail(
                ServerCheckStatus::CannotQuery,
                format!(
                    "Purge could not open the administrator part: {}",
                    win32_text(e.code())
                ),
            );
        }
    };
    let Ok(image) = process.image_path() else {
        return ServerCheck::fail(
            ServerCheckStatus::CannotQuery,
            "Purge could not read the administrator part's image.",
        );
    };
    // Ordinal and case-insensitive, as NTFS compares names; no normalisation.
    if !same_path(&image, expected_image) {
        return ServerCheck::fail(ServerCheckStatus::ImageMismatch, NOT_OURS);
    }
    if require_elevation {
        // A token that cannot be read is not known to be elevated.
        let elevated = Token::of_query_process(&process)
            .and_then(|t| t.elevated())
            .unwrap_or(false);
        if !elevated {
            return ServerCheck::fail(
                ServerCheckStatus::NotElevated,
                "The administrator part is not running with administrator permission.",
            );
        }
    }
    ServerCheck {
        status: ServerCheckStatus::Ok,
        reason: String::new(),
    }
}
