//! The UI's end of the broker's named pipe (M3 design 3.3 step 3; review M3-R2 B2).
//!
//! [`PipeClient::open`] opens `\\.\pipe\purge-<name>` the one way the broker accepts:
//!
//! - `GENERIC_READ | GENERIC_WRITE`, `OPEN_EXISTING`, not inheritable, so no child of the UI holds the
//!   link.
//! - `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` (static tracking): the broker may identify the
//!   client before it has written anything (`PipeServer::peer`, review M3-R1 S1), and it can never act
//!   *as* the client, only read who it is.
//! - `FILE_FLAG_OVERLAPPED`: the reader thread sits in a read for the whole life of the link, and
//!   Windows serialises the I/O of a synchronous handle, so a write (`engine.hello` first, and the
//!   broker sends nothing before it) would wait behind that read for ever (review M3-R2 B2). With an
//!   overlapped handle one thread may read while another writes.
//!
//! [`PipeClient::server_process_id`] is `GetNamedPipeServerProcessId`, for the UI's server check
//! before it writes a byte. [`PipeClient::shut_down`] wakes a read or write in flight on another thread
//! and makes every later one fail, so the reader thread ends without the handle being closed under it.
//!
//! All I/O waits for its kernel operation to be over before it returns (a timed-out or shut-down
//! operation is cancelled and waited for), so no kernel I/O outlives its buffer. Nothing here changes
//! system state outside the pipe object.
#![cfg(feature = "read")]

use std::mem;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_OPERATION_ABORTED,
    ERROR_PIPE_NOT_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects, WaitForSingleObject,
};

use crate::os::{Win32Error, wide};

/// `GENERIC_READ`.
const GENERIC_READ: u32 = 0x8000_0000;
/// `GENERIC_WRITE`.
const GENERIC_WRITE: u32 = 0x4000_0000;

/// The flags of the client handle: overlapped, identification-level static QoS.
pub const CLIENT_FLAGS: u32 =
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION;

/// Errors of the client end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PipeClientError {
    /// The operation did not complete within its timeout and was cancelled.
    #[error("pipe operation timed out")]
    TimedOut,
    /// The server closed its end.
    #[error("the pipe server disconnected")]
    Disconnected,
    /// [`PipeClient::shut_down`] was called.
    #[error("the pipe link was shut down")]
    ShutDown,
    /// Any other Win32 failure.
    #[error(transparent)]
    Win32(#[from] Win32Error),
}

/// A manual-reset event.
struct Event(OwnedHandle);

impl Event {
    fn new() -> Result<Event, Win32Error> {
        // SAFETY: anonymous, unnamed, manual-reset, not signalled; default security; not inheritable.
        let h = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if h.is_null() {
            return Err(Win32Error::last());
        }
        // SAFETY: a fresh handle owned by nobody else.
        Ok(Event(unsafe { OwnedHandle::from_raw_handle(h) }))
    }

    fn raw(&self) -> HANDLE {
        self.0.as_raw_handle()
    }
}

/// The client end of a named pipe, opened overlapped with identification-level QoS. `Sync`: one
/// thread may read while another writes.
#[derive(Debug)]
pub struct PipeClient {
    handle: OwnedHandle,
    /// Signalled by [`PipeClient::shut_down`]; every wait also waits on it.
    shutdown: OwnedHandle,
}

impl PipeClient {
    /// One attempt to open `path` (`\\.\pipe\...`). The error is the `CreateFileW` error, e.g.
    /// `ERROR_FILE_NOT_FOUND` (no such pipe yet) or `ERROR_PIPE_BUSY` (the one instance is taken).
    pub fn open(path: &Path) -> Result<PipeClient, Win32Error> {
        let shutdown = Event::new()?;
        let w = wide(path);
        // SAFETY: NUL-terminated name; null security attributes (not inheritable); no template.
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                CLIENT_FLAGS,
                ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            return Err(Win32Error::last());
        }
        // SAFETY: a fresh handle owned by nobody else.
        let handle = unsafe { OwnedHandle::from_raw_handle(h) };
        Ok(PipeClient {
            handle,
            shutdown: shutdown.0,
        })
    }

    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }

    /// Whether [`PipeClient::shut_down`] was called: checked before every operation, so one that
    /// would complete at once (data already buffered) fails too.
    fn is_shut_down(&self) -> bool {
        // SAFETY: valid event handle; a zero wait only reads its state.
        unsafe { WaitForSingleObject(self.shutdown.as_raw_handle(), 0) == WAIT_OBJECT_0 }
    }

    /// `GetNamedPipeServerProcessId`: the pid of the process that created the pipe instance.
    pub fn server_process_id(&self) -> Result<u32, Win32Error> {
        let mut pid = 0u32;
        // SAFETY: valid pipe handle; `pid` is a valid out-pointer.
        if unsafe { GetNamedPipeServerProcessId(self.raw(), &mut pid) } == 0 {
            return Err(Win32Error::last());
        }
        Ok(pid)
    }

    /// Wakes a read or write in flight (on any thread) and makes every later one fail with
    /// [`PipeClientError::ShutDown`]. The handle stays open until the client is dropped: a holder
    /// that wants the server to see the pipe close must also let go of its last reference.
    pub fn shut_down(&self) {
        // SAFETY: valid event handle.
        unsafe { SetEvent(self.shutdown.as_raw_handle()) };
    }

    /// Reads up to `buf.len()` bytes, waiting up to `timeout` (`None`: no limit). `Ok(0)` is end of
    /// stream: the server closed its end.
    pub fn read_with_timeout(
        &self,
        buf: &mut [u8],
        timeout: Option<Duration>,
    ) -> Result<usize, PipeClientError> {
        if self.is_shut_down() {
            return Err(PipeClientError::ShutDown);
        }
        if buf.is_empty() {
            return Ok(0);
        }
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let event = Event::new()?;
        // SAFETY: plain data; zero is valid.
        let mut storage: OVERLAPPED = unsafe { mem::zeroed() };
        storage.hEvent = event.raw();
        // Only this pointer is used from here on: the kernel writes the structure while the
        // operation runs, so no Rust reference to it may exist meanwhile.
        let ov = ptr::addr_of_mut!(storage);
        // SAFETY: `buf` holds `len` writable bytes and, like `ov`, outlives the operation, which
        // `finish` waits for.
        let ok = unsafe { ReadFile(self.raw(), buf.as_mut_ptr(), len, ptr::null_mut(), ov) };
        if ok == 0 {
            let e = Win32Error::last();
            if e.code() != ERROR_IO_PENDING {
                return map(Err(e.into()), true);
            }
        }
        // SAFETY: `ov` is the operation just started on this handle; its event is `event`.
        map(
            unsafe { self.finish(ov, event.raw(), timeout) }.map(|n| n as usize),
            true,
        )
    }

    /// Writes all of `buf` within `timeout` in total. After an error an unknown part of `buf` may have
    /// been written: the stream is no longer framed and the link must end.
    pub fn write_all_with_timeout(
        &self,
        mut buf: &[u8],
        timeout: Duration,
    ) -> Result<(), PipeClientError> {
        let deadline = Instant::now() + timeout;
        while !buf.is_empty() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(PipeClientError::TimedOut);
            }
            let n = self.write_some(buf, left)?;
            if n == 0 {
                return Err(PipeClientError::Disconnected);
            }
            buf = &buf[n..];
        }
        Ok(())
    }

    fn write_some(&self, buf: &[u8], timeout: Duration) -> Result<usize, PipeClientError> {
        if self.is_shut_down() {
            return Err(PipeClientError::ShutDown);
        }
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let event = Event::new()?;
        // SAFETY: plain data; zero is valid.
        let mut storage: OVERLAPPED = unsafe { mem::zeroed() };
        storage.hEvent = event.raw();
        // Only this pointer is used from here on (see `read_with_timeout`).
        let ov = ptr::addr_of_mut!(storage);
        // SAFETY: `buf` holds `len` readable bytes and, like `ov`, outlives the operation.
        let ok = unsafe { WriteFile(self.raw(), buf.as_ptr(), len, ptr::null_mut(), ov) };
        if ok == 0 {
            let e = Win32Error::last();
            if e.code() != ERROR_IO_PENDING {
                return map(Err(e.into()), false);
            }
        }
        // SAFETY: `ov` is the operation just started on this handle; its event is `event`.
        map(
            unsafe { self.finish(ov, event.raw(), Some(timeout)) }.map(|n| n as usize),
            false,
        )
    }

    /// Waits for the operation behind `ov` up to `timeout` or until [`PipeClient::shut_down`],
    /// cancelling it then. Returns only when the kernel is done with `ov` and its buffer.
    ///
    /// # Safety
    ///
    /// `ov` points to the live `OVERLAPPED` of an operation started on this handle, whose `hEvent`
    /// is `event`, and no reference to it exists while this runs (the kernel may write it).
    unsafe fn finish(
        &self,
        ov: *mut OVERLAPPED,
        event: HANDLE,
        timeout: Option<Duration>,
    ) -> Result<u32, PipeClientError> {
        let ms = timeout.map_or(INFINITE, |t| {
            u32::try_from(t.as_millis()).map_or(INFINITE - 1, |ms| ms.min(INFINITE - 1))
        });
        let handles = [event, self.shutdown.as_raw_handle()];
        // SAFETY: two live event handles; wait for any.
        let waited = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, ms) };
        let cancelled = waited != WAIT_OBJECT_0;
        if cancelled {
            // Timeout, shutdown or a failed wait: cancel, then wait below for the cancel to complete.
            // SAFETY: valid handle; `ov` identifies the operation and is still alive.
            unsafe { CancelIoEx(self.raw(), ov) };
        }
        let mut n = 0u32;
        // SAFETY: valid handle and `ov`; bWait = TRUE blocks until the operation is complete.
        if unsafe { GetOverlappedResult(self.raw(), ov, &mut n, 1) } != 0 {
            // Completed, possibly while being cancelled: the bytes count.
            return Ok(n);
        }
        let e = Win32Error::last();
        if cancelled && e.code() == ERROR_OPERATION_ABORTED {
            return Err(if waited == WAIT_TIMEOUT {
                PipeClientError::TimedOut
            } else {
                PipeClientError::ShutDown
            });
        }
        Err(e.into())
    }
}

/// Maps the results: a closed server end is end of stream for a read and
/// [`PipeClientError::Disconnected`] for a write. A shut-down link fails every later call.
fn map<T: Default>(r: Result<T, PipeClientError>, read: bool) -> Result<T, PipeClientError> {
    match r {
        Err(PipeClientError::Win32(e))
            if matches!(
                e.code(),
                ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
            ) =>
        {
            if read {
                Ok(T::default())
            } else {
                Err(PipeClientError::Disconnected)
            }
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;
    use crate::pipe::{PipeOptions, PipeServer};
    use crate::process::ProcessHandle;

    fn random_name() -> String {
        let a = crate::os::random_u64().unwrap();
        let b = crate::os::random_u64().unwrap();
        format!("{a:016x}{b:016x}")
    }

    fn server() -> PipeServer {
        let me = crate::sid::current_user_sid().unwrap();
        PipeServer::create(
            &random_name(),
            &me,
            PipeOptions {
                read_timeout: Some(Duration::from_secs(10)),
                write_timeout: Duration::from_secs(10),
                buffer_size: 4096,
            },
        )
        .unwrap()
    }

    #[test]
    fn a_missing_pipe_is_file_not_found() {
        let path = format!(r"\\.\pipe\purge-{}", random_name());
        assert_eq!(
            PipeClient::open(Path::new(&path)).unwrap_err(),
            Win32Error::FILE_NOT_FOUND
        );
    }

    #[test]
    fn the_broker_identifies_this_client_before_it_writes() {
        // The broker's own server: with identification-level static QoS the peer is readable before
        // the client sent anything (the broker's `identify` relies on it).
        let mut s = server();
        let c = PipeClient::open(Path::new(s.path())).unwrap();
        s.wait_for_client(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(c.server_process_id().unwrap(), std::process::id());
        let peer = s.peer().unwrap();
        let me = ProcessHandle::current().unwrap();
        let expected = crate::pipe::ExpectedPeer {
            pid: std::process::id(),
            creation_time: me.creation_time().unwrap(),
            image: std::env::current_exe().unwrap(),
            user_sid: crate::sid::current_user_sid().unwrap(),
        };
        assert_eq!(peer.check(&expected), Ok(()));
    }

    #[test]
    fn a_write_completes_while_a_read_is_pending() {
        // Review M3-R2 B2: the server sends nothing before it has the line; the client's reader is
        // already inside a read on another thread.
        let mut s = server();
        let c = std::sync::Arc::new(PipeClient::open(Path::new(s.path())).unwrap());
        s.wait_for_client(Some(Duration::from_secs(5))).unwrap();
        let reader = {
            let c = c.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 16];
                let n = c.read_with_timeout(&mut buf, Some(Duration::from_secs(10)));
                (n, buf)
            })
        };
        std::thread::sleep(Duration::from_millis(200));
        c.write_all_with_timeout(b"hello\n", Duration::from_secs(2))
            .unwrap();
        let mut line = [0u8; 6];
        (&s).read_exact(&mut line).unwrap();
        assert_eq!(&line, b"hello\n");
        std::io::Write::write_all(&mut &s, b"ok\n").unwrap();
        let (n, buf) = reader.join().unwrap();
        assert_eq!(n, Ok(3));
        assert_eq!(&buf[..3], b"ok\n");
    }

    #[test]
    fn shut_down_wakes_a_pending_read_and_fails_later_ones() {
        let mut s = server();
        let c = std::sync::Arc::new(PipeClient::open(Path::new(s.path())).unwrap());
        s.wait_for_client(Some(Duration::from_secs(5))).unwrap();
        let reader = {
            let c = c.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 16];
                c.read_with_timeout(&mut buf, None)
            })
        };
        std::thread::sleep(Duration::from_millis(100));
        c.shut_down();
        assert_eq!(reader.join().unwrap(), Err(PipeClientError::ShutDown));
        let mut buf = [0u8; 4];
        assert_eq!(
            c.read_with_timeout(&mut buf, Some(Duration::from_secs(1))),
            Err(PipeClientError::ShutDown)
        );
        assert_eq!(
            c.write_all_with_timeout(b"x", Duration::from_secs(1)),
            Err(PipeClientError::ShutDown)
        );
    }

    #[test]
    fn a_read_with_nothing_to_read_times_out_and_the_link_stays_usable() {
        let mut s = server();
        let c = PipeClient::open(Path::new(s.path())).unwrap();
        s.wait_for_client(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 8];
        let started = Instant::now();
        assert_eq!(
            c.read_with_timeout(&mut buf, Some(Duration::from_millis(200))),
            Err(PipeClientError::TimedOut)
        );
        assert!(started.elapsed() >= Duration::from_millis(150));
        // The cancelled read consumed nothing.
        std::io::Write::write_all(&mut &s, b"ok").unwrap();
        assert_eq!(
            c.read_with_timeout(&mut buf, Some(Duration::from_secs(5))),
            Ok(2)
        );
    }

    /// More than the pipe's buffers hold, so a write waits for a server that does not read.
    const BIG: usize = 1024 * 1024;

    #[test]
    fn a_write_the_server_does_not_read_times_out() {
        let mut s = server();
        let c = PipeClient::open(Path::new(s.path())).unwrap();
        s.wait_for_client(Some(Duration::from_secs(5))).unwrap();
        let big = vec![b'x'; BIG];
        let started = Instant::now();
        assert_eq!(
            c.write_all_with_timeout(&big, Duration::from_millis(300)),
            Err(PipeClientError::TimedOut)
        );
        assert!(started.elapsed() >= Duration::from_millis(250));
        drop(s);
    }

    #[test]
    fn shut_down_wakes_a_blocked_write() {
        let mut s = server();
        let c = std::sync::Arc::new(PipeClient::open(Path::new(s.path())).unwrap());
        s.wait_for_client(Some(Duration::from_secs(5))).unwrap();
        let writer = {
            let c = c.clone();
            std::thread::spawn(move || {
                let big = vec![b'x'; BIG];
                let started = Instant::now();
                (
                    c.write_all_with_timeout(&big, Duration::from_secs(30)),
                    started.elapsed(),
                )
            })
        };
        std::thread::sleep(Duration::from_millis(200));
        c.shut_down();
        let (result, took) = writer.join().unwrap();
        assert_eq!(result, Err(PipeClientError::ShutDown));
        assert!(took < Duration::from_secs(10), "{took:?}");
        drop(s);
    }

    #[test]
    fn a_closed_server_is_end_of_stream() {
        let mut s = server();
        let c = PipeClient::open(Path::new(s.path())).unwrap();
        s.wait_for_client(Some(Duration::from_secs(5))).unwrap();
        drop(s);
        let mut buf = [0u8; 4];
        assert_eq!(
            c.read_with_timeout(&mut buf, Some(Duration::from_secs(5))),
            Ok(0)
        );
        assert_eq!(
            c.write_all_with_timeout(b"x", Duration::from_secs(5)),
            Err(PipeClientError::Disconnected)
        );
    }
}
