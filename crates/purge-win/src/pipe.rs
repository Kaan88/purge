//! The broker's named pipe server and the identity of its client (M3 design 3.3, threats T2, T5, T13).
//!
//! [`PipeServer::create`] makes `\\.\pipe\purge-<name>` as the **first and only** instance
//! (`FILE_FLAG_FIRST_PIPE_INSTANCE`, `nMaxInstances = 1`), refuses remote clients
//! (`PIPE_REJECT_REMOTE_CLIENTS`), and sets a protected DACL with exactly two entries, the given user
//! SID and SYSTEM, each with `FILE_GENERIC_READ | FILE_GENERIC_WRITE`, plus a medium mandatory label
//! with no-write-up and no-read-up, so low-integrity and AppContainer processes of the same user cannot
//! open it. A name that exists already is [`PipeError::NameTaken`]; the broker then exits.
//!
//! The one instance is kept for the server's whole life: a refused client is disconnected with
//! [`PipeServer::disconnect`] and the same instance waits again, so the name is never free for another
//! process to take while the broker runs.
//!
//! All I/O is overlapped with a timeout ([`PipeOptions`]): `wait_for_client`, `read_with_timeout` and
//! `write_all_with_timeout`
//! return [`PipeError::TimedOut`] instead of blocking. A timed-out operation is cancelled and waited
//! for before the call returns, so no kernel I/O outlives its buffer. One thread may read while another
//! writes (`&self`); connecting and disconnecting need `&mut self`.
//!
//! [`PipeServer::peer`] reads the client: pid (`GetNamedPipeClientProcessId`), a held
//! [`ProcessHandle`] opened before anything is compared, its creation time and image path, and the
//! client's token through `ImpersonateNamedPipeClient` / `OpenThreadToken` / `RevertToSelf`. The
//! impersonation lives in a guard whose drop reverts; if the revert fails the process aborts, so no
//! path continues as the client. [`Peer::check`] compares against what the broker expects (design 3.3
//! step 4).
//!
//! Nothing here changes system state outside the pipe object itself.
#![cfg(feature = "read")]

use std::ffi::c_void;
use std::io;
use std::marker::PhantomData;
use std::mem;
use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_CANNOT_IMPERSONATE, ERROR_IO_PENDING,
    ERROR_NO_DATA, ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_NOT_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, RevertToSelf, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{CreateEventW, INFINITE, WaitForSingleObject};

use crate::os::{Win32Error, from_wide, wide};
use crate::process::ProcessHandle;
use crate::token::{Token, TokenFacts};

/// Prefix of every pipe name: `\\.\pipe\purge-`.
pub const PIPE_PREFIX: &str = r"\\.\pipe\purge-";

/// Length of the random part of the name: 128 bits as hex digits.
pub const NAME_LEN: usize = 32;

/// Access each of the two DACL entries grants: `FILE_GENERIC_READ | FILE_GENERIC_WRITE`, what a client
/// opening with `GENERIC_READ | GENERIC_WRITE` (the .NET `NamedPipeClientStream` with `InOut`) needs.
/// No `WRITE_DAC`, `WRITE_OWNER` or `DELETE`. `FILE_CREATE_PIPE_INSTANCE` is part of
/// `FILE_GENERIC_WRITE`; the one-instance limit is what stops a second instance.
pub const CLIENT_ACCESS: u32 = 0x0012_019F;

/// Timeouts and buffer sizes of a [`PipeServer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeOptions {
    /// Limit of one `read` through [`std::io::Read`]; `None` waits without limit.
    pub read_timeout: Option<Duration>,
    /// Limit of one `write_all` through [`std::io::Write`] (design T13: 30 s).
    pub write_timeout: Duration,
    /// In and out buffer size hint passed to `CreateNamedPipeW`.
    pub buffer_size: u32,
}

impl Default for PipeOptions {
    fn default() -> Self {
        PipeOptions {
            read_timeout: None,
            write_timeout: Duration::from_secs(30),
            buffer_size: 64 * 1024,
        }
    }
}

/// Errors of the pipe server.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PipeError {
    /// The name is not [`NAME_LEN`] hex digits.
    #[error("pipe name is not {NAME_LEN} hex digits")]
    InvalidName,
    /// The SID for the DACL is not of the form `S-1-<digits>(-<digits>)*`.
    #[error("not a SID string")]
    InvalidSid,
    /// The pipe name exists already (another process created it first).
    #[error("the pipe name exists already")]
    NameTaken,
    /// The operation did not complete within its timeout and was cancelled.
    #[error("pipe operation timed out")]
    TimedOut,
    /// The client closed its end (or connected and closed before the wait completed).
    #[error("the pipe client disconnected")]
    Disconnected,
    /// No client is connected.
    #[error("no pipe client is connected")]
    NotConnected,
    /// The calling thread already has an impersonation token; [`PipeServer::peer`] refuses to replace
    /// or drop it.
    #[error("the calling thread already impersonates")]
    ThreadImpersonating,
    /// Nothing has been read from the client yet: `ImpersonateNamedPipeClient` fails with
    /// `ERROR_CANNOT_IMPERSONATE` until the server has read data from the pipe. Read first, then ask.
    #[error("nothing read from the pipe client yet")]
    ReadFirst,
    /// Any other Win32 failure.
    #[error(transparent)]
    Win32(#[from] Win32Error),
}

impl From<PipeError> for io::Error {
    fn from(e: PipeError) -> Self {
        let kind = match e {
            PipeError::TimedOut => io::ErrorKind::TimedOut,
            PipeError::Disconnected => io::ErrorKind::BrokenPipe,
            PipeError::NotConnected => io::ErrorKind::NotConnected,
            PipeError::InvalidName | PipeError::InvalidSid => io::ErrorKind::InvalidInput,
            PipeError::Win32(w) => return w.into(),
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, e)
    }
}

/// True for `[0-9A-Fa-f]{NAME_LEN}`.
pub fn valid_name(name: &str) -> bool {
    name.len() == NAME_LEN && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// True for `S-1-<digits>(-<digits>)*`: nothing that could end an SDDL entry or add another.
pub fn valid_sid(sid: &str) -> bool {
    let Some(rest) = sid.strip_prefix("S-1-") else {
        return false;
    };
    rest.split('-').all(|part| {
        !part.is_empty() && part.len() <= 10 && part.bytes().all(|b| b.is_ascii_digit())
    })
}

/// The SDDL of the pipe: protected DACL for `user_sid` and SYSTEM, medium label, no-write-up and
/// no-read-up. `user_sid` must pass [`valid_sid`].
pub fn pipe_sddl(user_sid: &str) -> Result<String, PipeError> {
    if !valid_sid(user_sid) {
        return Err(PipeError::InvalidSid);
    }
    Ok(format!(
        "D:P(A;;{CLIENT_ACCESS:#x};;;{user_sid})(A;;{CLIENT_ACCESS:#x};;;SY)S:(ML;;NWNR;;;ME)"
    ))
}

/// Memory from `LocalAlloc`, freed on drop.
struct LocalMem(*mut c_void);

impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API that allocates with LocalAlloc.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// A manual-reset event for one overlapped operation.
struct Event(OwnedHandle);

impl Event {
    fn new() -> Result<Event, Win32Error> {
        // SAFETY: anonymous, unnamed event; default security; not inheritable.
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

/// Milliseconds for a Win32 wait: `None` is `INFINITE`; anything longer than that is capped below it.
fn wait_ms(timeout: Option<Duration>) -> u32 {
    timeout.map_or(INFINITE, |t| {
        u32::try_from(t.as_millis()).map_or(INFINITE - 1, |ms| ms.min(INFINITE - 1))
    })
}

/// The server end of `\\.\pipe\purge-<name>`, one instance.
#[derive(Debug)]
pub struct PipeServer {
    handle: OwnedHandle,
    path: String,
    options: PipeOptions,
}

impl PipeServer {
    /// Creates the first and only instance of `\\.\pipe\purge-<name>`, its DACL for `user_sid` and
    /// SYSTEM ([`pipe_sddl`]). Does not wait for a client.
    pub fn create(
        name: &str,
        user_sid: &str,
        options: PipeOptions,
    ) -> Result<PipeServer, PipeError> {
        if !valid_name(name) {
            return Err(PipeError::InvalidName);
        }
        let sddl = wide(pipe_sddl(user_sid)?);
        let path = format!("{PIPE_PREFIX}{name}");

        let mut psd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: NUL-terminated SDDL; `psd` receives a LocalAlloc descriptor.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(Win32Error::last().into());
        }
        let sd = LocalMem(psd);
        let sa = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        let path_w = wide(&path);
        // SAFETY: NUL-terminated name; `sa` and the descriptor it points to are alive for the call.
        let h = unsafe {
            CreateNamedPipeW(
                path_w.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                options.buffer_size,
                options.buffer_size,
                0,
                &sa,
            )
        };
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            let e = Win32Error::last();
            // With FILE_FLAG_FIRST_PIPE_INSTANCE an existing name fails with access denied; an existing
            // instance at its limit fails with pipe busy.
            return Err(match e.code() {
                ERROR_ACCESS_DENIED | ERROR_PIPE_BUSY => PipeError::NameTaken,
                _ => e.into(),
            });
        }
        // SAFETY: a fresh handle owned by nobody else.
        let handle = unsafe { OwnedHandle::from_raw_handle(h) };
        Ok(PipeServer {
            handle,
            path,
            options,
        })
    }

    /// The full pipe path (`\\.\pipe\purge-<name>`).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The options the server was created with.
    pub fn options(&self) -> PipeOptions {
        self.options
    }

    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }

    /// Waits up to `timeout` (`None`: no limit) for a client to connect. A client that connected and
    /// closed before the wait ended gives [`PipeError::Disconnected`], and the instance is already
    /// disconnected for the next wait.
    pub fn wait_for_client(&mut self, timeout: Option<Duration>) -> Result<(), PipeError> {
        let event = Event::new()?;
        // SAFETY: plain data; zero is valid.
        let mut storage: OVERLAPPED = unsafe { mem::zeroed() };
        storage.hEvent = event.raw();
        // Only this pointer is used from here on: the kernel writes the structure while the
        // operation runs, so no Rust reference to it may exist meanwhile.
        let ov = ptr::addr_of_mut!(storage);
        // SAFETY: valid pipe handle; `ov` lives on this frame until the operation has finished.
        if unsafe { ConnectNamedPipe(self.raw(), ov) } == 0 {
            let e = Win32Error::last();
            match e.code() {
                ERROR_PIPE_CONNECTED => return Ok(()),
                ERROR_NO_DATA => {
                    self.disconnect()?;
                    return Err(PipeError::Disconnected);
                }
                ERROR_IO_PENDING => {}
                _ => return Err(e.into()),
            }
        }
        // SAFETY: `ov` is the operation just started on this handle; its event is `event`.
        match unsafe { self.finish(ov, event.raw(), timeout) } {
            Ok(_) => Ok(()),
            Err(PipeError::Win32(e)) if e.code() == ERROR_NO_DATA => {
                self.disconnect()?;
                Err(PipeError::Disconnected)
            }
            Err(e) => Err(e),
        }
    }

    /// Disconnects the current client (if any), discarding unread data; the instance can wait again.
    pub fn disconnect(&mut self) -> Result<(), PipeError> {
        // SAFETY: valid pipe handle.
        if unsafe { DisconnectNamedPipe(self.raw()) } == 0 {
            let e = Win32Error::last();
            if e.code() != ERROR_PIPE_NOT_CONNECTED {
                return Err(e.into());
            }
        }
        Ok(())
    }

    /// Reads up to `buf.len()` bytes, waiting up to `timeout` (`None`: no limit). `Ok(0)` is end of
    /// stream: the client closed its end. On a timeout nothing was read (a read that completed while
    /// it was being cancelled returns its bytes instead).
    pub fn read_with_timeout(
        &self,
        buf: &mut [u8],
        timeout: Option<Duration>,
    ) -> Result<usize, PipeError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let event = Event::new()?;
        // SAFETY: plain data; zero is valid.
        let mut storage: OVERLAPPED = unsafe { mem::zeroed() };
        storage.hEvent = event.raw();
        // Only this pointer is used from here on (see `wait_for_client`).
        let ov = ptr::addr_of_mut!(storage);
        // SAFETY: `buf` holds `len` writable bytes and, like `ov`, outlives the operation, which
        // `finish` waits for.
        let ok = unsafe { ReadFile(self.raw(), buf.as_mut_ptr(), len, ptr::null_mut(), ov) };
        if ok == 0 {
            let e = Win32Error::last();
            if e.code() != ERROR_IO_PENDING {
                return map_read(Err(e.into()));
            }
        }
        // SAFETY: `ov` is the operation just started on this handle; its event is `event`.
        map_read(unsafe { self.finish(ov, event.raw(), timeout) }.map(|n| n as usize))
    }

    /// Writes some of `buf`, waiting up to `timeout`.
    fn write_some(&self, buf: &[u8], timeout: Option<Duration>) -> Result<usize, PipeError> {
        let len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let event = Event::new()?;
        // SAFETY: plain data; zero is valid.
        let mut storage: OVERLAPPED = unsafe { mem::zeroed() };
        storage.hEvent = event.raw();
        // Only this pointer is used from here on (see `wait_for_client`).
        let ov = ptr::addr_of_mut!(storage);
        // SAFETY: `buf` holds `len` readable bytes and, like `ov`, outlives the operation.
        let ok = unsafe { WriteFile(self.raw(), buf.as_ptr(), len, ptr::null_mut(), ov) };
        if ok == 0 {
            let e = Win32Error::last();
            if e.code() != ERROR_IO_PENDING {
                return map_write(Err(e.into()));
            }
        }
        // SAFETY: `ov` is the operation just started on this handle; its event is `event`.
        map_write(unsafe { self.finish(ov, event.raw(), timeout) }.map(|n| n as usize))
    }

    /// Writes all of `buf` within `timeout` in total. After a [`PipeError::TimedOut`] an unknown part
    /// of `buf` may have been written: the stream is no longer framed and the caller must disconnect.
    pub fn write_all_with_timeout(
        &self,
        mut buf: &[u8],
        timeout: Duration,
    ) -> Result<(), PipeError> {
        let deadline = Instant::now() + timeout;
        while !buf.is_empty() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(PipeError::TimedOut);
            }
            let n = self.write_some(buf, Some(left))?;
            if n == 0 {
                return Err(PipeError::Disconnected);
            }
            buf = &buf[n..];
        }
        Ok(())
    }

    /// Waits for the overlapped operation behind `ov` (started on this handle with `ov.hEvent` set)
    /// up to `timeout`, cancelling it on timeout. Returns only when the kernel is done with `ov` and
    /// the operation's buffer.
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
    ) -> Result<u32, PipeError> {
        // SAFETY: `event` is the live event of the pending operation.
        let waited = unsafe { WaitForSingleObject(event, wait_ms(timeout)) };
        let mut cancelled = false;
        if waited != WAIT_OBJECT_0 {
            // Timeout or a failed wait: cancel, then wait below for the cancellation to complete.
            // SAFETY: valid handle; `ov` identifies the operation and is still alive.
            unsafe { CancelIoEx(self.raw(), ov) };
            cancelled = true;
        }
        let mut n = 0u32;
        // SAFETY: valid handle and `ov`; bWait = TRUE blocks until the operation is complete.
        if unsafe { GetOverlappedResult(self.raw(), ov, &mut n, 1) } != 0 {
            // Completed, possibly while being cancelled: the bytes count.
            return Ok(n);
        }
        let e = Win32Error::last();
        if cancelled && waited == WAIT_TIMEOUT && e.code() == ERROR_OPERATION_ABORTED {
            return Err(PipeError::TimedOut);
        }
        Err(e.into())
    }

    /// The security descriptor of the pipe (owner, DACL and label) in SDDL form, read back from the
    /// handle.
    pub fn sddl(&self) -> Result<String, Win32Error> {
        let info =
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
        let mut psd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: valid handle; only the descriptor out-pointer is requested.
        let rc = unsafe {
            GetSecurityInfo(
                self.raw(),
                SE_KERNEL_OBJECT,
                info,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut psd,
            )
        };
        Win32Error::check(rc)?;
        let sd = LocalMem(psd);
        let mut text: *mut u16 = ptr::null_mut();
        let mut text_len = 0u32;
        // SAFETY: valid descriptor; `text` receives a LocalAlloc string of `text_len` units.
        if unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd.0,
                SDDL_REVISION_1,
                info,
                &mut text,
                &mut text_len,
            )
        } == 0
        {
            return Err(Win32Error::last());
        }
        let text_mem = LocalMem(text.cast());
        // SAFETY: `text` points to `text_len` readable UTF-16 units, alive until `text_mem` drops.
        let units =
            unsafe { std::slice::from_raw_parts(text_mem.0 as *const u16, text_len as usize) };
        Ok(from_wide(units))
    }

    /// The connected client: its pid, a held process handle, creation time, image path and token
    /// facts (by impersonation, reverted before this returns). Compare with [`Peer::check`].
    ///
    /// Ask after the first read from the client. A client that opened with
    /// `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` (static tracking, as the UI does) can be
    /// identified at once; one that opened without SQOS flags (dynamic tracking) has no security
    /// context before its first write, `ImpersonateNamedPipeClient` fails with
    /// `ERROR_CANNOT_IMPERSONATE`, and this returns [`PipeError::ReadFirst`] (nothing is kept). So
    /// the broker reads the first request line, asks for the peer, and answers nothing before
    /// [`Peer::check`] passed (design 3.3 steps 4 to 6).
    pub fn peer(&self) -> Result<Peer, PipeError> {
        let mut pid = 0u32;
        // SAFETY: valid pipe handle; `pid` is a valid out-pointer.
        if unsafe { GetNamedPipeClientProcessId(self.raw(), &mut pid) } == 0 {
            let e = Win32Error::last();
            return Err(match e.code() {
                ERROR_PIPE_NOT_CONNECTED => PipeError::NotConnected,
                _ => e.into(),
            });
        }
        // The handle first: from here on the pid names this process and no later one.
        let process = ProcessHandle::open(pid)?;
        let creation_time = process.creation_time()?;
        let image = process.image_path()?;
        let process_token = Token::of_process(&process)?.facts()?;
        let token = self.client_token()?.facts()?;
        Ok(Peer {
            pid,
            process,
            creation_time,
            image,
            token,
            process_token,
        })
    }

    /// The client's token, opened while impersonating it; the impersonation is over when this returns.
    fn client_token(&self) -> Result<Token, PipeError> {
        if Token::of_current_thread()?.is_some() {
            return Err(PipeError::ThreadImpersonating);
        }
        let guard = Impersonation::of_pipe_client(self.handle.as_handle()).map_err(|e| {
            if e.code() == ERROR_CANNOT_IMPERSONATE {
                PipeError::ReadFirst
            } else {
                PipeError::Win32(e)
            }
        })?;
        let token = Token::of_current_thread();
        drop(guard);
        token?.ok_or(PipeError::Win32(Win32Error::INVALID_DATA))
    }
}

/// Maps the read results: a closed client end is end of stream.
fn map_read(r: Result<usize, PipeError>) -> Result<usize, PipeError> {
    match r {
        Err(PipeError::Win32(e)) if e.code() == ERROR_BROKEN_PIPE => Ok(0),
        Err(PipeError::Win32(e)) if e.code() == ERROR_PIPE_NOT_CONNECTED => {
            Err(PipeError::NotConnected)
        }
        other => other,
    }
}

/// Maps the write results: a closed or closing client end is [`PipeError::Disconnected`].
fn map_write(r: Result<usize, PipeError>) -> Result<usize, PipeError> {
    match r {
        Err(PipeError::Win32(e)) if matches!(e.code(), ERROR_BROKEN_PIPE | ERROR_NO_DATA) => {
            Err(PipeError::Disconnected)
        }
        Err(PipeError::Win32(e)) if e.code() == ERROR_PIPE_NOT_CONNECTED => {
            Err(PipeError::NotConnected)
        }
        other => other,
    }
}

impl io::Read for &PipeServer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Ok(self.read_with_timeout(buf, self.options.read_timeout)?)
    }
}

impl io::Write for &PipeServer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_all_with_timeout(buf, self.options.write_timeout)?;
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        Ok(self.write_all_with_timeout(buf, self.options.write_timeout)?)
    }

    /// Written bytes are in the pipe once `write` returns; there is nothing to flush (and
    /// `FlushFileBuffers` would block until the client has read them).
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Read for PipeServer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        io::Read::read(&mut &*self, buf)
    }
}

impl io::Write for PipeServer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::Write::write(&mut &*self, buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        io::Write::write_all(&mut &*self, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The calling thread impersonates the pipe client while this lives. Not `Send`: impersonation
/// belongs to the thread that started it. Drop reverts; if `RevertToSelf` fails the process aborts,
/// because going on would run as the client.
struct Impersonation {
    _thread_bound: PhantomData<*const ()>,
}

impl Impersonation {
    fn of_pipe_client(pipe: BorrowedHandle<'_>) -> Result<Impersonation, Win32Error> {
        // SAFETY: valid pipe handle.
        if unsafe { ImpersonateNamedPipeClient(pipe.as_raw_handle()) } == 0 {
            let e = Win32Error::last();
            // Nothing should have changed, but make sure the thread is itself again.
            revert_or_abort();
            return Err(e);
        }
        Ok(Impersonation {
            _thread_bound: PhantomData,
        })
    }
}

impl Drop for Impersonation {
    fn drop(&mut self) {
        revert_or_abort();
    }
}

fn revert_or_abort() {
    // SAFETY: plain call; reverting a thread that does not impersonate is a no-op.
    if unsafe { RevertToSelf() } == 0 {
        std::process::abort();
    }
}

/// What the broker expects of its client (design 3.3 step 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedPeer {
    /// `--parent`.
    pub pid: u32,
    /// `--parent-ctime` (FILETIME).
    pub creation_time: u64,
    /// `<broker's own directory>\Purge.exe`.
    pub image: PathBuf,
    /// The broker's own user SID.
    pub user_sid: String,
}

/// Why a client was refused, in the order [`Peer::check`] tests them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PeerMismatch {
    /// `GetNamedPipeClientProcessId` is not the expected pid.
    #[error("client pid differs")]
    Pid,
    /// The client process was created at another time (another process with a reused pid).
    #[error("client creation time differs")]
    CreationTime,
    /// The client process has exited.
    #[error("client process has exited")]
    Exited,
    /// The client image is not the expected path.
    #[error("client image path differs")]
    Image,
    /// The client runs as another account (`other_account`, design 3.5).
    #[error("client runs as another account")]
    Account,
    /// The client's token (by impersonation) differs from the primary token of the process the pid
    /// names: user, elevation or integrity. The pipe was not opened by that process as it is now.
    #[error("client token differs from the client process's token")]
    Token,
}

/// The connected client, read by [`PipeServer::peer`].
#[derive(Debug)]
pub struct Peer {
    /// `GetNamedPipeClientProcessId`.
    pub pid: u32,
    /// Opened right after the pid was read and before any comparison; keep it while the client is
    /// served (its signal is the client's exit).
    pub process: ProcessHandle,
    /// Creation time of `process` (FILETIME).
    pub creation_time: u64,
    /// Image path of `process`.
    pub image: PathBuf,
    /// Facts of the client's token (by impersonation).
    pub token: TokenFacts,
    /// Facts of the primary token of `process`.
    pub process_token: TokenFacts,
}

impl Peer {
    /// Compares the client with `expected`: pid, creation time, still running, image path (ordinal,
    /// case-insensitive, as NTFS compares names), user SID, and the client token against the
    /// process's own token. The first difference is the answer.
    pub fn check(&self, expected: &ExpectedPeer) -> Result<(), PeerMismatch> {
        if self.pid != expected.pid || self.process.pid() != expected.pid {
            return Err(PeerMismatch::Pid);
        }
        if self.creation_time != expected.creation_time {
            return Err(PeerMismatch::CreationTime);
        }
        if self.process.has_exited().unwrap_or(true) {
            return Err(PeerMismatch::Exited);
        }
        if !same_path(&self.image, &expected.image) {
            return Err(PeerMismatch::Image);
        }
        if self.token.user_sid != expected.user_sid {
            return Err(PeerMismatch::Account);
        }
        if self.token != self.process_token {
            return Err(PeerMismatch::Token);
        }
        Ok(())
    }
}

/// Ordinal, case-insensitive comparison of two paths (`CompareStringOrdinal` with `bIgnoreCase`), no
/// normalisation: `a\b` and `a\.\b` differ.
pub fn same_path(a: &Path, b: &Path) -> bool {
    let a: Vec<u16> = wide(a);
    let b: Vec<u16> = wide(b);
    let (la, lb) = (a.len() - 1, b.len() - 1);
    let (Ok(la), Ok(lb)) = (i32::try_from(la), i32::try_from(lb)) else {
        return false;
    };
    // SAFETY: both buffers hold the stated number of units.
    unsafe { CompareStringOrdinal(a.as_ptr(), la, b.as_ptr(), lb, 1) == CSTR_EQUAL }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};

    use windows_sys::Win32::Storage::FileSystem::{SECURITY_ANONYMOUS, SECURITY_IDENTIFICATION};
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

    use super::*;

    fn random_name() -> String {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        let mut out = String::new();
        for i in 0..2u64 {
            let mut h = RandomState::new().build_hasher();
            h.write_u64(i);
            h.write_u32(std::process::id());
            h.write_u128(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
            );
            out.push_str(&format!("{:016x}", h.finish()));
        }
        out
    }

    fn me() -> String {
        crate::sid::current_user_sid().unwrap()
    }

    fn opts() -> PipeOptions {
        PipeOptions {
            read_timeout: Some(Duration::from_secs(10)),
            write_timeout: Duration::from_secs(10),
            buffer_size: 4096,
        }
    }

    fn server() -> PipeServer {
        PipeServer::create(&random_name(), &me(), opts()).unwrap()
    }

    /// Opens the client end in this process with identification-level QoS, as the UI does.
    fn connect(path: &str) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(path)
    }

    fn expected_self() -> ExpectedPeer {
        let me_h = ProcessHandle::current().unwrap();
        ExpectedPeer {
            pid: std::process::id(),
            creation_time: me_h.creation_time().unwrap(),
            image: std::env::current_exe().unwrap(),
            user_sid: me(),
        }
    }

    #[test]
    fn names_and_sids() {
        assert!(valid_name("0123456789abcdefABCDEF0123456789"));
        assert!(!valid_name("0123456789abcdef"));
        assert!(!valid_name("0123456789abcdefABCDEF012345678g"));
        assert!(!valid_name(r"..\..\0123456789abcdef0123456789"));
        assert!(valid_sid("S-1-5-18"));
        assert!(valid_sid("S-1-5-21-1-2-3-1001"));
        for bad in [
            "",
            "S-1-",
            "S-1-5-",
            "S-1-5--18",
            "s-1-5-18",
            "S-1-5-18)(A;;GA;;;WD",
            "S-1-5-18 ",
            "S-1-5-99999999999",
            "WD",
        ] {
            assert!(!valid_sid(bad), "{bad:?}");
            assert_eq!(pipe_sddl(bad), Err(PipeError::InvalidSid));
        }
        assert_eq!(
            PipeServer::create("nothex", &me(), opts()).unwrap_err(),
            PipeError::InvalidName
        );
        assert_eq!(
            PipeServer::create(&random_name(), "S-1-5-18)(A;;GA;;;WD", opts()).unwrap_err(),
            PipeError::InvalidSid
        );
    }

    #[test]
    fn second_instance_fails() {
        let s = server();
        let name = &s.path()[PIPE_PREFIX.len()..];
        assert_eq!(
            PipeServer::create(name, &me(), opts()).unwrap_err(),
            PipeError::NameTaken
        );
        // Another instance without FILE_FLAG_FIRST_PIPE_INSTANCE (a squatter adding an instance) is
        // refused by the one-instance limit.
        let w = wide(s.path());
        // SAFETY: NUL-terminated name; default security.
        let h = unsafe {
            CreateNamedPipeW(
                w.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE,
                255,
                4096,
                4096,
                0,
                ptr::null(),
            )
        };
        let e = Win32Error::last();
        if h != INVALID_HANDLE_VALUE {
            // SAFETY: we own the handle just created.
            drop(unsafe { OwnedHandle::from_raw_handle(h) });
            panic!("a second instance was created");
        }
        assert!(
            matches!(e.code(), ERROR_PIPE_BUSY | ERROR_ACCESS_DENIED),
            "{e}"
        );
    }

    #[test]
    fn a_squatted_name_is_taken() {
        // A process that created the name first, without the DACL, wins; the broker gets NameTaken.
        let name = random_name();
        let w = wide(format!("{PIPE_PREFIX}{name}"));
        // SAFETY: NUL-terminated name; default security.
        let h = unsafe {
            CreateNamedPipeW(
                w.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE,
                255,
                4096,
                4096,
                0,
                ptr::null(),
            )
        };
        assert_ne!(h, INVALID_HANDLE_VALUE, "{}", Win32Error::last());
        // SAFETY: we own the handle just created.
        let _squatter = unsafe { OwnedHandle::from_raw_handle(h) };
        assert_eq!(
            PipeServer::create(&name, &me(), opts()).unwrap_err(),
            PipeError::NameTaken
        );
    }

    #[test]
    fn dacl_as_specified() {
        let s = server();
        let sddl = s.sddl().unwrap();
        println!("{sddl}");
        let sid = me();
        let dacl = sddl.split("D:").nth(1).unwrap();
        let dacl = dacl.split("S:").next().unwrap();
        assert_eq!(dacl, format!("P(A;;0x12019f;;;{sid})(A;;0x12019f;;;SY)"));
        // Windows adds the SACL's auto-inherited flag (`S:AI(...)`); the label entry is exact.
        let sacl = sddl.split("S:").nth(1).unwrap();
        assert!(sacl.ends_with("(ML;;NWNR;;;ME)"), "{sddl}");
        assert_eq!(sacl.matches('(').count(), 1, "{sddl}");

        let sec = crate::secure::handle_security(&s.handle).unwrap();
        assert!(sec.dacl_protected);
        let aces = sec.aces();
        assert_eq!(aces.len(), 2, "{aces:?}");
        assert!(aces.iter().all(|a| a.is_allow() && a.mask == CLIENT_ACCESS));
        assert_eq!(aces[0].sid.as_deref(), Some(sid.as_str()));
        assert_eq!(aces[1].sid.as_deref(), Some("S-1-5-18"));
    }

    #[test]
    fn dacl_without_our_sid_refuses_us() {
        // Only SYSTEM (twice): this test process, elevated or not, is refused at open.
        let s = PipeServer::create(&random_name(), "S-1-5-18", opts()).unwrap();
        let err = connect(s.path()).unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(ERROR_ACCESS_DENIED as i32),
            "{err}"
        );
    }

    #[test]
    fn remote_path_is_refused() {
        let mut s = server();
        let remote = s.path().replacen(r"\\.\", r"\\localhost\", 1);
        // Through the SMB redirector the client is remote: refused (or no server service at all).
        assert!(connect(&remote).is_err());
        assert_eq!(
            s.wait_for_client(Some(Duration::from_millis(50))),
            Err(PipeError::TimedOut)
        );
    }

    #[test]
    fn wait_timeout_then_connect() {
        let mut s = server();
        let t = Instant::now();
        assert_eq!(
            s.wait_for_client(Some(Duration::from_millis(200))),
            Err(PipeError::TimedOut)
        );
        assert!(
            t.elapsed() >= Duration::from_millis(190),
            "{:?}",
            t.elapsed()
        );
        // The instance survived the cancelled wait.
        let path = s.path().to_owned();
        let client = std::thread::spawn(move || {
            let mut c = connect(&path).unwrap();
            c.write_all(b"hello\n").unwrap();
            let mut back = [0u8; 3];
            c.read_exact(&mut back).unwrap();
            back
        });
        s.wait_for_client(Some(Duration::from_secs(10))).unwrap();
        let mut buf = [0u8; 6];
        (&s).read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello\n");
        io::Write::write_all(&mut &s, b"ok\n").unwrap();
        assert_eq!(&client.join().unwrap(), b"ok\n");
        // The client has closed: end of stream, then a write fails.
        assert_eq!(
            s.read_with_timeout(&mut buf, Some(Duration::from_secs(5))),
            Ok(0)
        );
        assert_eq!(
            s.write_all_with_timeout(b"x", Duration::from_secs(5)),
            Err(PipeError::Disconnected)
        );
    }

    #[test]
    fn read_and_write_timeouts() {
        let mut s = server();
        let c = connect(s.path()).unwrap();
        s.wait_for_client(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 16];
        let t = Instant::now();
        assert_eq!(
            s.read_with_timeout(&mut buf, Some(Duration::from_millis(200))),
            Err(PipeError::TimedOut)
        );
        assert!(t.elapsed() >= Duration::from_millis(190));
        // Data written after a timed-out read is still read whole.
        (&c).write_all(b"late").unwrap();
        assert_eq!(
            s.read_with_timeout(&mut buf, Some(Duration::from_secs(5))),
            Ok(4)
        );
        assert_eq!(&buf[..4], b"late");
        // The client never reads: a write larger than the buffers times out.
        let big = vec![0u8; 1 << 20];
        let t = Instant::now();
        assert_eq!(
            s.write_all_with_timeout(&big, Duration::from_millis(300)),
            Err(PipeError::TimedOut)
        );
        assert!(t.elapsed() >= Duration::from_millis(290));
        assert!(t.elapsed() < Duration::from_secs(10));
        // io::Read maps a timeout to ErrorKind::TimedOut.
        let short = PipeOptions {
            read_timeout: Some(Duration::from_millis(50)),
            ..opts()
        };
        let mut s2 = PipeServer::create(&random_name(), &me(), short).unwrap();
        let _c2 = connect(s2.path()).unwrap();
        s2.wait_for_client(Some(Duration::from_secs(5))).unwrap();
        let err = (&s2).read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        drop(c);
    }

    #[test]
    fn peer_of_own_client_and_refusals() {
        let mut s = server();
        let c = connect(s.path()).unwrap();
        s.wait_for_client(Some(Duration::from_secs(5))).unwrap();
        // The UI's check: the server pid seen from the client end is this process.
        let mut server_pid = 0u32;
        // SAFETY: valid client handle; valid out-pointer.
        assert_ne!(
            unsafe { GetNamedPipeServerProcessId(c.as_raw_handle(), &mut server_pid) },
            0
        );
        assert_eq!(server_pid, std::process::id());

        (&c).write_all(b"x").unwrap();
        let mut one = [0u8; 1];
        assert_eq!(
            s.read_with_timeout(&mut one, Some(Duration::from_secs(5))),
            Ok(1)
        );
        let peer = s.peer().unwrap();
        // Reverted: the test thread has no token after peer().
        assert!(Token::of_current_thread().unwrap().is_none());
        println!("peer: {peer:?}");
        assert_eq!(peer.token, crate::token::current_process_facts().unwrap());

        let ok = expected_self();
        assert_eq!(peer.check(&ok), Ok(()));
        let upper = PathBuf::from(ok.image.to_string_lossy().to_uppercase());
        assert_eq!(
            peer.check(&ExpectedPeer {
                image: upper,
                ..ok.clone()
            }),
            Ok(())
        );
        assert_eq!(
            peer.check(&ExpectedPeer {
                pid: ok.pid + 4,
                ..ok.clone()
            }),
            Err(PeerMismatch::Pid)
        );
        assert_eq!(
            peer.check(&ExpectedPeer {
                creation_time: ok.creation_time + 1,
                ..ok.clone()
            }),
            Err(PeerMismatch::CreationTime)
        );
        assert_eq!(
            peer.check(&ExpectedPeer {
                image: ok.image.with_file_name("Purge.exe"),
                ..ok.clone()
            }),
            Err(PeerMismatch::Image)
        );
        assert_eq!(
            peer.check(&ExpectedPeer {
                user_sid: "S-1-5-18".into(),
                ..ok.clone()
            }),
            Err(PeerMismatch::Account)
        );
        assert_eq!(peer.process_token, peer.token);
        let lower = Peer {
            token: TokenFacts {
                integrity_rid: 0x1000,
                ..peer.token.clone()
            },
            process: ProcessHandle::current().unwrap(),
            image: peer.image.clone(),
            process_token: peer.process_token.clone(),
            ..peer
        };
        assert_eq!(lower.check(&ok), Err(PeerMismatch::Token));

        // Refuse and serve the next client on the same instance. Between the disconnect and the next
        // wait the instance is busy, so the client retries (the UI retries for up to 10 s).
        s.disconnect().unwrap();
        drop(c);
        let path = s.path().to_owned();
        let next = std::thread::spawn(move || {
            let t = Instant::now();
            loop {
                match connect(&path) {
                    Ok(c) => break c,
                    Err(e)
                        if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                            && t.elapsed() < Duration::from_secs(10) =>
                    {
                        std::thread::sleep(Duration::from_millis(20))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        });
        s.wait_for_client(Some(Duration::from_secs(10))).unwrap();
        let c2 = next.join().unwrap();
        (&c2).write_all(b"y").unwrap();
        assert_eq!(
            s.read_with_timeout(&mut one, Some(Duration::from_secs(5))),
            Ok(1)
        );
        assert_eq!(s.peer().unwrap().check(&ok), Ok(()));
    }

    #[test]
    fn peer_before_any_read() {
        // A client with identification-level static QoS (the UI's) can be identified before it wrote
        // anything (recorded; the broker still asks after the first read).
        let mut s = server();
        let _c = connect(s.path()).unwrap();
        s.wait_for_client(Some(Duration::from_secs(5))).unwrap();
        match s.peer() {
            Ok(p) => println!("peer before any read: ok ({})", p.token.user_sid),
            Err(PipeError::ReadFirst) => println!("peer before any read: ReadFirst"),
            Err(e) => panic!("{e}"),
        }
        assert!(Token::of_current_thread().unwrap().is_none());
    }

    #[test]
    fn anonymous_client_gives_no_account() {
        let mut s = server();
        let c = OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_ANONYMOUS)
            .open(s.path())
            .unwrap();
        s.wait_for_client(Some(Duration::from_secs(5))).unwrap();
        (&c).write_all(b"x").unwrap();
        let mut one = [0u8; 1];
        assert_eq!(
            s.read_with_timeout(&mut one, Some(Duration::from_secs(5))),
            Ok(1)
        );
        match s.peer() {
            Err(e) => println!("anonymous client: {e}"),
            Ok(p) => {
                println!("anonymous client token: {:?}", p.token);
                assert_eq!(p.check(&expected_self()), Err(PeerMismatch::Account));
            }
        }
        assert!(Token::of_current_thread().unwrap().is_none());
    }

    #[test]
    fn peer_in_another_process() {
        let mut s = server();
        // cmd opens the pipe itself (the redirect of a block), writes one line, then waits for a line
        // on its stdin, so cmd.exe is the client and stays connected until the test releases it.
        let mut child = Command::new("cmd.exe")
            .raw_arg(format!("/d /c \"(echo hi& set /p x=)>{}\"", s.path()))
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        s.wait_for_client(Some(Duration::from_secs(30))).unwrap();
        // cmd opens without SQOS flags (impersonation level, dynamic tracking): no client context
        // exists before its first write, so asking before the first read gives ReadFirst.
        match s.peer() {
            Err(PipeError::ReadFirst) => {}
            Ok(p) => println!("peer before the first read of a dynamic-tracking client: {p:?}"),
            Err(e) => panic!("{e}"),
        }
        assert!(Token::of_current_thread().unwrap().is_none());
        let mut line = [0u8; 4];
        (&s).read_exact(&mut line).unwrap();
        assert_eq!(&line, b"hi\r\n");
        let peer = s.peer().unwrap();
        assert_eq!(peer.pid, child.id());
        let child_h = ProcessHandle::open(child.id()).unwrap();
        let ok = ExpectedPeer {
            pid: child.id(),
            creation_time: child_h.creation_time().unwrap(),
            image: crate::known_folders::known_folder(crate::known_folders::KnownFolder::System)
                .unwrap()
                .join("cmd.exe"),
            user_sid: me(),
        };
        println!("child peer: {peer:?}");
        assert_eq!(peer.check(&ok), Ok(()));
        // The UI's own pid and creation time are not the child's.
        assert_eq!(
            peer.check(&ExpectedPeer {
                pid: std::process::id(),
                ..ok.clone()
            }),
            Err(PeerMismatch::Pid)
        );
        assert_eq!(
            peer.check(&ExpectedPeer {
                image: std::env::current_exe().unwrap(),
                ..ok.clone()
            }),
            Err(PeerMismatch::Image)
        );
        child.stdin.take().unwrap().write_all(b"ok\r\n").unwrap();
        assert!(child.wait().unwrap().success());
        // The held handle outlives the client; an exited client is refused.
        assert!(
            peer.process
                .wait_exit(Some(Duration::from_secs(10)))
                .unwrap()
        );
        assert_eq!(peer.check(&ok), Err(PeerMismatch::Exited));
    }

    #[test]
    fn path_comparison() {
        assert!(same_path(
            Path::new(r"C:\Program Files\Purge\Purge.exe"),
            Path::new(r"c:\program files\purge\PURGE.EXE")
        ));
        assert!(!same_path(
            Path::new(r"C:\Program Files\Purge\Purge.exe"),
            Path::new(r"C:\Program Files\Purge\.\Purge.exe")
        ));
        assert!(!same_path(
            Path::new(r"C:\Program Files\Purge\Purge.exe"),
            Path::new(r"C:\Program Files\Purge\Purge.exe ")
        ));
        assert!(same_path(Path::new("Ä"), Path::new("ä")));
    }
}
