//! The UI's two process starts (feature `run`): the medium engine as a child over stdio, and the
//! elevated broker through `ShellExecuteExW("runas")` (M3 design 3.3 step 1; ENGINE_PLAN.md A9.2).
//!
//! - [`StdioJob::spawn`]: `CreateProcessW` suspended, put in a fresh Job object with
//!   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, then resumed. The child inherits exactly three handles,
//!   named in `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`: the read end of its stdin pipe, the write end of its
//!   stdout pipe and `NUL` as its stderr. Our ends are never inheritable. The child's ends are made
//!   inheritable only for the `CreateProcessW` call and closed right after it, so another process
//!   started meanwhile by this one cannot keep them (which would keep the engine's stdout open after
//!   it ends). Dropping the [`StdioJob`] closes the job, which ends the engine and everything it
//!   started, also when the UI crashes.
//! - [`run_as`]: `ShellExecuteExW` with the verb `runas`, `SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC`,
//!   no owner window (hwnd 0: DECISIONS 2026-11-23 "UAC prompt owner") and `SW_SHOWNORMAL` (the
//!   broker's first window is its consent dialog, M3-R2 S7), on a thread of its own initialised as a
//!   single-threaded COM apartment, as the shell requires. The returned [`LaunchedProcess`] holds the
//!   process handle, so the pid cannot be reused while the UI talks to it.
//! - [`allow_set_foreground_window`]: lets the broker bring its consent dialog to the front.
#![cfg(feature = "run")]

use std::ffi::c_void;
use std::fs::File;
use std::mem;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Com::{
    COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetExitCodeProcess, GetProcessId, INFINITE,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES,
    STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};
use windows_sys::Win32::UI::Shell::{
    SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{AllowSetForegroundWindow, SW_SHOWNORMAL};

use crate::os::{Win32Error, wide};

/// `GENERIC_WRITE`.
const GENERIC_WRITE: u32 = 0x4000_0000;
/// `STILL_ACTIVE`: what `GetExitCodeProcess` answers while the process runs.
const STILL_ACTIVE: u32 = 259;

fn own(h: HANDLE) -> Result<OwnedHandle, Win32Error> {
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        Err(Win32Error::last())
    } else {
        // SAFETY: `h` is a fresh handle owned by nobody else.
        Ok(unsafe { OwnedHandle::from_raw_handle(h) })
    }
}

fn set_inherit(h: &OwnedHandle, on: bool) -> Result<(), Win32Error> {
    // SAFETY: valid handle; only the inherit flag is changed.
    if unsafe {
        SetHandleInformation(
            h.as_raw_handle(),
            HANDLE_FLAG_INHERIT,
            if on { HANDLE_FLAG_INHERIT } else { 0 },
        )
    } == 0
    {
        return Err(Win32Error::last());
    }
    Ok(())
}

/// Milliseconds for a Win32 wait: `None` is `INFINITE`; anything longer is capped below it.
fn wait_ms(timeout: Option<Duration>) -> u32 {
    timeout.map_or(INFINITE, |t| {
        u32::try_from(t.as_millis()).map_or(INFINITE - 1, |ms| ms.min(INFINITE - 1))
    })
}

/// The exit code of a process handle once it has ended (waiting up to `timeout`); `None` while it
/// runs.
fn exit_code_of(process: HANDLE, timeout: Option<Duration>) -> Option<u32> {
    // SAFETY: valid process handle with SYNCHRONIZE.
    match unsafe { WaitForSingleObject(process, wait_ms(timeout)) } {
        WAIT_OBJECT_0 => {}
        _ => return None,
    }
    let mut code = 0u32;
    // SAFETY: valid process handle and out-pointer.
    if unsafe { GetExitCodeProcess(process, &mut code) } == 0 || code == STILL_ACTIVE {
        return None;
    }
    Some(code)
}

/// A child process with two pipes, inside a kill-on-close Job object.
#[derive(Debug)]
pub struct StdioJob {
    /// The child's stdin: requests are written here. Closing it is the child's end of input.
    pub stdin: File,
    /// The child's stdout: answers are read here; end of stream once the child has ended.
    pub stdout: File,
    /// The job and the process.
    pub child: JobChild,
}

/// The job and the process of a [`StdioJob`]. Dropping it closes the job, which ends the child and
/// everything it started.
#[derive(Debug)]
pub struct JobChild {
    job: OwnedHandle,
    process: OwnedHandle,
    pid: u32,
}

impl JobChild {
    /// The child's pid.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The exit code once the child has ended, waiting up to `timeout`; `None` while it runs.
    pub fn exit_code(&self, timeout: Option<Duration>) -> Option<u32> {
        exit_code_of(self.process.as_raw_handle(), timeout)
    }

    /// The job handle, for tests that look at it.
    pub fn job(&self) -> &OwnedHandle {
        &self.job
    }
}

/// `PROC_THREAD_ATTRIBUTE_LIST` memory, deleted and freed on drop.
struct AttributeList {
    buf: Vec<usize>,
    initialised: bool,
}

impl AttributeList {
    fn new(count: u32) -> Result<AttributeList, Win32Error> {
        let mut size = 0usize;
        // SAFETY: the size query: a null list, `size` receives the bytes needed.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &mut size) };
        if size == 0 {
            return Err(Win32Error::last());
        }
        let mut list = AttributeList {
            buf: vec![0usize; size.div_ceil(mem::size_of::<usize>())],
            initialised: false,
        };
        // SAFETY: `buf` holds at least `size` bytes, pointer-aligned.
        if unsafe { InitializeProcThreadAttributeList(list.ptr(), count, 0, &mut size) } == 0 {
            return Err(Win32Error::last());
        }
        list.initialised = true;
        Ok(list)
    }

    fn ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buf.as_mut_ptr().cast()
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if self.initialised {
            // SAFETY: an initialised list that nothing uses any more.
            unsafe { DeleteProcThreadAttributeList(self.ptr()) };
        }
    }
}

impl StdioJob {
    /// Starts `exe` with `arguments` (the command line is `"<exe>" <arguments>`; `exe` must exist),
    /// in `exe`'s directory, with no console window, suspended; puts it in a new kill-on-close job;
    /// then resumes it. Its stdin and stdout are the two pipes, its stderr is `NUL`.
    pub fn spawn(exe: &Path, arguments: &str) -> Result<StdioJob, Win32Error> {
        // The job first, so the process never runs outside it.
        // SAFETY: anonymous job, default security.
        let job = own(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) })?;
        // SAFETY: plain data; zero is valid.
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `limits` is a valid structure of the stated size.
        if unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(Win32Error::last());
        }

        // Every handle is created not inheritable.
        let sa = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: 0,
        };
        let pipe = || -> Result<(OwnedHandle, OwnedHandle), Win32Error> {
            let (mut r, mut w): (HANDLE, HANDLE) = (ptr::null_mut(), ptr::null_mut());
            // SAFETY: two out-pointers; `sa` is valid for the call.
            if unsafe { CreatePipe(&mut r, &mut w, &sa, 0) } == 0 {
                return Err(Win32Error::last());
            }
            Ok((own(r)?, own(w)?))
        };
        let (in_read, in_write) = pipe()?;
        let (out_read, out_write) = pipe()?;
        let nul_name = wide("NUL");
        // SAFETY: NUL-terminated name; `sa` valid; no template.
        let nul = own(unsafe {
            CreateFileW(
                nul_name.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &sa,
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        })?;

        let mut inherit: [HANDLE; 3] = [
            in_read.as_raw_handle(),
            out_write.as_raw_handle(),
            nul.as_raw_handle(),
        ];
        let mut attributes = AttributeList::new(1)?;
        // SAFETY: an initialised list; `inherit` holds three handles and outlives CreateProcessW.
        if unsafe {
            UpdateProcThreadAttribute(
                attributes.ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                inherit.as_mut_ptr().cast::<c_void>(),
                mem::size_of_val(&inherit),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
        {
            return Err(Win32Error::last());
        }

        // SAFETY: plain data; zero is valid once `cb` is set.
        let mut info: STARTUPINFOEXW = unsafe { mem::zeroed() };
        info.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
        info.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        info.StartupInfo.hStdInput = in_read.as_raw_handle();
        info.StartupInfo.hStdOutput = out_write.as_raw_handle();
        info.StartupInfo.hStdError = nul.as_raw_handle();
        info.lpAttributeList = attributes.ptr();

        // CreateProcessW may write into the command line, so it gets its own buffer.
        let mut command = wide(format!("\"{}\" {arguments}", exe.display()));
        let application = wide(exe);
        let directory = exe.parent().map(wide);
        // SAFETY: plain data.
        let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };

        // The child's three ends are inheritable for this call only (see the module comment).
        for h in [&in_read, &out_write, &nul] {
            set_inherit(h, true)?;
        }
        // SAFETY: NUL-terminated application name and directory (or null); `command` is a mutable
        // NUL-terminated buffer; `info` and its attribute list are valid; only the listed handles are
        // inherited.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
                ptr::null(),
                directory.as_ref().map_or(ptr::null(), |d| d.as_ptr()),
                &info.StartupInfo,
                &mut pi,
            )
        };
        let error = Win32Error::last();
        // The child's ends belong to the child now (or to nobody); ours stay.
        drop((in_read, out_write, nul));
        drop(attributes);
        if created == 0 {
            return Err(error);
        }
        let process = own(pi.hProcess)?;
        let thread = own(pi.hThread)?;
        // SAFETY: both handles are valid.
        if unsafe { AssignProcessToJobObject(job.as_raw_handle(), process.as_raw_handle()) } == 0 {
            let e = Win32Error::last();
            // The process never ran: do not leave it suspended.
            // SAFETY: valid process handle.
            unsafe { TerminateProcess(process.as_raw_handle(), 1) };
            return Err(e);
        }
        // SAFETY: valid handle of the suspended primary thread.
        if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
            // Closing the job (on return) ends the process.
            return Err(Win32Error::last());
        }
        Ok(StdioJob {
            stdin: File::from(in_write),
            stdout: File::from(out_read),
            child: JobChild {
                job,
                process,
                pid: pi.dwProcessId,
            },
        })
    }
}

/// A process `ShellExecuteExW` started: its handle (all the rights the shell gave), held so the pid is
/// not reused while it is open.
#[derive(Debug)]
pub struct LaunchedProcess {
    handle: OwnedHandle,
    pid: u32,
}

impl LaunchedProcess {
    /// The pid (`GetProcessId` of the handle).
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The exit code once the process has ended; `None` while it runs (no wait).
    pub fn exit_code(&self) -> Option<u32> {
        exit_code_of(self.handle.as_raw_handle(), Some(Duration::ZERO))
    }

    /// Best effort: `TerminateProcess` while it runs. For an elevated process the handle a medium
    /// caller gets does not allow it, and the call is refused and ignored (review M3-R2 N2).
    pub fn terminate(&self) {
        if self.exit_code().is_none() {
            // SAFETY: valid process handle; a refusal changes nothing.
            unsafe { TerminateProcess(self.handle.as_raw_handle(), 1) };
        }
    }
}

/// `ShellExecuteExW("runas")` of `file` with `parameters` in `directory`, on a new STA thread, with no
/// owner window. Blocks while Windows shows its prompt. The error is the shell's
/// (`ERROR_CANCELLED`, 1223, when the user says No). `Ok` with no process handle is
/// [`Win32Error::INVALID_DATA`].
pub fn run_as(
    file: &Path,
    parameters: &str,
    directory: &Path,
) -> Result<LaunchedProcess, Win32Error> {
    let file = wide(file);
    let parameters = wide(parameters);
    let directory = wide(directory);
    let thread = std::thread::Builder::new()
        .name("purge-broker-launch".into())
        .spawn(move || -> Result<(usize, u32), Win32Error> {
            // SAFETY: plain call on this new thread; balanced by CoUninitialize below when it worked.
            let hr = unsafe {
                CoInitializeEx(
                    ptr::null(),
                    (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
                )
            };
            let verb = wide("runas");
            // SAFETY: plain data; zero is valid once cbSize is set.
            let mut info: SHELLEXECUTEINFOW = unsafe { mem::zeroed() };
            info.cbSize = mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
            info.hwnd = ptr::null_mut();
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = parameters.as_ptr();
            info.lpDirectory = directory.as_ptr();
            info.nShow = SW_SHOWNORMAL;
            // SAFETY: every string is NUL-terminated and outlives the call.
            let ok = unsafe { ShellExecuteExW(&mut info) };
            let result = if ok == 0 {
                Err(Win32Error::last())
            } else if info.hProcess.is_null() {
                Err(Win32Error::INVALID_DATA)
            } else {
                // SAFETY: valid process handle the shell handed over.
                let pid = unsafe { GetProcessId(info.hProcess) };
                Ok((info.hProcess as usize, pid))
            };
            if hr >= 0 {
                // SAFETY: balances the successful CoInitializeEx of this thread.
                unsafe { CoUninitialize() };
            }
            result
        })
        .map_err(|_| Win32Error::INVALID_PARAMETER)?;
    let (raw, pid) = thread.join().map_err(|_| Win32Error::INVALID_DATA)??;
    // SAFETY: the handle the shell returned, owned by nobody else.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw as HANDLE) };
    if pid == 0 {
        return Err(Win32Error::INVALID_DATA);
    }
    Ok(LaunchedProcess { handle, pid })
}

/// `AllowSetForegroundWindow(pid)`: lets that process bring its window to the front. A refusal is not
/// an error (the UI then names the prompt in its waiting state); the answer says whether it was
/// allowed.
pub fn allow_set_foreground_window(pid: u32) -> bool {
    // SAFETY: plain call.
    unsafe { AllowSetForegroundWindow(pid) != 0 }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};

    use windows_sys::Win32::Foundation::WAIT_TIMEOUT;

    use super::*;

    /// Whether a handle's wait times out at once (it is not signalled).
    fn is_unsignalled(h: &OwnedHandle) -> bool {
        // SAFETY: valid handle.
        unsafe { WaitForSingleObject(h.as_raw_handle(), 0) == WAIT_TIMEOUT }
    }

    fn cmd() -> std::path::PathBuf {
        crate::known_folders::known_folder(crate::known_folders::KnownFolder::System)
            .unwrap()
            .join("cmd.exe")
    }

    #[test]
    fn a_child_talks_over_its_pipes_and_dies_with_its_job() {
        // cmd reads one line and echoes it, then waits for another line.
        let mut job = StdioJob::spawn(
            &cmd(),
            "/d /q /c \"set /p x=& call echo got %x%& set /p y=\"",
        )
        .unwrap();
        job.stdin.write_all(b"hi\r\n").unwrap();
        let mut line = String::new();
        BufReader::new(&job.stdout).read_line(&mut line).unwrap();
        assert_eq!(line.trim_end(), "got hi");
        assert_eq!(job.child.exit_code(Some(Duration::from_millis(50))), None);
        let pid = job.child.pid();
        let held = crate::process::ProcessHandle::open(pid).unwrap();
        assert!(is_unsignalled(job.child.job()));
        drop(job);
        assert!(held.wait_exit(Some(Duration::from_secs(10))).unwrap());
    }

    #[test]
    fn a_missing_program_is_an_error() {
        let exe = std::env::temp_dir().join("purge-no-such-engine.exe");
        let e = StdioJob::spawn(&exe, "").unwrap_err();
        assert!(e.is_not_found(), "{e}");
    }

    #[test]
    fn the_exit_code_is_read() {
        let job = StdioJob::spawn(&cmd(), "/d /c exit 7").unwrap();
        assert_eq!(job.child.exit_code(Some(Duration::from_secs(10))), Some(7));
    }
}
