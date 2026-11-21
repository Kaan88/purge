//! Process enumeration (feature `read`) and launching an uninstaller inside a Job object (feature `run`).
//!
//! Read side (feature `read`): [`snapshot_processes`] (a Toolhelp32 process snapshot) and
//! [`process_image_path`] (`QueryFullProcessImageNameW`). Neither creates, opens for writing or signals
//! any process; the Live system source uses them to list running processes.
//!
//! Run side (feature `run`, ENGINE_PLAN.md §4.4 "Launch and wait"): `JobProcess::spawn` creates the
//! process suspended, assigns it to a fresh Job object that does **not** allow breakaway, then resumes it,
//! so every process it starts (including NSIS/Inno copies re-launched from `%TEMP%`) is tracked by the
//! job. `JobProcess::wait_tree` polls the job's process list until it is empty. Also behind `run`:
//! `mutex_exists` (for `Global\_MSIExecute`). `CreateProcessW` and the Job object APIs are compiled only
//! with `run`; nothing in `read` creates processes.

#![cfg(feature = "read")]

use std::io;
use std::mem;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;

use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW, SetThreadPriority, THREAD_MODE_BACKGROUND_BEGIN,
    THREAD_MODE_BACKGROUND_END,
};

#[cfg(feature = "run")]
pub use job::{
    JobProcess, MSI_EXECUTE_MUTEX, SpawnOptions, TreeWait, msi_execute_running, mutex_exists,
};

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

fn raw(h: &OwnedHandle) -> HANDLE {
    h.as_raw_handle() as HANDLE
}

/// Wraps a handle returned by a Win32 call; null is an error.
fn own(h: HANDLE) -> io::Result<OwnedHandle> {
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        Err(last_error())
    } else {
        // SAFETY: `h` is a fresh handle owned by nobody else.
        Ok(unsafe { OwnedHandle::from_raw_handle(h as _) })
    }
}

/// One entry of a Toolhelp32 process snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEntry {
    /// Process id.
    pub pid: u32,
    /// Parent process id at creation (the parent may have exited and the id been reused).
    pub parent_pid: u32,
    /// Executable file name (no directory).
    pub exe_file: String,
}

/// All processes, from `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)`.
pub fn snapshot_processes() -> io::Result<Vec<ProcessEntry>> {
    // SAFETY: plain call.
    let snap = own(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) })?;
    // SAFETY: plain data; `dwSize` set below.
    let mut entry: PROCESSENTRY32W = unsafe { mem::zeroed() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut out = Vec::new();
    // SAFETY: valid snapshot handle and entry.
    let mut ok = unsafe { Process32FirstW(raw(&snap), &mut entry) };
    while ok != 0 {
        let len = entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(entry.szExeFile.len());
        out.push(ProcessEntry {
            pid: entry.th32ProcessID,
            parent_pid: entry.th32ParentProcessID,
            exe_file: String::from_utf16_lossy(&entry.szExeFile[..len]),
        });
        // SAFETY: as above.
        ok = unsafe { Process32NextW(raw(&snap), &mut entry) };
    }
    let err = last_error();
    if err.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) && out.is_empty() {
        return Err(err);
    }
    Ok(out)
}

/// Full Win32 image path of a process. `Ok(None)` when the process is gone or cannot be opened
/// (protected processes, other sessions without rights).
pub fn process_image_path(pid: u32) -> io::Result<Option<PathBuf>> {
    // SAFETY: plain call.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return Ok(None);
    }
    // SAFETY: we own the handle just opened.
    let h = unsafe { OwnedHandle::from_raw_handle(h as _) };
    let mut buf = vec![0u16; 32 * 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` characters.
    if unsafe {
        QueryFullProcessImageNameW(raw(&h), PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
    } == 0
    {
        return Ok(None);
    }
    Ok(Some(PathBuf::from(String::from_utf16_lossy(
        &buf[..len as usize],
    ))))
}

/// Puts the **calling thread** into background mode (`on`: `THREAD_MODE_BACKGROUND_BEGIN`, which lowers
/// its CPU, I/O and memory priority) or takes it out again (`THREAD_MODE_BACKGROUND_END`). It changes
/// only this thread's scheduling, nothing else of the process or the system. Asking for the mode the
/// thread is already in is not an error. Used by the local baseline build (BASELINE_LOCAL_DESIGN.md §5,
/// "background I/O and CPU priority").
pub fn set_thread_background(on: bool) -> io::Result<()> {
    /// `ERROR_THREAD_MODE_ALREADY_BACKGROUND`.
    const ALREADY_BACKGROUND: i32 = 400;
    /// `ERROR_THREAD_MODE_NOT_BACKGROUND`.
    const NOT_BACKGROUND: i32 = 401;
    let mode = if on {
        THREAD_MODE_BACKGROUND_BEGIN
    } else {
        THREAD_MODE_BACKGROUND_END
    };
    // SAFETY: the pseudo handle of the calling thread; plain call.
    if unsafe { SetThreadPriority(GetCurrentThread(), mode) } != 0 {
        return Ok(());
    }
    let err = last_error();
    match err.raw_os_error() {
        Some(ALREADY_BACKGROUND | NOT_BACKGROUND) => Ok(()),
        _ => Err(err),
    }
}

/// Process creation, Job objects and the MSI mutex probe (feature `run` only).
#[cfg(feature = "run")]
mod job {
    use std::ffi::c_void;
    use std::io;
    use std::mem;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use std::path::Path;
    use std::ptr;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_BASIC_PROCESS_ID_LIST, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation, QueryInformationJobObject,
        SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW,
        GetExitCodeProcess, OpenMutexW, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW,
        SYNCHRONIZATION_SYNCHRONIZE, TerminateProcess, WaitForSingleObject,
    };

    use super::{last_error, own, raw};

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// The Windows Installer execution mutex: present while an MSI transaction runs.
    pub const MSI_EXECUTE_MUTEX: &str = r"Global\_MSIExecute";

    /// How [`JobProcess::spawn`] starts the process.
    #[derive(Debug, Clone, Default)]
    pub struct SpawnOptions<'a> {
        /// Working directory; `None` inherits ours.
        pub current_dir: Option<&'a Path>,
        /// Start console programs without a console window (`CREATE_NO_WINDOW`).
        pub hide_console: bool,
        /// Terminate every process in the job when the [`JobProcess`] is dropped
        /// (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`). Off by default: an uninstaller is never killed implicitly.
        pub kill_on_drop: bool,
    }

    /// Outcome of [`JobProcess::wait_tree`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TreeWait {
        /// Every process in the job has exited. `exit_code` is the root process's exit code.
        Exited {
            /// Exit code of the process [`JobProcess::spawn`] started.
            exit_code: u32,
        },
        /// The timeout elapsed with processes still in the job.
        TimedOut,
    }

    /// A process started inside its own Job object.
    #[derive(Debug)]
    pub struct JobProcess {
        job: OwnedHandle,
        process: OwnedHandle,
        pid: u32,
    }

    impl JobProcess {
        /// Starts `command_line` (passed verbatim to `CreateProcessW`) suspended, puts it in a new Job object
        /// with breakaway disallowed, and resumes it.
        pub fn spawn(command_line: &str, options: &SpawnOptions<'_>) -> io::Result<Self> {
            // SAFETY: anonymous job, default security.
            let job = own(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) })?;

            // Explicit limits: no BREAKAWAY_OK / SILENT_BREAKAWAY_OK, so children cannot leave the job.
            // SAFETY: plain data; zero is valid.
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
            if options.kill_on_drop {
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            }
            // SAFETY: `limits` is a valid structure of the stated size.
            let ok = unsafe {
                SetInformationJobObject(
                    raw(&job),
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            };
            if ok == 0 {
                return Err(last_error());
            }

            let mut cmd = wide(command_line);
            let cwd = options.current_dir.map(|d| {
                d.as_os_str()
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect::<Vec<u16>>()
            });
            // SAFETY: plain data; zero is valid once `cb` is set.
            let mut si: STARTUPINFOW = unsafe { mem::zeroed() };
            si.cb = mem::size_of::<STARTUPINFOW>() as u32;
            // SAFETY: plain data.
            let mut pi: PROCESS_INFORMATION = unsafe { mem::zeroed() };
            let mut flags = CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
            if options.hide_console {
                flags |= CREATE_NO_WINDOW;
            }
            // SAFETY: `cmd` is a mutable NUL-terminated buffer; `cwd` is NUL-terminated or null; no handles
            // are inherited.
            let ok = unsafe {
                CreateProcessW(
                    ptr::null(),
                    cmd.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    flags,
                    ptr::null(),
                    cwd.as_ref().map_or(ptr::null(), |c| c.as_ptr()),
                    &si,
                    &mut pi,
                )
            };
            if ok == 0 {
                return Err(last_error());
            }
            let process = own(pi.hProcess)?;
            let thread = own(pi.hThread)?;

            // SAFETY: both handles are valid.
            if unsafe { AssignProcessToJobObject(raw(&job), raw(&process)) } == 0 {
                let err = last_error();
                // The process never ran: do not leave it suspended.
                // SAFETY: valid process handle.
                unsafe { TerminateProcess(raw(&process), 1) };
                return Err(err);
            }
            // SAFETY: valid thread handle of the suspended primary thread.
            if unsafe { ResumeThread(raw(&thread)) } == u32::MAX {
                let err = last_error();
                // SAFETY: valid job handle.
                unsafe { TerminateJobObject(raw(&job), 1) };
                return Err(err);
            }
            drop(thread);
            Ok(JobProcess {
                job,
                process,
                pid: pi.dwProcessId,
            })
        }

        /// Process id of the root process.
        pub fn pid(&self) -> u32 {
            self.pid
        }

        /// Ids of the processes currently in the job (the root included while it runs).
        pub fn process_ids(&self) -> io::Result<Vec<u32>> {
            let header =
                mem::size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() - mem::size_of::<usize>();
            let mut capacity = 64usize;
            loop {
                // usize-aligned buffer: header (two u32) + `capacity` ULONG_PTR entries.
                let words = header / mem::size_of::<usize>() + capacity;
                let mut buf = vec![0usize; words];
                let bytes = (words * mem::size_of::<usize>()) as u32;
                // SAFETY: `buf` holds `bytes` bytes.
                let ok = unsafe {
                    QueryInformationJobObject(
                        raw(&self.job),
                        JobObjectBasicProcessIdList,
                        buf.as_mut_ptr().cast::<c_void>(),
                        bytes,
                        ptr::null_mut(),
                    )
                };
                if ok == 0 {
                    let err = last_error();
                    if err.raw_os_error() == Some(ERROR_MORE_DATA as i32) {
                        capacity *= 4;
                        continue;
                    }
                    return Err(err);
                }
                // SAFETY: the buffer starts with a JOBOBJECT_BASIC_PROCESS_ID_LIST header.
                let list = unsafe { &*(buf.as_ptr() as *const JOBOBJECT_BASIC_PROCESS_ID_LIST) };
                if list.NumberOfAssignedProcesses as usize > capacity {
                    capacity = list.NumberOfAssignedProcesses as usize + 16;
                    continue;
                }
                let n = (list.NumberOfProcessIdsInList as usize).min(capacity);
                let ids =
                    &buf[header / mem::size_of::<usize>()..header / mem::size_of::<usize>() + n];
                return Ok(ids.iter().map(|&id| id as u32).collect());
            }
        }

        /// Exit code of the root process, or `None` while it runs.
        pub fn exit_code(&self) -> io::Result<Option<u32>> {
            // SAFETY: valid process handle.
            if unsafe { WaitForSingleObject(raw(&self.process), 0) } != WAIT_OBJECT_0 {
                return Ok(None);
            }
            let mut code = 0u32;
            // SAFETY: valid process handle and out-pointer.
            if unsafe { GetExitCodeProcess(raw(&self.process), &mut code) } == 0 {
                return Err(last_error());
            }
            Ok(Some(code))
        }

        /// Waits for the root process only. Returns its exit code, or `None` on timeout.
        pub fn wait_root(&self, timeout: Duration) -> io::Result<Option<u32>> {
            let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
            // SAFETY: valid process handle.
            match unsafe { WaitForSingleObject(raw(&self.process), ms) } {
                WAIT_OBJECT_0 => self.exit_code(),
                WAIT_TIMEOUT => Ok(None),
                _ => Err(last_error()),
            }
        }

        /// Waits until the job holds no process (the whole tree has exited), polling the process list every
        /// `poll`. On success, also returns the root's exit code.
        pub fn wait_tree(&self, timeout: Duration, poll: Duration) -> io::Result<TreeWait> {
            let start = Instant::now();
            loop {
                if self.process_ids()?.is_empty() {
                    // The root is in the job, so an empty job means it exited.
                    let exit_code = self.wait_root(Duration::from_secs(5))?.unwrap_or(u32::MAX);
                    return Ok(TreeWait::Exited { exit_code });
                }
                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    return Ok(TreeWait::TimedOut);
                }
                std::thread::sleep(poll.min(timeout - elapsed));
            }
        }

        /// Terminates every process in the job.
        pub fn terminate(&self, exit_code: u32) -> io::Result<()> {
            // SAFETY: valid job handle.
            if unsafe { TerminateJobObject(raw(&self.job), exit_code) } == 0 {
                return Err(last_error());
            }
            Ok(())
        }
    }

    /// True when a named mutex exists. Access denied counts as existing (the object is there; we may not
    /// open it). Use with [`MSI_EXECUTE_MUTEX`].
    pub fn mutex_exists(name: &str) -> io::Result<bool> {
        let name_w = wide(name);
        // SAFETY: NUL-terminated name.
        let h = unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, 0, name_w.as_ptr()) };
        if !h.is_null() {
            // SAFETY: we own the handle just opened.
            drop(unsafe { OwnedHandle::from_raw_handle(h as _) });
            return Ok(true);
        }
        let err = last_error();
        match err.raw_os_error().map(|c| c as u32) {
            Some(ERROR_FILE_NOT_FOUND) => Ok(false),
            Some(ERROR_ACCESS_DENIED) => Ok(true),
            _ => Err(err),
        }
    }

    /// True while a Windows Installer transaction holds `Global\_MSIExecute`.
    pub fn msi_execute_running() -> io::Result<bool> {
        mutex_exists(MSI_EXECUTE_MUTEX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_mode_of_a_thread() {
        std::thread::spawn(|| {
            set_thread_background(true).unwrap();
            set_thread_background(true).unwrap();
            set_thread_background(false).unwrap();
            set_thread_background(false).unwrap();
        })
        .join()
        .unwrap();
    }

    #[test]
    fn own_image_path() {
        let me = process_image_path(std::process::id()).unwrap().unwrap();
        assert_eq!(me, std::env::current_exe().unwrap());
        assert!(
            snapshot_processes()
                .unwrap()
                .iter()
                .any(|e| e.pid == std::process::id())
        );
        assert_eq!(process_image_path(u32::MAX - 3).unwrap(), None);
    }

    #[cfg(feature = "run")]
    mod run {
        use std::time::{Duration, Instant};

        use super::super::*;

        fn opts() -> SpawnOptions<'static> {
            SpawnOptions {
                hide_console: true,
                ..Default::default()
            }
        }

        #[test]
        fn waits_for_full_tree() {
            let started = Instant::now();
            let job =
                JobProcess::spawn("cmd /c start /b ping -n 3 127.0.0.1 >NUL", &opts()).unwrap();
            // cmd exits right away; ping keeps running inside the job.
            let root = job.wait_root(Duration::from_secs(10)).unwrap();
            assert_eq!(root, Some(0));
            let ids = job.process_ids().unwrap();
            assert!(!ids.is_empty(), "ping should still be running in the job");
            assert!(!ids.contains(&job.pid()));
            let names: Vec<_> = ids
                .iter()
                .filter_map(|&id| process_image_path(id).ok().flatten())
                .collect();
            println!("job processes after cmd exited: {names:?}");
            assert!(
                names.iter().any(|p| p
                    .file_name()
                    .is_some_and(|n| n.eq_ignore_ascii_case("ping.exe"))),
                "{names:?}"
            );
            let snapshot = snapshot_processes().unwrap();
            assert!(
                snapshot
                    .iter()
                    .any(|e| ids.contains(&e.pid) && e.exe_file.eq_ignore_ascii_case("ping.exe"))
            );

            let outcome = job
                .wait_tree(Duration::from_secs(30), Duration::from_millis(50))
                .unwrap();
            assert_eq!(outcome, TreeWait::Exited { exit_code: 0 });
            assert!(job.process_ids().unwrap().is_empty());
            // ping -n 3 takes about two seconds.
            assert!(
                started.elapsed() >= Duration::from_millis(1500),
                "{:?}",
                started.elapsed()
            );
        }

        #[test]
        fn exit_code_and_timeout() {
            let job = JobProcess::spawn("cmd /c exit 7", &opts()).unwrap();
            assert_eq!(
                job.wait_tree(Duration::from_secs(10), Duration::from_millis(20))
                    .unwrap(),
                TreeWait::Exited { exit_code: 7 }
            );
            assert_eq!(job.exit_code().unwrap(), Some(7));

            let job = JobProcess::spawn(
                "ping -n 30 127.0.0.1",
                &SpawnOptions {
                    kill_on_drop: true,
                    ..opts()
                },
            )
            .unwrap();
            assert_eq!(job.exit_code().unwrap(), None);
            assert_eq!(
                job.wait_tree(Duration::from_millis(300), Duration::from_millis(50))
                    .unwrap(),
                TreeWait::TimedOut
            );
            job.terminate(42).unwrap();
            assert_eq!(
                job.wait_tree(Duration::from_secs(10), Duration::from_millis(20))
                    .unwrap(),
                TreeWait::Exited { exit_code: 42 }
            );
        }

        #[test]
        fn spawn_failure_is_error() {
            assert!(JobProcess::spawn(r"C:\definitely\not\here.exe", &opts()).is_err());
        }

        #[test]
        fn mutexes() {
            assert!(!mutex_exists(r"Local\purge-test-no-such-mutex-4c1f").unwrap());
            // Whatever the answer, the MSI mutex probe must not fail.
            println!("_MSIExecute present: {}", msi_execute_running().unwrap());
        }
    }
}
