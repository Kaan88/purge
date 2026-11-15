//! Restart Manager: who holds a file (`write` feature).
//!
//! ENGINE_PLAN.md §7.3 and §7.6 step 2. An [`RmSession`] wraps `RmStartSession` / `RmEndSession`;
//! [`RmSession::register_files`] registers files only (`RmRegisterResources` with no processes and no
//! services), and [`RmSession::lockers`] lists the processes and services that hold them (`RmGetList`), so
//! the report can name them.
//!
//! M2 only queries. [`RmSession::shutdown`] (`RmShutdown`) exists for the consent path of M3 (close the
//! app, stop the service, restart Explorer, each with the user's consent); nothing in this module calls
//! it, and the executor calls it only behind an explicit allow flag. `RmRestart` is not wrapped.
//!
//! Restart Manager allows a limited number of sessions per machine (64); a session is ended when the
//! [`RmSession`] is dropped. An unelevated caller cannot see every process: such holders are then missing
//! from the list and [`LockerList::reboot_reasons`] has [`RebootReasons::PERMISSION_DENIED`] set.

use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
use windows_sys::Win32::System::RestartManager::{
    CCH_RM_SESSION_KEY, RM_INVALID_TS_SESSION, RM_PROCESS_INFO, RmConsole, RmCritical,
    RmEndSession, RmExplorer, RmForceShutdown, RmGetList, RmMainWindow, RmOtherWindow,
    RmRebootReasonCriticalProcess, RmRebootReasonCriticalService, RmRebootReasonDetectedSelf,
    RmRebootReasonPermissionDenied, RmRebootReasonSessionMismatch, RmRegisterResources, RmService,
    RmShutdown, RmStartSession, RmUnknownApp,
};
use windows_sys::core::PCWSTR;

use crate::os::{Win32Error, from_wide};
use crate::reg::filetime_u64;

/// What kind of application holds a file (`RM_APP_TYPE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockerKind {
    /// `RmUnknownApp`: none of the kinds below.
    Unknown,
    /// `RmMainWindow`: a process with a top-level window.
    MainWindow,
    /// `RmOtherWindow`: a process with windows, but no main window.
    OtherWindow,
    /// `RmService`: a Windows service; [`Locker::service_name`] names it.
    Service,
    /// `RmExplorer`: Windows Explorer.
    Explorer,
    /// `RmConsole`: a console application.
    Console,
    /// `RmCritical`: a process Restart Manager will not shut down (a critical system process, or the
    /// calling process itself, which also sets [`RebootReasons::DETECTED_SELF`]).
    Critical,
    /// A value this version does not know.
    Other(i32),
}

impl LockerKind {
    fn from_raw(raw: i32) -> LockerKind {
        [
            (RmUnknownApp, LockerKind::Unknown),
            (RmMainWindow, LockerKind::MainWindow),
            (RmOtherWindow, LockerKind::OtherWindow),
            (RmService, LockerKind::Service),
            (RmExplorer, LockerKind::Explorer),
            (RmConsole, LockerKind::Console),
            (RmCritical, LockerKind::Critical),
        ]
        .into_iter()
        .find_map(|(value, kind)| (value == raw).then_some(kind))
        .unwrap_or(LockerKind::Other(raw))
    }
}

/// One process (or service) that holds a registered file (`RM_PROCESS_INFO`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locker {
    /// Process id.
    pub pid: u32,
    /// Process creation time (FILETIME ticks). With `pid` it identifies the process instance, so a
    /// reused pid is not mistaken for the same process.
    pub start_time: u64,
    /// Display name of the application (`strAppName`): a window title, the service display name or the
    /// executable name, as Restart Manager chooses.
    pub app_name: String,
    /// Service short name, for [`LockerKind::Service`].
    pub service_name: Option<String>,
    /// Application kind.
    pub kind: LockerKind,
    /// Whether Restart Manager could restart it after a shutdown (`bRestartable`).
    pub restartable: bool,
    /// Terminal Services session id, `None` when unknown (`RM_INVALID_TS_SESSION`).
    pub ts_session: Option<u32>,
}

impl Locker {
    fn from_raw(info: &RM_PROCESS_INFO) -> Locker {
        let service = from_wide(&info.strServiceShortName);
        Locker {
            pid: info.Process.dwProcessId,
            start_time: filetime_u64(info.Process.ProcessStartTime),
            app_name: from_wide(&info.strAppName),
            service_name: (!service.is_empty()).then_some(service),
            kind: LockerKind::from_raw(info.ApplicationType),
            restartable: info.bRestartable != 0,
            ts_session: (info.TSSessionId != RM_INVALID_TS_SESSION as u32)
                .then_some(info.TSSessionId),
        }
    }
}

/// Why a reboot would be needed to free the registered files (`RM_REBOOT_REASON` bits).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RebootReasons(pub u32);

impl RebootReasons {
    /// `RmRebootReasonPermissionDenied`: the caller lacks rights to see or shut down some holder; the
    /// locker list may be incomplete.
    pub const PERMISSION_DENIED: u32 = RmRebootReasonPermissionDenied as u32;
    /// `RmRebootReasonSessionMismatch`: a holder runs in another Terminal Services session.
    pub const SESSION_MISMATCH: u32 = RmRebootReasonSessionMismatch as u32;
    /// `RmRebootReasonCriticalProcess`: a holder is a critical process.
    pub const CRITICAL_PROCESS: u32 = RmRebootReasonCriticalProcess as u32;
    /// `RmRebootReasonCriticalService`: a holder is a critical service.
    pub const CRITICAL_SERVICE: u32 = RmRebootReasonCriticalService as u32;
    /// `RmRebootReasonDetectedSelf`: the calling process itself holds a file.
    pub const DETECTED_SELF: u32 = RmRebootReasonDetectedSelf as u32;

    /// No reason: every holder could be shut down without a reboot.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Whether `bit` (one of the constants above) is set.
    pub fn has(self, bit: u32) -> bool {
        self.0 & bit != 0
    }
}

/// Result of [`RmSession::list`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LockerList {
    /// Processes and services holding a registered file.
    pub lockers: Vec<Locker>,
    /// Why freeing them would need a reboot.
    pub reboot_reasons: RebootReasons,
}

/// Attempts at `RmGetList` when the list grows between the size query and the read.
const GET_LIST_ATTEMPTS: usize = 5;

/// A Restart Manager session, ended on drop.
#[derive(Debug)]
pub struct RmSession {
    handle: u32,
}

impl RmSession {
    /// Starts a session (`RmStartSession`). Fails with `ERROR_MAX_SESSIONS_REACHED` when the machine has
    /// too many open sessions.
    pub fn start() -> Result<RmSession, Win32Error> {
        let mut handle = 0u32;
        let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
        // SAFETY: valid out-pointers; `key` holds CCH_RM_SESSION_KEY + 1 characters as required.
        Win32Error::check(unsafe { RmStartSession(&mut handle, 0, key.as_mut_ptr()) })?;
        Ok(RmSession { handle })
    }

    /// Registers files (absolute paths, files only, not directories) with the session
    /// (`RmRegisterResources`). Registering is cumulative; an empty slice does nothing. A relative path
    /// or a path with an interior NUL is refused with `ERROR_INVALID_PARAMETER` before anything is
    /// registered.
    pub fn register_files<P: AsRef<Path>>(&mut self, paths: &[P]) -> Result<(), Win32Error> {
        if paths.is_empty() {
            return Ok(());
        }
        let mut wides = Vec::with_capacity(paths.len());
        for p in paths {
            let p = p.as_ref();
            if !p.is_absolute() {
                return Err(Win32Error::INVALID_PARAMETER);
            }
            let w: Vec<u16> = p.as_os_str().encode_wide().collect();
            if w.contains(&0) {
                return Err(Win32Error::INVALID_PARAMETER);
            }
            wides.push(
                w.into_iter()
                    .chain(std::iter::once(0))
                    .collect::<Vec<u16>>(),
            );
        }
        let ptrs: Vec<PCWSTR> = wides.iter().map(|w| w.as_ptr()).collect();
        let count = u32::try_from(ptrs.len()).map_err(|_| Win32Error::INVALID_PARAMETER)?;
        // SAFETY: `ptrs` holds `count` NUL-terminated strings that outlive the call; no processes and no
        // services are registered.
        Win32Error::check(unsafe {
            RmRegisterResources(
                self.handle,
                count,
                ptrs.as_ptr(),
                0,
                ptr::null(),
                0,
                ptr::null(),
            )
        })
    }

    /// The processes and services holding any registered file, with the reboot reasons (`RmGetList`).
    pub fn list(&self) -> Result<LockerList, Win32Error> {
        let mut capacity = 0u32;
        for _ in 0..GET_LIST_ATTEMPTS {
            let mut buf = vec![RM_PROCESS_INFO::default(); capacity as usize];
            let mut needed = 0u32;
            let mut count = capacity;
            let mut reasons = 0u32;
            // SAFETY: `buf` holds `count` entries (null-equivalent empty buffer when 0); valid
            // out-pointers.
            let rc = unsafe {
                RmGetList(
                    self.handle,
                    &mut needed,
                    &mut count,
                    if buf.is_empty() {
                        ptr::null_mut()
                    } else {
                        buf.as_mut_ptr()
                    },
                    &mut reasons,
                )
            };
            if rc == ERROR_MORE_DATA {
                // The list grew (or this was the size query): retry with room to spare.
                capacity = needed.saturating_add(4);
                continue;
            }
            Win32Error::check(rc)?;
            let n = (count as usize).min(buf.len());
            return Ok(LockerList {
                lockers: buf[..n].iter().map(Locker::from_raw).collect(),
                reboot_reasons: RebootReasons(reasons),
            });
        }
        Err(Win32Error::MORE_DATA)
    }

    /// The processes and services holding any registered file (`RmGetList`), without the reboot reasons.
    pub fn lockers(&self) -> Result<Vec<Locker>, Win32Error> {
        self.list().map(|l| l.lockers)
    }

    /// Shuts down the holders of the registered files (`RmShutdown`); with `force`, applications that do
    /// not respond are terminated (`RmForceShutdown`).
    ///
    /// Changes the running system. Call only after the user consented to closing exactly these
    /// applications or stopping these services (M3); the M2 executor never calls it without an explicit
    /// allow flag.
    pub fn shutdown(&mut self, force: bool) -> Result<(), Win32Error> {
        let flags = if force { RmForceShutdown as u32 } else { 0 };
        // SAFETY: live session handle; no progress callback.
        Win32Error::check(unsafe { RmShutdown(self.handle, flags, None) })
    }

    /// Ends the session (`RmEndSession`) and reports its result; dropping does the same silently.
    pub fn end(self) -> Result<(), Win32Error> {
        let handle = self.handle;
        std::mem::forget(self);
        // SAFETY: the session handle is live and, with `self` forgotten, ended exactly once.
        Win32Error::check(unsafe { RmEndSession(handle) })
    }
}

impl Drop for RmSession {
    fn drop(&mut self) {
        // SAFETY: the session handle is live and ended exactly once.
        unsafe { RmEndSession(self.handle) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    /// A unique scratch directory under `std::env::temp_dir()`, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Scratch {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let dir = std::env::temp_dir()
                .join(format!("purge-win-rm-{tag}-{}-{nanos}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A child process (`ping`) whose standard output is `path`, so it holds the file open.
    struct Holder(Child);

    impl Holder {
        fn spawn(path: &Path) -> Holder {
            let file = File::create(path).unwrap();
            // The Command (and with it our copy of the handle) is dropped at the end of this
            // statement; only the child keeps the file open.
            let child = Command::new("ping")
                .args(["-n", "60", "127.0.0.1"])
                .stdin(Stdio::null())
                .stdout(file)
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            Holder(child)
        }
    }

    impl Drop for Holder {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn lockers_of(path: &Path) -> LockerList {
        let mut s = RmSession::start().unwrap();
        s.register_files(&[path]).unwrap();
        let list = s.list().unwrap();
        s.end().unwrap();
        list
    }

    #[test]
    fn kinds() {
        assert_eq!(LockerKind::from_raw(RmService), LockerKind::Service);
        assert_eq!(LockerKind::from_raw(RmConsole), LockerKind::Console);
        assert_eq!(LockerKind::from_raw(RmCritical), LockerKind::Critical);
        assert_eq!(LockerKind::from_raw(RmUnknownApp), LockerKind::Unknown);
        assert_eq!(LockerKind::from_raw(77), LockerKind::Other(77));
        let r = RebootReasons(RebootReasons::PERMISSION_DENIED | RebootReasons::DETECTED_SELF);
        assert!(r.has(RebootReasons::PERMISSION_DENIED));
        assert!(!r.has(RebootReasons::CRITICAL_SERVICE));
        assert!(!r.is_empty());
        assert!(RebootReasons::default().is_empty());
    }

    #[test]
    fn child_process_holding_a_file_is_named() {
        let dir = Scratch::new("child");
        let path = dir.0.join("held.txt");
        let mut holder = Holder::spawn(&path);
        let pid = holder.0.id();

        let list = lockers_of(&path);
        println!("lockers: {list:?}");
        let me = list
            .lockers
            .iter()
            .find(|l| l.pid == pid)
            .unwrap_or_else(|| panic!("child {pid} not reported: {list:?}"));
        assert!(me.start_time > 0);
        assert!(!me.app_name.is_empty());
        assert_eq!(me.service_name, None);
        assert_ne!(me.kind, LockerKind::Service);
        // This process no longer holds the file.
        assert!(list.lockers.iter().all(|l| l.pid != std::process::id()));

        // Once the child is gone, a new session no longer reports it.
        holder.0.kill().unwrap();
        holder.0.wait().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let after = lockers_of(&path);
            if after.lockers.iter().all(|l| l.pid != pid) {
                break;
            }
            assert!(Instant::now() < deadline, "still reported: {after:?}");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[test]
    fn own_handle_is_reported() {
        let dir = Scratch::new("self");
        let path = dir.0.join("mine.bin");
        let file = File::create(&path).unwrap();
        let mut s = RmSession::start().unwrap();
        s.register_files(&[&path]).unwrap();
        let list = s.list().unwrap();
        println!("lockers: {list:?}");
        assert!(
            list.lockers.iter().any(|l| l.pid == std::process::id()),
            "{list:?}"
        );
        drop(file);
        drop(s);
    }

    #[test]
    fn registration_rules() {
        let dir = Scratch::new("reg");
        let free = dir.0.join("free.txt");
        std::fs::write(&free, b"x").unwrap();

        let mut s = RmSession::start().unwrap();
        // Nothing registered: an empty list.
        s.register_files::<&Path>(&[]).unwrap();
        assert_eq!(s.list().unwrap(), LockerList::default());
        // Refused before anything is registered.
        assert_eq!(
            s.register_files(&[Path::new(r"relative\file.txt")]),
            Err(Win32Error::INVALID_PARAMETER)
        );
        let nul = PathBuf::from(format!("{}\0x", free.display()));
        assert_eq!(s.register_files(&[nul]), Err(Win32Error::INVALID_PARAMETER));
        // A closed file and a missing file: no holder from this process or its children.
        s.register_files(&[free.clone(), dir.0.join("missing.txt")])
            .unwrap();
        let list = s.list().unwrap();
        assert!(
            list.lockers.iter().all(|l| l.pid != std::process::id()),
            "{list:?}"
        );
        s.end().unwrap();
    }

    #[test]
    fn many_sessions_are_released() {
        // More sessions than the per-machine limit, one after another: each must be ended.
        for _ in 0..80 {
            let s = RmSession::start().unwrap();
            drop(s);
        }
    }

    #[test]
    #[ignore = "shuts down a process through Restart Manager; VM only"]
    fn shutdown_closes_the_holder_vm() {
        let dir = Scratch::new("shutdown");
        let path = dir.0.join("held.txt");
        let mut holder = Holder::spawn(&path);
        let pid = holder.0.id();
        let mut s = RmSession::start().unwrap();
        s.register_files(&[&path]).unwrap();
        assert!(s.lockers().unwrap().iter().any(|l| l.pid == pid));
        s.shutdown(true).unwrap();
        let status = holder.0.wait().unwrap();
        println!("holder exited: {status:?}");
        assert!(s.lockers().unwrap().iter().all(|l| l.pid != pid));
        s.end().unwrap();
    }
}
