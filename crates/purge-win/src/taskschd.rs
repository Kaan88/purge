//! Task Scheduler 2.0: list and read XML under `read`, delete and register under `write` (M1b).
//!
//! The C-WIN contract (docs/M1B_DESIGN.json, package M1B-WIN-TASK) and the M1B-SPIKE result
//! (vm/spikes/m1b/RESULT.json, `task`). Everything goes through the `ITaskService` COM interfaces of the
//! local Task Scheduler; the module also needs feature `com` (the `windows` crate).
//!
//! - [`list_all`] walks every folder from `\` (`GetFolders`, depth cap [`ListLimits::max_depth`]) and
//!   every task in it with `TASK_ENUM_HIDDEN` (cap [`ListLimits::max_tasks`]). Going over a cap is an
//!   error, never a shorter list. A task whose definition cannot be read is returned with
//!   [`RawTask::unreadable`] set and no actions; it is never dropped. A folder removed between its
//!   parent's listing and its own reads as empty (it holds nothing any more); any other folder error
//!   fails the whole listing.
//! - [`read_xml`] returns `IRegisteredTask::get_Xml` unchanged and the SDDL of
//!   `GetSecurityDescriptor(OWNER | GROUP | DACL)`. [`read_task`] reads one task as [`list_all`] does.
//! - [`delete`] calls `ITaskFolder::DeleteTask(name, 0)` on the task's parent folder. A missing task or
//!   folder is `Ok`: the caller's probe decides what that means. Folders are never deleted.
//! - [`register_xml`] calls `ITaskFolder::RegisterTask(name, xml, TASK_CREATE, VT_EMPTY, VT_EMPTY,
//!   TASK_LOGON_NONE, VT_EMPTY)`: create only, the principal and logon type come from the XML. Missing
//!   parent folders are created with the default security descriptor. Over an existing task the call
//!   fails with [`WinError::AlreadyExists`] and changes nothing (spike: `0x800700B7`, task unchanged).
//!
//! Spike-driven difference from the contract text: the `sddl` argument of [`register_xml`] is not
//! passed to `RegisterTask`. The spike measured that passing the `GetSecurityDescriptor` SDDL adds a
//! `RegistrationInfo/SecurityDescriptor` element to the stored XML and reorders the stored descriptor
//! (`AI` flag, explicit ACE first), while registering the XML alone restores XML and SDDL byte for
//! byte (the XML already carries the descriptor element when the task had one).
//!
//! What this module never does: it never starts, ends, stops, enables or disables a task, never
//! registers with an update flag, never changes a security descriptor and never removes a folder.
//! `tests/taskschd.rs` greps this file to prove it.
//!
//! Paths: a task path is the full path Task Scheduler reports (`\Vendor\Updater`). Before any call it
//! must start with a backslash, have no empty segment, no `.` or `..` segment, no control character or
//! `/`, and be at most 260 UTF-16 units long; otherwise [`WinError::InvalidPath`].
//!
//! COM: each public function enters the multithreaded apartment on the calling thread for its own
//! duration and leaves it before returning, on every path ([`Apartment`]); a thread already in a
//! single-threaded apartment (`RPC_E_CHANGED_MODE`) is used as it is and not uninitialised. No state is
//! kept between calls.
#![cfg(all(feature = "read", feature = "com"))]

use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoUninitialize,
};
use windows::Win32::System::TaskScheduler::{
    IAction, IComHandlerAction, IExecAction, IRegisteredTask, ITaskDefinition, ITaskFolder,
    ITaskService, TASK_ACTION_COM_HANDLER, TASK_ACTION_EXEC, TASK_ACTION_SEND_EMAIL,
    TASK_ACTION_SHOW_MESSAGE, TASK_ACTION_TYPE, TASK_ENUM_HIDDEN, TASK_LOGON_TYPE,
    TASK_STATE_RUNNING, TaskScheduler,
};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{BSTR, Interface};

/// The longest task path accepted, in UTF-16 units.
pub const MAX_PATH_LEN: usize = 260;

/// `OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION`.
const SD_OWNER_GROUP_DACL: i32 = 0x1 | 0x2 | 0x4;

/// `HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)`.
const HR_FILE_NOT_FOUND: u32 = 0x8007_0002;
/// `HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND)`.
const HR_PATH_NOT_FOUND: u32 = 0x8007_0003;
/// `E_ACCESSDENIED`.
const HR_ACCESS_DENIED: u32 = 0x8007_0005;
/// `HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS)`: `TASK_CREATE` over an existing task (spike).
#[cfg(feature = "write")]
const HR_ALREADY_EXISTS: u32 = 0x8007_00B7;
/// `HRESULT_FROM_WIN32(ERROR_LOGON_FAILURE)`: a stored-password task registered without it (spike).
#[cfg(feature = "write")]
const HR_LOGON_FAILURE: u32 = 0x8007_052E;
/// `RPC_E_CHANGED_MODE`: the thread is already in a single-threaded apartment.
const HR_CHANGED_MODE: u32 = 0x8001_0106;
/// `E_UNEXPECTED`, used for a negative collection count.
const HR_UNEXPECTED: u32 = 0x8000_FFFF;

/// Why a Task Scheduler call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WinError {
    /// The task path broke a rule of the module documentation. Nothing was called.
    #[error("invalid task path: {0:?}")]
    InvalidPath(String),
    /// The XML handed to [`register_xml`] is empty, contains a NUL, or would start the task at
    /// registration (a `RegistrationTrigger`). Nothing was called.
    #[error("task XML refused: {0}")]
    InvalidXml(&'static str),
    /// [`register_xml`]: a task with this path exists already. It was not changed.
    #[error("task already exists: {0}")]
    AlreadyExists(String),
    /// [`register_xml`]: the task's principal stores a password, and a task cannot be registered from
    /// its XML alone (spike: `0x8007052E`). Nothing was registered.
    #[error("task needs its stored password to be registered: {0}")]
    PasswordNeeded(String),
    /// [`list_all`]: more tasks than [`ListLimits::max_tasks`].
    #[error("more than {max} scheduled tasks")]
    TooManyTasks {
        /// The cap.
        max: usize,
    },
    /// [`list_all`]: a folder deeper than [`ListLimits::max_depth`].
    #[error("task folder {path:?} is deeper than {max} levels")]
    TooDeep {
        /// The first folder found below the cap (empty when its path could not be read).
        path: String,
        /// The cap.
        max: usize,
    },
    /// A string Task Scheduler returned is not valid UTF-16 where exact text is required.
    #[error("{step} returned text that is not valid UTF-16")]
    InvalidUtf16 {
        /// The call.
        step: &'static str,
    },
    /// A COM call failed.
    #[error("{step} failed with HRESULT {hresult:#010x}")]
    Com {
        /// The call.
        step: &'static str,
        /// Its `HRESULT`, as an unsigned value (`0x80070005` and so on).
        hresult: u32,
    },
}

impl WinError {
    /// The `HRESULT` of a failed COM call.
    pub fn hresult(&self) -> Option<u32> {
        match self {
            WinError::Com { hresult, .. } => Some(*hresult),
            _ => None,
        }
    }

    /// The call was refused with `E_ACCESSDENIED`.
    pub fn is_access_denied(&self) -> bool {
        self.hresult() == Some(HR_ACCESS_DENIED)
    }
}

/// Caps of [`list_all_with`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListLimits {
    /// Folder depth below `\` (a task in `\A\B` is at depth 2). A deeper folder is an error.
    pub max_depth: usize,
    /// Tasks in total. More is an error.
    pub max_tasks: usize,
}

impl ListLimits {
    /// The caps of the contract: depth 32, 20,000 tasks.
    pub const DEFAULT: ListLimits = ListLimits {
        max_depth: 32,
        max_tasks: 20_000,
    };
}

impl Default for ListLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// One action of a task, as Task Scheduler stores it (mirrors `purge_model::object::TaskAction`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawAction {
    /// `IExecAction`. Empty arguments and working directory are `None`.
    Exec {
        /// `Path`, as stored (environment variables not expanded).
        path: String,
        /// `Arguments`.
        arguments: Option<String>,
        /// `WorkingDirectory`.
        working_dir: Option<String>,
    },
    /// `IComHandlerAction`. Empty data is `None`.
    ComHandler {
        /// `ClassId`, as stored.
        clsid: String,
        /// `Data`.
        data: Option<String>,
    },
    /// Any other action type: `send_email`, `show_message`, or `type_<n>` for an unknown one.
    Other {
        /// The type name.
        kind: String,
    },
}

/// `TASK_LOGON_TYPE` of a task's principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogonType {
    /// `TASK_LOGON_NONE`.
    None,
    /// `TASK_LOGON_PASSWORD`: the password is stored.
    Password,
    /// `TASK_LOGON_S4U`.
    S4u,
    /// `TASK_LOGON_INTERACTIVE_TOKEN`.
    InteractiveToken,
    /// `TASK_LOGON_GROUP`.
    Group,
    /// `TASK_LOGON_SERVICE_ACCOUNT`.
    ServiceAccount,
    /// `TASK_LOGON_INTERACTIVE_TOKEN_OR_PASSWORD`: a password may be stored.
    InteractiveTokenOrPassword,
    /// A value this build does not know.
    Other(i32),
}

impl LogonType {
    fn from_raw(t: TASK_LOGON_TYPE) -> LogonType {
        match t.0 {
            0 => LogonType::None,
            1 => LogonType::Password,
            2 => LogonType::S4u,
            3 => LogonType::InteractiveToken,
            4 => LogonType::Group,
            5 => LogonType::ServiceAccount,
            6 => LogonType::InteractiveTokenOrPassword,
            n => LogonType::Other(n),
        }
    }

    /// The task may hold a stored password, so it cannot be registered again from its XML alone
    /// (`Password`, `InteractiveTokenOrPassword`, and any unknown type).
    pub fn may_store_password(self) -> bool {
        matches!(
            self,
            LogonType::Password | LogonType::InteractiveTokenOrPassword | LogonType::Other(_)
        )
    }
}

/// One registered task, as [`list_all`] and [`read_task`] return it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTask {
    /// Full path, starting with a backslash, as Task Scheduler returns it.
    pub path: String,
    /// `IRegisteredTask::get_Enabled` (`false` when it could not be read).
    pub enabled: bool,
    /// `Some(true)` when `get_State` reports a running instance, `None` when the state could not be
    /// read.
    pub running: Option<bool>,
    /// `Settings.Hidden` (`false` when unreadable).
    pub hidden: bool,
    /// The actions in order. Empty when [`RawTask::unreadable`].
    pub actions: Vec<RawAction>,
    /// `Principal.LogonType` (`None` when unreadable).
    pub logon_type: Option<LogonType>,
    /// `Principal.UserId`; `None` when empty or unreadable.
    pub user_id: Option<String>,
    /// `RegistrationInfo.Author`; `None` when empty or unreadable.
    pub author: Option<String>,
    /// The definition could not be read in full (access denied, corrupt, text that is not UTF-16, a
    /// path that is not UTF-16). Then `actions` is empty and every definition field is its default,
    /// never a partial list.
    pub unreadable: bool,
}

/// Every task the caller can see, under [`ListLimits::DEFAULT`]. See the module documentation.
pub fn list_all() -> Result<Vec<RawTask>, WinError> {
    list_all_with(ListLimits::DEFAULT)
}

/// [`list_all`] with explicit caps.
pub fn list_all_with(limits: ListLimits) -> Result<Vec<RawTask>, WinError> {
    with_com(|| {
        let svc = connect()?;
        let root = get_folder(&svc, "\\")?;
        walk(ComFolder(root), limits)
    })
}

/// One task by full path, read as [`list_all`] reads it; `None` when it does not exist.
pub fn read_task(path: &str) -> Result<Option<RawTask>, WinError> {
    let p = TaskPath::parse(path)?;
    with_com(|| {
        let svc = connect()?;
        match open_task(&svc, &p)? {
            Some(task) => read_registered(&task).map(Some),
            None => Ok(None),
        }
    })
}

/// The stored XML (`get_Xml`, unchanged) and SDDL (`GetSecurityDescriptor(OWNER | GROUP | DACL)`) of a
/// task; `None` when the task or its folder does not exist.
pub fn read_xml(path: &str) -> Result<Option<(String, String)>, WinError> {
    let p = TaskPath::parse(path)?;
    with_com(|| {
        let svc = connect()?;
        let Some(task) = open_task(&svc, &p)? else {
            return Ok(None);
        };
        // SAFETY: `task` is a live interface pointer owned by this frame.
        let xml = unsafe { task.Xml() }.map_err(com("IRegisteredTask::get_Xml"))?;
        // SAFETY: as above; the flags are plain SECURITY_INFORMATION bits.
        let sddl = unsafe { task.GetSecurityDescriptor(SD_OWNER_GROUP_DACL) }
            .map_err(com("IRegisteredTask::GetSecurityDescriptor"))?;
        Ok(Some((
            exact(&xml, "IRegisteredTask::get_Xml")?,
            exact(&sddl, "IRegisteredTask::GetSecurityDescriptor")?,
        )))
    })
}

/// Deletes one task with `DeleteTask(name, 0)` on its parent folder. A missing task or folder is `Ok`.
#[cfg(feature = "write")]
pub fn delete(path: &str) -> Result<(), WinError> {
    let p = TaskPath::parse(path)?;
    with_com(|| {
        let svc = connect()?;
        let folder = match get_folder(&svc, &p.parent()) {
            Ok(f) => f,
            Err(e) if is_not_found(&e) => return Ok(()),
            Err(e) => return Err(e),
        };
        let name = BSTR::from(p.name());
        // SAFETY: `folder` is live; `name` is a valid BSTR; flags must be 0.
        match unsafe { folder.DeleteTask(&name, 0) } {
            Ok(()) => Ok(()),
            Err(e) => {
                let e = com("ITaskFolder::DeleteTask")(e);
                if is_not_found(&e) { Ok(()) } else { Err(e) }
            }
        }
    })
}

/// Registers a task from its XML, create only. See the module documentation.
///
/// `sddl` is accepted for the contract signature but not passed to Task Scheduler (spike result):
/// the descriptor stored for the task comes from the XML and the folder, as at the original
/// registration. The caller compares the SDDL read back with its backup.
///
/// Refused before any call: an empty XML, an XML with a NUL, and an XML containing
/// `RegistrationTrigger` (that trigger starts the task when it is registered).
#[cfg(feature = "write")]
pub fn register_xml(path: &str, xml: &str, sddl: &str) -> Result<(), WinError> {
    use windows::Win32::System::TaskScheduler::{TASK_CREATE, TASK_LOGON_NONE};

    let p = TaskPath::parse(path)?;
    check_register_xml(xml)?;
    let _not_passed = sddl;
    with_com(|| {
        let svc = connect()?;
        let folder = open_or_create_folders(&svc, p.folders())?;
        let empty = VARIANT::default();
        let name = BSTR::from(p.name());
        let text = BSTR::from(xml);
        // SAFETY: `folder` is live; every argument is a valid BSTR or a VT_EMPTY VARIANT that
        // outlives the call. TASK_CREATE only: the call fails over an existing task.
        let registered = unsafe {
            folder.RegisterTask(
                &name,
                &text,
                TASK_CREATE.0,
                &empty,
                &empty,
                TASK_LOGON_NONE,
                &empty,
            )
        };
        match registered {
            Ok(_task) => Ok(()),
            Err(e) => match com("ITaskFolder::RegisterTask")(e) {
                WinError::Com {
                    hresult: HR_ALREADY_EXISTS,
                    ..
                } => Err(WinError::AlreadyExists(p.full.clone())),
                WinError::Com {
                    hresult: HR_LOGON_FAILURE,
                    ..
                } => Err(WinError::PasswordNeeded(p.full.clone())),
                other => Err(other),
            },
        }
    })
}

/// The register-time XML checks (no COM).
#[cfg(feature = "write")]
fn check_register_xml(xml: &str) -> Result<(), WinError> {
    if xml.trim().is_empty() {
        return Err(WinError::InvalidXml("empty"));
    }
    if xml.contains('\0') {
        return Err(WinError::InvalidXml("contains a NUL character"));
    }
    if xml.contains("RegistrationTrigger") {
        return Err(WinError::InvalidXml(
            "has a RegistrationTrigger, which would start the task when it is registered",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------
// Paths

/// A validated task path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TaskPath {
    full: String,
    segments: Vec<String>,
}

impl TaskPath {
    fn parse(path: &str) -> Result<TaskPath, WinError> {
        let bad = || WinError::InvalidPath(path.to_owned());
        if path.encode_utf16().count() > MAX_PATH_LEN {
            return Err(bad());
        }
        let rest = path.strip_prefix('\\').ok_or_else(bad)?;
        let mut segments = Vec::new();
        for seg in rest.split('\\') {
            if seg.is_empty()
                || seg == "."
                || seg == ".."
                || seg.chars().any(|c| c.is_control() || c == '/')
            {
                return Err(bad());
            }
            segments.push(seg.to_owned());
        }
        Ok(TaskPath {
            full: path.to_owned(),
            segments,
        })
    }

    /// The folder segments (everything but the last).
    fn folders(&self) -> &[String] {
        &self.segments[..self.segments.len().saturating_sub(1)]
    }

    /// The task name (the last segment; never empty after `parse`).
    fn name(&self) -> &str {
        self.segments.last().map_or("", String::as_str)
    }

    /// The parent folder's full path (`\` for a task in the root folder).
    fn parent(&self) -> String {
        let mut s = String::from("\\");
        s.push_str(&self.folders().join("\\"));
        s
    }
}

/// Checks a task path against the rules of the module documentation without touching Task Scheduler.
pub fn validate_path(path: &str) -> Result<(), WinError> {
    TaskPath::parse(path).map(|_| ())
}

// ---------------------------------------------------------------------------------------------------
// COM plumbing

/// The calling thread's membership of a COM apartment for the duration of one public call.
struct Apartment {
    uninit: bool,
}

impl Apartment {
    fn enter() -> Result<Apartment, WinError> {
        // SAFETY: plain call with a null reserved pointer; the result decides whether we uninitialise.
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.0 as u32 == HR_CHANGED_MODE {
            // Already in a single-threaded apartment: COM is usable, but this call did not
            // initialise it, so it must not uninitialise it either.
            return Ok(Apartment { uninit: false });
        }
        if hr.is_err() {
            return Err(WinError::Com {
                step: "CoInitializeEx",
                hresult: hr.0 as u32,
            });
        }
        // S_OK or S_FALSE: both add one reference that CoUninitialize balances.
        Ok(Apartment { uninit: true })
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.uninit {
            // SAFETY: balances the successful CoInitializeEx of `enter`. The guard lives only inside
            // `with_com`, on the thread that entered, and every interface pointer of the call is
            // released before it drops.
            unsafe { CoUninitialize() };
        }
    }
}

/// Runs `f` inside an [`Apartment`]. Every COM object `f` creates is released when `f` returns, before
/// the apartment is left; the result carries no COM object.
fn with_com<T>(f: impl FnOnce() -> Result<T, WinError>) -> Result<T, WinError> {
    let apartment = Apartment::enter()?;
    let result = f();
    drop(apartment);
    result
}

/// Maps a `windows` error to [`WinError::Com`] (dropping any error object it holds).
fn com(step: &'static str) -> impl Fn(windows::core::Error) -> WinError {
    move |e| WinError::Com {
        step,
        hresult: e.code().0 as u32,
    }
}

fn is_not_found(e: &WinError) -> bool {
    matches!(e.hresult(), Some(HR_FILE_NOT_FOUND | HR_PATH_NOT_FOUND))
}

/// Exact text: invalid UTF-16 is an error.
fn exact(b: &BSTR, step: &'static str) -> Result<String, WinError> {
    String::from_utf16(b).map_err(|_| WinError::InvalidUtf16 { step })
}

fn connect() -> Result<ITaskService, WinError> {
    // SAFETY: the CLSID is the Task Scheduler coclass; no outer object.
    let svc: ITaskService = unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER) }
        .map_err(com("CoCreateInstance(TaskScheduler)"))?;
    let empty = VARIANT::default();
    // SAFETY: four VT_EMPTY variants: the local machine as the current user.
    unsafe { svc.Connect(&empty, &empty, &empty, &empty) }.map_err(com("ITaskService::Connect"))?;
    Ok(svc)
}

fn get_folder(svc: &ITaskService, path: &str) -> Result<ITaskFolder, WinError> {
    // SAFETY: `svc` is live; the BSTR outlives the call.
    unsafe { svc.GetFolder(&BSTR::from(path)) }.map_err(com("ITaskService::GetFolder"))
}

/// The registered task at `p`, or `None` when it or its folder does not exist.
fn open_task(svc: &ITaskService, p: &TaskPath) -> Result<Option<IRegisteredTask>, WinError> {
    let folder = match get_folder(svc, &p.parent()) {
        Ok(f) => f,
        Err(e) if is_not_found(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    // SAFETY: `folder` is live; the BSTR outlives the call.
    match unsafe { folder.GetTask(&BSTR::from(p.name())) } {
        Ok(t) => Ok(Some(t)),
        Err(e) => {
            let e = com("ITaskFolder::GetTask")(e);
            if is_not_found(&e) { Ok(None) } else { Err(e) }
        }
    }
}

/// Opens `\seg1\seg2...`, creating each missing folder with the default security descriptor.
#[cfg(feature = "write")]
fn open_or_create_folders(svc: &ITaskService, segs: &[String]) -> Result<ITaskFolder, WinError> {
    let mut cur = get_folder(svc, "\\")?;
    for seg in segs {
        let name = BSTR::from(seg.as_str());
        // SAFETY: `cur` is live; the BSTR outlives the call.
        let next = match unsafe { cur.GetFolder(&name) } {
            Ok(f) => f,
            Err(e) => {
                let e = com("ITaskFolder::GetFolder")(e);
                if !is_not_found(&e) {
                    return Err(e);
                }
                // SAFETY: as above; a VT_EMPTY sddl means the default descriptor.
                match unsafe { cur.CreateFolder(&name, &VARIANT::default()) } {
                    Ok(f) => f,
                    Err(e) => {
                        let e = com("ITaskFolder::CreateFolder")(e);
                        if e.hresult() != Some(HR_ALREADY_EXISTS) {
                            return Err(e);
                        }
                        // Created by someone else in between: open it.
                        // SAFETY: as above.
                        unsafe { cur.GetFolder(&name) }.map_err(com("ITaskFolder::GetFolder"))?
                    }
                }
            }
        };
        cur = next;
    }
    Ok(cur)
}

fn count(n: i32, step: &'static str) -> Result<usize, WinError> {
    usize::try_from(n).map_err(|_| WinError::Com {
        step,
        hresult: HR_UNEXPECTED,
    })
}

// ---------------------------------------------------------------------------------------------------
// Walk

/// A folder of the tree [`walk`] visits (the live one is [`ComFolder`]; tests use a fake).
trait FolderNode: Sized {
    /// Full path, for [`WinError::TooDeep`].
    fn path(&self) -> Result<String, WinError>;
    /// The direct subfolders.
    fn subfolders(&self) -> Result<Vec<Self>, WinError>;
    /// The tasks directly in this folder, hidden ones included; `None` when there are more than
    /// `room` (nothing is read then).
    fn tasks(&self, room: usize) -> Result<Option<Vec<RawTask>>, WinError>;
}

fn walk<N: FolderNode>(root: N, limits: ListLimits) -> Result<Vec<RawTask>, WinError> {
    let too_many = WinError::TooManyTasks {
        max: limits.max_tasks,
    };
    let mut out = Vec::new();
    let mut stack = vec![(root, 0usize)];
    while let Some((node, depth)) = stack.pop() {
        let room = limits.max_tasks.saturating_sub(out.len());
        match node.tasks(room)? {
            Some(tasks) if tasks.len() <= room => out.extend(tasks),
            _ => return Err(too_many),
        }
        let subs = node.subfolders()?;
        if let Some(first) = subs.first()
            && depth + 1 > limits.max_depth
        {
            return Err(WinError::TooDeep {
                path: first.path().unwrap_or_default(),
                max: limits.max_depth,
            });
        }
        // Reverse so that folders come out in the order Task Scheduler lists them.
        stack.extend(subs.into_iter().rev().map(|s| (s, depth + 1)));
    }
    Ok(out)
}

/// A live `ITaskFolder`.
struct ComFolder(ITaskFolder);

impl FolderNode for ComFolder {
    fn path(&self) -> Result<String, WinError> {
        // SAFETY: the folder is live.
        let p = unsafe { self.0.Path() }.map_err(com("ITaskFolder::get_Path"))?;
        Ok(String::from_utf16_lossy(&p))
    }

    fn subfolders(&self) -> Result<Vec<ComFolder>, WinError> {
        // SAFETY: the folder is live; flags must be 0.
        let coll = match unsafe { self.0.GetFolders(0) }.map_err(com("ITaskFolder::GetFolders")) {
            Ok(c) => c,
            // Removed since its parent listed it: it has nothing left to list.
            Err(e) if is_not_found(&e) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        // SAFETY: `coll` is live.
        let n = unsafe { coll.Count() }.map_err(com("ITaskFolderCollection::get_Count"))?;
        let n = count(n, "ITaskFolderCollection::get_Count")?;
        let mut out = Vec::with_capacity(n);
        for i in 1..=n {
            let index = VARIANT::from(i as i32);
            // SAFETY: `coll` is live; collections are 1-based; `index` outlives the call.
            let f =
                unsafe { coll.get_Item(&index) }.map_err(com("ITaskFolderCollection::get_Item"))?;
            out.push(ComFolder(f));
        }
        Ok(out)
    }

    fn tasks(&self, room: usize) -> Result<Option<Vec<RawTask>>, WinError> {
        // SAFETY: the folder is live; TASK_ENUM_HIDDEN is a plain flag.
        let coll = match unsafe { self.0.GetTasks(TASK_ENUM_HIDDEN.0) }
            .map_err(com("ITaskFolder::GetTasks"))
        {
            Ok(c) => c,
            // Removed since its parent listed it: no task is left in it.
            Err(e) if is_not_found(&e) => return Ok(Some(Vec::new())),
            Err(e) => return Err(e),
        };
        // SAFETY: `coll` is live.
        let n = unsafe { coll.Count() }.map_err(com("IRegisteredTaskCollection::get_Count"))?;
        let n = count(n, "IRegisteredTaskCollection::get_Count")?;
        if n > room {
            return Ok(None);
        }
        let mut out = Vec::with_capacity(n);
        for i in 1..=n {
            let index = VARIANT::from(i as i32);
            // SAFETY: as in `subfolders`.
            let t = unsafe { coll.get_Item(&index) }
                .map_err(com("IRegisteredTaskCollection::get_Item"))?;
            out.push(read_registered(&t)?);
        }
        Ok(Some(out))
    }
}

// ---------------------------------------------------------------------------------------------------
// One task

/// Reads one registered task. Only a failure to read its path is an error; anything the definition
/// cannot give marks the task unreadable.
fn read_registered(task: &IRegisteredTask) -> Result<RawTask, WinError> {
    // SAFETY: `task` is live for every call below.
    let path_b = unsafe { task.Path() }.map_err(com("IRegisteredTask::get_Path"))?;
    let (path, path_ok) = match String::from_utf16(&path_b) {
        Ok(p) => (p, true),
        Err(_) => (String::from_utf16_lossy(&path_b), false),
    };
    // SAFETY: as above.
    let enabled = unsafe { task.Enabled() }.map(|b| b.0 != 0);
    // SAFETY: as above.
    let running = unsafe { task.State() }
        .ok()
        .map(|s| s == TASK_STATE_RUNNING);
    let def = if path_ok {
        // SAFETY: as above.
        unsafe { task.Definition() }
            .ok()
            .and_then(|d| read_definition(&d))
    } else {
        None
    };
    let mut raw = RawTask {
        path,
        enabled: enabled.as_ref().is_ok_and(|e| *e),
        running,
        hidden: false,
        actions: Vec::new(),
        logon_type: None,
        user_id: None,
        author: None,
        unreadable: true,
    };
    if let (Some(d), Ok(_)) = (def, enabled) {
        raw.hidden = d.hidden;
        raw.actions = d.actions;
        raw.logon_type = Some(d.logon_type);
        raw.user_id = d.user_id;
        raw.author = d.author;
        raw.unreadable = false;
    }
    Ok(raw)
}

/// The definition fields of [`RawTask`].
struct Definition {
    hidden: bool,
    actions: Vec<RawAction>,
    logon_type: LogonType,
    user_id: Option<String>,
    author: Option<String>,
}

/// Reads the definition in full, or `None` when any part of it cannot be read.
fn read_definition(def: &ITaskDefinition) -> Option<Definition> {
    // SAFETY: every interface pointer below is live for the call; the out-pointers are valid locals.
    unsafe {
        let mut hidden = Default::default();
        def.Settings().ok()?.Hidden(&mut hidden).ok()?;

        let principal = def.Principal().ok()?;
        let mut logon = TASK_LOGON_TYPE::default();
        principal.LogonType(&mut logon).ok()?;
        let mut user = BSTR::new();
        principal.UserId(&mut user).ok()?;

        let mut author = BSTR::new();
        def.RegistrationInfo().ok()?.Author(&mut author).ok()?;

        let coll = def.Actions().ok()?;
        let mut n = 0i32;
        coll.Count(&mut n).ok()?;
        let n = usize::try_from(n).ok()?;
        let mut actions = Vec::with_capacity(n);
        for i in 1..=n {
            let a = coll.get_Item(i as i32).ok()?;
            actions.push(read_action(&a)?);
        }

        Some(Definition {
            hidden: hidden.0 != 0,
            actions,
            logon_type: LogonType::from_raw(logon),
            user_id: optional(&user)?,
            author: optional(&author)?,
        })
    }
}

/// One action, or `None` when it cannot be read.
fn read_action(a: &IAction) -> Option<RawAction> {
    // SAFETY: `a` and the interfaces cast from it are live; out-pointers are valid locals.
    unsafe {
        let mut t = TASK_ACTION_TYPE::default();
        a.Type(&mut t).ok()?;
        match t {
            TASK_ACTION_EXEC => {
                let e: IExecAction = a.cast().ok()?;
                let (mut path, mut args, mut dir) = (BSTR::new(), BSTR::new(), BSTR::new());
                e.Path(&mut path).ok()?;
                e.Arguments(&mut args).ok()?;
                e.WorkingDirectory(&mut dir).ok()?;
                Some(RawAction::Exec {
                    path: String::from_utf16(&path).ok()?,
                    arguments: optional(&args)?,
                    working_dir: optional(&dir)?,
                })
            }
            TASK_ACTION_COM_HANDLER => {
                let c: IComHandlerAction = a.cast().ok()?;
                let (mut clsid, mut data) = (BSTR::new(), BSTR::new());
                c.ClassId(&mut clsid).ok()?;
                c.Data(&mut data).ok()?;
                Some(RawAction::ComHandler {
                    clsid: String::from_utf16(&clsid).ok()?,
                    data: optional(&data)?,
                })
            }
            TASK_ACTION_SEND_EMAIL => Some(RawAction::Other {
                kind: "send_email".to_owned(),
            }),
            TASK_ACTION_SHOW_MESSAGE => Some(RawAction::Other {
                kind: "show_message".to_owned(),
            }),
            other => Some(RawAction::Other {
                kind: format!("type_{}", other.0),
            }),
        }
    }
}

/// Empty is `Some(None)`; invalid UTF-16 is `None` (the caller marks the task unreadable).
fn optional(b: &BSTR) -> Option<Option<String>> {
    if b.is_empty() {
        Some(None)
    } else {
        String::from_utf16(b).ok().map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake folder tree: `(path, task count, children)`.
    #[derive(Clone)]
    struct Fake {
        path: String,
        tasks: usize,
        children: Vec<Fake>,
    }

    fn fake(path: &str, tasks: usize, children: Vec<Fake>) -> Fake {
        Fake {
            path: path.to_owned(),
            tasks,
            children,
        }
    }

    impl FolderNode for Fake {
        fn path(&self) -> Result<String, WinError> {
            Ok(self.path.clone())
        }
        fn subfolders(&self) -> Result<Vec<Fake>, WinError> {
            Ok(self.children.clone())
        }
        fn tasks(&self, room: usize) -> Result<Option<Vec<RawTask>>, WinError> {
            if self.tasks > room {
                return Ok(None);
            }
            Ok(Some(
                (0..self.tasks)
                    .map(|i| RawTask {
                        path: format!("{}\\t{i}", self.path.trim_end_matches('\\')),
                        enabled: true,
                        running: Some(false),
                        hidden: false,
                        actions: Vec::new(),
                        logon_type: Some(LogonType::InteractiveToken),
                        user_id: None,
                        author: None,
                        unreadable: false,
                    })
                    .collect(),
            ))
        }
    }

    /// `\a\b\c`: depth 3, one task per folder (4 in total).
    fn chain() -> Fake {
        fake(
            "\\",
            1,
            vec![fake(
                "\\a",
                1,
                vec![fake("\\a\\b", 1, vec![fake("\\a\\b\\c", 1, vec![])])],
            )],
        )
    }

    #[test]
    fn depth_and_count_caps() {
        let lim = |max_depth, max_tasks| ListLimits {
            max_depth,
            max_tasks,
        };
        // Exactly at both caps: the whole list, in folder order.
        let all = walk(chain(), lim(3, 4)).unwrap();
        let paths: Vec<_> = all.iter().map(|t| t.path.as_str()).collect();
        assert_eq!(paths, ["\\t0", "\\a\\t0", "\\a\\b\\t0", "\\a\\b\\c\\t0"]);
        // One level too deep: an error naming the folder, never a shorter list.
        assert_eq!(
            walk(chain(), lim(2, 4)),
            Err(WinError::TooDeep {
                path: "\\a\\b\\c".into(),
                max: 2
            })
        );
        // One task too many: an error, never a shorter list.
        assert_eq!(
            walk(chain(), lim(3, 3)),
            Err(WinError::TooManyTasks { max: 3 })
        );
        // A single folder over the cap on its own.
        assert_eq!(
            walk(fake("\\", 5, vec![]), lim(0, 4)),
            Err(WinError::TooManyTasks { max: 4 })
        );
        // Depth 0 with no subfolders is fine.
        assert_eq!(walk(fake("\\", 2, vec![]), lim(0, 2)).unwrap().len(), 2);
        assert_eq!(ListLimits::default(), lim(32, 20_000));
    }

    #[test]
    fn path_rules() {
        for ok in ["\\t", "\\Vendor\\Updater", "\\a b\\c.d\\...x"] {
            let p = TaskPath::parse(ok).unwrap();
            assert_eq!(p.full, ok);
        }
        let p = TaskPath::parse("\\A\\B\\T").unwrap();
        assert_eq!(p.parent(), "\\A\\B");
        assert_eq!(p.name(), "T");
        assert_eq!(p.folders(), ["A", "B"]);
        let p = TaskPath::parse("\\T").unwrap();
        assert_eq!(p.parent(), "\\");
        assert_eq!(p.name(), "T");
        let long_ok = format!("\\{}", "x".repeat(MAX_PATH_LEN - 1));
        assert!(TaskPath::parse(&long_ok).is_ok());
        let long_bad = format!("\\{}", "x".repeat(MAX_PATH_LEN));
        for bad in [
            "", "\\", "t", "\\\\t", "\\a\\\\t", "\\a\\", "\\.\\t", "\\..\\t", "\\a\\..", "\\a\\.",
            "\\a/b", "\\a\0b", "\\a\nb",
        ] {
            assert_eq!(
                TaskPath::parse(bad),
                Err(WinError::InvalidPath(bad.into())),
                "{bad:?}"
            );
        }
        assert!(TaskPath::parse(&long_bad).is_err());
    }

    #[cfg(feature = "write")]
    #[test]
    fn register_xml_checks() {
        assert_eq!(check_register_xml(""), Err(WinError::InvalidXml("empty")));
        assert!(check_register_xml("<Task>\0</Task>").is_err());
        assert!(
            check_register_xml("<Task><Triggers><RegistrationTrigger/></Triggers></Task>").is_err()
        );
        assert!(check_register_xml("<Task/>").is_ok());
    }

    #[test]
    fn logon_type_mapping() {
        assert_eq!(LogonType::from_raw(TASK_LOGON_TYPE(1)), LogonType::Password);
        assert_eq!(
            LogonType::from_raw(TASK_LOGON_TYPE(6)),
            LogonType::InteractiveTokenOrPassword
        );
        assert_eq!(LogonType::from_raw(TASK_LOGON_TYPE(9)), LogonType::Other(9));
        assert!(LogonType::Password.may_store_password());
        assert!(!LogonType::S4u.may_store_password());
        assert!(!LogonType::InteractiveToken.may_store_password());
    }
}
