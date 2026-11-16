//! Service Control Manager: query under `read`, mutation under `write` (M1b).
//! Thin, safe wrappers over the Win32 APIs the engine needs, and nothing else.
//!
//! ENGINE_PLAN.md §5.7.2, the C-WIN contract (docs/M1B_DESIGN.json, package M1B-WIN-SCM) and the VM spike
//! (vm/spikes/m1b/RESULT.json, section `service`).
//!
//! - [`query`] (feature `read`): `QueryServiceConfigW`, `QueryServiceConfig2W` for the nine items of
//!   `purge.svcdef/1` (C-DEF), `QueryServiceObjectSecurity` (owner, group, DACL) as SDDL and
//!   `QueryServiceStatusEx`. A missing service is `Ok(None)`; an information level the OS does not know is
//!   `None` for that item, not an error.
//! - [`delete`], [`create`], [`set_config2`], [`set_security`] (feature `write`): the delete and the
//!   re-create sequence of the executor (M1B-X-SERVICE).
//!
//! What this module never does: it never changes a service's run state, never sends a control code,
//! never changes the main configuration of an existing service (start type, binary path, account) and
//! never subscribes to status notifications. The only SCM entry points used are the ones named above plus
//! `OpenSCManagerW`, `OpenServiceW`, `DeleteService`, `CreateServiceW`, `ChangeServiceConfig2W`,
//! `SetServiceObjectSecurity` and `CloseServiceHandle`. A test greps this crate for the forbidden names.
//!
//! Rules carried by the code (spike results where the design differed):
//! - Least access: the manager is opened with `SC_MANAGER_CONNECT` (plus `SC_MANAGER_CREATE_SERVICE` for
//!   [`create`]); each service handle asks only for what its call needs.
//! - [`delete`] refuses a service that is not `SERVICE_STOPPED` ([`WinError::InUse`]) or that is not a
//!   plain Win32 service (drivers, per-user and packaged services: [`WinError::Refused`]) before
//!   `DeleteService` is reached. After `DeleteService` it closes its own handle and only then opens the
//!   service again: while any handle is open, the deleter's own included, the service is only marked for
//!   delete and stays openable (spike `marked_for_delete`). Still openable after that close means another
//!   handle keeps it: [`ScmDelete::Marked`].
//! - [`create`] takes the binary path as the raw `ImagePath` string of the key backup: `QueryServiceConfigW`
//!   returns it with environment variables expanded (spike `query_config_expands_image_path`), so the
//!   [`ScmConfig::binary_path`] of a query is not a re-create argument. The password is always null.
//!   A name that is only marked for delete gives [`WinError::MarkedForDelete`] (1072), distinct from
//!   [`WinError::Exists`]. Only plain Win32 services with start type auto, demand or disabled are created.
//! - [`set_config2`] sets one item. The caller applies only items whose value the key backup holds
//!   ([`Config2Kind::registry_entries`]); setting the others writes values the original never had. An
//!   empty trigger list (error 87) and launch protection 0 (error 2) are refused with
//!   [`WinError::NotSettable`] before the SCM is called.
//! - [`set_security`] sets the DACL only (`DACL_SECURITY_INFORMATION`): owner and group fail with 1307 and
//!   are not wanted. An SDDL without a DACL or with a NULL DACL (no access control) is refused.
//! - Buffers are sized by the API's own needed-size answer, capped at [`BUFFER_CAP`]; a larger answer is
//!   [`WinError::BufferTooLarge`]. Every pointer inside a returned buffer is checked to lie inside it and
//!   every string to be terminated and valid UTF-16 there ([`WinError::Malformed`] otherwise).
//! - Every SCM handle and every `LocalAlloc` block is owned by a guard that frees it on every path.
#![cfg(feature = "read")]

use std::ffi::c_void;
use std::fmt;
use std::mem::size_of;
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_LEVEL, ERROR_MORE_DATA, ERROR_NOT_SUPPORTED,
    ERROR_SERVICE_DOES_NOT_EXIST, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, IsValidSecurityDescriptor,
    OWNER_SECURITY_INFORMATION,
};
use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW, QueryServiceConfig2W,
    QueryServiceConfigW, QueryServiceObjectSecurity, QueryServiceStatusEx, SC_ACTION, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
    SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_FAILURE_ACTIONS,
    SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, SERVICE_CONFIG_LAUNCH_PROTECTED,
    SERVICE_CONFIG_PRESHUTDOWN_INFO, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
    SERVICE_CONFIG_SERVICE_SID_INFO, SERVICE_CONFIG_TRIGGER_INFO, SERVICE_DESCRIPTIONW,
    SERVICE_FAILURE_ACTIONSW, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_REQUIRED_PRIVILEGES_INFOW, SERVICE_STATUS_PROCESS, SERVICE_STOPPED, SERVICE_TRIGGER,
    SERVICE_TRIGGER_INFO, SERVICE_TRIGGER_SPECIFIC_DATA_ITEM, SERVICE_WIN32_OWN_PROCESS,
    SERVICE_WIN32_SHARE_PROCESS,
};

use crate::os::Win32Error;

#[cfg(feature = "write")]
use windows_sys::Win32::Foundation::{
    ERROR_DUPLICATE_SERVICE_NAME, ERROR_SERVICE_EXISTS, ERROR_SERVICE_MARKED_FOR_DELETE,
};
#[cfg(feature = "write")]
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
#[cfg(feature = "write")]
use windows_sys::Win32::Security::{ACL, GetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR};
#[cfg(feature = "write")]
use windows_sys::Win32::Storage::FileSystem::{DELETE, WRITE_DAC};
#[cfg(feature = "write")]
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, CreateServiceW, DeleteService, SC_ACTION_OWN_RESTART, SC_ACTION_RESTART,
    SC_MANAGER_CREATE_SERVICE, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG, SERVICE_DEMAND_START,
    SERVICE_DISABLED, SERVICE_START, SetServiceObjectSecurity,
};
#[cfg(feature = "write")]
use windows_sys::core::GUID;

/// The largest buffer any query here allocates (256 KiB). A larger needed-size answer is an error.
pub const BUFFER_CAP: u32 = 256 * 1024;

/// The longest service name and display name the SCM accepts, in UTF-16 units.
pub const MAX_NAME_UNITS: usize = 256;

/// `SERVICE_INTERACTIVE_PROCESS`: the legacy flag that may accompany a Win32 service type.
const SERVICE_INTERACTIVE_PROCESS: u32 = 0x100;

/// Attempts of the needed-size loop (the answer may grow between two calls).
const SIZE_ATTEMPTS: usize = 4;

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

/// Why an SCM call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WinError {
    /// The name is empty, longer than [`MAX_NAME_UNITS`], or contains `/`, `\` or NUL. Nothing was called.
    #[error("invalid service name {0:?}")]
    InvalidName(String),
    /// Another argument is malformed (a NUL inside a string, an empty list entry, an SDDL that does not
    /// parse or has no DACL). Nothing was changed.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// The service (or the definition to create) is not a plain Win32 own- or shared-process service with
    /// a start type this module handles: drivers, per-user and packaged services are never touched.
    #[error("refused: {0}")]
    Refused(String),
    /// `ERROR_SERVICE_DOES_NOT_EXIST` from a mutating call ([`query`] returns `Ok(None)` instead).
    #[error("the service does not exist")]
    NotFound,
    /// [`delete`]: the service is not stopped; `DeleteService` was not called.
    #[error("the service is not stopped (current state {state})")]
    InUse {
        /// `dwCurrentState` (`SERVICE_RUNNING` = 4, `SERVICE_STOP_PENDING` = 3, ...).
        state: u32,
    },
    /// [`create`]: `ERROR_SERVICE_EXISTS`, a service with this name exists.
    #[error("a service with this name already exists")]
    Exists,
    /// `ERROR_SERVICE_MARKED_FOR_DELETE`: the name belongs to a service that is deleted but still held
    /// open by some handle; it disappears when the last handle closes (or at the next restart).
    #[error("a service with this name is marked for delete and still open")]
    MarkedForDelete,
    /// [`create`]: `ERROR_DUPLICATE_SERVICE_NAME`, the display name is another service's name or
    /// display name.
    #[error("the display name is already used by another service")]
    DuplicateName,
    /// [`set_config2`]: this value of the item cannot be set (the spike saw the SCM refuse it) and is the
    /// default of a new service anyway.
    #[error("config2 item {item} cannot be set to this value: {reason}")]
    NotSettable {
        /// The item ([`Config2Kind::name`]).
        item: &'static str,
        /// Why.
        reason: &'static str,
    },
    /// An API asked for a buffer larger than [`BUFFER_CAP`].
    #[error("{call} asked for a {needed}-byte buffer (cap {BUFFER_CAP})")]
    BufferTooLarge {
        /// The call.
        call: &'static str,
        /// Its needed-size answer.
        needed: u32,
    },
    /// An API returned data that does not hold together (a pointer outside the buffer, an unterminated
    /// or invalid UTF-16 string, a count past the end).
    #[error("{call} returned malformed data: {what}")]
    Malformed {
        /// The call.
        call: &'static str,
        /// What was wrong.
        what: &'static str,
    },
    /// Any other failure of a Win32 call.
    #[error("{call} failed: {error}")]
    Api {
        /// The call.
        call: &'static str,
        /// Its error.
        error: Win32Error,
    },
}

impl WinError {
    /// The Win32 error behind an [`WinError::Api`] failure.
    pub fn win32(&self) -> Option<Win32Error> {
        match self {
            WinError::Api { error, .. } => Some(*error),
            _ => None,
        }
    }

    /// `ERROR_ACCESS_DENIED` from any call (for example an unelevated caller).
    pub fn is_access_denied(&self) -> bool {
        self.win32().is_some_and(Win32Error::is_access_denied)
    }
}

fn api(call: &'static str, code: u32) -> WinError {
    WinError::Api {
        call,
        error: Win32Error(code),
    }
}

// ---------------------------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------------------------

/// Everything [`query`] reads about one service: what `purge.svcdef/1` (C-DEF) records, plus the status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScmService {
    /// The name as passed to [`query`].
    pub name: String,
    /// `QueryServiceConfigW`.
    pub config: ScmConfig,
    /// `QueryServiceConfig2W`, one field per level.
    pub config2: ScmConfig2,
    /// `QueryServiceObjectSecurity(OWNER | GROUP | DACL)` as SDDL (`O:..G:..D:..`).
    pub sddl: String,
    /// `QueryServiceStatusEx(SC_STATUS_PROCESS_INFO)`.
    pub status: ScmStatus,
}

/// The main configuration (`QUERY_SERVICE_CONFIGW`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScmConfig {
    /// `dwServiceType`.
    pub service_type: u32,
    /// `dwStartType`.
    pub start_type: u32,
    /// `dwErrorControl`.
    pub error_control: u32,
    /// `lpBinaryPathName`, with environment variables **expanded** by the SCM. Re-create from the raw
    /// `ImagePath` of the key backup instead (spike).
    pub binary_path: String,
    /// `lpLoadOrderGroup`; an empty string is `None`.
    pub load_order_group: Option<String>,
    /// `dwTagId`.
    pub tag_id: u32,
    /// `lpDependencies`: service names, and group names prefixed with `+` (`SC_GROUP_IDENTIFIER`).
    pub dependencies: Vec<String>,
    /// `lpServiceStartName` (the account); an empty string is `None`.
    pub service_start_name: Option<String>,
    /// `lpDisplayName`; an empty string is `None`.
    pub display_name: Option<String>,
}

/// The `QueryServiceConfig2W` items. `None` means the level is not supported by this OS (or, for the
/// pointer-valued items, that the SCM returned no value).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScmConfig2 {
    /// `SERVICE_CONFIG_DESCRIPTION`; `None` when the service has no description.
    pub description: Option<String>,
    /// `SERVICE_CONFIG_DELAYED_AUTO_START_INFO`.
    pub delayed_auto_start: Option<bool>,
    /// `SERVICE_CONFIG_FAILURE_ACTIONS`.
    pub failure_actions: Option<FailureActions>,
    /// `SERVICE_CONFIG_FAILURE_ACTIONS_FLAG`.
    pub failure_actions_flag: Option<bool>,
    /// `SERVICE_CONFIG_SERVICE_SID_INFO`.
    pub service_sid_type: Option<u32>,
    /// `SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO`; `None` when the SCM returns no list.
    pub required_privileges: Option<Vec<String>>,
    /// `SERVICE_CONFIG_PRESHUTDOWN_INFO`, milliseconds.
    pub preshutdown_timeout_ms: Option<u32>,
    /// `SERVICE_CONFIG_TRIGGER_INFO`; `Some(empty)` for a service without triggers.
    pub triggers: Option<Vec<ScmTrigger>>,
    /// `SERVICE_CONFIG_LAUNCH_PROTECTED`.
    pub launch_protected: Option<u32>,
}

impl ScmConfig2 {
    /// Every present item, in the order the spike applied them (description, failure actions, failure
    /// flag, delayed start, SID type, privileges, preshutdown, triggers, launch protection). The caller
    /// keeps only the kinds whose value the key backup holds before passing them to [`set_config2`].
    pub fn items(&self) -> Vec<Config2Item> {
        let mut out = Vec::new();
        if let Some(v) = &self.description {
            out.push(Config2Item::Description(v.clone()));
        }
        if let Some(v) = &self.failure_actions {
            out.push(Config2Item::FailureActions(v.clone()));
        }
        if let Some(v) = self.failure_actions_flag {
            out.push(Config2Item::FailureActionsFlag(v));
        }
        if let Some(v) = self.delayed_auto_start {
            out.push(Config2Item::DelayedAutoStart(v));
        }
        if let Some(v) = self.service_sid_type {
            out.push(Config2Item::ServiceSidType(v));
        }
        if let Some(v) = &self.required_privileges {
            out.push(Config2Item::RequiredPrivileges(v.clone()));
        }
        if let Some(v) = self.preshutdown_timeout_ms {
            out.push(Config2Item::PreshutdownTimeout(v));
        }
        if let Some(v) = &self.triggers {
            out.push(Config2Item::Triggers(v.clone()));
        }
        if let Some(v) = self.launch_protected {
            out.push(Config2Item::LaunchProtected(v));
        }
        out
    }
}

/// `SERVICE_FAILURE_ACTIONSW`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FailureActions {
    /// `dwResetPeriod`, seconds.
    pub reset_period: u32,
    /// `lpRebootMsg`. When set through [`set_config2`], `None` leaves the message unchanged.
    pub reboot_msg: Option<String>,
    /// `lpCommand`. When set through [`set_config2`], `None` leaves the command unchanged.
    pub command: Option<String>,
    /// `lpsaActions`.
    pub actions: Vec<FailureAction>,
}

/// `SC_ACTION`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureAction {
    /// `Type`: `SC_ACTION_NONE` 0, `SC_ACTION_RESTART` 1, `SC_ACTION_REBOOT` 2, `SC_ACTION_RUN_COMMAND` 3,
    /// `SC_ACTION_OWN_RESTART` 4.
    pub action_type: u32,
    /// `Delay`, milliseconds.
    pub delay_ms: u32,
}

/// `SERVICE_TRIGGER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScmTrigger {
    /// `dwTriggerType`.
    pub trigger_type: u32,
    /// `dwAction` (1 start, 2 stop).
    pub action: u32,
    /// `pTriggerSubtype`; `None` for a null pointer.
    pub subtype: Option<ScmGuid>,
    /// `pDataItems`.
    pub data: Vec<TriggerDataItem>,
}

/// `SERVICE_TRIGGER_SPECIFIC_DATA_ITEM`: the type and the raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggerDataItem {
    /// `dwDataType` (1 binary, 2 string, 3 level, 4 keyword any, 5 keyword all).
    pub data_type: u32,
    /// The `cbData` bytes at `pData`, exactly as the SCM returned them.
    pub bytes: Vec<u8>,
}

/// A GUID as its 16 bytes in Windows memory layout (`Data1`, `Data2`, `Data3` little-endian, then
/// `Data4`). Displays as `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` in lower case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScmGuid(pub [u8; 16]);

impl ScmGuid {
    /// Parses `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, with or without braces, any case.
    pub fn parse(s: &str) -> Option<ScmGuid> {
        let s = s
            .strip_prefix('{')
            .and_then(|r| r.strip_suffix('}'))
            .unwrap_or(s);
        let parts: Vec<&str> = s.split('-').collect();
        let [a, b, c, d, e] = parts.as_slice() else {
            return None;
        };
        if a.len() != 8 || b.len() != 4 || c.len() != 4 || d.len() != 4 || e.len() != 12 {
            return None;
        }
        if !s.chars().all(|ch| ch == '-' || ch.is_ascii_hexdigit()) {
            return None;
        }
        let data1 = u32::from_str_radix(a, 16).ok()?;
        let data2 = u16::from_str_radix(b, 16).ok()?;
        let data3 = u16::from_str_radix(c, 16).ok()?;
        let tail = format!("{d}{e}");
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&data1.to_le_bytes());
        out[4..6].copy_from_slice(&data2.to_le_bytes());
        out[6..8].copy_from_slice(&data3.to_le_bytes());
        for (i, slot) in out[8..].iter_mut().enumerate() {
            *slot = u8::from_str_radix(tail.get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        Some(ScmGuid(out))
    }

    #[cfg(feature = "write")]
    fn to_guid(self) -> GUID {
        let b = self.0;
        GUID {
            data1: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            data2: u16::from_le_bytes([b[4], b[5]]),
            data3: u16::from_le_bytes([b[6], b[7]]),
            data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
        }
    }
}

impl fmt::Display for ScmGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{{{:08x}-{:04x}-{:04x}-",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
        )?;
        for x in &b[8..10] {
            write!(f, "{x:02x}")?;
        }
        f.write_str("-")?;
        for x in &b[10..] {
            write!(f, "{x:02x}")?;
        }
        f.write_str("}")
    }
}

/// `SERVICE_STATUS_PROCESS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScmStatus {
    /// `dwServiceType`.
    pub service_type: u32,
    /// `dwCurrentState` (`SERVICE_STOPPED` = 1).
    pub current_state: u32,
    /// `dwControlsAccepted`.
    pub controls_accepted: u32,
    /// `dwWin32ExitCode`.
    pub win32_exit_code: u32,
    /// `dwServiceSpecificExitCode`.
    pub service_specific_exit_code: u32,
    /// `dwProcessId` (0 when not running).
    pub process_id: u32,
    /// `dwServiceFlags`.
    pub service_flags: u32,
}

impl ScmStatus {
    /// `dwCurrentState == SERVICE_STOPPED`.
    pub fn is_stopped(&self) -> bool {
        self.current_state == SERVICE_STOPPED
    }
}

impl From<SERVICE_STATUS_PROCESS> for ScmStatus {
    fn from(s: SERVICE_STATUS_PROCESS) -> Self {
        ScmStatus {
            service_type: s.dwServiceType,
            current_state: s.dwCurrentState,
            controls_accepted: s.dwControlsAccepted,
            win32_exit_code: s.dwWin32ExitCode,
            service_specific_exit_code: s.dwServiceSpecificExitCode,
            process_id: s.dwProcessId,
            service_flags: s.dwServiceFlags,
        }
    }
}

/// One `ChangeServiceConfig2W` item, as [`set_config2`] takes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Config2Item {
    /// `SERVICE_CONFIG_DESCRIPTION`; an empty string deletes the description.
    Description(String),
    /// `SERVICE_CONFIG_FAILURE_ACTIONS`.
    FailureActions(FailureActions),
    /// `SERVICE_CONFIG_FAILURE_ACTIONS_FLAG`.
    FailureActionsFlag(bool),
    /// `SERVICE_CONFIG_DELAYED_AUTO_START_INFO` (only valid for an auto-start service).
    DelayedAutoStart(bool),
    /// `SERVICE_CONFIG_SERVICE_SID_INFO`.
    ServiceSidType(u32),
    /// `SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO`.
    RequiredPrivileges(Vec<String>),
    /// `SERVICE_CONFIG_PRESHUTDOWN_INFO`, milliseconds.
    PreshutdownTimeout(u32),
    /// `SERVICE_CONFIG_TRIGGER_INFO`; an empty list is refused ([`WinError::NotSettable`]).
    Triggers(Vec<ScmTrigger>),
    /// `SERVICE_CONFIG_LAUNCH_PROTECTED`; 0 is refused ([`WinError::NotSettable`]).
    LaunchProtected(u32),
}

impl Config2Item {
    /// The kind of this item.
    pub fn kind(&self) -> Config2Kind {
        match self {
            Config2Item::Description(_) => Config2Kind::Description,
            Config2Item::FailureActions(_) => Config2Kind::FailureActions,
            Config2Item::FailureActionsFlag(_) => Config2Kind::FailureActionsFlag,
            Config2Item::DelayedAutoStart(_) => Config2Kind::DelayedAutoStart,
            Config2Item::ServiceSidType(_) => Config2Kind::ServiceSidType,
            Config2Item::RequiredPrivileges(_) => Config2Kind::RequiredPrivileges,
            Config2Item::PreshutdownTimeout(_) => Config2Kind::PreshutdownTimeout,
            Config2Item::Triggers(_) => Config2Kind::Triggers,
            Config2Item::LaunchProtected(_) => Config2Kind::LaunchProtected,
        }
    }
}

/// The nine config2 items of `purge.svcdef/1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Config2Kind {
    /// `SERVICE_CONFIG_DESCRIPTION`.
    Description,
    /// `SERVICE_CONFIG_FAILURE_ACTIONS`.
    FailureActions,
    /// `SERVICE_CONFIG_FAILURE_ACTIONS_FLAG`.
    FailureActionsFlag,
    /// `SERVICE_CONFIG_DELAYED_AUTO_START_INFO`.
    DelayedAutoStart,
    /// `SERVICE_CONFIG_SERVICE_SID_INFO`.
    ServiceSidType,
    /// `SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO`.
    RequiredPrivileges,
    /// `SERVICE_CONFIG_PRESHUTDOWN_INFO`.
    PreshutdownTimeout,
    /// `SERVICE_CONFIG_TRIGGER_INFO`.
    Triggers,
    /// `SERVICE_CONFIG_LAUNCH_PROTECTED`.
    LaunchProtected,
}

impl Config2Kind {
    /// All kinds, in [`ScmConfig2::items`] order.
    pub const ALL: [Config2Kind; 9] = [
        Config2Kind::Description,
        Config2Kind::FailureActions,
        Config2Kind::FailureActionsFlag,
        Config2Kind::DelayedAutoStart,
        Config2Kind::ServiceSidType,
        Config2Kind::RequiredPrivileges,
        Config2Kind::PreshutdownTimeout,
        Config2Kind::Triggers,
        Config2Kind::LaunchProtected,
    ];

    /// The `dwInfoLevel` of `QueryServiceConfig2W` / `ChangeServiceConfig2W`.
    pub fn level(self) -> u32 {
        match self {
            Config2Kind::Description => SERVICE_CONFIG_DESCRIPTION,
            Config2Kind::FailureActions => SERVICE_CONFIG_FAILURE_ACTIONS,
            Config2Kind::FailureActionsFlag => SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            Config2Kind::DelayedAutoStart => SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            Config2Kind::ServiceSidType => SERVICE_CONFIG_SERVICE_SID_INFO,
            Config2Kind::RequiredPrivileges => SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            Config2Kind::PreshutdownTimeout => SERVICE_CONFIG_PRESHUTDOWN_INFO,
            Config2Kind::Triggers => SERVICE_CONFIG_TRIGGER_INFO,
            Config2Kind::LaunchProtected => SERVICE_CONFIG_LAUNCH_PROTECTED,
        }
    }

    /// The field name in `purge.svcdef/1` `config2` (and in the spike's `config2_items`).
    pub fn name(self) -> &'static str {
        match self {
            Config2Kind::Description => "description",
            Config2Kind::FailureActions => "failure_actions",
            Config2Kind::FailureActionsFlag => "failure_actions_flag",
            Config2Kind::DelayedAutoStart => "delayed_auto_start",
            Config2Kind::ServiceSidType => "service_sid_type",
            Config2Kind::RequiredPrivileges => "required_privileges",
            Config2Kind::PreshutdownTimeout => "preshutdown_timeout_ms",
            Config2Kind::Triggers => "triggers",
            Config2Kind::LaunchProtected => "launch_protected",
        }
    }

    /// The entries of the `Services\<name>` key that hold this item, as the spike mapped them: value
    /// names, and `TriggerInfo\` (trailing backslash) for a subkey. The item is applied on re-create only
    /// when the key backup holds at least one of them.
    pub fn registry_entries(self) -> &'static [&'static str] {
        match self {
            Config2Kind::Description => &["Description"],
            Config2Kind::FailureActions => &["FailureActions", "FailureCommand", "RebootMessage"],
            Config2Kind::FailureActionsFlag => &["FailureActionsOnNonCrashFailures"],
            Config2Kind::DelayedAutoStart => &["DelayedAutostart"],
            Config2Kind::ServiceSidType => &["ServiceSidType"],
            Config2Kind::RequiredPrivileges => &["RequiredPrivileges"],
            Config2Kind::PreshutdownTimeout => &["PreshutdownTimeout"],
            Config2Kind::Triggers => &["TriggerInfo\\"],
            Config2Kind::LaunchProtected => &["LaunchProtected"],
        }
    }
}

/// Whether `service_type` is a plain Win32 service: `SERVICE_WIN32_OWN_PROCESS`,
/// `SERVICE_WIN32_SHARE_PROCESS` or both (a split svchost service reports `0x30` in its status while its
/// configuration says `0x20`), optionally with `SERVICE_INTERACTIVE_PROCESS`, and no driver, per-user or
/// packaged-service bit. The only kind [`delete`] and [`create`] act on.
pub fn is_plain_win32_service(service_type: u32) -> bool {
    const WIN32: u32 = SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS;
    let base = service_type & !SERVICE_INTERACTIVE_PROCESS;
    base != 0 && base & !WIN32 == 0
}

// ---------------------------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------------------------

/// NUL-terminated UTF-16 of a service name, or [`WinError::InvalidName`].
fn service_name_arg(name: &str) -> Result<Vec<u16>, WinError> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let bad = units.is_empty() || units.len() > MAX_NAME_UNITS || name.contains(['/', '\\', '\0']);
    if bad {
        return Err(WinError::InvalidName(name.to_owned()));
    }
    Ok(nul_terminated(units))
}

fn nul_terminated(mut units: Vec<u16>) -> Vec<u16> {
    units.push(0);
    units
}

/// NUL-terminated UTF-16 of a string argument that must not contain NUL.
#[cfg(feature = "write")]
fn string_arg(field: &str, s: &str) -> Result<Vec<u16>, WinError> {
    if s.contains('\0') {
        return Err(WinError::InvalidArgument(format!("{field} contains NUL")));
    }
    Ok(nul_terminated(s.encode_utf16().collect()))
}

/// A `REG_MULTI_SZ`-style list (each entry NUL-terminated, one more NUL at the end). Entries must be
/// non-empty and free of NUL: either would end the list early and smuggle in or drop entries.
#[cfg(feature = "write")]
fn multi_sz_arg(field: &str, list: &[String]) -> Result<Vec<u16>, WinError> {
    let mut out = Vec::new();
    for entry in list {
        if entry.is_empty() {
            return Err(WinError::InvalidArgument(format!(
                "{field} has an empty entry"
            )));
        }
        out.extend(string_arg(field, entry)?);
    }
    out.push(0);
    if list.is_empty() {
        // An empty list is two NULs, never one.
        out.push(0);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Handles and buffers
// ---------------------------------------------------------------------------------------------

/// Owns one non-null `SC_HANDLE` (manager or service) and closes it on drop.
struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenSCManagerW / OpenServiceW / CreateServiceW, is non-null, is
        // owned by this guard alone and is closed exactly once.
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn open_manager(access: u32) -> Result<ScHandle, WinError> {
    // SAFETY: null machine and database name select the local active database.
    let h = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), access) };
    if h.is_null() {
        return Err(WinError::Api {
            call: "OpenSCManagerW",
            error: Win32Error::last(),
        });
    }
    Ok(ScHandle(h))
}

/// `OpenServiceW`; the error is the raw Win32 code so callers can tell "does not exist" apart.
fn open_service(mgr: &ScHandle, name: &[u16], access: u32) -> Result<ScHandle, u32> {
    // SAFETY: `mgr` is a live manager handle; `name` is NUL-terminated.
    let h = unsafe { OpenServiceW(mgr.0, name.as_ptr(), access) };
    if h.is_null() {
        return Err(Win32Error::last().code());
    }
    Ok(ScHandle(h))
}

/// Frees a `LocalAlloc` block on drop.
struct LocalMem(*mut c_void);

impl Drop for LocalMem {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API that documents LocalFree as its deallocator and is
            // freed exactly once.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// A zeroed, 8-byte aligned byte buffer of `len` bytes.
struct AlignedBuf {
    words: Vec<u64>,
    len: usize,
}

impl AlignedBuf {
    fn new(len: usize) -> AlignedBuf {
        AlignedBuf {
            words: vec![0u64; len.div_ceil(8)],
            len,
        }
    }

    /// Null for an empty buffer, so the first needed-size call passes `(NULL, 0)`.
    fn as_mut_ptr(&mut self) -> *mut u8 {
        if self.len == 0 {
            ptr::null_mut()
        } else {
            self.words.as_mut_ptr().cast()
        }
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: `words` holds at least `len` initialised bytes (len.div_ceil(8) words); u8 has no
        // alignment requirement; the slice borrows `self`.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.len) }
    }
}

/// Why the needed-size loop stopped.
#[derive(Debug, PartialEq, Eq)]
enum SizedError {
    /// The API failed with this code (not a buffer-size answer).
    Api(u32),
    /// The API asked for more than the cap.
    TooLarge(u32),
    /// The API kept answering "too small" without a usable size.
    NoProgress(u32),
}

/// Calls `f(buffer, size, &mut needed)` first with `(NULL, 0)`, then with a buffer of the size the API
/// asked for, up to [`SIZE_ATTEMPTS`] times. `f` returns `Err(GetLastError())` when the API fails. An
/// answer over `cap` is [`SizedError::TooLarge`] and nothing is allocated for it.
fn sized_query<F>(cap: u32, mut f: F) -> Result<AlignedBuf, SizedError>
where
    F: FnMut(*mut u8, u32, &mut u32) -> Result<(), u32>,
{
    let mut buf = AlignedBuf::new(0);
    let mut last = 0u32;
    for _ in 0..SIZE_ATTEMPTS {
        let mut needed = 0u32;
        let size = u32::try_from(buf.len).map_err(|_| SizedError::TooLarge(u32::MAX))?;
        match f(buf.as_mut_ptr(), size, &mut needed) {
            Ok(()) => return Ok(buf),
            Err(code) if code == ERROR_INSUFFICIENT_BUFFER || code == ERROR_MORE_DATA => {
                if needed > cap {
                    return Err(SizedError::TooLarge(needed));
                }
                if needed as usize <= buf.len {
                    return Err(SizedError::NoProgress(code));
                }
                last = code;
                buf = AlignedBuf::new(needed as usize);
            }
            Err(code) => return Err(SizedError::Api(code)),
        }
    }
    Err(SizedError::NoProgress(last))
}

fn sized_error(call: &'static str, e: SizedError) -> WinError {
    match e {
        SizedError::Api(code) | SizedError::NoProgress(code) => api(call, code),
        SizedError::TooLarge(needed) => WinError::BufferTooLarge { call, needed },
    }
}

/// Plain-old-data types [`View::read`] may produce from arbitrary bytes.
///
/// # Safety
/// Every bit pattern of `size_of::<Self>()` bytes must be a valid value (integers and raw pointers only).
unsafe trait Pod: Copy {}
// SAFETY: integers.
unsafe impl Pod for u32 {}
// SAFETY: integers.
unsafe impl Pod for i32 {}
// SAFETY: integers and raw pointers only.
unsafe impl Pod for QUERY_SERVICE_CONFIGW {}
// SAFETY: a raw pointer.
unsafe impl Pod for SERVICE_DESCRIPTIONW {}
// SAFETY: integers and raw pointers only.
unsafe impl Pod for SERVICE_FAILURE_ACTIONSW {}
// SAFETY: integers.
unsafe impl Pod for SC_ACTION {}
// SAFETY: a raw pointer.
unsafe impl Pod for SERVICE_REQUIRED_PRIVILEGES_INFOW {}
// SAFETY: integers and raw pointers only.
unsafe impl Pod for SERVICE_TRIGGER_INFO {}
// SAFETY: integers and raw pointers only.
unsafe impl Pod for SERVICE_TRIGGER {}
// SAFETY: integers and raw pointers only.
unsafe impl Pod for SERVICE_TRIGGER_SPECIFIC_DATA_ITEM {}

/// A bounds-checked view of a buffer an API filled: every pointer read from it must point inside it.
struct View<'a> {
    bytes: &'a [u8],
}

type Bad = &'static str;

impl<'a> View<'a> {
    fn new(bytes: &'a [u8]) -> View<'a> {
        View { bytes }
    }

    fn base(&self) -> usize {
        self.bytes.as_ptr() as usize
    }

    /// The `T` at byte offset `off`.
    fn read<T: Pod>(&self, off: usize) -> Result<T, Bad> {
        let end = off.checked_add(size_of::<T>()).ok_or("offset overflows")?;
        if end > self.bytes.len() {
            return Err("structure runs past the end of the buffer");
        }
        // SAFETY: `off..end` lies inside the slice; T is Pod (any bit pattern is valid); the read is
        // unaligned-safe.
        Ok(unsafe { ptr::read_unaligned(self.bytes.as_ptr().add(off).cast::<T>()) })
    }

    /// Offset of pointer `p` inside the buffer; `None` for null.
    fn offset(&self, p: usize) -> Result<Option<usize>, Bad> {
        if p == 0 {
            return Ok(None);
        }
        let base = self.base();
        if p < base || p - base >= self.bytes.len() {
            return Err("pointer outside the returned buffer");
        }
        Ok(Some(p - base))
    }

    /// The NUL-terminated UTF-16 string at `off` and the offset just past its terminator.
    fn wstr_at(&self, off: usize) -> Result<(String, usize), Bad> {
        let mut units = Vec::new();
        let mut i = off;
        loop {
            let pair = self
                .bytes
                .get(i..i + 2)
                .ok_or("string without terminator inside the buffer")?;
            let u = u16::from_le_bytes([pair[0], pair[1]]);
            i += 2;
            if u == 0 {
                break;
            }
            units.push(u);
        }
        let s = String::from_utf16(&units).map_err(|_| "string is not valid UTF-16")?;
        Ok((s, i))
    }

    fn wstr(&self, p: *const u16) -> Result<Option<String>, Bad> {
        match self.offset(p as usize)? {
            None => Ok(None),
            Some(off) => self.wstr_at(off).map(|(s, _)| Some(s)),
        }
    }

    /// A double-NUL-terminated list; `None` for null.
    fn multi_sz(&self, p: *const u16) -> Result<Option<Vec<String>>, Bad> {
        let Some(mut off) = self.offset(p as usize)? else {
            return Ok(None);
        };
        let mut out = Vec::new();
        loop {
            let (s, next) = self.wstr_at(off)?;
            if s.is_empty() {
                return Ok(Some(out));
            }
            out.push(s);
            off = next;
        }
    }

    /// `n` bytes at `p`; zero bytes need no pointer.
    fn bytes_at(&self, p: *const u8, n: usize) -> Result<Vec<u8>, Bad> {
        if n == 0 {
            return Ok(Vec::new());
        }
        let off = self
            .offset(p as usize)?
            .ok_or("null pointer with a length")?;
        let end = off.checked_add(n).ok_or("length overflows")?;
        self.bytes
            .get(off..end)
            .map(<[u8]>::to_vec)
            .ok_or("data runs past the end of the buffer")
    }

    /// `count` elements at `p`; zero elements need no pointer.
    fn array<T: Pod>(&self, p: *const T, count: usize) -> Result<Vec<T>, Bad> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let off = self
            .offset(p as usize)?
            .ok_or("null pointer with a count")?;
        let total = count
            .checked_mul(size_of::<T>())
            .and_then(|n| off.checked_add(n))
            .ok_or("count overflows")?;
        if total > self.bytes.len() {
            return Err("array runs past the end of the buffer");
        }
        (0..count)
            .map(|i| self.read(off + i * size_of::<T>()))
            .collect()
    }
}

// ---------------------------------------------------------------------------------------------
// Parsing (pure: buffer in, value out)
// ---------------------------------------------------------------------------------------------

fn non_empty(s: Option<String>) -> Option<String> {
    s.filter(|s| !s.is_empty())
}

fn parse_config(v: &View<'_>) -> Result<ScmConfig, Bad> {
    let q: QUERY_SERVICE_CONFIGW = v.read(0)?;
    Ok(ScmConfig {
        service_type: q.dwServiceType,
        start_type: q.dwStartType,
        error_control: q.dwErrorControl,
        binary_path: v.wstr(q.lpBinaryPathName)?.unwrap_or_default(),
        load_order_group: non_empty(v.wstr(q.lpLoadOrderGroup)?),
        tag_id: q.dwTagId,
        dependencies: v.multi_sz(q.lpDependencies)?.unwrap_or_default(),
        service_start_name: non_empty(v.wstr(q.lpServiceStartName)?),
        display_name: non_empty(v.wstr(q.lpDisplayName)?),
    })
}

fn parse_description(v: &View<'_>) -> Result<Option<String>, Bad> {
    let d: SERVICE_DESCRIPTIONW = v.read(0)?;
    v.wstr(d.lpDescription)
}

fn parse_failure_actions(v: &View<'_>) -> Result<FailureActions, Bad> {
    let f: SERVICE_FAILURE_ACTIONSW = v.read(0)?;
    let actions = v
        .array(f.lpsaActions, f.cActions as usize)?
        .into_iter()
        .map(|a: SC_ACTION| FailureAction {
            action_type: a.Type as u32,
            delay_ms: a.Delay,
        })
        .collect();
    Ok(FailureActions {
        reset_period: f.dwResetPeriod,
        reboot_msg: v.wstr(f.lpRebootMsg)?,
        command: v.wstr(f.lpCommand)?,
        actions,
    })
}

fn parse_bool(v: &View<'_>) -> Result<bool, Bad> {
    v.read::<i32>(0).map(|b| b != 0)
}

fn parse_u32(v: &View<'_>) -> Result<u32, Bad> {
    v.read::<u32>(0)
}

fn parse_privileges(v: &View<'_>) -> Result<Option<Vec<String>>, Bad> {
    let p: SERVICE_REQUIRED_PRIVILEGES_INFOW = v.read(0)?;
    v.multi_sz(p.pmszRequiredPrivileges)
}

fn parse_triggers(v: &View<'_>) -> Result<Vec<ScmTrigger>, Bad> {
    let info: SERVICE_TRIGGER_INFO = v.read(0)?;
    let mut out = Vec::new();
    for t in v.array(info.pTriggers, info.cTriggers as usize)? {
        let t: SERVICE_TRIGGER = t;
        let subtype = if t.pTriggerSubtype.is_null() {
            None
        } else {
            let b = v.bytes_at(t.pTriggerSubtype.cast(), 16)?;
            let arr: [u8; 16] = b.try_into().map_err(|_| "subtype is not 16 bytes")?;
            Some(ScmGuid(arr))
        };
        let mut data = Vec::new();
        for item in v.array(t.pDataItems, t.cDataItems as usize)? {
            let item: SERVICE_TRIGGER_SPECIFIC_DATA_ITEM = item;
            data.push(TriggerDataItem {
                data_type: item.dwDataType,
                bytes: v.bytes_at(item.pData, item.cbData as usize)?,
            });
        }
        out.push(ScmTrigger {
            trigger_type: t.dwTriggerType,
            action: t.dwAction,
            subtype,
            data,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------------
// Query (feature read)
// ---------------------------------------------------------------------------------------------

/// Reads one service: configuration, the config2 items, SDDL (owner, group, DACL) and status.
/// `Ok(None)` when no service has this name. The handle is opened with
/// `SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL`; a caller that may not read the
/// security descriptor gets an access-denied [`WinError::Api`].
pub fn query(name: &str) -> Result<Option<ScmService>, WinError> {
    let wname = service_name_arg(name)?;
    let mgr = open_manager(SC_MANAGER_CONNECT)?;
    let svc = match open_service(
        &mgr,
        &wname,
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | READ_CONTROL,
    ) {
        Ok(h) => h,
        Err(ERROR_SERVICE_DOES_NOT_EXIST) => return Ok(None),
        Err(code) => return Err(api("OpenServiceW", code)),
    };

    const CONFIG: &str = "QueryServiceConfigW";
    let buf = sized_query(BUFFER_CAP, |p, n, needed| {
        // SAFETY: `svc` is live; `p` is null with `n` 0 or an 8-byte aligned buffer of `n` bytes.
        let ok = unsafe { QueryServiceConfigW(svc.0, p.cast(), n, needed) };
        if ok == 0 {
            Err(Win32Error::last().code())
        } else {
            Ok(())
        }
    })
    .map_err(|e| sized_error(CONFIG, e))?;
    let config = parse_config(&View::new(buf.bytes()))
        .map_err(|what| WinError::Malformed { call: CONFIG, what })?;

    let config2 = ScmConfig2 {
        description: config2(&svc, Config2Kind::Description, parse_description)?.flatten(),
        failure_actions: config2(&svc, Config2Kind::FailureActions, parse_failure_actions)?,
        delayed_auto_start: config2(&svc, Config2Kind::DelayedAutoStart, parse_bool)?,
        failure_actions_flag: config2(&svc, Config2Kind::FailureActionsFlag, parse_bool)?,
        service_sid_type: config2(&svc, Config2Kind::ServiceSidType, parse_u32)?,
        required_privileges: config2(&svc, Config2Kind::RequiredPrivileges, parse_privileges)?
            .flatten(),
        preshutdown_timeout_ms: config2(&svc, Config2Kind::PreshutdownTimeout, parse_u32)?,
        triggers: config2(&svc, Config2Kind::Triggers, parse_triggers)?,
        launch_protected: config2(&svc, Config2Kind::LaunchProtected, parse_u32)?,
    };

    let status = status_of(&svc).map_err(|code| api("QueryServiceStatusEx", code))?;
    let sddl = sddl_of(&svc)?;
    Ok(Some(ScmService {
        name: name.to_owned(),
        config,
        config2,
        sddl,
        status,
    }))
}

/// One `QueryServiceConfig2W` level; `Ok(None)` when the OS does not support the level.
fn config2<T>(
    svc: &ScHandle,
    kind: Config2Kind,
    parse: impl Fn(&View<'_>) -> Result<T, Bad>,
) -> Result<Option<T>, WinError> {
    const CALL: &str = "QueryServiceConfig2W";
    let level = kind.level();
    let buf = match sized_query(BUFFER_CAP, |p, n, needed| {
        // SAFETY: `svc` is live; `p` is null with `n` 0 or an 8-byte aligned buffer of `n` bytes.
        let ok = unsafe { QueryServiceConfig2W(svc.0, level, p, n, needed) };
        if ok == 0 {
            Err(Win32Error::last().code())
        } else {
            Ok(())
        }
    }) {
        Ok(buf) => buf,
        Err(SizedError::Api(code))
            if code == ERROR_INVALID_LEVEL || code == ERROR_NOT_SUPPORTED =>
        {
            return Ok(None);
        }
        Err(e) => return Err(sized_error(CALL, e)),
    };
    parse(&View::new(buf.bytes()))
        .map(Some)
        .map_err(|what| WinError::Malformed { call: CALL, what })
}

/// `QueryServiceStatusEx(SC_STATUS_PROCESS_INFO)`; the error is the raw Win32 code.
fn status_of(svc: &ScHandle) -> Result<ScmStatus, u32> {
    let mut s = SERVICE_STATUS_PROCESS::default();
    let mut needed = 0u32;
    // SAFETY: `svc` is live; the buffer is one SERVICE_STATUS_PROCESS of the stated size.
    let ok = unsafe {
        QueryServiceStatusEx(
            svc.0,
            SC_STATUS_PROCESS_INFO,
            (&mut s as *mut SERVICE_STATUS_PROCESS).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(Win32Error::last().code());
    }
    Ok(ScmStatus::from(s))
}

/// Owner, group and DACL as SDDL.
fn sddl_of(svc: &ScHandle) -> Result<String, WinError> {
    const CALL: &str = "QueryServiceObjectSecurity";
    let info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut buf = sized_query(BUFFER_CAP, |p, n, needed| {
        // SAFETY: `svc` is live (opened with READ_CONTROL); `p` is null with `n` 0 or a buffer of `n`
        // bytes.
        let ok = unsafe { QueryServiceObjectSecurity(svc.0, info, p.cast(), n, needed) };
        if ok == 0 {
            Err(Win32Error::last().code())
        } else {
            Ok(())
        }
    })
    .map_err(|e| sized_error(CALL, e))?;
    if buf.len == 0 {
        return Err(WinError::Malformed {
            call: CALL,
            what: "empty security descriptor",
        });
    }
    let psd: *mut c_void = buf.as_mut_ptr().cast();
    // SAFETY: `psd` points to the self-relative descriptor the call wrote into `buf`, alive here.
    if unsafe { IsValidSecurityDescriptor(psd) } == 0 {
        return Err(WinError::Malformed {
            call: CALL,
            what: "invalid security descriptor",
        });
    }
    let mut text: *mut u16 = ptr::null_mut();
    let mut text_len = 0u32;
    // SAFETY: valid descriptor (checked above); `text` receives a LocalAlloc string of `text_len`
    // units.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            info,
            &mut text,
            &mut text_len,
        )
    };
    if ok == 0 {
        return Err(WinError::Api {
            call: "ConvertSecurityDescriptorToStringSecurityDescriptorW",
            error: Win32Error::last(),
        });
    }
    let mem = LocalMem(text.cast());
    if mem.0.is_null() {
        return Err(WinError::Malformed {
            call: "ConvertSecurityDescriptorToStringSecurityDescriptorW",
            what: "null string",
        });
    }
    // SAFETY: on success `text` points to `text_len` readable UTF-16 units (terminator included),
    // alive until `mem` drops.
    let units = unsafe { std::slice::from_raw_parts(mem.0 as *const u16, text_len as usize) };
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    String::from_utf16(&units[..end]).map_err(|_| WinError::Malformed {
        call: "ConvertSecurityDescriptorToStringSecurityDescriptorW",
        what: "SDDL is not valid UTF-16",
    })
}

// ---------------------------------------------------------------------------------------------
// Delete (feature write)
// ---------------------------------------------------------------------------------------------

/// What [`delete`] achieved.
#[cfg(feature = "write")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScmDelete {
    /// The service is gone: after `DeleteService` and the close of the deleter's own handle it can no
    /// longer be opened.
    Deleted,
    /// The service is marked for delete: some other handle still holds it open (or it was already
    /// marked). It disappears when the last handle closes, at the latest at the next restart; until
    /// then `DeleteFlag` is 1 in its key and [`create`] with its name fails with
    /// [`WinError::MarkedForDelete`]. Also returned when the re-open check fails with an error other
    /// than "does not exist": the caller verifies through the registry.
    Marked,
}

/// The calls [`delete`] makes, so tests can drive it with a simulated SCM. `Svc` is an RAII handle:
/// dropping it closes the handle.
#[cfg(feature = "write")]
trait DeleteOps {
    type Svc;
    fn open(&mut self, name: &[u16], access: u32) -> Result<Self::Svc, u32>;
    fn status(&mut self, svc: &Self::Svc) -> Result<ScmStatus, u32>;
    fn delete(&mut self, svc: &Self::Svc) -> Result<(), u32>;
}

#[cfg(feature = "write")]
struct LiveOps {
    mgr: ScHandle,
}

#[cfg(feature = "write")]
impl DeleteOps for LiveOps {
    type Svc = ScHandle;

    fn open(&mut self, name: &[u16], access: u32) -> Result<ScHandle, u32> {
        open_service(&self.mgr, name, access)
    }

    fn status(&mut self, svc: &ScHandle) -> Result<ScmStatus, u32> {
        status_of(svc)
    }

    fn delete(&mut self, svc: &ScHandle) -> Result<(), u32> {
        // SAFETY: `svc` is a live service handle opened with DELETE.
        if unsafe { DeleteService(svc.0) } == 0 {
            return Err(Win32Error::last().code());
        }
        Ok(())
    }
}

/// Deletes a stopped, plain Win32 service. Never stops anything: a service in any state other than
/// `SERVICE_STOPPED` is [`WinError::InUse`] and `DeleteService` is not called. A missing service is
/// [`WinError::NotFound`]. See [`ScmDelete`] for the two outcomes.
#[cfg(feature = "write")]
pub fn delete(name: &str) -> Result<ScmDelete, WinError> {
    let wname = service_name_arg(name)?;
    let mut ops = LiveOps {
        mgr: open_manager(SC_MANAGER_CONNECT)?,
    };
    delete_with(&mut ops, &wname)
}

#[cfg(feature = "write")]
fn delete_with<O: DeleteOps>(ops: &mut O, wname: &[u16]) -> Result<ScmDelete, WinError> {
    let svc = match ops.open(wname, DELETE | SERVICE_QUERY_STATUS) {
        Ok(h) => h,
        Err(ERROR_SERVICE_DOES_NOT_EXIST) => return Err(WinError::NotFound),
        Err(code) => return Err(api("OpenServiceW", code)),
    };
    let status = ops
        .status(&svc)
        .map_err(|code| api("QueryServiceStatusEx", code))?;
    if !is_plain_win32_service(status.service_type) {
        return Err(WinError::Refused(format!(
            "service type {:#x} is not a plain Win32 service",
            status.service_type
        )));
    }
    if !status.is_stopped() {
        return Err(WinError::InUse {
            state: status.current_state,
        });
    }
    let already_marked = match ops.delete(&svc) {
        Ok(()) => false,
        Err(ERROR_SERVICE_MARKED_FOR_DELETE) => true,
        Err(code) => return Err(api("DeleteService", code)),
    };
    // Our own handle keeps a deleted service alive (spike): close it before looking again.
    drop(svc);
    if already_marked {
        return Ok(ScmDelete::Marked);
    }
    match ops.open(wname, SERVICE_QUERY_STATUS) {
        Ok(again) => {
            drop(again);
            Ok(ScmDelete::Marked)
        }
        Err(ERROR_SERVICE_DOES_NOT_EXIST) => Ok(ScmDelete::Deleted),
        Err(_) => Ok(ScmDelete::Marked),
    }
}

// ---------------------------------------------------------------------------------------------
// Create (feature write)
// ---------------------------------------------------------------------------------------------

/// The arguments of [`create`]. There is no password field: the password is always null.
#[cfg(feature = "write")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScmCreate {
    /// The service (key) name.
    pub name: String,
    /// The display name; `None` passes null. Pass `None` when the key backup has no `DisplayName`.
    pub display_name: Option<String>,
    /// `SERVICE_WIN32_OWN_PROCESS` or `SERVICE_WIN32_SHARE_PROCESS` (optionally with
    /// `SERVICE_INTERACTIVE_PROCESS`); anything else is refused.
    pub service_type: u32,
    /// `SERVICE_AUTO_START`, `SERVICE_DEMAND_START` or `SERVICE_DISABLED`; anything else is refused.
    pub start_type: u32,
    /// `SERVICE_ERROR_IGNORE` .. `SERVICE_ERROR_CRITICAL` (0..=3).
    pub error_control: u32,
    /// The **raw** `ImagePath` string of the key backup (`REG_EXPAND_SZ` not expanded), not the
    /// expanded [`ScmConfig::binary_path`] of a query.
    pub binary_path: String,
    /// The load order group; `None` (or empty) passes null.
    pub load_order_group: Option<String>,
    /// Dependencies (service names, `+`group names); empty passes null.
    pub dependencies: Vec<String>,
    /// The account; `None` passes null (LocalSystem).
    pub service_start_name: Option<String>,
}

/// The checked, NUL-terminated UTF-16 arguments of `CreateServiceW`.
#[cfg(feature = "write")]
#[derive(Debug)]
struct CreateArgs {
    name: Vec<u16>,
    display_name: Option<Vec<u16>>,
    binary_path: Vec<u16>,
    load_order_group: Option<Vec<u16>>,
    dependencies: Option<Vec<u16>>,
    service_start_name: Option<Vec<u16>>,
}

#[cfg(feature = "write")]
impl CreateArgs {
    fn build(def: &ScmCreate) -> Result<CreateArgs, WinError> {
        let name = service_name_arg(&def.name)?;
        if !is_plain_win32_service(def.service_type) {
            return Err(WinError::Refused(format!(
                "service type {:#x} is not a plain Win32 service",
                def.service_type
            )));
        }
        if ![SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_DISABLED].contains(&def.start_type) {
            return Err(WinError::Refused(format!(
                "start type {} is not auto, demand or disabled",
                def.start_type
            )));
        }
        if def.error_control > 3 {
            return Err(WinError::InvalidArgument(format!(
                "error control {} is not 0..=3",
                def.error_control
            )));
        }
        if def.binary_path.is_empty() {
            return Err(WinError::InvalidArgument("empty binary path".into()));
        }
        let binary_path = string_arg("binary path", &def.binary_path)?;
        let display_name = match &def.display_name {
            None => None,
            Some(d) if d.is_empty() || d.encode_utf16().count() > MAX_NAME_UNITS => {
                return Err(WinError::InvalidArgument(format!(
                    "display name {d:?} is empty or longer than {MAX_NAME_UNITS} units"
                )));
            }
            Some(d) => Some(string_arg("display name", d)?),
        };
        let load_order_group = match def.load_order_group.as_deref() {
            None | Some("") => None,
            Some(g) => Some(string_arg("load order group", g)?),
        };
        let dependencies = if def.dependencies.is_empty() {
            None
        } else {
            Some(multi_sz_arg("dependencies", &def.dependencies)?)
        };
        let service_start_name = match def.service_start_name.as_deref() {
            None => None,
            Some("") => {
                return Err(WinError::InvalidArgument(
                    "empty account name (pass None for LocalSystem)".into(),
                ));
            }
            Some(a) => Some(string_arg("account", a)?),
        };
        Ok(CreateArgs {
            name,
            display_name,
            binary_path,
            load_order_group,
            dependencies,
            service_start_name,
        })
    }
}

#[cfg(feature = "write")]
fn opt_ptr(v: &Option<Vec<u16>>) -> *const u16 {
    v.as_ref().map_or(ptr::null(), |v| v.as_ptr())
}

/// Creates a service from a backed-up definition. The new service is never started; its start type is
/// the one given. The password is always null, so an account with a stored password needs it set by
/// the user afterwards. The config2 items and the DACL are separate calls ([`set_config2`],
/// [`set_security`]).
#[cfg(feature = "write")]
pub fn create(def: &ScmCreate) -> Result<(), WinError> {
    let args = CreateArgs::build(def)?;
    let mgr = open_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    // SAFETY: `mgr` is live; every string is NUL-terminated (the dependency list double-NUL
    // terminated) or null; no tag id is requested; the password is null.
    let h = unsafe {
        CreateServiceW(
            mgr.0,
            args.name.as_ptr(),
            opt_ptr(&args.display_name),
            SERVICE_QUERY_STATUS,
            def.service_type,
            def.start_type,
            def.error_control,
            args.binary_path.as_ptr(),
            opt_ptr(&args.load_order_group),
            ptr::null_mut(),
            opt_ptr(&args.dependencies),
            opt_ptr(&args.service_start_name),
            ptr::null(),
        )
    };
    if h.is_null() {
        let code = Win32Error::last().code();
        return Err(match code {
            ERROR_SERVICE_EXISTS => WinError::Exists,
            ERROR_SERVICE_MARKED_FOR_DELETE => WinError::MarkedForDelete,
            ERROR_DUPLICATE_SERVICE_NAME => WinError::DuplicateName,
            _ => api("CreateServiceW", code),
        });
    }
    drop(ScHandle(h));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Config2 (feature write)
// ---------------------------------------------------------------------------------------------

/// The info structure one `ChangeServiceConfig2W` call points at.
#[cfg(feature = "write")]
enum Info {
    Description(Box<SERVICE_DESCRIPTIONW>),
    Failure(Box<SERVICE_FAILURE_ACTIONSW>),
    /// Every one-DWORD structure (delayed start and failure flag as BOOL, SID type, preshutdown,
    /// launch protection).
    Dword(Box<u32>),
    Privileges(Box<SERVICE_REQUIRED_PRIVILEGES_INFOW>),
    Triggers(Box<SERVICE_TRIGGER_INFO>),
}

/// A built `ChangeServiceConfig2W` argument and all the memory its pointers reach. Pointers go only to
/// heap blocks (boxes and vector contents) that are never touched again, so moving this value keeps
/// them valid.
#[cfg(feature = "write")]
struct Config2Arg {
    kind: Config2Kind,
    info: Info,
    needs_start_access: bool,
    _strings: Vec<Vec<u16>>,
    _actions: Vec<SC_ACTION>,
    _guids: Vec<GUID>,
    _bytes: Vec<Vec<u8>>,
    _items: Vec<Vec<SERVICE_TRIGGER_SPECIFIC_DATA_ITEM>>,
    _triggers: Vec<SERVICE_TRIGGER>,
}

#[cfg(feature = "write")]
impl Config2Arg {
    fn new(kind: Config2Kind, info: Info) -> Config2Arg {
        Config2Arg {
            kind,
            info,
            needs_start_access: false,
            _strings: Vec::new(),
            _actions: Vec::new(),
            _guids: Vec::new(),
            _bytes: Vec::new(),
            _items: Vec::new(),
            _triggers: Vec::new(),
        }
    }

    fn info_ptr(&self) -> *const c_void {
        match &self.info {
            Info::Description(b) => (&**b as *const SERVICE_DESCRIPTIONW).cast(),
            Info::Failure(b) => (&**b as *const SERVICE_FAILURE_ACTIONSW).cast(),
            Info::Dword(b) => (&**b as *const u32).cast(),
            Info::Privileges(b) => (&**b as *const SERVICE_REQUIRED_PRIVILEGES_INFOW).cast(),
            Info::Triggers(b) => (&**b as *const SERVICE_TRIGGER_INFO).cast(),
        }
    }

    fn build(item: &Config2Item) -> Result<Config2Arg, WinError> {
        let kind = item.kind();
        let dword = |v: u32| -> Result<Config2Arg, WinError> {
            Ok(Config2Arg::new(kind, Info::Dword(Box::new(v))))
        };
        match item {
            Config2Item::Description(s) => {
                let mut text = string_arg("description", s)?;
                let info = SERVICE_DESCRIPTIONW {
                    lpDescription: text.as_mut_ptr(),
                };
                let mut arg = Config2Arg::new(kind, Info::Description(Box::new(info)));
                arg._strings.push(text);
                Ok(arg)
            }
            Config2Item::FailureActions(fa) => Config2Arg::failure_actions(fa),
            Config2Item::FailureActionsFlag(b) | Config2Item::DelayedAutoStart(b) => {
                dword(u32::from(*b))
            }
            Config2Item::ServiceSidType(v) | Config2Item::PreshutdownTimeout(v) => dword(*v),
            Config2Item::LaunchProtected(0) => Err(WinError::NotSettable {
                item: kind.name(),
                reason: "launch protection 0 is refused by the SCM (error 2) and is the default",
            }),
            Config2Item::LaunchProtected(v) => dword(*v),
            Config2Item::RequiredPrivileges(list) => {
                let mut text = multi_sz_arg("required privileges", list)?;
                let info = SERVICE_REQUIRED_PRIVILEGES_INFOW {
                    pmszRequiredPrivileges: text.as_mut_ptr(),
                };
                let mut arg = Config2Arg::new(kind, Info::Privileges(Box::new(info)));
                arg._strings.push(text);
                Ok(arg)
            }
            Config2Item::Triggers(list) => Config2Arg::triggers(list),
        }
    }

    fn failure_actions(fa: &FailureActions) -> Result<Config2Arg, WinError> {
        let count = u32::try_from(fa.actions.len())
            .map_err(|_| WinError::InvalidArgument("too many failure actions".into()))?;
        let mut strings = Vec::new();
        let mut opt = |field: &str, s: &Option<String>| -> Result<*mut u16, WinError> {
            match s {
                None => Ok(ptr::null_mut()),
                Some(s) => {
                    let mut w = string_arg(field, s)?;
                    let p = w.as_mut_ptr();
                    strings.push(w);
                    Ok(p)
                }
            }
        };
        let reboot = opt("reboot message", &fa.reboot_msg)?;
        let command = opt("failure command", &fa.command)?;
        let mut actions: Vec<SC_ACTION> = fa
            .actions
            .iter()
            .map(|a| SC_ACTION {
                Type: a.action_type as i32,
                Delay: a.delay_ms,
            })
            .collect();
        // A non-null array even for zero actions, as the spike passed it.
        if actions.is_empty() {
            actions.reserve(1);
        }
        let info = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: fa.reset_period,
            lpRebootMsg: reboot,
            lpCommand: command,
            cActions: count,
            lpsaActions: actions.as_mut_ptr(),
        };
        let needs_start_access = fa.actions.iter().any(|a| {
            a.action_type == SC_ACTION_RESTART as u32
                || a.action_type == SC_ACTION_OWN_RESTART as u32
        });
        let mut arg = Config2Arg::new(Config2Kind::FailureActions, Info::Failure(Box::new(info)));
        arg.needs_start_access = needs_start_access;
        arg._strings = strings;
        arg._actions = actions;
        Ok(arg)
    }

    fn triggers(list: &[ScmTrigger]) -> Result<Config2Arg, WinError> {
        if list.is_empty() {
            return Err(WinError::NotSettable {
                item: Config2Kind::Triggers.name(),
                reason: "an empty trigger list is refused by the SCM (error 87) and is the default",
            });
        }
        let too_many = || WinError::InvalidArgument("trigger list too large".into());
        let count = u32::try_from(list.len()).map_err(|_| too_many())?;
        // All subtypes first, so the vector never grows after pointers into it are taken.
        let mut guids: Vec<GUID> = list
            .iter()
            .filter_map(|t| t.subtype.map(ScmGuid::to_guid))
            .collect();
        let mut guid_ptrs = guids.iter_mut().map(|g| g as *mut GUID);
        let mut bytes = Vec::new();
        let mut items_all = Vec::new();
        let mut triggers = Vec::with_capacity(list.len());
        for t in list {
            let subtype: *mut GUID = match t.subtype {
                None => ptr::null_mut(),
                Some(_) => guid_ptrs.next().ok_or_else(|| {
                    WinError::InvalidArgument("trigger subtype count mismatch".into())
                })?,
            };
            let mut items = Vec::with_capacity(t.data.len());
            for d in &t.data {
                let cb = u32::try_from(d.bytes.len()).map_err(|_| too_many())?;
                let mut data = d.bytes.clone();
                let p = if data.is_empty() {
                    ptr::null_mut()
                } else {
                    data.as_mut_ptr()
                };
                bytes.push(data);
                items.push(SERVICE_TRIGGER_SPECIFIC_DATA_ITEM {
                    dwDataType: d.data_type,
                    cbData: cb,
                    pData: p,
                });
            }
            let item_count = u32::try_from(items.len()).map_err(|_| too_many())?;
            let items_ptr = if items.is_empty() {
                ptr::null_mut()
            } else {
                items.as_mut_ptr()
            };
            items_all.push(items);
            triggers.push(SERVICE_TRIGGER {
                dwTriggerType: t.trigger_type,
                dwAction: t.action,
                pTriggerSubtype: subtype,
                cDataItems: item_count,
                pDataItems: items_ptr,
            });
        }
        drop(guid_ptrs);
        let info = SERVICE_TRIGGER_INFO {
            cTriggers: count,
            pTriggers: triggers.as_mut_ptr(),
            pReserved: ptr::null_mut(),
        };
        let mut arg = Config2Arg::new(Config2Kind::Triggers, Info::Triggers(Box::new(info)));
        arg._guids = guids;
        arg._bytes = bytes;
        arg._items = items_all;
        arg._triggers = triggers;
        Ok(arg)
    }
}

/// Sets one config2 item of an existing service (`ChangeServiceConfig2W`). The handle asks for
/// `SERVICE_CHANGE_CONFIG`, plus `SERVICE_START` access only for failure actions that restart the
/// service (the API requires that right to accept them; nothing is started). Failure actions with a
/// reboot action additionally need the caller's `SeShutdownPrivilege` enabled, which this module never
/// enables: without it the SCM's error is returned.
#[cfg(feature = "write")]
pub fn set_config2(name: &str, item: Config2Item) -> Result<(), WinError> {
    let wname = service_name_arg(name)?;
    let arg = Config2Arg::build(&item)?;
    let mut access = SERVICE_CHANGE_CONFIG;
    if arg.needs_start_access {
        access |= SERVICE_START;
    }
    let mgr = open_manager(SC_MANAGER_CONNECT)?;
    let svc = match open_service(&mgr, &wname, access) {
        Ok(h) => h,
        Err(ERROR_SERVICE_DOES_NOT_EXIST) => return Err(WinError::NotFound),
        Err(code) => return Err(api("OpenServiceW", code)),
    };
    // SAFETY: `svc` is live with SERVICE_CHANGE_CONFIG; `info_ptr` points to the level's structure,
    // whose pointers all reach memory owned by `arg`, alive for the call.
    let ok = unsafe { ChangeServiceConfig2W(svc.0, arg.kind.level(), arg.info_ptr()) };
    if ok == 0 {
        let code = Win32Error::last().code();
        return Err(match code {
            ERROR_SERVICE_MARKED_FOR_DELETE => WinError::MarkedForDelete,
            _ => api("ChangeServiceConfig2W", code),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Security (feature write)
// ---------------------------------------------------------------------------------------------

/// A security descriptor converted from SDDL, holding a present, non-null DACL. Freed on drop.
#[cfg(feature = "write")]
struct SddlDescriptor(LocalMem);

#[cfg(feature = "write")]
impl SddlDescriptor {
    /// Longest SDDL accepted (UTF-16 units).
    const MAX_UNITS: usize = 64 * 1024;

    fn from_sddl(sddl: &str) -> Result<SddlDescriptor, WinError> {
        if sddl.is_empty() || sddl.encode_utf16().count() > Self::MAX_UNITS {
            return Err(WinError::InvalidArgument(
                "SDDL is empty or too long".into(),
            ));
        }
        let text = string_arg("SDDL", sddl)?;
        let mut psd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `text` is NUL-terminated; `psd` receives a LocalAlloc block; the size is not wanted.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut psd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(WinError::InvalidArgument(format!(
                "SDDL does not parse: {}",
                Win32Error::last()
            )));
        }
        let sd = SddlDescriptor(LocalMem(psd));
        if sd.0.0.is_null() {
            return Err(WinError::InvalidArgument("SDDL gave no descriptor".into()));
        }
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl: *mut ACL = ptr::null_mut();
        // SAFETY: valid descriptor from the conversion; out-pointers are locals.
        if unsafe { GetSecurityDescriptorDacl(sd.0.0, &mut present, &mut dacl, &mut defaulted) }
            == 0
        {
            return Err(WinError::Api {
                call: "GetSecurityDescriptorDacl",
                error: Win32Error::last(),
            });
        }
        if present == 0 {
            return Err(WinError::InvalidArgument("SDDL has no DACL".into()));
        }
        if dacl.is_null() {
            return Err(WinError::InvalidArgument(
                "SDDL has a NULL DACL (no access control)".into(),
            ));
        }
        Ok(sd)
    }
}

/// Sets the DACL of an existing service from SDDL (`SetServiceObjectSecurity` with
/// `DACL_SECURITY_INFORMATION` only; owner, group and SACL in the string are ignored). The SDDL must
/// carry a DACL that is present and not NULL.
#[cfg(feature = "write")]
pub fn set_security(name: &str, sddl: &str) -> Result<(), WinError> {
    let wname = service_name_arg(name)?;
    let sd = SddlDescriptor::from_sddl(sddl)?;
    let mgr = open_manager(SC_MANAGER_CONNECT)?;
    let svc = match open_service(&mgr, &wname, WRITE_DAC) {
        Ok(h) => h,
        Err(ERROR_SERVICE_DOES_NOT_EXIST) => return Err(WinError::NotFound),
        Err(code) => return Err(api("OpenServiceW", code)),
    };
    // SAFETY: `svc` is live with WRITE_DAC; `sd` is a valid descriptor alive for the call.
    let ok = unsafe { SetServiceObjectSecurity(svc.0, DACL_SECURITY_INFORMATION, sd.0.0) };
    if ok == 0 {
        let code = Win32Error::last().code();
        return Err(match code {
            ERROR_SERVICE_MARKED_FOR_DELETE => WinError::MarkedForDelete,
            _ => api("SetServiceObjectSecurity", code),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- buffers -------------------------------------------------------------------------------

    #[test]
    fn oversized_buffer_answer_is_error() {
        let mut calls = 0;
        let r = sized_query(BUFFER_CAP, |p, n, needed| {
            calls += 1;
            assert!(p.is_null() && n == 0, "nothing is allocated for the answer");
            *needed = BUFFER_CAP + 1;
            Err(ERROR_INSUFFICIENT_BUFFER)
        });
        assert_eq!(r.err(), Some(SizedError::TooLarge(BUFFER_CAP + 1)));
        assert_eq!(calls, 1);
        assert_eq!(
            sized_error("X", SizedError::TooLarge(BUFFER_CAP + 1)),
            WinError::BufferTooLarge {
                call: "X",
                needed: BUFFER_CAP + 1
            }
        );
        // u32::MAX (a hostile or broken answer) as well.
        let r = sized_query(BUFFER_CAP, |_, _, needed| {
            *needed = u32::MAX;
            Err(ERROR_MORE_DATA)
        });
        assert_eq!(r.err(), Some(SizedError::TooLarge(u32::MAX)));
    }

    #[test]
    fn buffer_at_the_cap_is_allocated() {
        let mut sizes = Vec::new();
        let r = sized_query(BUFFER_CAP, |p, n, needed| {
            sizes.push(n);
            if n < BUFFER_CAP {
                *needed = BUFFER_CAP;
                return Err(ERROR_INSUFFICIENT_BUFFER);
            }
            assert!(!p.is_null());
            assert_eq!(p as usize % 8, 0, "8-byte aligned");
            Ok(())
        })
        .unwrap();
        assert_eq!(r.len, BUFFER_CAP as usize);
        assert_eq!(sizes, [0, BUFFER_CAP]);
    }

    #[test]
    fn buffer_grows_when_the_answer_grows() {
        let mut sizes = Vec::new();
        let r = sized_query(BUFFER_CAP, |_, n, needed| {
            sizes.push(n);
            match n {
                0 => {
                    *needed = 16;
                    Err(ERROR_INSUFFICIENT_BUFFER)
                }
                16 => {
                    *needed = 40;
                    Err(ERROR_INSUFFICIENT_BUFFER)
                }
                _ => Ok(()),
            }
        })
        .unwrap();
        assert_eq!(r.len, 40);
        assert_eq!(sizes, [0, 16, 40]);
    }

    #[test]
    fn buffer_loop_stops_without_progress_and_on_other_errors() {
        let r = sized_query(BUFFER_CAP, |_, n, needed| {
            *needed = n;
            Err(ERROR_INSUFFICIENT_BUFFER)
        });
        assert_eq!(
            r.err(),
            Some(SizedError::NoProgress(ERROR_INSUFFICIENT_BUFFER))
        );
        let mut calls = 0;
        let r = sized_query(BUFFER_CAP, |_, n, needed| {
            calls += 1;
            *needed = n + 8;
            Err(ERROR_INSUFFICIENT_BUFFER)
        });
        assert!(matches!(r, Err(SizedError::NoProgress(_))));
        assert_eq!(calls, SIZE_ATTEMPTS);
        let r = sized_query(BUFFER_CAP, |_, _, _| Err(5));
        assert_eq!(r.err(), Some(SizedError::Api(5)));
    }

    // --- parsing -------------------------------------------------------------------------------

    /// An 8-byte aligned scratch buffer: structures and strings are written at chosen offsets and
    /// pointers are real addresses inside it, as the SCM returns them.
    struct Synth {
        buf: AlignedBuf,
    }

    impl Synth {
        fn new(len: usize) -> Synth {
            Synth {
                buf: AlignedBuf::new(len),
            }
        }
        fn addr(&mut self, off: usize) -> usize {
            self.buf.as_mut_ptr() as usize + off
        }
        fn put<T: Copy>(&mut self, off: usize, v: T) {
            assert!(off + size_of::<T>() <= self.buf.len);
            // SAFETY: in bounds (asserted); unaligned write.
            unsafe { ptr::write_unaligned(self.buf.as_mut_ptr().add(off).cast::<T>(), v) };
        }
        fn put_bytes(&mut self, off: usize, b: &[u8]) {
            for (i, x) in b.iter().enumerate() {
                self.put(off + i, *x);
            }
        }
        /// UTF-16 + NUL at `off`; returns its address.
        fn put_str(&mut self, off: usize, s: &str) -> usize {
            let mut o = off;
            for u in s.encode_utf16().chain([0]) {
                self.put(o, u);
                o += 2;
            }
            self.addr(off)
        }
        fn view(&self) -> View<'_> {
            View::new(self.buf.bytes())
        }
    }

    #[test]
    fn parse_config_reads_every_field() {
        let mut s = Synth::new(512);
        let bin = s.put_str(100, r"%SystemRoot%\x.exe");
        let grp = s.put_str(160, "");
        // Dependencies: "RpcSs\0+Grp\0\0".
        let deps = s.put_str(200, "RpcSs");
        s.put_str(212, "+Grp");
        s.put::<u16>(222, 0);
        let acct = s.put_str(260, r"NT AUTHORITY\LocalService");
        let disp = s.put_str(320, "Display");
        s.put(
            0,
            QUERY_SERVICE_CONFIGW {
                dwServiceType: 0x10,
                dwStartType: 3,
                dwErrorControl: 1,
                lpBinaryPathName: bin as *mut u16,
                lpLoadOrderGroup: grp as *mut u16,
                dwTagId: 7,
                lpDependencies: deps as *mut u16,
                lpServiceStartName: acct as *mut u16,
                lpDisplayName: disp as *mut u16,
            },
        );
        let c = parse_config(&s.view()).unwrap();
        assert_eq!(
            c,
            ScmConfig {
                service_type: 0x10,
                start_type: 3,
                error_control: 1,
                binary_path: r"%SystemRoot%\x.exe".into(),
                load_order_group: None,
                tag_id: 7,
                dependencies: vec!["RpcSs".into(), "+Grp".into()],
                service_start_name: Some(r"NT AUTHORITY\LocalService".into()),
                display_name: Some("Display".into()),
            }
        );
    }

    #[test]
    fn parse_rejects_pointers_outside_the_buffer() {
        let mut s = Synth::new(128);
        let outside = s.addr(0) + 4096;
        s.put(
            0,
            SERVICE_DESCRIPTIONW {
                lpDescription: outside as *mut u16,
            },
        );
        assert_eq!(
            parse_description(&s.view()),
            Err("pointer outside the returned buffer")
        );
        // A pointer below the buffer.
        let below = s.addr(0).wrapping_sub(16);
        s.put(
            0,
            SERVICE_DESCRIPTIONW {
                lpDescription: below as *mut u16,
            },
        );
        assert!(parse_description(&s.view()).is_err());
    }

    #[test]
    fn parse_rejects_unterminated_and_invalid_strings() {
        let mut s = Synth::new(32);
        // "abc..." filling the buffer to its end with no NUL.
        for i in 0..12 {
            s.put::<u16>(8 + 2 * i, 0x61);
        }
        let p = s.addr(8);
        s.put(
            0,
            SERVICE_DESCRIPTIONW {
                lpDescription: p as *mut u16,
            },
        );
        assert_eq!(
            parse_description(&s.view()),
            Err("string without terminator inside the buffer")
        );
        // A lone surrogate: not repaired lossily, refused.
        s.put::<u16>(8, 0xD800);
        s.put::<u16>(10, 0);
        assert_eq!(
            parse_description(&s.view()),
            Err("string is not valid UTF-16")
        );
    }

    #[test]
    fn parse_rejects_short_buffer_and_counts_past_the_end() {
        let s = Synth::new(4);
        assert!(parse_config(&s.view()).is_err());
        let mut s = Synth::new(64);
        let arr = s.addr(40);
        s.put(
            0,
            SERVICE_FAILURE_ACTIONSW {
                dwResetPeriod: 0,
                lpRebootMsg: ptr::null_mut(),
                lpCommand: ptr::null_mut(),
                cActions: 4, // 32 bytes from offset 40: past 64
                lpsaActions: arr as *mut SC_ACTION,
            },
        );
        assert_eq!(
            parse_failure_actions(&s.view()),
            Err("array runs past the end of the buffer")
        );
        s.put(
            0,
            SERVICE_FAILURE_ACTIONSW {
                dwResetPeriod: 0,
                lpRebootMsg: ptr::null_mut(),
                lpCommand: ptr::null_mut(),
                cActions: u32::MAX,
                lpsaActions: arr as *mut SC_ACTION,
            },
        );
        assert!(parse_failure_actions(&s.view()).is_err());
    }

    #[test]
    fn parse_failure_actions_and_privileges() {
        let mut s = Synth::new(256);
        let cmd = s.put_str(100, "cmd /c x");
        let arr = s.addr(48);
        s.put(
            48,
            SC_ACTION {
                Type: 1,
                Delay: 60_000,
            },
        );
        s.put(56, SC_ACTION { Type: 0, Delay: 0 });
        s.put(
            0,
            SERVICE_FAILURE_ACTIONSW {
                dwResetPeriod: 86_400,
                lpRebootMsg: ptr::null_mut(),
                lpCommand: cmd as *mut u16,
                cActions: 2,
                lpsaActions: arr as *mut SC_ACTION,
            },
        );
        assert_eq!(
            parse_failure_actions(&s.view()).unwrap(),
            FailureActions {
                reset_period: 86_400,
                reboot_msg: None,
                command: Some("cmd /c x".into()),
                actions: vec![
                    FailureAction {
                        action_type: 1,
                        delay_ms: 60_000
                    },
                    FailureAction {
                        action_type: 0,
                        delay_ms: 0
                    },
                ],
            }
        );

        let mut s = Synth::new(128);
        let list = s.put_str(16, "SeChangeNotifyPrivilege");
        s.put::<u16>(16 + 2 * 24, 0);
        s.put(
            0,
            SERVICE_REQUIRED_PRIVILEGES_INFOW {
                pmszRequiredPrivileges: list as *mut u16,
            },
        );
        assert_eq!(
            parse_privileges(&s.view()).unwrap(),
            Some(vec!["SeChangeNotifyPrivilege".to_string()])
        );
        s.put(
            0,
            SERVICE_REQUIRED_PRIVILEGES_INFOW {
                pmszRequiredPrivileges: ptr::null_mut(),
            },
        );
        assert_eq!(parse_privileges(&s.view()).unwrap(), None);
    }

    #[test]
    fn parse_triggers_reads_subtype_and_data() {
        let guid = ScmGuid::parse("{4f27f2de-14e2-430b-a549-7cd48cbc8245}").unwrap();
        let mut s = Synth::new(512);
        let trig = s.addr(64);
        let sub = s.addr(200);
        s.put_bytes(200, &guid.0);
        let items = s.addr(240);
        let data = s.addr(300);
        s.put_bytes(300, &[1, 2, 3]);
        s.put(
            240,
            SERVICE_TRIGGER_SPECIFIC_DATA_ITEM {
                dwDataType: 1,
                cbData: 3,
                pData: data as *mut u8,
            },
        );
        s.put(
            64,
            SERVICE_TRIGGER {
                dwTriggerType: 2,
                dwAction: 1,
                pTriggerSubtype: sub as *mut GUIDBytes,
                cDataItems: 1,
                pDataItems: items as *mut SERVICE_TRIGGER_SPECIFIC_DATA_ITEM,
            },
        );
        s.put(
            0,
            SERVICE_TRIGGER_INFO {
                cTriggers: 1,
                pTriggers: trig as *mut SERVICE_TRIGGER,
                pReserved: ptr::null_mut(),
            },
        );
        assert_eq!(
            parse_triggers(&s.view()).unwrap(),
            vec![ScmTrigger {
                trigger_type: 2,
                action: 1,
                subtype: Some(guid),
                data: vec![TriggerDataItem {
                    data_type: 1,
                    bytes: vec![1, 2, 3]
                }],
            }]
        );
        // No triggers: an empty list, not None.
        s.put(
            0,
            SERVICE_TRIGGER_INFO {
                cTriggers: 0,
                pTriggers: ptr::null_mut(),
                pReserved: ptr::null_mut(),
            },
        );
        assert_eq!(parse_triggers(&s.view()).unwrap(), Vec::new());
        // A data item whose length runs past the buffer.
        s.put(
            240,
            SERVICE_TRIGGER_SPECIFIC_DATA_ITEM {
                dwDataType: 1,
                cbData: 4096,
                pData: data as *mut u8,
            },
        );
        s.put(
            0,
            SERVICE_TRIGGER_INFO {
                cTriggers: 1,
                pTriggers: trig as *mut SERVICE_TRIGGER,
                pReserved: ptr::null_mut(),
            },
        );
        assert!(parse_triggers(&s.view()).is_err());
    }

    /// The pointee type of `SERVICE_TRIGGER::pTriggerSubtype`.
    type GUIDBytes = windows_sys::core::GUID;

    #[test]
    fn guid_display_and_parse_round_trip() {
        // NETWORK_MANAGER_FIRST_IP_ADDRESS_ARRIVAL_GUID.
        let g = ScmGuid::parse("{4F27F2DE-14E2-430B-A549-7CD48CBC8245}").unwrap();
        assert_eq!(&g.0[..4], &[0xde, 0xf2, 0x27, 0x4f], "Data1 little-endian");
        assert_eq!(&g.0[8..10], &[0xa5, 0x49], "Data4 as stored");
        assert_eq!(g.to_string(), "{4f27f2de-14e2-430b-a549-7cd48cbc8245}");
        assert_eq!(
            ScmGuid::parse("4f27f2de-14e2-430b-a549-7cd48cbc8245"),
            Some(g)
        );
        for bad in [
            "",
            "{}",
            "{4f27f2de-14e2-430b-a549-7cd48cbc824}",
            "{4f27f2de-14e2-430b-a549-7cd48cbc82455}",
            "{4f27f2de_14e2-430b-a549-7cd48cbc8245}",
            "{+f27f2de-14e2-430b-a549-7cd48cbc8245}",
            "{4f27f2de-14e2-430b-a549-7cd48cbc824g}",
        ] {
            assert_eq!(ScmGuid::parse(bad), None, "{bad}");
        }
    }

    // --- names and kinds -----------------------------------------------------------------------

    #[test]
    fn service_names_are_checked_before_any_call() {
        assert!(service_name_arg("PurgeTestSvc").is_ok());
        let long = "a".repeat(MAX_NAME_UNITS + 1);
        for bad in ["", "a\\b", "a/b", "a\0b", long.as_str()] {
            assert_eq!(
                service_name_arg(bad),
                Err(WinError::InvalidName(bad.to_owned())),
                "{bad:?}"
            );
        }
        assert!(service_name_arg(&"a".repeat(MAX_NAME_UNITS)).is_ok());
    }

    #[test]
    fn plain_win32_types_only() {
        // 0x30: the status type of a split svchost service (seen on the host for EventLog, Schedule).
        for ok in [0x10, 0x20, 0x30, 0x110, 0x120] {
            assert!(is_plain_win32_service(ok), "{ok:#x}");
        }
        // Kernel and file-system drivers, adapter, recognizer, per-user template and instance,
        // packaged service, and nonsense combinations.
        for bad in [
            0x1, 0x2, 0x4, 0x8, 0x50, 0x60, 0xd0, 0xe0, 0x210, 0x100, 0x0, 0x11, 0x31,
        ] {
            assert!(!is_plain_win32_service(bad), "{bad:#x}");
        }
    }

    #[test]
    fn config2_kind_names_match_spike_result() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vm/spikes/m1b/RESULT.json"
        ))
        .unwrap();
        // Every item name the spike applied or listed under `naive.config2` is a kind name.
        let names: Vec<&str> = Config2Kind::ALL.iter().map(|k| k.name()).collect();
        for n in [
            "description",
            "failure_actions",
            "failure_actions_flag",
            "delayed_auto_start",
            "service_sid_type",
            "required_privileges",
            "preshutdown_timeout_ms",
            "triggers",
            "launch_protected",
        ] {
            assert!(text.contains(&format!("\"{n}\"")), "{n} not in RESULT.json");
            assert!(names.contains(&n), "{n}");
        }
        let levels: Vec<u32> = Config2Kind::ALL.iter().map(|k| k.level()).collect();
        assert_eq!(levels, [1, 2, 4, 3, 5, 6, 7, 8, 12]);
        assert_eq!(Config2Kind::Triggers.registry_entries(), ["TriggerInfo\\"]);
    }

    #[test]
    fn config2_items_in_spike_order() {
        let c2 = ScmConfig2 {
            description: Some("d".into()),
            delayed_auto_start: Some(false),
            failure_actions: Some(FailureActions::default()),
            failure_actions_flag: Some(true),
            service_sid_type: Some(1),
            required_privileges: Some(vec![]),
            preshutdown_timeout_ms: Some(10_000),
            triggers: Some(vec![]),
            launch_protected: Some(0),
        };
        let kinds: Vec<Config2Kind> = c2.items().iter().map(Config2Item::kind).collect();
        assert_eq!(kinds, Config2Kind::ALL);
        assert!(ScmConfig2::default().items().is_empty());
    }

    // --- delete through a simulated SCM ---------------------------------------------------------

    #[cfg(feature = "write")]
    mod delete_sim {
        use std::cell::RefCell;
        use std::rc::Rc;

        use super::*;

        /// The SCM behaviour the spike recorded: a deleted service stays (marked) while any handle is
        /// open, the deleter's own included, and vanishes when the last one closes.
        struct SimState {
            exists: bool,
            marked: bool,
            handles: u32,
            other_handle_open: bool,
            state: u32,
            service_type: u32,
            log: Vec<String>,
        }

        struct Sim(Rc<RefCell<SimState>>);

        struct SimSvc(Rc<RefCell<SimState>>);

        impl Drop for SimSvc {
            fn drop(&mut self) {
                let mut s = self.0.borrow_mut();
                s.handles -= 1;
                s.log.push("close".into());
                if s.marked && s.handles == 0 && !s.other_handle_open {
                    s.exists = false;
                }
            }
        }

        impl DeleteOps for Sim {
            type Svc = SimSvc;
            fn open(&mut self, name: &[u16], access: u32) -> Result<SimSvc, u32> {
                let mut s = self.0.borrow_mut();
                s.log.push(format!(
                    "open {} {access:#x}",
                    String::from_utf16_lossy(&name[..name.len() - 1])
                ));
                if !s.exists {
                    return Err(ERROR_SERVICE_DOES_NOT_EXIST);
                }
                s.handles += 1;
                Ok(SimSvc(self.0.clone()))
            }
            fn status(&mut self, _: &SimSvc) -> Result<ScmStatus, u32> {
                let mut s = self.0.borrow_mut();
                s.log.push("status".into());
                Ok(ScmStatus {
                    service_type: s.service_type,
                    current_state: s.state,
                    controls_accepted: 0,
                    win32_exit_code: 0,
                    service_specific_exit_code: 0,
                    process_id: if s.state == SERVICE_STOPPED { 0 } else { 4242 },
                    service_flags: 0,
                })
            }
            fn delete(&mut self, _: &SimSvc) -> Result<(), u32> {
                let mut s = self.0.borrow_mut();
                s.log.push("delete".into());
                if s.marked {
                    return Err(ERROR_SERVICE_MARKED_FOR_DELETE);
                }
                s.marked = true;
                Ok(())
            }
        }

        fn sim(state: u32, other_handle_open: bool) -> (Sim, Rc<RefCell<SimState>>) {
            let st = Rc::new(RefCell::new(SimState {
                exists: true,
                marked: false,
                handles: 0,
                other_handle_open,
                state,
                service_type: SERVICE_WIN32_OWN_PROCESS,
                log: Vec::new(),
            }));
            (Sim(st.clone()), st)
        }

        fn run(sim: &mut Sim, name: &str) -> Result<ScmDelete, WinError> {
            delete_with(sim, &service_name_arg(name).unwrap())
        }

        /// Hostile: a running built-in service. The status call says RUNNING; DeleteService is never
        /// reached.
        #[test]
        fn delete_refuses_running_service() {
            const SERVICE_RUNNING: u32 = 4;
            let (mut ops, st) = sim(SERVICE_RUNNING, false);
            assert_eq!(
                run(&mut ops, "EventLog"),
                Err(WinError::InUse {
                    state: SERVICE_RUNNING
                })
            );
            let s = st.borrow();
            assert!(!s.log.iter().any(|l| l == "delete"), "{:?}", s.log);
            assert!(s.exists && !s.marked && s.handles == 0);
            // Every non-stopped state is refused the same way.
            for state in [2, 3, 5, 6, 7] {
                let (mut ops, st) = sim(state, false);
                assert_eq!(run(&mut ops, "EventLog"), Err(WinError::InUse { state }));
                assert!(!st.borrow().log.iter().any(|l| l == "delete"));
            }
        }

        #[test]
        fn delete_refuses_drivers_and_user_services() {
            for t in [0x1, 0x2, 0x50, 0x60] {
                let (mut ops, st) = sim(SERVICE_STOPPED, false);
                st.borrow_mut().service_type = t;
                assert!(matches!(run(&mut ops, "Drv"), Err(WinError::Refused(_))));
                assert!(!st.borrow().log.iter().any(|l| l == "delete"));
            }
        }

        #[test]
        fn delete_accepts_split_svchost_status_type() {
            let (mut ops, st) = sim(SERVICE_STOPPED, false);
            st.borrow_mut().service_type = 0x30;
            assert_eq!(run(&mut ops, "PurgeShared"), Ok(ScmDelete::Deleted));
        }

        #[test]
        fn delete_closes_own_handle_before_reopen() {
            let (mut ops, st) = sim(SERVICE_STOPPED, false);
            assert_eq!(run(&mut ops, "PurgeSvc"), Ok(ScmDelete::Deleted));
            let s = st.borrow();
            assert_eq!(
                s.log,
                [
                    "open PurgeSvc 0x10004",
                    "status",
                    "delete",
                    "close",
                    "open PurgeSvc 0x4"
                ]
            );
            assert!(!s.exists && s.handles == 0);
        }

        #[test]
        fn delete_with_another_handle_open_is_marked() {
            let (mut ops, st) = sim(SERVICE_STOPPED, true);
            assert_eq!(run(&mut ops, "PurgeSvc"), Ok(ScmDelete::Marked));
            let s = st.borrow();
            assert!(s.exists && s.marked && s.handles == 0, "{:?}", s.log);
            assert_eq!(s.log.last().map(String::as_str), Some("close"));
        }

        #[test]
        fn delete_of_already_marked_service_is_marked() {
            let (mut ops, st) = sim(SERVICE_STOPPED, true);
            st.borrow_mut().marked = true;
            assert_eq!(run(&mut ops, "PurgeSvc"), Ok(ScmDelete::Marked));
            let s = st.borrow();
            assert_eq!(
                s.log,
                ["open PurgeSvc 0x10004", "status", "delete", "close"]
            );
        }

        #[test]
        fn delete_missing_is_not_found() {
            let (mut ops, st) = sim(SERVICE_STOPPED, false);
            st.borrow_mut().exists = false;
            assert_eq!(run(&mut ops, "PurgeSvc"), Err(WinError::NotFound));
        }
    }

    // --- create and config2 arguments -----------------------------------------------------------

    #[cfg(feature = "write")]
    fn def() -> ScmCreate {
        ScmCreate {
            name: "PurgeTestSvc".into(),
            display_name: Some("Purge test".into()),
            service_type: SERVICE_WIN32_OWN_PROCESS,
            start_type: SERVICE_DEMAND_START,
            error_control: 1,
            binary_path: r#""%ProgramFiles%\Purge Test\svc.exe" -k"#.into(),
            load_order_group: Some(String::new()),
            dependencies: vec!["RpcSs".into(), "+NetworkProvider".into()],
            service_start_name: Some(r"NT AUTHORITY\LocalService".into()),
        }
    }

    #[cfg(feature = "write")]
    fn utf16(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[cfg(feature = "write")]
    #[test]
    fn create_args_keep_raw_path_and_build_dependency_list() {
        let a = CreateArgs::build(&def()).unwrap();
        assert_eq!(
            a.binary_path,
            nul_terminated(utf16(r#""%ProgramFiles%\Purge Test\svc.exe" -k"#))
        );
        assert_eq!(a.load_order_group, None, "empty group passes null");
        let mut deps = utf16("RpcSs");
        deps.push(0);
        deps.extend(utf16("+NetworkProvider"));
        deps.extend([0, 0]);
        assert_eq!(a.dependencies, Some(deps));
        let mut d = def();
        d.dependencies.clear();
        d.display_name = None;
        d.service_start_name = None;
        let a = CreateArgs::build(&d).unwrap();
        assert_eq!(
            (a.dependencies, a.display_name, a.service_start_name),
            (None, None, None)
        );
    }

    /// Hostile: a definition that would smuggle an extra dependency through an embedded NUL or an empty
    /// entry, or plant a driver or a boot-start service.
    #[cfg(feature = "write")]
    #[test]
    fn create_args_refuse_bad_definitions() {
        type Want = fn(&WinError) -> bool;
        let cases: Vec<(ScmCreate, Want)> = vec![
            (
                ScmCreate {
                    dependencies: vec!["RpcSs\0EvilSvc".into()],
                    ..def()
                },
                |e| matches!(e, WinError::InvalidArgument(_)),
            ),
            (
                ScmCreate {
                    dependencies: vec![String::new(), "X".into()],
                    ..def()
                },
                |e| matches!(e, WinError::InvalidArgument(_)),
            ),
            (
                ScmCreate {
                    binary_path: "C:\\a.exe\0 -evil".into(),
                    ..def()
                },
                |e| matches!(e, WinError::InvalidArgument(_)),
            ),
            (
                ScmCreate {
                    binary_path: String::new(),
                    ..def()
                },
                |e| matches!(e, WinError::InvalidArgument(_)),
            ),
            (
                ScmCreate {
                    service_type: 0x1,
                    ..def()
                },
                |e| matches!(e, WinError::Refused(_)),
            ),
            (
                ScmCreate {
                    service_type: 0x50,
                    ..def()
                },
                |e| matches!(e, WinError::Refused(_)),
            ),
            (
                ScmCreate {
                    start_type: 0,
                    ..def()
                },
                |e| matches!(e, WinError::Refused(_)),
            ),
            (
                ScmCreate {
                    start_type: 1,
                    ..def()
                },
                |e| matches!(e, WinError::Refused(_)),
            ),
            (
                ScmCreate {
                    error_control: 4,
                    ..def()
                },
                |e| matches!(e, WinError::InvalidArgument(_)),
            ),
            (
                ScmCreate {
                    service_start_name: Some(String::new()),
                    ..def()
                },
                |e| matches!(e, WinError::InvalidArgument(_)),
            ),
            (
                ScmCreate {
                    display_name: Some(String::new()),
                    ..def()
                },
                |e| matches!(e, WinError::InvalidArgument(_)),
            ),
            (
                ScmCreate {
                    name: "a\\b".into(),
                    ..def()
                },
                |e| matches!(e, WinError::InvalidName(_)),
            ),
        ];
        for (d, want) in cases {
            let e = CreateArgs::build(&d).unwrap_err();
            assert!(want(&e), "{d:?}: {e:?}");
        }
    }

    #[cfg(feature = "write")]
    #[test]
    fn config2_defaults_the_scm_refuses_are_not_settable() {
        for item in [
            Config2Item::Triggers(vec![]),
            Config2Item::LaunchProtected(0),
        ] {
            assert!(
                matches!(
                    Config2Arg::build(&item),
                    Err(WinError::NotSettable { item: n, .. }) if n == item.kind().name()
                ),
                "{item:?}"
            );
        }
        assert!(Config2Arg::build(&Config2Item::LaunchProtected(3)).is_ok());
    }

    #[cfg(feature = "write")]
    #[test]
    fn config2_args_point_at_owned_data() {
        // SAFETY (whole test): the pointers read here come from the built argument, alive in scope.
        let a = Config2Arg::build(&Config2Item::Description("hi".into())).unwrap();
        assert_eq!(a.kind.level(), SERVICE_CONFIG_DESCRIPTION);
        let d = unsafe { &*(a.info_ptr() as *const SERVICE_DESCRIPTIONW) };
        assert_eq!(unsafe { crate::os::from_wide_ptr(d.lpDescription) }, "hi");

        let a = Config2Arg::build(&Config2Item::DelayedAutoStart(true)).unwrap();
        assert_eq!(unsafe { *(a.info_ptr() as *const u32) }, 1);

        let a = Config2Arg::build(&Config2Item::RequiredPrivileges(vec![
            "SeA".into(),
            "SeB".into(),
        ]))
        .unwrap();
        let p = unsafe { &*(a.info_ptr() as *const SERVICE_REQUIRED_PRIVILEGES_INFOW) };
        let units = unsafe { std::slice::from_raw_parts(p.pmszRequiredPrivileges, 9) };
        assert_eq!(units, [83, 101, 65, 0, 83, 101, 66, 0, 0]);
        assert!(matches!(
            Config2Arg::build(&Config2Item::RequiredPrivileges(vec![String::new()])),
            Err(WinError::InvalidArgument(_))
        ));

        let fa = FailureActions {
            reset_period: 60,
            reboot_msg: None,
            command: Some("c".into()),
            actions: vec![FailureAction {
                action_type: 1,
                delay_ms: 5,
            }],
        };
        let a = Config2Arg::build(&Config2Item::FailureActions(fa)).unwrap();
        assert!(
            a.needs_start_access,
            "restart action needs SERVICE_START access"
        );
        let f = unsafe { &*(a.info_ptr() as *const SERVICE_FAILURE_ACTIONSW) };
        assert_eq!((f.dwResetPeriod, f.cActions), (60, 1));
        assert!(f.lpRebootMsg.is_null(), "None leaves the message unchanged");
        let act = unsafe { *f.lpsaActions };
        assert_eq!((act.Type, act.Delay), (1, 5));
        let a = Config2Arg::build(&Config2Item::FailureActions(FailureActions::default())).unwrap();
        assert!(!a.needs_start_access);
        let f = unsafe { &*(a.info_ptr() as *const SERVICE_FAILURE_ACTIONSW) };
        assert!(!f.lpsaActions.is_null() && f.cActions == 0);

        let g = ScmGuid::parse("{4f27f2de-14e2-430b-a549-7cd48cbc8245}").unwrap();
        let triggers = vec![
            ScmTrigger {
                trigger_type: 2,
                action: 1,
                subtype: Some(g),
                data: vec![],
            },
            ScmTrigger {
                trigger_type: 20,
                action: 1,
                subtype: None,
                data: vec![
                    TriggerDataItem {
                        data_type: 2,
                        bytes: vec![104, 0, 0, 0],
                    },
                    TriggerDataItem {
                        data_type: 1,
                        bytes: vec![],
                    },
                ],
            },
        ];
        let a = Config2Arg::build(&Config2Item::Triggers(triggers)).unwrap();
        let ti = unsafe { &*(a.info_ptr() as *const SERVICE_TRIGGER_INFO) };
        assert_eq!(ti.cTriggers, 2);
        let ts = unsafe { std::slice::from_raw_parts(ti.pTriggers, 2) };
        let sub = unsafe { *ts[0].pTriggerSubtype };
        assert_eq!(sub.data1, 0x4f27f2de);
        assert_eq!(sub.data4, [0xa5, 0x49, 0x7c, 0xd4, 0x8c, 0xbc, 0x82, 0x45]);
        assert!(ts[0].pDataItems.is_null() && ts[0].cDataItems == 0);
        assert!(ts[1].pTriggerSubtype.is_null());
        let items = unsafe { std::slice::from_raw_parts(ts[1].pDataItems, 2) };
        assert_eq!((items[0].dwDataType, items[0].cbData), (2, 4));
        assert_eq!(
            unsafe { std::slice::from_raw_parts(items[0].pData, 4) },
            [104, 0, 0, 0]
        );
        assert!(items[1].pData.is_null() && items[1].cbData == 0);
    }

    // --- SDDL ----------------------------------------------------------------------------------

    /// Hostile: a definition whose SDDL would leave the service without access control.
    #[cfg(feature = "write")]
    #[test]
    fn sddl_without_a_real_dacl_is_refused() {
        for bad in [
            "D:NO_ACCESS_CONTROL",
            "O:SYG:SY",
            "",
            "not sddl",
            "D:(A;;GA;;;WD)\0",
        ] {
            assert!(
                matches!(
                    SddlDescriptor::from_sddl(bad),
                    Err(WinError::InvalidArgument(_))
                ),
                "{bad:?}"
            );
        }
        SddlDescriptor::from_sddl(
            "O:SYG:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)",
        )
        .unwrap();
        // An empty but present DACL is a real (deny-all) DACL.
        SddlDescriptor::from_sddl("D:").unwrap();
    }
}
