//! Identities and fingerprints of system objects: services, scheduled tasks and firewall rules
//! (contract C-OBJECT, M1b). Plain data only; the digest and the parsers arrive with M1B-MODEL.

use serde::{Deserialize, Serialize};

/// The kind of a system object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjectKind {
    /// A Windows service.
    #[serde(rename = "service")]
    Service,
    /// A scheduled task.
    #[serde(rename = "task")]
    Task,
    /// A Windows Firewall rule.
    #[serde(rename = "firewall_rule")]
    FirewallRule,
}

/// Scan-time fingerprint of a system object: its kind and the SHA-256 of its identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectFp {
    /// What kind of object the digest covers.
    pub kind: ObjectKind,
    /// 64 lower-case hex digits.
    pub sha256: String,
}

/// What identifies a Windows service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceIdentity {
    /// Service key name.
    pub name: String,
    /// `ImagePath` as stored (`REG_EXPAND_SZ` not expanded).
    pub image_path: Option<String>,
    /// `Parameters\ServiceDll`, else the top-level `ServiceDll`.
    pub service_dll: Option<String>,
    /// `Type`.
    pub service_type: u32,
    /// `Start`.
    pub start: u32,
    /// `ObjectName`.
    pub object_name: Option<String>,
}

/// One action of a scheduled task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum TaskAction {
    /// Run a program.
    #[serde(rename = "exec")]
    Exec {
        /// Program path.
        path: String,
        /// Command-line arguments.
        arguments: Option<String>,
        /// Working directory.
        working_dir: Option<String>,
    },
    /// Call a COM handler.
    #[serde(rename = "com_handler")]
    ComHandler {
        /// CLSID of the handler.
        clsid: String,
        /// Handler data.
        data: Option<String>,
    },
    /// Any other action type.
    #[serde(rename = "other")]
    Other {
        /// Name of the action kind. Serialised as `other_kind`: the tag already uses `kind`.
        #[serde(rename = "other_kind")]
        kind: String,
    },
}

/// What identifies a scheduled task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskIdentity {
    /// Task path; starts with a backslash, as Task Scheduler returns it.
    pub path: String,
    /// The task's actions, in order.
    pub actions: Vec<TaskAction>,
}

/// What identifies a firewall rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallIdentity {
    /// Registry value name, equal to the WMI `InstanceID`.
    pub id: String,
    /// The raw registry string, byte for byte.
    pub rule: String,
}
