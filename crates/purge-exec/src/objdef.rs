//! Stored definitions of system objects, kept for undo (M1b, C-DEF).
//!
//! Before a service, scheduled task or firewall rule is deleted, everything needed to create it again is
//! written to the op's definition file, `def\<op>.json` in the session directory
//! ([`BackupKind::Definition`]). Three documents, one per object kind:
//!
//! - `purge.svcdef/1` ([`SvcDef`]): the SCM configuration, the config2 items, the service's security
//!   descriptor, a reference to the separate verified `purge.regbackup/1` backup of the whole
//!   `Services\<name>` tree ([`SvcDef::key_backup`]) and whether the service's account holds no stored
//!   password ([`SvcDef::account_builtin`]).
//! - `purge.taskdef/1` ([`TaskDef`]): the task's registration XML and the facts read with it.
//! - `purge.fwdef/1` ([`FwDef`]): the rule's raw registry string and its fields.
//!
//! What undo does with them was measured by the M1b spike (`vm/spikes/m1b/README.md`), and the spike wins
//! over the contract's first text: a service is created from the raw `ImagePath` of the key backup (the
//! `config.binary_path` that `QueryServiceConfigW` reports is expanded and is kept here as read, not as
//! the create argument), config2 items are applied only where the key backup holds their value, the
//! descriptor's DACL only, and every backed-up value the create did not write is written back. A task is
//! registered from its XML alone (no SDDL argument); one with a stored password cannot be registered again
//! (`UndoConflict::PasswordNeeded`). A firewall rule is re-created under its own id
//! ([`purge_model::FIREWALL_RESTORE_EXACT`]). The act modules own those procedures; this module owns the
//! files.
//!
//! # Writing and reading
//!
//! [`write_def`] writes through the store's existing create-in-store path ([`SessionDir::create_file`]):
//! the same chain checks and descriptors as a registry backup, write, flush of the file and its
//! directory, read back through the same handle (fault point `backup.written`), re-open through the
//! store's checks, same file id, bytes and document equal (fault point `backup.verified`). Its
//! [`BackupRef`] (size and SHA-256 of the bytes read back) goes into the op's journal intent, inside the
//! inverse. A definition that cannot be read back equal is a [`DefWriteError`]: the item is skipped with
//! `NoVerifiedBackup` ([`DefWriteError::outcome`]) and nothing is deleted.
//!
//! [`read_def`] reads only the file a journal record names: the [`BackupRef`] comes from the op's intent,
//! never from a definition or from the plan. It refuses a reference outside `def\`, a file whose size or
//! SHA-256 differs from the journal (`BackupTampered`), a missing file (`BackupMissing`), a file over
//! [`MAX_DEF_BYTES`], and a document whose `schema` is not the one expected or that fails its own checks
//! ([`ObjectDef::check`]).
//!
//! The service's key backup ([`SvcDef::key_backup`]) is a reference inside a verified definition; the act
//! module takes it only through [`SvcDef::key_backup_for`], which requires the op's own registry backup
//! name ([`backup_rel`]), and reads it with the registry backup reader.

use std::fmt;
use std::io::Write;
use std::path::PathBuf;

use purge_model::exec::journal::UndoConflict;
use purge_model::exec::op::{BackupRef, ItemOutcome, OpId, SkipReason};
use purge_model::{FirewallIdentity, ObjectKind, ServiceIdentity, TaskAction, TaskIdentity};
use purge_win::fs_write::FsError;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::act_reg::already_exists;
use crate::fault;
use crate::gate::Stamp;
use crate::journal::sha256_bytes;
use crate::storage::{
    BackupKind, DEF_DIR, REG_BACKUP_DIR, SessionDir, StorageError, StoreFile, backup_rel,
};

/// The `schema` of a service definition.
pub const SVCDEF_SCHEMA: &str = "purge.svcdef/1";
/// The `schema` of a scheduled-task definition.
pub const TASKDEF_SCHEMA: &str = "purge.taskdef/1";
/// The `schema` of a firewall-rule definition.
pub const FWDEF_SCHEMA: &str = "purge.fwdef/1";

/// The largest definition file written or read: 4 MiB. A task's XML is the largest part and is a few
/// kilobytes; Task Scheduler itself refuses far smaller documents.
pub const MAX_DEF_BYTES: u64 = 4 << 20;

// ---------------------------------------------------------------------------------------------------
// The documents
// ---------------------------------------------------------------------------------------------------

/// A stored object definition: one of [`SvcDef`], [`TaskDef`], [`FwDef`].
pub trait ObjectDef: Serialize + DeserializeOwned + PartialEq + fmt::Debug {
    /// The `schema` string the document must carry.
    const SCHEMA: &'static str;
    /// The kind of object the document describes.
    const KIND: ObjectKind;

    /// The document's `schema` string.
    fn schema(&self) -> &str;

    /// The identity digest of the object the definition was read from (C-OBJECT), 64 lower-case hex
    /// digits. It must equal the validated stamp ([`check_def_identity`]).
    fn identity_sha256(&self) -> &str;

    /// The identity digest the document's own fields imply, when they hold the whole identity: the
    /// task's path and actions, the rule's id and raw string. `None` for a service, whose identity
    /// holds the raw `ImagePath` and `ServiceDll`, which live in the key backup.
    fn implied_identity(&self) -> Option<String>;

    /// The checks of the document's own fields beyond the schema and the digest form; a message on a
    /// failure.
    fn check_fields(&self) -> Result<(), String>;

    /// Every check a definition passes before it is written and after it is read: the schema string is
    /// [`ObjectDef::SCHEMA`], the identity digest is 64 lower-case hex digits and equals the one the
    /// fields imply ([`ObjectDef::implied_identity`]), and the fields pass [`ObjectDef::check_fields`].
    fn check(&self) -> Result<(), String> {
        if self.schema() != Self::SCHEMA {
            return Err(format!(
                "the schema is {:?}, not {:?}",
                self.schema(),
                Self::SCHEMA
            ));
        }
        if !is_digest(self.identity_sha256()) {
            return Err("the identity digest is not 64 lower-case hex digits".to_owned());
        }
        if self
            .implied_identity()
            .is_some_and(|implied| implied != self.identity_sha256())
        {
            return Err(
                "the identity digest is not the one the definition's fields imply".to_owned(),
            );
        }
        self.check_fields()
    }
}

/// Whether `s` is 64 lower-case hex digits.
fn is_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `purge.svcdef/1`: everything needed to create a service again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvcDef {
    /// Always [`SVCDEF_SCHEMA`].
    pub schema: String,
    /// The service name, as the SCM reports it.
    pub name: String,
    /// The identity digest of the service as validated ([`ServiceIdentity::fp`]).
    pub identity_sha256: String,
    /// `QueryServiceConfigW`, as read.
    pub config: SvcConfig,
    /// `QueryServiceConfig2W`, as read; an item that could not be read or is not set is `null`.
    pub config2: SvcConfig2,
    /// The service object's security descriptor as SDDL (`QueryServiceObjectSecurity`). Undo applies
    /// only its DACL, and only when the key backup holds a `Security` subkey (spike).
    pub sddl: String,
    /// The separate verified `purge.regbackup/1` backup of the whole `Services\<name>` tree. Read it
    /// only through [`SvcDef::key_backup_for`].
    pub key_backup: BackupRef,
    /// Whether the service runs under an account Windows holds no password for ([`account_builtin`] of
    /// `config.service_start_name`). When false the delete loses a stored password: the scan states
    /// `Reversibility::Partial` from this alone (spike).
    pub account_builtin: bool,
}

/// The `QUERY_SERVICE_CONFIGW` fields of a service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvcConfig {
    /// `dwServiceType`.
    pub service_type: u32,
    /// `dwStartType`.
    pub start_type: u32,
    /// `dwErrorControl`.
    pub error_control: u32,
    /// `lpBinaryPathName` as `QueryServiceConfigW` reports it (environment strings expanded). Not the
    /// create argument: undo creates from the raw `ImagePath` of the key backup.
    pub binary_path: String,
    /// `lpLoadOrderGroup`; `null` when empty.
    pub load_order_group: Option<String>,
    /// `dwTagId`.
    pub tag_id: u32,
    /// `lpDependencies`, one entry per name (a group keeps its `SC_GROUP_IDENTIFIER` prefix).
    pub dependencies: Vec<String>,
    /// `lpServiceStartName`; `null` when empty.
    pub service_start_name: Option<String>,
    /// `lpDisplayName`; `null` when empty.
    pub display_name: Option<String>,
}

/// The config2 items of a service; `null` for an item that is not set or could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvcConfig2 {
    /// `SERVICE_CONFIG_DESCRIPTION`.
    pub description: Option<String>,
    /// `SERVICE_CONFIG_DELAYED_AUTO_START_INFO`.
    pub delayed_auto_start: Option<bool>,
    /// `SERVICE_CONFIG_FAILURE_ACTIONS`.
    pub failure_actions: Option<SvcFailureActions>,
    /// `SERVICE_CONFIG_FAILURE_ACTIONS_FLAG`.
    pub failure_actions_flag: Option<bool>,
    /// `SERVICE_CONFIG_SERVICE_SID_INFO`.
    pub service_sid_type: Option<u32>,
    /// `SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO`.
    pub required_privileges: Option<Vec<String>>,
    /// `SERVICE_CONFIG_PRESHUTDOWN_INFO`, in milliseconds.
    pub preshutdown_timeout_ms: Option<u32>,
    /// `SERVICE_CONFIG_TRIGGER_INFO`.
    pub triggers: Option<Vec<SvcTrigger>>,
    /// `SERVICE_CONFIG_LAUNCH_PROTECTED`.
    pub launch_protected: Option<u32>,
}

/// `SERVICE_FAILURE_ACTIONSW`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvcFailureActions {
    /// `dwResetPeriod`, in seconds.
    pub reset_period: u32,
    /// `lpRebootMsg`.
    pub reboot_msg: Option<String>,
    /// `lpCommand`.
    pub command: Option<String>,
    /// `lpsaActions`.
    pub actions: Vec<SvcFailureAction>,
}

/// One `SC_ACTION`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvcFailureAction {
    /// `Type`.
    #[serde(rename = "type")]
    pub action_type: u32,
    /// `Delay`, in milliseconds.
    pub delay_ms: u32,
}

/// One `SERVICE_TRIGGER`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvcTrigger {
    /// `dwTriggerType`.
    #[serde(rename = "type")]
    pub trigger_type: u32,
    /// `dwAction`.
    pub action: u32,
    /// `pTriggerSubtype`, as a GUID string.
    pub subtype: String,
    /// `pDataItems`.
    pub data: Vec<SvcTriggerData>,
}

/// One `SERVICE_TRIGGER_SPECIFIC_DATA_ITEM`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvcTriggerData {
    /// `dwDataType`.
    #[serde(rename = "type")]
    pub data_type: u32,
    /// The item's bytes, standard base64.
    pub base64: String,
}

impl SvcDef {
    /// The key backup when it is the op's own registry backup (`reg\<op>.regbackup.json`,
    /// [`backup_rel`]); `None` otherwise. The only way an act module takes the reference: a definition
    /// never chooses which file is read.
    pub fn key_backup_for(&self, op: OpId) -> Option<&BackupRef> {
        (self.key_backup.path == backup_rel(BackupKind::Registry, op)).then_some(&self.key_backup)
    }
}

impl ObjectDef for SvcDef {
    const SCHEMA: &'static str = SVCDEF_SCHEMA;
    const KIND: ObjectKind = ObjectKind::Service;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn identity_sha256(&self) -> &str {
        &self.identity_sha256
    }

    fn implied_identity(&self) -> Option<String> {
        None
    }

    fn check_fields(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("the service name is empty".to_owned());
        }
        let in_reg = self
            .key_backup
            .path
            .strip_prefix(REG_BACKUP_DIR)
            .and_then(|rest| rest.strip_prefix('\\'))
            .is_some_and(|leaf| !leaf.contains('\\'));
        if !self.key_backup.is_session_relative() || !in_reg {
            return Err(format!(
                "the key backup {:?} is not a registry backup of the session",
                self.key_backup.path
            ));
        }
        if self.account_builtin != account_builtin(self.config.service_start_name.as_deref()) {
            return Err("account_builtin does not match the service's account".to_owned());
        }
        Ok(())
    }
}

/// Whether a service running under `service_start_name` holds no stored password (C-DEF): `None`,
/// `LocalSystem`, `NT AUTHORITY\LocalService`, `NT AUTHORITY\NetworkService`, or `NT SERVICE\...`,
/// ignoring ASCII case. The rule is [`ServiceIdentity::account_builtin`]'s, the one the scan uses for
/// `Reversibility::Partial`.
pub fn account_builtin(service_start_name: Option<&str>) -> bool {
    ServiceIdentity {
        object_name: service_start_name.map(str::to_owned),
        ..ServiceIdentity::default()
    }
    .account_builtin()
}

/// `purge.taskdef/1`: everything needed to register a scheduled task again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskDef {
    /// Always [`TASKDEF_SCHEMA`].
    pub schema: String,
    /// The task's path, starting with `\`, as Task Scheduler returns it.
    pub path: String,
    /// The identity digest of the task as validated ([`TaskIdentity::fp`] of `path` and `actions`).
    pub identity_sha256: String,
    /// The task's actions, as in its identity.
    pub actions: Vec<TaskAction>,
    /// The registration XML (`IRegisteredTask::get_Xml`). Undo registers from it alone (spike).
    pub xml: String,
    /// The task's security descriptor as SDDL, as read. Not passed to the registration (spike: passing
    /// it is not exact).
    pub sddl: String,
    /// Whether the task was enabled.
    pub enabled: bool,
    /// The principal's `TASK_LOGON_TYPE`.
    pub logon_type: u32,
    /// Whether the principal holds a stored password; such a task cannot be registered again
    /// (`UndoConflict::PasswordNeeded`).
    pub stored_password: bool,
}

impl ObjectDef for TaskDef {
    const SCHEMA: &'static str = TASKDEF_SCHEMA;
    const KIND: ObjectKind = ObjectKind::Task;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn identity_sha256(&self) -> &str {
        &self.identity_sha256
    }

    fn implied_identity(&self) -> Option<String> {
        Some(
            TaskIdentity {
                path: self.path.clone(),
                actions: self.actions.clone(),
            }
            .fp()
            .sha256,
        )
    }

    fn check_fields(&self) -> Result<(), String> {
        if !self.path.starts_with('\\') || self.path.len() < 2 {
            return Err(format!("the task path {:?} is not a task path", self.path));
        }
        if self.xml.is_empty() {
            return Err("the task XML is empty".to_owned());
        }
        Ok(())
    }
}

/// `purge.fwdef/1`: everything needed to create a firewall rule again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FwDef {
    /// Always [`FWDEF_SCHEMA`].
    pub schema: String,
    /// The rule's id: its registry value name and WMI `InstanceID`.
    pub id: String,
    /// The identity digest of the rule as validated ([`FirewallIdentity::fp`] of `id` and `rule`).
    pub identity_sha256: String,
    /// The raw registry string, byte for byte.
    pub rule: String,
    /// The rule's fields, in order, repeated keys kept.
    pub fields: Vec<(String, String)>,
}

impl ObjectDef for FwDef {
    const SCHEMA: &'static str = FWDEF_SCHEMA;
    const KIND: ObjectKind = ObjectKind::FirewallRule;

    fn schema(&self) -> &str {
        &self.schema
    }

    fn identity_sha256(&self) -> &str {
        &self.identity_sha256
    }

    fn implied_identity(&self) -> Option<String> {
        Some(
            FirewallIdentity {
                id: self.id.clone(),
                rule: self.rule.clone(),
            }
            .fp()
            .sha256,
        )
    }

    fn check_fields(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("the rule id is empty".to_owned());
        }
        if self.rule.is_empty() {
            return Err("the rule string is empty".to_owned());
        }
        Ok(())
    }
}

/// Whether `def` describes the object that was validated: `validated` is an object stamp of the
/// definition's kind whose digest equals [`ObjectDef::identity_sha256`]. Anything else is
/// `ChangedSinceScan`: the act module re-reads identity and definition in one backend call sequence, and
/// a definition of another object must never back the delete of this one.
pub fn check_def_identity<T: ObjectDef>(def: &T, validated: &Stamp) -> Result<(), SkipReason> {
    match validated {
        Stamp::Object { kind, sha256 }
            if *kind == T::KIND && is_digest(sha256) && sha256 == def.identity_sha256() =>
        {
            Ok(())
        }
        _ => Err(SkipReason::ChangedSinceScan),
    }
}

// ---------------------------------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------------------------------

/// Why a definition file could not be written as verified. The item is skipped
/// ([`DefWriteError::outcome`]); nothing was deleted.
#[derive(Debug, thiserror::Error)]
pub enum DefWriteError {
    /// The store refused (integrity check, existing file, I/O on the layout).
    #[error("definition file: {0}")]
    Storage(#[from] StorageError),
    /// Writing to the created file failed.
    #[error("definition file {}: {op} failed: {detail}", .path.display())]
    File {
        /// What was being done.
        op: &'static str,
        /// The file, for messages.
        path: PathBuf,
        /// The error.
        detail: String,
    },
    /// The file did not read back as written.
    #[error("definition file {} did not read back as written", .0.display())]
    ReadBackMismatch(PathBuf),
    /// The definition fails its own checks, cannot be encoded, or is larger than [`MAX_DEF_BYTES`].
    #[error("the definition is not usable: {0}")]
    Invalid(String),
}

impl DefWriteError {
    /// The outcome to journal for the item (without an intent): `Skipped{NoVerifiedBackup}`.
    pub fn outcome(&self) -> ItemOutcome {
        ItemOutcome::Skipped {
            reason: SkipReason::NoVerifiedBackup,
        }
    }

    /// Whether a storage directory failed its integrity check, which concerns the whole run
    /// (`AbortReason::StorageIntegrity`) rather than this item.
    pub fn is_storage_integrity(&self) -> bool {
        matches!(self, DefWriteError::Storage(StorageError::Integrity { .. }))
    }
}

/// Writes `def` as op `op`'s definition file (`def\<op>.json`) through the store and returns its
/// reference for the journal.
///
/// The definition must pass [`ObjectDef::check`] and encode to at most [`MAX_DEF_BYTES`]. The file is
/// created new by the store ([`SessionDir::create_file`]: chain re-checked, the store file descriptor,
/// relative to the checked `def` directory's handle), written, flushed with its directory and read back
/// through the same handle; it is closed (fault point `backup.written`), opened again through the store's
/// checks ([`SessionDir::open_file`]), required to be the same file, read through that handle, and its
/// bytes and document compared with what was meant (fault point `backup.verified`). The reference holds
/// the size and SHA-256 of the bytes read back. A failure while the created handle is open discards the
/// file through that handle; nothing is removed by name.
///
/// A file of that name that a crash left before the op's intent (named by no journal record) is adopted
/// when it is a store file that parses to exactly `def`, the definition built now from a fresh read;
/// otherwise it is deleted through the store ([`SessionDir::delete_backup_file`]) and written anew.
pub fn write_def<T: ObjectDef>(
    session: &SessionDir,
    op: OpId,
    def: &T,
) -> Result<BackupRef, DefWriteError> {
    def.check().map_err(DefWriteError::Invalid)?;
    let text = serde_json::to_vec(def).map_err(|e| DefWriteError::Invalid(e.to_string()))?;
    if u64::try_from(text.len()).map_or(true, |n| n > MAX_DEF_BYTES) {
        return Err(DefWriteError::Invalid(format!(
            "the definition has {} bytes, more than {MAX_DEF_BYTES}",
            text.len()
        )));
    }
    let rel = backup_rel(BackupKind::Definition, op);
    let mut created = match session.create_file(&rel) {
        Err(e) if already_exists(&e) => {
            if let Some(adopted) = adopt(session, &rel, def) {
                return Ok(adopted);
            }
            session.delete_backup_file(&rel)?;
            session.create_file(&rel)?
        }
        created => created?,
    };
    if let Err(e) = write_created(&mut created, &text) {
        // The file is Purge's own, created a moment ago, and holds no verified definition.
        let _ = created.discard();
        return Err(e);
    }
    let id = created.file_id();
    drop(created);
    fault::point(fault::BACKUP_WRITTEN);

    let mut opened = session.open_file(&rel)?;
    let checked = opened.report_path();
    if opened.file_id() != id {
        return Err(DefWriteError::ReadBackMismatch(checked));
    }
    let back = opened.read_all(MAX_DEF_BYTES)?;
    drop(opened);
    if back != text {
        return Err(DefWriteError::ReadBackMismatch(checked));
    }
    match serde_json::from_slice::<T>(&back) {
        Ok(parsed) if &parsed == def => {}
        _ => return Err(DefWriteError::ReadBackMismatch(checked)),
    }
    let reference = BackupRef {
        path: rel,
        sha256: sha256_bytes(&back),
        bytes: back.len() as u64,
    };
    fault::point(fault::BACKUP_VERIFIED);
    Ok(reference)
}

/// The definition file `rel` as it is, when it is a store file that parses to exactly `def`; `None`
/// otherwise.
fn adopt<T: ObjectDef>(session: &SessionDir, rel: &str, def: &T) -> Option<BackupRef> {
    let mut file = session.open_file(rel).ok()?;
    let bytes = file.read_all(MAX_DEF_BYTES).ok()?;
    drop(file);
    let parsed: T = serde_json::from_slice(&bytes).ok()?;
    (&parsed == def).then(|| BackupRef {
        path: rel.to_owned(),
        sha256: sha256_bytes(&bytes),
        bytes: bytes.len() as u64,
    })
}

/// Writes `text` through the created store file, flushes it and its directory (through the directory's
/// checked handle), and reads it back through the same handle.
fn write_created(file: &mut StoreFile, text: &[u8]) -> Result<(), DefWriteError> {
    if let Err(e) = file.write_all(text) {
        return Err(DefWriteError::File {
            op: "write",
            path: file.report_path(),
            detail: e.to_string(),
        });
    }
    file.sync()?;
    file.sync_dir()?;
    if file.read_all(MAX_DEF_BYTES)? != text {
        return Err(DefWriteError::ReadBackMismatch(file.report_path()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------------------------------

/// Why a definition could not be read: the undo conflict to journal and a detail for the report.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{detail}")]
pub struct DefReadError {
    /// [`UndoConflict::BackupMissing`] or [`UndoConflict::BackupTampered`].
    pub conflict: UndoConflict,
    /// What was wrong.
    pub detail: String,
}

impl DefReadError {
    fn tampered(reference: &BackupRef, why: impl fmt::Display) -> DefReadError {
        DefReadError {
            conflict: UndoConflict::BackupTampered,
            detail: format!("the definition {} cannot be used: {why}", reference.path),
        }
    }
}

/// Reads the definition file `reference` names (taken from the op's journal intent), as a `T`.
///
/// In order: the reference must stay inside the session's `def` directory and name at most
/// [`MAX_DEF_BYTES`]; the file is opened through the store's checks ([`SessionDir::open_file`]) and read
/// through that handle; its size and SHA-256 must equal the reference; then its `schema` must be
/// [`ObjectDef::SCHEMA`], the document must parse as `T` (unknown members refused) and pass
/// [`ObjectDef::check`]. A missing file (or `def` directory) is [`UndoConflict::BackupMissing`]; every
/// other failure is [`UndoConflict::BackupTampered`].
pub fn read_def<T: ObjectDef>(
    session: &SessionDir,
    reference: &BackupRef,
) -> Result<T, UndoConflict> {
    read_def_detailed(session, reference).map_err(|e| e.conflict)
}

/// [`read_def`], with a detail for the report.
pub fn read_def_detailed<T: ObjectDef>(
    session: &SessionDir,
    reference: &BackupRef,
) -> Result<T, DefReadError> {
    let in_def = reference
        .path
        .strip_prefix(DEF_DIR)
        .and_then(|rest| rest.strip_prefix('\\'))
        .is_some_and(|leaf| !leaf.contains('\\'));
    if !reference.is_session_relative() || !in_def {
        return Err(DefReadError::tampered(
            reference,
            "the journal's reference is not a definition file of the session",
        ));
    }
    if reference.bytes > MAX_DEF_BYTES {
        return Err(DefReadError::tampered(
            reference,
            format_args!(
                "the journal names {} bytes, more than {MAX_DEF_BYTES}",
                reference.bytes
            ),
        ));
    }
    let mut file = match session.open_file(&reference.path) {
        Ok(file) => file,
        Err(StorageError::Io {
            source: FsError::NotFound,
            ..
        }) => {
            return Err(DefReadError {
                conflict: UndoConflict::BackupMissing,
                detail: format!("the definition {} is missing", reference.path),
            });
        }
        Err(e) => return Err(DefReadError::tampered(reference, e)),
    };
    if file.len_at_open() != reference.bytes {
        return Err(DefReadError::tampered(
            reference,
            "its size does not match the journal",
        ));
    }
    let bytes = file
        .read_all(MAX_DEF_BYTES)
        .map_err(|e| DefReadError::tampered(reference, e))?;
    drop(file);
    if bytes.len() as u64 != reference.bytes || sha256_bytes(&bytes) != reference.sha256 {
        return Err(DefReadError::tampered(
            reference,
            "its size or SHA-256 does not match the journal",
        ));
    }
    /// The schema member alone, read before the document is parsed as `T`.
    #[derive(Deserialize)]
    struct Head {
        schema: String,
    }
    let head: Head = serde_json::from_slice(&bytes)
        .map_err(|e| DefReadError::tampered(reference, format_args!("no schema: {e}")))?;
    if head.schema != T::SCHEMA {
        return Err(DefReadError::tampered(
            reference,
            format_args!("its schema is {:?}, not {:?}", head.schema, T::SCHEMA),
        ));
    }
    let def: T =
        serde_json::from_slice(&bytes).map_err(|e| DefReadError::tampered(reference, e))?;
    def.check()
        .map_err(|why| DefReadError::tampered(reference, why))?;
    Ok(def)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn svc() -> SvcDef {
        SvcDef {
            schema: SVCDEF_SCHEMA.into(),
            name: "VendorSvc".into(),
            identity_sha256: DIGEST.into(),
            config: SvcConfig {
                service_type: 0x10,
                start_type: 2,
                error_control: 1,
                binary_path: r"C:\Program Files\Vendor\svc.exe".into(),
                load_order_group: None,
                tag_id: 0,
                dependencies: vec![],
                service_start_name: Some("LocalSystem".into()),
                display_name: Some("Vendor".into()),
            },
            config2: SvcConfig2 {
                description: None,
                delayed_auto_start: None,
                failure_actions: None,
                failure_actions_flag: None,
                service_sid_type: None,
                required_privileges: None,
                preshutdown_timeout_ms: None,
                triggers: None,
                launch_protected: None,
            },
            sddl: "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)".into(),
            key_backup: BackupRef {
                path: backup_rel(BackupKind::Registry, OpId(3)),
                sha256: sha256_bytes(b"x"),
                bytes: 1,
            },
            account_builtin: true,
        }
    }

    #[test]
    fn svcdef_checks_its_own_fields() {
        assert_eq!(svc().check(), Ok(()));
        let mut bad = svc();
        bad.schema = "purge.svcdef/2".into();
        assert!(bad.check().is_err());
        let mut bad = svc();
        bad.identity_sha256 = DIGEST.to_uppercase();
        assert!(bad.check().is_err());
        let mut bad = svc();
        bad.account_builtin = false;
        assert!(bad.check().is_err());
        let mut bad = svc();
        bad.key_backup.path = r"def\000003.json".into();
        assert!(bad.check().is_err());
        let mut bad = svc();
        bad.key_backup.path = r"reg\..\x.json".into();
        assert!(bad.check().is_err());
        assert!(svc().key_backup_for(OpId(3)).is_some());
        assert!(svc().key_backup_for(OpId(4)).is_none());
    }

    #[test]
    fn task_and_rule_digests_must_be_the_ones_their_fields_imply() {
        let identity = TaskIdentity {
            path: r"\Vendor\Update".into(),
            actions: vec![TaskAction::Exec {
                path: r"C:\Vendor\u.exe".into(),
                arguments: None,
                working_dir: None,
            }],
        };
        let mut task = TaskDef {
            schema: TASKDEF_SCHEMA.into(),
            path: identity.path.clone(),
            identity_sha256: identity.fp().sha256,
            actions: identity.actions.clone(),
            xml: "<Task/>".into(),
            sddl: String::new(),
            enabled: true,
            logon_type: 3,
            stored_password: false,
        };
        assert_eq!(task.check(), Ok(()));
        task.path = r"\Vendor\Other".into();
        assert!(task.check().is_err());

        let rule = "v2.31|Action=Allow|Dir=In|Name=X|";
        let mut fw = FwDef {
            schema: FWDEF_SCHEMA.into(),
            id: "{A}".into(),
            identity_sha256: FirewallIdentity {
                id: "{A}".into(),
                rule: rule.into(),
            }
            .fp()
            .sha256,
            rule: rule.into(),
            fields: vec![("Action".into(), "Allow".into())],
        };
        assert_eq!(fw.check(), Ok(()));
        fw.rule.push(' ');
        assert!(fw.check().is_err());
    }

    #[test]
    fn def_identity_must_equal_the_validated_stamp() {
        let def = svc();
        let stamp = |kind, sha256: &str| Stamp::Object {
            kind,
            sha256: sha256.into(),
        };
        assert_eq!(
            check_def_identity(&def, &stamp(ObjectKind::Service, DIGEST)),
            Ok(())
        );
        let other = DIGEST.replace('0', "1");
        for validated in [
            stamp(ObjectKind::Service, &other),
            stamp(ObjectKind::Task, DIGEST),
            Stamp::Package,
        ] {
            assert_eq!(
                check_def_identity(&def, &validated),
                Err(SkipReason::ChangedSinceScan)
            );
        }
    }
}
