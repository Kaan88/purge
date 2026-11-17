//! Typed actions: AppX/MSIX package removal (M2-X-TYPED; ENGINE_PLAN.md §5.6 SYS-APPX, §7.4, §7.5, §7.8).
//!
//! In M2 the only typed action is [`ExecOp::RemovePackage`]. Services, scheduled tasks and firewall rules
//! have no executor yet (their delete and recreate are deferred): [`unsupported_target`] turns such an
//! item into a skip with a "not supported in this version" text.
//!
//! # Removing a package
//!
//! The removal has no inverse ([`Inverse::None`]): the package and its application data are gone for
//! good. So it fails closed at every step:
//!
//! 1. **Acknowledgement.** Without [`IrreversibleAck::Acknowledged`] for the item the result is
//!    `Skipped{GateBlocked{ReversibilityNone}}` and nothing is looked at. The executor derives the
//!    acknowledgement from the confirmed selection; this module does not decide it.
//! 2. **Identity.** The plan's full name must be a valid full name (`appx_write::validate_full_name`). The
//!    package is then looked up by enumeration in the removal scope and must match the full name exactly
//!    (ASCII case-insensitive, as Windows compares them) with the family name the full name implies
//!    (`Name_PublisherId`). A package with a similar name is never a match. No match is
//!    [`ItemOutcome::Vanished`]; more than one, or a family that does not fit, is
//!    [`SkipReason::ChangedSinceScan`].
//! 3. **Refusals** (SYS-APPX: never framework, resource, Store-signed or System-signed packages, or
//!    packages with dependents): see [`refusal`]. A package whose signature kind or whose dependents
//!    cannot be determined is refused too.
//! 4. **Definition.** The full package record ([`PackageDefinition`]) is written to the op's definition
//!    file `def\<op>.json` in the session directory, flushed, read back through the store's checks,
//!    compared and hashed. The [`BackupRef`] goes into the intent's `definition`; undo never reads it.
//! 5. **Remove and verify.** After the intent is durable, [`remove_package`] enumerates again (the
//!    package must still be exactly the one recorded and pass the refusals), removes it by full name and
//!    enumerates once more. Only a package that enumeration no longer lists counts as removed: the
//!    deployment service's own answer is never trusted alone (with `RemoveForAllUsers` it reports success
//!    for a package that is not installed at all).
//!
//! **Scope.** [`Target::AppxPackage`] records only the full name, not whose registration to remove, so
//! the removal is always for the current user ([`RemovalScope::CurrentUser`]), the narrowest scope.
//! `RemoveForAllUsers` is never chosen here until the plan target can name it. The current user is the
//! process token's: when the run names the user the scan was made for (`GateCtx::bind_user`) and the
//! token belongs to another user, or its user cannot be read, the removal is refused before anything is
//! listed ([`RULE_OTHER_USER`]; review M2 final M12).
//!
//! # Journal contract
//!
//! This module never writes the journal; it returns values the executor journals, in the order the
//! journal module fixes (write-ahead by construction, see [`crate::journal`]):
//!
//! 1. [`prepare_remove_package`] returns [`Prepared::Decided`] (journal it with
//!    `JournalWriter::done_without_intent`; every decided outcome is one that
//!    `ItemOutcome::allowed_without_intent` accepts), [`Prepared::Ready`] (the definition file is written
//!    and verified), or a [`DefinitionError`] (no definition file, nothing removed: journal
//!    [`DefinitionError::outcome`] without an intent, or abort the run when
//!    [`DefinitionError::is_storage_integrity`]). It hits `backup.written` and `backup.verified`.
//! 2. The executor writes [`PackageRemoval::intent`] with `JournalWriter::intent`, which returns the
//!    token once the intent is flushed, then hits `act.before`.
//! 3. [`remove_package`] takes the token as proof of the durable intent, re-checks, removes, hits
//!    `act.after`, verifies, and returns the [`TypedResult`] the executor passes to
//!    `JournalWriter::done` with that token.
//!
//! Undo: [`undo_typed`] says how the undo of a typed op is journalled; a removed package is always
//! [`UndoConflict::Irreversible`], recorded with `undo_conflict_without_intent`, never an error.
//!
//! The Windows calls sit behind [`PackageBackend`]: [`WinPackages`] goes through `purge_win::appx` and
//! `purge_win::appx_write`; unit tests use a fake.

use std::fmt;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use purge_model::exec::journal::{Intent, ItemFacts, UndoConflict, UndoOutcome};
use purge_model::exec::op::{BackupRef, ExecOp, FailCode, Inverse, ItemOutcome, OpId, SkipReason};
use purge_model::{Blocker, CandidateId, Target};
use purge_win::appx::{self, AppxPackage, AppxScope, ListOptions, SignatureKind};
use purge_win::appx_write::{self, DeploymentError, RemovalScope, RemoveOutcome};
use serde::{Deserialize, Serialize};

use crate::fault;
use crate::gate::GateCtx;
use crate::journal::{IntentToken, sha256_bytes};
use crate::recover::{self, Probe};
use crate::storage::{BackupKind, SessionDir, StorageError, StoreFile, backup_rel};

#[cfg(test)]
mod tests;

/// The `schema` of a package definition file.
pub const DEFINITION_SCHEMA: &str = "purge.appxdef/1";

/// The largest definition file read back. A package record is a few kilobytes.
pub const MAX_DEFINITION_BYTES: u64 = 1 << 20;

/// Deny rule id: a framework package (other packages run on it).
pub const RULE_FRAMEWORK: &str = "appx.framework";
/// Deny rule id: a resource package (part of another package).
pub const RULE_RESOURCE: &str = "appx.resource";
/// Deny rule id: a package signed by the Microsoft Store.
pub const RULE_STORE_SIGNED: &str = "appx.store_signed";
/// Deny rule id: a package that is part of Windows (System-signed).
pub const RULE_SYSTEM_SIGNED: &str = "appx.system_signed";
/// Deny rule id: the package's signature kind cannot be read or is one this build does not know.
pub const RULE_SIGNATURE_UNKNOWN: &str = "appx.signature_unknown";
/// Deny rule id: whether other packages depend on the package cannot be determined.
pub const RULE_DEPENDENTS_UNKNOWN: &str = "appx.dependents_unknown";
/// Deny rule id: the run's scan was made for another user than the one Purge runs as, whose
/// registration a removal for the current user would change ([`GateCtx::package_user_refusal`]).
pub const RULE_OTHER_USER: &str = "appx.other_user";

/// `E_INVALIDARG`, reported when the real backend is handed a name that is not a full name.
const E_INVALIDARG: i32 = 0x8007_0057_u32 as i32;

// ---------------------------------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------------------------------

/// How a typed action ended for one item, with a line for the report. The executor journals `outcome`;
/// `detail` says why (an [`ItemOutcome::Skipped`] has no text of its own).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedResult {
    /// The outcome to journal.
    pub outcome: ItemOutcome,
    /// Why, for the report; may be empty for a plain success.
    pub detail: String,
}

impl TypedResult {
    fn new(outcome: ItemOutcome, detail: impl Into<String>) -> TypedResult {
        TypedResult {
            outcome,
            detail: detail.into(),
        }
    }

    fn skipped(reason: SkipReason, detail: impl Into<String>) -> TypedResult {
        TypedResult::new(ItemOutcome::Skipped { reason }, detail)
    }

    fn blocked(blocker: Blocker, detail: impl Into<String>) -> TypedResult {
        TypedResult::skipped(SkipReason::GateBlocked { blocker }, detail)
    }

    fn failed(code: FailCode, os_error: Option<u32>, detail: impl Into<String>) -> TypedResult {
        let detail = detail.into();
        TypedResult {
            outcome: ItemOutcome::Failed {
                code,
                os_error,
                detail: detail.clone(),
            },
            detail,
        }
    }
}

/// Whether the user acknowledged, for this item, that its removal cannot be undone. The executor fills it
/// from the confirmed selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrreversibleAck {
    /// The item may be removed although it cannot be undone.
    Acknowledged,
    /// No acknowledgement: the item is skipped with the `ReversibilityNone` gate.
    Missing,
}

/// The skip for an item whose target has no executor in this version: none since M1b. Services,
/// scheduled tasks and firewall rules are run by `act_service`, `act_task` and `act_firewall`
/// (M1B-X-INTEG); one without its scan-time digest is skipped by the run as `ChangedSinceScan` before
/// any backup. Kept so that a target without an executor has one place to be named again; `None` for
/// every target.
pub fn unsupported_target(target: &Target) -> Option<TypedResult> {
    let _ = target;
    None
}

// ---------------------------------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------------------------------

/// One package as the backend lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageInfo {
    /// What `purge_win::appx` reports. Its own `dependencies` are moved to [`PackageInfo::dependencies`]
    /// and left `None` here, so the dependencies have one place.
    pub package: AppxPackage,
    /// Full names of the packages this package depends on (`Package.Dependencies`), or `None` when the
    /// backend cannot tell. One unknown entry in a listing makes the dependents of every package in it
    /// unknown, so nothing in that listing is removed.
    pub dependencies: Option<Vec<String>>,
}

/// Enumerating packages failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("listing packages failed: {detail}")]
pub struct ListError {
    /// The HRESULT or OS error code, when there is one.
    pub code: Option<i32>,
    /// What went wrong.
    pub detail: String,
}

/// The package calls a removal needs. [`WinPackages`] is the real one.
pub trait PackageBackend {
    /// Every package registered in `scope` ([`RemovalScope::CurrentUser`]: the calling user's).
    fn list(&self, scope: RemovalScope) -> Result<Vec<PackageInfo>, ListError>;

    /// Removes the package `full_name` for `scope`. Irreversible.
    fn remove(&self, full_name: &str, scope: RemovalScope) -> RemoveOutcome;
}

/// The real backend over `purge_win::appx` (enumeration) and `purge_win::appx_write` (removal).
///
/// Its listings read every package's dependencies (`ListOptions::dependencies`); a package whose list
/// cannot be read has [`PackageInfo::dependencies`] `None`, which refuses every removal from that listing
/// with [`RULE_DEPENDENTS_UNKNOWN`]. Whether a package is marked non-removable is not available through
/// the public package API, so it is not checked here; the deployment service is expected to refuse such a
/// removal itself, which ends `Failed` with the package still listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinPackages {
    timeout: Duration,
}

impl WinPackages {
    /// The backend with `appx_write::DEFAULT_REMOVE_TIMEOUT`.
    pub fn new() -> WinPackages {
        WinPackages {
            timeout: appx_write::DEFAULT_REMOVE_TIMEOUT,
        }
    }

    /// The backend with another bound on one removal.
    pub fn with_timeout(timeout: Duration) -> WinPackages {
        WinPackages { timeout }
    }
}

impl Default for WinPackages {
    fn default() -> WinPackages {
        WinPackages::new()
    }
}

impl PackageBackend for WinPackages {
    fn list(&self, scope: RemovalScope) -> Result<Vec<PackageInfo>, ListError> {
        let scope = match scope {
            RemovalScope::CurrentUser => AppxScope::CurrentUser,
            RemovalScope::AllUsers => AppxScope::AllUsers,
        };
        let options = ListOptions { dependencies: true };
        let packages = appx::list_packages_with(scope, options).map_err(|e| ListError {
            code: e.raw_os_error(),
            detail: e.to_string(),
        })?;
        Ok(packages
            .into_iter()
            .map(|mut package| {
                let dependencies = package.dependencies.take();
                PackageInfo {
                    package,
                    dependencies,
                }
            })
            .collect())
    }

    fn remove(&self, full_name: &str, scope: RemovalScope) -> RemoveOutcome {
        match appx_write::remove_package(full_name, scope, self.timeout) {
            Ok(outcome) => outcome,
            Err(e) => RemoveOutcome::Failed(DeploymentError {
                hresult: E_INVALIDARG,
                extended_hresult: None,
                error_text: Some(e.to_string()),
                activity_id: None,
            }),
        }
    }
}

// ---------------------------------------------------------------------------------------------------
// Definition file
// ---------------------------------------------------------------------------------------------------

/// One user a package is registered for, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefinitionUser {
    /// User SID string.
    pub sid: String,
    /// The package's install state for that user (`Installed`, `Staged`, ...).
    pub install_state: String,
}

/// The record of a package kept in `def\<op>.json` before it is removed (`purge.appxdef/1`). Undo does not
/// read it: it documents what was removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageDefinition {
    /// Always [`DEFINITION_SCHEMA`].
    pub schema: String,
    /// The op that removes the package.
    pub op: OpId,
    /// The plan item.
    pub item: CandidateId,
    /// Whose registration is removed: `CurrentUser` or `AllUsers`.
    pub scope: String,
    /// Package full name, as enumerated.
    pub full_name: String,
    /// Package family name, as enumerated.
    pub family_name: String,
    /// The name field of the full name.
    pub name: String,
    /// The version field of the full name.
    pub version: String,
    /// The architecture field of the full name.
    pub architecture: String,
    /// The resource id field of the full name; may be empty.
    pub resource_id: String,
    /// The publisher id field of the full name.
    pub publisher_id: String,
    /// `Package.InstalledPath`, when available.
    pub installed_location: Option<String>,
    /// `Package.EffectiveExternalPath` of a sparse package.
    pub effective_external_path: Option<String>,
    /// Signature kind (`Developer`, `Enterprise`, ...), when available.
    pub signature_kind: Option<String>,
    /// Framework package.
    pub is_framework: bool,
    /// Resource package.
    pub is_resource_package: bool,
    /// Users the package is registered for (only filled for an all-users listing).
    pub users: Vec<DefinitionUser>,
    /// Full names of the packages it depends on; `None` when the backend cannot tell.
    pub dependencies: Option<Vec<String>>,
}

impl PackageDefinition {
    fn new(op: OpId, item: &CandidateId, scope: RemovalScope, info: &PackageInfo) -> Self {
        let p = &info.package;
        let fields: Vec<&str> = p.full_name.split('_').collect();
        let field = |i: usize| fields.get(i).copied().unwrap_or_default().to_owned();
        PackageDefinition {
            schema: DEFINITION_SCHEMA.to_owned(),
            op,
            item: item.clone(),
            scope: scope_name(scope).to_owned(),
            full_name: p.full_name.clone(),
            family_name: p.family_name.clone(),
            name: field(0),
            version: field(1),
            architecture: field(2),
            resource_id: field(3),
            publisher_id: field(4),
            installed_location: p.installed_location.clone(),
            effective_external_path: p.effective_external_path.clone(),
            signature_kind: p.signature_kind.map(|k| format!("{k:?}")),
            is_framework: p.is_framework,
            is_resource_package: p.is_resource_package,
            users: p
                .users
                .iter()
                .map(|u| DefinitionUser {
                    sid: u.sid.clone(),
                    install_state: format!("{:?}", u.install_state),
                })
                .collect(),
            dependencies: info.dependencies.clone(),
        }
    }
}

/// The definition file could not be written and verified. Nothing was removed and no intent is needed.
#[derive(Debug, thiserror::Error)]
pub enum DefinitionError {
    /// The store refused (integrity check, existing file, I/O on the layout).
    #[error("definition file: {0}")]
    Storage(#[from] StorageError),
    /// Writing, flushing or reading the file failed.
    #[error("definition file {}: {op} failed: {detail}", .path.display())]
    File {
        /// What was being done.
        op: &'static str,
        /// The file.
        path: PathBuf,
        /// The error.
        detail: String,
    },
    /// The file did not read back as written.
    #[error("definition file {} did not read back as written", .0.display())]
    ReadBackMismatch(PathBuf),
    /// The definition could not be encoded.
    #[error("the package definition could not be encoded: {0}")]
    Encode(String),
}

impl DefinitionError {
    /// The outcome to journal for the item (without an intent): `Skipped{NoVerifiedBackup}`.
    pub fn outcome(&self) -> ItemOutcome {
        ItemOutcome::Skipped {
            reason: SkipReason::NoVerifiedBackup,
        }
    }

    /// Whether a storage directory failed its integrity check, which concerns the whole run
    /// (`AbortReason::StorageIntegrity`) rather than this item.
    pub fn is_storage_integrity(&self) -> bool {
        matches!(
            self,
            DefinitionError::Storage(StorageError::Integrity { .. })
        )
    }
}

/// Writes `def` to the op's definition file through the store's handles only: create-new with the
/// store's file descriptor ([`SessionDir::create_file`]), write, flush the file and its directory through
/// that handle and its directory's checked handle (`backup.written`), read the bytes back through the
/// same handle; then close it, re-open the file through the store's checks ([`SessionDir::open_file`]),
/// require the same file id, read it back through that handle, compare bytes and document
/// (`backup.verified`), and return its reference with the SHA-256 of the bytes read back. A failure while
/// the created handle is open discards the file through that handle ([`StoreFile::discard`]); nothing is
/// removed by name.
///
/// A definition file of that name that a crash left before the op's intent (named by no journal record)
/// is adopted when it parses to exactly `def`, the definition built now from the fresh listing: its
/// reference is then computed from the bytes read through the store's checked handle. Otherwise it is
/// deleted through the store ([`SessionDir::delete_backup_file`]) and the file written anew.
fn write_definition(
    session: &SessionDir,
    op: OpId,
    def: &PackageDefinition,
) -> Result<BackupRef, DefinitionError> {
    let rel = backup_rel(BackupKind::Definition, op);
    let text = serde_json::to_vec(def).map_err(|e| DefinitionError::Encode(e.to_string()))?;
    if u64::try_from(text.len()).map_or(true, |n| n > MAX_DEFINITION_BYTES) {
        return Err(DefinitionError::Encode(format!(
            "the definition has {} bytes, more than {MAX_DEFINITION_BYTES}",
            text.len()
        )));
    }
    let mut created = match session.create_file(&rel) {
        Err(e) if crate::act_reg::already_exists(&e) => {
            if let Some(adopted) = adopt_definition(session, &rel, def) {
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
    let now = opened.file_id();
    if now.volume_serial != id.volume_serial || now.id != id.id {
        return Err(DefinitionError::ReadBackMismatch(checked));
    }
    let back = opened.read_all(MAX_DEFINITION_BYTES)?;
    if back != text {
        return Err(DefinitionError::ReadBackMismatch(checked));
    }
    let parsed: PackageDefinition = serde_json::from_slice(&back)
        .map_err(|_| DefinitionError::ReadBackMismatch(checked.clone()))?;
    if &parsed != def {
        return Err(DefinitionError::ReadBackMismatch(checked));
    }
    let reference = BackupRef {
        path: rel,
        sha256: sha256_bytes(&back),
        bytes: back.len() as u64,
    };
    fault::point(fault::BACKUP_VERIFIED);
    Ok(reference)
}

/// The definition file `rel` as it is, when it parses to exactly `def`; `None` otherwise.
fn adopt_definition(session: &SessionDir, rel: &str, def: &PackageDefinition) -> Option<BackupRef> {
    let mut file = session.open_file(rel).ok()?;
    let bytes = file.read_all(MAX_DEFINITION_BYTES).ok()?;
    drop(file);
    let parsed: PackageDefinition = serde_json::from_slice(&bytes).ok()?;
    (&parsed == def).then(|| BackupRef {
        path: rel.to_owned(),
        sha256: sha256_bytes(&bytes),
        bytes: bytes.len() as u64,
    })
}

/// Writes `text` through the created store file, flushes it and its directory (through the directory's
/// checked handle), and reads it back through the same handle.
fn write_created(file: &mut StoreFile, text: &[u8]) -> Result<(), DefinitionError> {
    if let Err(e) = file.write_all(text) {
        return Err(DefinitionError::File {
            op: "write",
            path: file.report_path(),
            detail: e.to_string(),
        });
    }
    file.sync()?;
    file.sync_dir()?;
    if file.read_all(MAX_DEFINITION_BYTES)? != text {
        return Err(DefinitionError::ReadBackMismatch(file.report_path()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------
// Identity and refusals
// ---------------------------------------------------------------------------------------------------

fn scope_name(scope: RemovalScope) -> &'static str {
    match scope {
        RemovalScope::CurrentUser => "CurrentUser",
        RemovalScope::AllUsers => "AllUsers",
    }
}

/// The scope a removal uses. The plan target records only the full name, so the narrowest scope.
fn removal_scope(_full_name: &str) -> RemovalScope {
    RemovalScope::CurrentUser
}

/// The family name a valid full name implies: `Name_PublisherId`.
fn family_of(full_name: &str) -> Option<String> {
    let fields: Vec<&str> = full_name.split('_').collect();
    match fields[..] {
        [name, _, _, _, publisher] => Some(format!("{name}_{publisher}")),
        _ => None,
    }
}

/// What enumeration says about the package the plan names.
enum Lookup<'a> {
    /// Not registered in the scope.
    Absent,
    /// Exactly one package matches the full name and its family.
    Found(&'a PackageInfo),
    /// The match is not what the plan names (two matches, or another family).
    Mismatch(String),
}

/// Finds the plan's package in a listing: full name equal (ASCII case-insensitive) and the family the full
/// name implies.
fn lookup<'a>(full_name: &str, listing: &'a [PackageInfo]) -> Lookup<'a> {
    let matches: Vec<&PackageInfo> = listing
        .iter()
        .filter(|p| p.package.full_name.eq_ignore_ascii_case(full_name))
        .collect();
    match matches[..] {
        [] => Lookup::Absent,
        [one] => {
            let family_fits = family_of(full_name)
                .is_some_and(|family| family.eq_ignore_ascii_case(&one.package.family_name));
            if family_fits {
                Lookup::Found(one)
            } else {
                Lookup::Mismatch(format!(
                    "package {full_name} is registered with family {:?}, not the family its full name \
                     implies",
                    one.package.family_name
                ))
            }
        }
        _ => Lookup::Mismatch(format!(
            "{} packages are registered under the full name {full_name}",
            matches.len()
        )),
    }
}

/// Why `info` must not be removed, given the rest of the `listing` it came from (SYS-APPX). Checked in
/// this order:
///
/// | Condition | Blocker |
/// |---|---|
/// | framework package | `DenyListed{appx.framework}` |
/// | resource package | `DenyListed{appx.resource}` |
/// | Store-signed | `DenyListed{appx.store_signed}` |
/// | System-signed | `DenyListed{appx.system_signed}` |
/// | signature kind unavailable or unknown | `DenyListed{appx.signature_unknown}` |
/// | another listed package's dependencies are unknown | `DenyListed{appx.dependents_unknown}` |
/// | another listed package depends on it | `ReferencedByOtherApp{<that full name>}` |
///
/// Unsigned, developer- and enterprise-signed packages pass the signature check.
pub fn refusal(info: &PackageInfo, listing: &[PackageInfo]) -> Option<(Blocker, String)> {
    let p = &info.package;
    let deny = |rule: &str, why: String| {
        Some((
            Blocker::DenyListed {
                rule: rule.to_owned(),
            },
            why,
        ))
    };
    if p.is_framework {
        return deny(
            RULE_FRAMEWORK,
            format!("{} is a framework package", p.full_name),
        );
    }
    if p.is_resource_package {
        return deny(
            RULE_RESOURCE,
            format!("{} is a resource package", p.full_name),
        );
    }
    match p.signature_kind {
        Some(SignatureKind::None | SignatureKind::Developer | SignatureKind::Enterprise) => {}
        Some(SignatureKind::Store) => {
            return deny(
                RULE_STORE_SIGNED,
                format!("{} is signed by the Microsoft Store", p.full_name),
            );
        }
        Some(SignatureKind::System) => {
            return deny(
                RULE_SYSTEM_SIGNED,
                format!("{} is part of Windows", p.full_name),
            );
        }
        Some(SignatureKind::Other(kind)) => {
            return deny(
                RULE_SIGNATURE_UNKNOWN,
                format!("{} has signature kind {kind}, unknown here", p.full_name),
            );
        }
        None => {
            return deny(
                RULE_SIGNATURE_UNKNOWN,
                format!("the signature kind of {} cannot be read", p.full_name),
            );
        }
    }
    let others = listing
        .iter()
        .filter(|o| !o.package.full_name.eq_ignore_ascii_case(&p.full_name));
    let mut unknown = 0usize;
    for other in others {
        match &other.dependencies {
            None => unknown += 1,
            Some(deps) if deps.iter().any(|d| d.eq_ignore_ascii_case(&p.full_name)) => {
                return Some((
                    Blocker::ReferencedByOtherApp {
                        app: other.package.full_name.clone(),
                    },
                    format!("{} depends on {}", other.package.full_name, p.full_name),
                ));
            }
            Some(_) => {}
        }
    }
    if unknown > 0 {
        return deny(
            RULE_DEPENDENTS_UNKNOWN,
            format!(
                "the dependencies of {unknown} other package(s) cannot be read, so whether anything \
                 depends on {} is unknown",
                p.full_name
            ),
        );
    }
    None
}

/// Text of a list failure for a result.
fn list_failure(e: &ListError) -> (Option<u32>, String) {
    (e.code.and_then(win32_code), e.to_string())
}

/// The Win32 code inside an `HRESULT_FROM_WIN32` value, or a plain non-negative code.
fn win32_code(code: i32) -> Option<u32> {
    let bits = code as u32;
    if bits & 0xFFFF_0000 == 0x8007_0000 {
        Some(bits & 0xFFFF)
    } else if code > 0 {
        Some(bits)
    } else {
        None
    }
}

struct Hex(i32);

impl fmt::Display for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}", self.0 as u32)
    }
}

/// One line on a deployment error.
fn deployment_text(e: &DeploymentError) -> String {
    let mut text = format!("HRESULT {}", Hex(e.hresult));
    if let Some(ext) = e.extended_hresult {
        text.push_str(&format!(", extended {}", Hex(ext)));
    }
    if let Some(msg) = &e.error_text {
        text.push_str(&format!(": {}", msg.trim()));
    }
    if let Some(id) = &e.activity_id {
        text.push_str(&format!(" (activity {id})"));
    }
    text
}

// ---------------------------------------------------------------------------------------------------
// Prepare and act
// ---------------------------------------------------------------------------------------------------

/// What [`prepare_remove_package`] decided.
#[derive(Debug)]
pub enum Prepared {
    /// Decided without changing anything: journal the outcome with `done_without_intent`.
    Decided(TypedResult),
    /// The definition is written and verified: journal [`PackageRemoval::intent`], then call
    /// [`remove_package`] with its token.
    Ready(Box<PackageRemoval>),
}

/// A package removal that passed every check and whose definition is on disk. Only
/// [`prepare_remove_package`] makes one, and [`remove_package`] consumes it.
#[derive(Debug)]
pub struct PackageRemoval {
    intent: Intent,
    full_name: String,
    scope: RemovalScope,
    recorded: PackageInfo,
    definition: PackageDefinition,
}

impl PackageRemoval {
    /// The intent to journal before the removal: the op, [`Inverse::None`], the definition file and
    /// [`ItemFacts::Package`]. It passes `Intent::is_consistent`.
    pub fn intent(&self) -> &Intent {
        &self.intent
    }

    /// The definition written to the op's definition file.
    pub fn definition(&self) -> &PackageDefinition {
        &self.definition
    }

    /// Whose registration is removed.
    pub fn scope(&self) -> RemovalScope {
        self.scope
    }
}

/// [`prepare_remove_package`] for op `op` as journalled: the plan item and the op are taken from the op's
/// `validated` record that the executor wrote and handed to the gate context (`GateCtx::record`), so
/// they cannot differ from what the journal holds. This is the form the executor uses.
///
/// An op with no such record (never validated, refused at validation, or a package recorded as
/// [`ItemFacts::Absent`] or [`ItemFacts::Refused`], which `GateCtx::record` keeps no record of) and a
/// record of another kind (not an [`ExecOp::RemovePackage`] with [`ItemFacts::Package`]) are
/// [`Prepared::Decided`] `Failed{Internal}`, before any system call.
// The error type of `prepare_remove_package`, unchanged.
#[allow(clippy::result_large_err)]
pub fn prepare_remove_package_recorded(
    backend: &dyn PackageBackend,
    ctx: &GateCtx,
    session: &SessionDir,
    op: OpId,
    ack: IrreversibleAck,
) -> Result<Prepared, DefinitionError> {
    let Some((exec_op, record)) = ctx.journalled(op) else {
        return Ok(Prepared::Decided(TypedResult::failed(
            FailCode::Internal,
            None,
            format!("op {op} has no journalled validated record in this run; nothing done"),
        )));
    };
    let is_package = matches!(exec_op, ExecOp::RemovePackage { .. })
        && matches!(record.facts, ItemFacts::Package);
    if !is_package {
        return Ok(Prepared::Decided(TypedResult::failed(
            FailCode::Internal,
            None,
            format!(
                "the validated record of op {op} is a {} record, not a package removal; nothing done",
                exec_op.name()
            ),
        )));
    }
    if let Some(why) = ctx.package_user_refusal() {
        return Ok(Prepared::Decided(other_user(exec_op, &why)));
    }
    prepare_remove_package(backend, session, op, &record.item, exec_op, ack)
}

/// The result of a package removal refused because Purge does not run as the user the scan was made
/// for ([`GateCtx::package_user_refusal`]): `Skipped{GateBlocked{DenyListed{appx.other_user}}}`, before
/// any package call.
fn other_user(exec_op: &ExecOp, why: &str) -> TypedResult {
    let full_name = match exec_op {
        ExecOp::RemovePackage { full_name } => full_name.as_str(),
        _ => "",
    };
    TypedResult::blocked(
        Blocker::DenyListed {
            rule: RULE_OTHER_USER.to_owned(),
        },
        format!("package {full_name}: {why}; left untouched"),
    )
}

/// Decides whether op `op` (plan item `item`, `exec_op` an [`ExecOp::RemovePackage`]) may remove its
/// package, and if so writes the package's definition file into `session`. Never removes anything.
///
/// The lower-level form: the caller vouches that `item` and `exec_op` are those of the op's journalled
/// `validated` record. The executor uses [`prepare_remove_package_recorded`], which takes them from
/// that record.
///
/// Returns [`Prepared::Decided`] for: a missing acknowledgement (`Skipped{GateBlocked{ReversibilityNone}}`,
/// before any system call), an op that is not a package removal or a full name that is not valid
/// (`Failed{Internal}`), a failed enumeration (`Failed{PackageApi}`), an absent package (`Vanished`), a
/// package that is not the one named (`Skipped{ChangedSinceScan}`), and the refusals of [`refusal`]
/// (`Skipped{GateBlocked{..}}`).
pub fn prepare_remove_package(
    backend: &dyn PackageBackend,
    session: &SessionDir,
    op: OpId,
    item: &CandidateId,
    exec_op: &ExecOp,
    ack: IrreversibleAck,
) -> Result<Prepared, DefinitionError> {
    let decided = |r: TypedResult| Ok(Prepared::Decided(r));
    let ExecOp::RemovePackage { full_name } = exec_op else {
        return decided(TypedResult::failed(
            FailCode::Internal,
            None,
            format!("{} is not a typed op; nothing done", exec_op.name()),
        ));
    };
    if ack != IrreversibleAck::Acknowledged {
        return decided(TypedResult::blocked(
            Blocker::ReversibilityNone,
            format!(
                "removing package {full_name} cannot be undone and was not acknowledged; left untouched"
            ),
        ));
    }
    if let Err(e) = appx_write::validate_full_name(full_name) {
        return decided(TypedResult::failed(
            FailCode::Internal,
            None,
            format!("the plan names {full_name:?}, which is not a package full name: {e}"),
        ));
    }
    let scope = removal_scope(full_name);
    let listing = match backend.list(scope) {
        Ok(listing) => listing,
        Err(e) => {
            let (os_error, text) = list_failure(&e);
            return decided(TypedResult::failed(
                FailCode::PackageApi,
                os_error,
                format!("{text}; package {full_name} left untouched"),
            ));
        }
    };
    let info = match lookup(full_name, &listing) {
        Lookup::Absent => {
            return decided(TypedResult::new(
                ItemOutcome::Vanished,
                format!(
                    "package {full_name} is not registered for the {} scope",
                    scope_name(scope)
                ),
            ));
        }
        Lookup::Mismatch(why) => {
            return decided(TypedResult::skipped(SkipReason::ChangedSinceScan, why));
        }
        Lookup::Found(info) => info.clone(),
    };
    if let Some((blocker, why)) = refusal(&info, &listing) {
        return decided(TypedResult::blocked(
            blocker,
            format!("{why}; left untouched"),
        ));
    }
    let definition = PackageDefinition::new(op, item, scope, &info);
    let reference = write_definition(session, op, &definition)?;
    let intent = Intent {
        op,
        item: item.clone(),
        exec_op: exec_op.clone(),
        inverse: Inverse::None,
        definition: Some(reference),
        pre: ItemFacts::Package,
    };
    Ok(Prepared::Ready(Box::new(PackageRemoval {
        intent,
        full_name: full_name.clone(),
        scope,
        recorded: info,
        definition,
    })))
}

/// Removes the package of `removal`, whose intent `token` proves durable, and verifies by enumeration that
/// it is gone. The executor hits `act.before` before the call and passes the result to
/// `JournalWriter::done` with the token.
///
/// Right before the removal the package is enumerated again: absent is `Vanished`; not exactly the
/// recorded package (any field, its dependencies included) is `Skipped{ChangedSinceScan}`; a refusal of
/// [`refusal`] against the fresh listing is `Skipped{GateBlocked{..}}`. After the removal (and the
/// `act.after` fault point) the scope is enumerated once more:
///
/// | Deployment result | Still listed | Not listed |
/// |---|---|---|
/// | `Removed` | `Failed{VerifyFailed}` | `Done` |
/// | `NotFound` | `Failed{PackageApi}` | `Vanished` |
/// | `InUse` | `Failed{InUse}` | `Done` |
/// | `Failed` (access denied) | `Failed{AccessDenied}` | `Done` |
/// | `Failed` (other) | `Failed{PackageApi}` | `Done` |
/// | `TimedOut` | `Failed{PackageApi}` | `Done` |
///
/// A failed enumeration after the removal is `Failed{VerifyFailed}` (state unknown). A token of another op
/// is `Failed{Internal}` and nothing is called.
pub fn remove_package(
    backend: &dyn PackageBackend,
    removal: Box<PackageRemoval>,
    token: &IntentToken,
) -> TypedResult {
    let PackageRemoval {
        intent,
        full_name,
        scope,
        recorded,
        ..
    } = *removal;
    if token.op() != intent.op || token.item() != &intent.item {
        return TypedResult::failed(
            FailCode::Internal,
            None,
            format!(
                "the intent token is for op {}, not op {}; package {full_name} left untouched",
                token.op(),
                intent.op
            ),
        );
    }
    let listing = match backend.list(scope) {
        Ok(listing) => listing,
        Err(e) => {
            let (os_error, text) = list_failure(&e);
            return TypedResult::failed(
                FailCode::PackageApi,
                os_error,
                format!("{text}; package {full_name} left untouched"),
            );
        }
    };
    match lookup(&full_name, &listing) {
        Lookup::Absent => {
            return TypedResult::new(
                ItemOutcome::Vanished,
                format!("package {full_name} was unregistered before Purge removed it"),
            );
        }
        Lookup::Mismatch(why) => {
            return TypedResult::skipped(SkipReason::ChangedSinceScan, why);
        }
        Lookup::Found(now) if *now != recorded => {
            return TypedResult::skipped(
                SkipReason::ChangedSinceScan,
                format!("package {full_name} changed after its definition was recorded"),
            );
        }
        Lookup::Found(now) => {
            if let Some((blocker, why)) = refusal(now, &listing) {
                return TypedResult::blocked(blocker, format!("{why}; left untouched"));
            }
        }
    }

    let outcome = backend.remove(&full_name, scope);
    fault::point(fault::ACT_AFTER);

    let still_listed = match backend.list(scope) {
        Ok(after) => !matches!(lookup(&full_name, &after), Lookup::Absent),
        Err(e) => {
            return TypedResult::failed(
                FailCode::VerifyFailed,
                None,
                format!(
                    "the removal of {full_name} returned {}, but whether it is gone cannot be \
                     verified: {e}",
                    outcome_name(&outcome)
                ),
            );
        }
    };
    verdict(&full_name, scope, &outcome, still_listed)
}

fn outcome_name(outcome: &RemoveOutcome) -> &'static str {
    match outcome {
        RemoveOutcome::Removed => "Removed",
        RemoveOutcome::NotFound => "NotFound",
        RemoveOutcome::InUse(_) => "InUse",
        RemoveOutcome::Failed(_) => "Failed",
        RemoveOutcome::TimedOut => "TimedOut",
    }
}

/// The result of a removal from the deployment result and the enumeration after it.
fn verdict(
    full_name: &str,
    scope: RemovalScope,
    outcome: &RemoveOutcome,
    still_listed: bool,
) -> TypedResult {
    let scope = scope_name(scope);
    if !still_listed {
        return match outcome {
            RemoveOutcome::Removed => TypedResult::new(ItemOutcome::Done, ""),
            RemoveOutcome::NotFound => TypedResult::new(
                ItemOutcome::Vanished,
                format!("package {full_name} was unregistered before Purge removed it"),
            ),
            RemoveOutcome::InUse(e) | RemoveOutcome::Failed(e) => TypedResult::new(
                ItemOutcome::Done,
                format!(
                    "the package API reported a failure ({}), but {full_name} is no longer \
                     registered for the {scope} scope",
                    deployment_text(e)
                ),
            ),
            RemoveOutcome::TimedOut => TypedResult::new(
                ItemOutcome::Done,
                format!(
                    "the removal timed out, but {full_name} is no longer registered for the {scope} \
                     scope"
                ),
            ),
        };
    }
    match outcome {
        RemoveOutcome::Removed => TypedResult::failed(
            FailCode::VerifyFailed,
            None,
            format!(
                "the package API reported {full_name} removed, but it is still registered for the \
                 {scope} scope"
            ),
        ),
        RemoveOutcome::NotFound => TypedResult::failed(
            FailCode::PackageApi,
            None,
            format!(
                "the package API did not find {full_name}, but it is registered for the {scope} scope"
            ),
        ),
        RemoveOutcome::InUse(e) => TypedResult::failed(
            FailCode::InUse,
            win32_code(e.hresult),
            format!("{full_name} is in use: {}", deployment_text(e)),
        ),
        RemoveOutcome::Failed(e) => {
            let code = if e.is_access_denied() {
                FailCode::AccessDenied
            } else {
                FailCode::PackageApi
            };
            TypedResult::failed(
                code,
                win32_code(e.hresult),
                format!("removing {full_name} failed: {}", deployment_text(e)),
            )
        }
        RemoveOutcome::TimedOut => TypedResult::failed(
            FailCode::PackageApi,
            None,
            format!("removing {full_name} timed out and was cancelled; it is still registered"),
        ),
    }
}

// ---------------------------------------------------------------------------------------------------
// Undo
// ---------------------------------------------------------------------------------------------------

/// How the undo of a typed op is journalled. A typed op never runs an inverse, so neither variant needs
/// an `undo_intent`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypedUndo {
    /// The op changed nothing: `undo_done_without_intent(op, outcome)`.
    Done(UndoOutcome),
    /// The op cannot be undone: `undo_conflict_without_intent(op, conflict, detail)`.
    Conflict {
        /// Always [`UndoConflict::Irreversible`] for a removed package.
        conflict: UndoConflict,
        /// Text for the report.
        detail: String,
    },
}

/// The undo of a typed op: what to journal, as a record, never an error. `done` is the op's `done`
/// outcome, or `None` when the journal holds only its intent (the run stopped during the removal).
///
/// A package removal whose outcome left the system unchanged (`Vanished`, `Skipped`, or `Failed` with any
/// code but `VerifyFailed`) is [`UndoOutcome::NothingToUndo`]; every other case (`Done`, `VerifyFailed`,
/// intent only) is [`UndoConflict::Irreversible`]. `None` for an op that is not typed.
pub fn undo_typed(
    exec_op: &ExecOp,
    inverse: &Inverse,
    done: Option<&ItemOutcome>,
) -> Option<TypedUndo> {
    let ExecOp::RemovePackage { full_name } = exec_op else {
        return None;
    };
    let unchanged = match done {
        Some(ItemOutcome::Failed { code, .. }) => *code != FailCode::VerifyFailed,
        Some(outcome) => !outcome.changed_system(),
        None => false,
    };
    if unchanged {
        return Some(TypedUndo::Done(UndoOutcome::NothingToUndo));
    }
    let note = if matches!(inverse, Inverse::None) {
        ""
    } else {
        " (the journal names an inverse for it, which is ignored)"
    };
    Some(TypedUndo::Conflict {
        conflict: UndoConflict::Irreversible,
        detail: format!(
            "package {full_name} was removed (or its removal may have run); removing a package cannot be \
             undone{note}"
        ),
    })
}

// ---------------------------------------------------------------------------------------------------
// Recovery: an intent without its `done`
// ---------------------------------------------------------------------------------------------------

/// What became of the package removal of `intent`, an intent with no `done` (recovery's probe; see the
/// table in [`crate::recover`]): not listed is `Done(Done)`, listed is `NotDone`, a failed listing is
/// `Attention`. Changes nothing.
pub fn probe_package(backend: &dyn PackageBackend, intent: &Intent) -> Probe {
    let ExecOp::RemovePackage { full_name } = &intent.exec_op else {
        return Probe::Attention {
            detail: "the intent is not a package removal".to_owned(),
        };
    };
    let listed = backend
        .list(removal_scope(full_name))
        .ok()
        .map(|listing| !matches!(lookup(full_name, &listing), Lookup::Absent));
    recover::probe_package(listed)
}

/// Removes the package of `intent` forward, under the token `JournalWriter::resume_intent` handed out
/// for it (recovery's resume of an op its probe found still listed), after the checks of the run: the
/// header's acknowledgement of irreversible removals (`allow_irreversible`), the package as listed now
/// being the one the intent's definition file (its backup reference) records, and no [`refusal`] against
/// the fresh listing, and Purge running as the user the scan was made for
/// ([`GateCtx::package_user_refusal`] of `ctx`, the resumed run's context). Verified as
/// [`remove_package`] verifies. A token of another op is `Failed{Internal}` and nothing is called.
pub fn complete_package(
    backend: &dyn PackageBackend,
    ctx: &GateCtx,
    session: &SessionDir,
    intent: &Intent,
    allow_irreversible: bool,
    token: &IntentToken,
) -> TypedResult {
    let ExecOp::RemovePackage { full_name } = &intent.exec_op else {
        return TypedResult::failed(
            FailCode::Internal,
            None,
            "the intent is not a package removal",
        );
    };
    if token.op() != intent.op || token.item() != &intent.item {
        return TypedResult::failed(
            FailCode::Internal,
            None,
            format!(
                "the intent token is for op {}, not op {}; package {full_name} left untouched",
                token.op(),
                intent.op
            ),
        );
    }
    if !allow_irreversible {
        return TypedResult::blocked(
            Blocker::ReversibilityNone,
            format!("package {full_name}: irreversible removals were not acknowledged"),
        );
    }
    if let Some(why) = ctx.package_user_refusal() {
        return other_user(&intent.exec_op, &why);
    }
    let scope = removal_scope(full_name);
    let listing = match backend.list(scope) {
        Ok(listing) => listing,
        Err(e) => {
            let (os_error, text) = list_failure(&e);
            return TypedResult::failed(
                FailCode::PackageApi,
                os_error,
                format!("{text}; package {full_name} left untouched"),
            );
        }
    };
    let now = match lookup(full_name, &listing) {
        Lookup::Absent => {
            return TypedResult::new(
                ItemOutcome::Vanished,
                format!("package {full_name} is no longer registered"),
            );
        }
        Lookup::Mismatch(why) => return TypedResult::skipped(SkipReason::ChangedSinceScan, why),
        Lookup::Found(now) => now,
    };
    let recorded = intent
        .definition
        .as_ref()
        .and_then(|reference| read_definition(session, reference));
    if recorded != Some(PackageDefinition::new(intent.op, &intent.item, scope, now)) {
        return TypedResult::skipped(
            SkipReason::ChangedSinceScan,
            format!(
                "package {full_name} is not the one its definition file records, or the file cannot \
                 be read; left untouched"
            ),
        );
    }
    if let Some((blocker, why)) = refusal(now, &listing) {
        return TypedResult::blocked(blocker, format!("{why}; left untouched"));
    }
    let outcome = backend.remove(full_name, scope);
    let still_listed = match backend.list(scope) {
        Ok(after) => !matches!(lookup(full_name, &after), Lookup::Absent),
        Err(e) => {
            return TypedResult::failed(
                FailCode::VerifyFailed,
                None,
                format!(
                    "the removal of {full_name} returned {}, but whether it is gone cannot be \
                     verified: {e}",
                    outcome_name(&outcome)
                ),
            );
        }
    };
    verdict(full_name, scope, &outcome, still_listed)
}

/// The definition file `reference` names, read through the store's checks and checked against its
/// size and SHA-256; `None` when it cannot be read, does not match or does not parse.
fn read_definition(session: &SessionDir, reference: &BackupRef) -> Option<PackageDefinition> {
    if !reference.is_session_relative() {
        return None;
    }
    let mut file = session.open_file(&reference.path).ok()?;
    let bytes = file.read_all(MAX_DEFINITION_BYTES).ok()?;
    let matches = bytes.len() as u64 == reference.bytes && sha256_bytes(&bytes) == reference.sha256;
    if !matches {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}
