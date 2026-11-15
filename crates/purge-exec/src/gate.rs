//! Execute-time gate: live fact collection and the guard verdict on the acting handle (M2-X-GATE).
//!
//! ENGINE_PLAN.md §5.10, §7.2, §7.6. This is the only place in the executor where facts about the items
//! of a plan are read from the system. The verdicts themselves are pure and live in
//! [`purge_guard::live`]; this module opens the objects, fills the guard's fact structs from the open
//! handles, asks for the verdict and hands the **same** handle back for the action.
//!
//! # The two passes
//!
//! - **Validate** ([`validate`], [`validate_all`]) at the start of a run: each item is opened through a
//!   read-only handle, its facts are read, the guard decides with [`Binding::Capture`], and the result is a
//!   [`Stamp`] (what the act will be bound to) plus the [`ItemFacts`] for the journal's `validated`
//!   record. No handle that could change anything is opened.
//! - **Act** ([`open_and_check_path`], [`open_and_check_key`]) immediately before each action: the item is
//!   opened with the access the action needs, every fact is read from **that** handle, the guard decides
//!   with [`Binding::Recheck`] against the stamp, and on a pass the open handle is returned inside
//!   [`CheckedPath`] / [`CheckedKey`]. The action must be performed on it; nothing is reopened between
//!   check and act. On any other outcome the handle is closed before the function returns.
//!
//! # Outcomes
//!
//! Every gate call ends in a [`GateOutcome`]: `Pass`, `Vanished` (the item is gone: success, nothing to
//! do; "not found" is mapped before the guard is asked), `Locked` (a sharing violation on the acting
//! handle, while a read-only look says the item would pass: for the locked-file ladder), `Refused` (a
//! guard or gate refusal; [`Refusal::is_hard`] tells skip from block) and `Failed` (the system refused
//! the open, e.g. access denied; Purge never raises its own access).
//!
//! # Failing closed
//!
//! A fact that cannot be read stays `None` in the guard's structs, and the guard refuses. The walk below a
//! directory that is moved whole reports `complete = false` on any error or skipped entry. The blast
//! radius (5,000 files by default, [`GateItem::max_files`]) is enforced here with
//! [`Blocker::TooLarge`]. [`GateCtx::new`] fails unless the process could be switched to
//! `PHCM_EXPOSE_PLACEHOLDERS`, without which cloud placeholders hide their attributes (G7).
//!
//! # Residual races
//!
//! The directory walk and the hard-link name listing are path based (`FindFirstFileExW`,
//! `FindFirstFileNameW`); each directory is opened and checked (plain directory, final path equal, the
//! root's identity equal to the acting handle's) before it is listed. Someone who can write inside the tree
//! can still add a link after the walk; the walk cannot stop a writer, it only refuses what it saw.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use purge_guard::deny::{DenyList, Exemptions};
use purge_guard::live::{
    self, AncestorWrite, Binding, BootMove, DestinationFacts, FileIdentity, KeyAddress,
    KeyAncestor, KeyCheck, KeyFacts, KeyNode, KeyOp, KeyProbe, KeyRoot, PLACEHOLDER_ATTRIBUTES,
    PathCheck, PathFacts, PathOp, PathStamp, QuarantineCheck, Refusal, StoreCheck, StoreOp,
    StoreScope, TreeFacts, UndoKeyFacts, UndoPathCheck, ValueStamp, ValueState, VolumeFacts,
    is_cloud_reparse_tag,
};
use purge_guard::prefix;
use purge_model::exec::journal::{FileFacts, GateExemptions, ItemFacts, RegFacts, ValueFacts};
use purge_model::exec::op::{ExecOp, FileIdHex, OpId, Sha256Hex};
use purge_model::{Blocker, Candidate, FileTime, ScanMode, Target, VerifyGone, View};
use purge_win::fs::{FileHandle, FileMeta, list_dir, volume_info};
use purge_win::fs_write::{DestDir, FsError, MoveHandle, extended_path};
use purge_win::os::Win32Error;
use purge_win::reg::{RegRoot, RegValue, RegView};
use purge_win::reg_write::{KeyAccess, NAME_NOT_REPRESENTABLE, WKey, WKeyInfo};
use purge_win::secure::{Security, handle_security, open_for_security};
use purge_win::sid::{TRUSTED_INSTALLER_SID, is_admin_only_writable};
use sha2::{Digest, Sha256};

mod ffi;
#[cfg(test)]
mod tests;

/// Stable codes for refusals the gate raises itself (the guard's own codes are in
/// [`purge_guard::live::reason`]).
pub mod reason {
    /// The path cannot be put into `\\?\` form (relative, `.`/`..` segment, device path).
    pub const PATH_FORM: &str = "gate.path-form";
    /// The tree below a directory moved whole holds more files or directories than the item may.
    pub const BLAST_RADIUS: &str = "gate.blast-radius";
    /// A name on the key path cannot be addressed exactly (not valid UTF-16).
    pub const NAME_NOT_REPRESENTABLE: &str = "gate.name-not-representable";
    /// Facts the journal needs (counts, class, owner, value size) could not be read.
    pub const FACTS_UNREADABLE: &str = "gate.facts-unreadable";
    /// The stamp given to the act does not fit the item's operation.
    pub const STAMP_KIND: &str = "gate.stamp-kind";
    /// The executor op has no file-system or registry gate (wrong function for the op).
    pub const OP_KIND: &str = "gate.op-kind";
}

/// A refusal for which no dedicated blocker exists: reported as a deny rule named after the reason, as
/// the guard does.
fn rule(reason: &'static str) -> Refusal {
    Refusal {
        blocker: Blocker::DenyListed {
            rule: reason.to_owned(),
        },
        reason,
    }
}

/// How a gate call ended.
#[derive(Debug)]
pub enum GateOutcome<T> {
    /// Every rule passed. For an act call, `T` holds the open handle to act on.
    Pass(T),
    /// The item no longer exists. Success: there is nothing to do.
    Vanished,
    /// The acting handle could not be opened because another process holds the item without delete
    /// sharing (a running image, an open file), or, for a directory, with access denied (something open
    /// below it); a read-only look let it through the gate. Only file-system items end like this.
    Locked(LockedPath),
    /// The guard or the gate refused the item. [`Refusal::is_hard`]: `false` means skip as changed.
    Refused(Refusal),
    /// The system refused to open the item (access denied and the like); the item is reported failed.
    Failed(Win32Error),
}

impl<T> GateOutcome<T> {
    /// The value of a `Pass`.
    pub fn pass(self) -> Option<T> {
        match self {
            GateOutcome::Pass(value) => Some(value),
            _ => None,
        }
    }

    /// The refusal of a `Refused`.
    pub fn refusal(&self) -> Option<&Refusal> {
        match self {
            GateOutcome::Refused(refusal) => Some(refusal),
            _ => None,
        }
    }

    /// Whether the item vanished.
    pub fn is_vanished(&self) -> bool {
        matches!(self, GateOutcome::Vanished)
    }

    fn map<U>(self, f: impl FnOnce(T) -> U) -> GateOutcome<U> {
        match self {
            GateOutcome::Pass(value) => GateOutcome::Pass(f(value)),
            GateOutcome::Vanished => GateOutcome::Vanished,
            GateOutcome::Locked(locked) => GateOutcome::Locked(locked),
            GateOutcome::Refused(refusal) => GateOutcome::Refused(refusal),
            GateOutcome::Failed(e) => GateOutcome::Failed(e),
        }
    }
}

/// A locked file-system item: what a read-only handle showed while the acting handle could not be opened.
/// The locked-file ladder (§7.6) works from this; it re-opens the item when it acts.
#[derive(Debug, Clone)]
pub struct LockedPath {
    /// The facts the read-only handle gave (they passed the gate against the stamp).
    pub facts: PathFacts,
    /// The item's stamp, equal to the validated one.
    pub stamp: PathStamp,
    /// The open error of the acting handle: a sharing or lock violation, or access denied on a directory
    /// (something open below it may cause that). The ladder decides by this error; for a directory with
    /// access denied it must not assume "in use" is certain.
    pub error: Win32Error,
}

// ---------------------------------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------------------------------

/// Owner and TrustedInstaller facts of one object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityFacts {
    /// The owner SID (`S-1-5-...`).
    pub owner: Option<String>,
    /// The owner is TrustedInstaller.
    pub owner_is_ti: Option<bool>,
    /// For a file or directory: an explicit (not inherited) ACE names TrustedInstaller. For a key: any
    /// ACE does.
    pub ti_ace: Option<bool>,
}

/// The facts the gate reads through this trait rather than directly, so tests can put in owners and
/// volumes a test machine cannot produce unelevated (TrustedInstaller ownership, removable or FAT
/// volumes). Releases always use [`LiveHost`]; only `cfg(test)` and the `test-support` feature can install
/// another one ([`GateCtx::with_host`]).
pub trait HostFacts: Send + Sync + fmt::Debug {
    /// Owner and TrustedInstaller facts of a file or directory from its security descriptor (`None` when
    /// the descriptor could not be read from the handle).
    fn file_security(&self, security: Option<&Security>) -> SecurityFacts;
    /// Owner and TrustedInstaller facts of a key, read from its handle.
    fn key_security(&self, key: &WKey) -> SecurityFacts;
    /// Facts about the volume the item lies on: `final_path` is the handle's final path and
    /// `volume_serial` the serial of its `FILE_ID_INFO`. `None` when the volume cannot be told, or is not
    /// the one the handle is on.
    fn volume(&self, final_path: &str, volume_serial: u64) -> Option<VolumeFacts>;
}

/// The facts as the system gives them.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveHost;

impl HostFacts for LiveHost {
    fn file_security(&self, security: Option<&Security>) -> SecurityFacts {
        let Some(security) = security else {
            return SecurityFacts::default();
        };
        SecurityFacts {
            owner: security.owner.clone(),
            owner_is_ti: security
                .owner
                .as_deref()
                .map(|owner| owner == TRUSTED_INSTALLER_SID),
            ti_ace: Some(security.aces().iter().any(|ace| {
                !ace.is_inherited() && ace.sid.as_deref() == Some(TRUSTED_INSTALLER_SID)
            })),
        }
    }

    fn key_security(&self, key: &WKey) -> SecurityFacts {
        match key.security() {
            Ok(security) => SecurityFacts {
                owner_is_ti: security
                    .owner_sid
                    .as_deref()
                    .map(|owner| owner == TRUSTED_INSTALLER_SID),
                owner: security.owner_sid,
                ti_ace: Some(security.dacl_names_trusted_installer),
            },
            Err(_) => SecurityFacts::default(),
        }
    }

    fn volume(&self, final_path: &str, volume_serial: u64) -> Option<VolumeFacts> {
        let info = volume_info(Path::new(final_path)).ok()?;
        // The 32-bit serial of GetVolumeInformationW is the low half of the 64-bit FILE_ID_INFO serial.
        (u64::from(info.serial) == volume_serial & 0xFFFF_FFFF).then(|| VolumeFacts {
            drive_fixed: info.is_fixed(),
            fs_name: info.fs_name,
        })
    }
}

/// Why a [`GateCtx`] could not be set up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GateSetupError {
    /// `RtlSetProcessPlaceholderCompatibilityMode(PHCM_EXPOSE_PLACEHOLDERS)` failed or did not stick
    /// (the mode or error code the system reported instead).
    #[error("cannot expose cloud placeholders to the process (mode {0})")]
    Placeholders(i8),
}

/// Switches the process to `PHCM_EXPOSE_PLACEHOLDERS`, so cloud placeholders show their attributes and
/// tags (gate G7). [`GateCtx::new`] calls it; calling it again is harmless.
pub fn expose_placeholders() -> Result<(), GateSetupError> {
    ffi::expose_placeholders().map_err(GateSetupError::Placeholders)
}

/// What every gate call of one run shares.
#[derive(Debug)]
pub struct GateCtx {
    deny: DenyList,
    removed_whole: Vec<String>,
    scope: StoreScope,
    host: Box<dyn HostFacts>,
    validated: BTreeMap<OpId, Stamp>,
}

impl GateCtx {
    /// A context for one run.
    ///
    /// - `deny`: the deny-list compiled from the live `GuardEnv` (its `purge_dirs` must hold Purge's
    ///   store roots).
    /// - `selected`: the ops of every selected item. The paths of the `QuarantineMove` ops are the paths
    ///   this run removes whole, against which hard links are judged (G6).
    /// - `scope`: this session's own store directories, for quarantine destinations and store items.
    ///
    /// Sets `PHCM_EXPOSE_PLACEHOLDERS` for the process and fails if that is not possible.
    pub fn new(
        deny: DenyList,
        selected: &[ExecOp],
        scope: StoreScope,
    ) -> Result<GateCtx, GateSetupError> {
        Self::build(deny, selected, scope, Box::new(LiveHost))
    }

    /// [`GateCtx::new`] with injected [`HostFacts`]. Tests only.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_host(
        deny: DenyList,
        selected: &[ExecOp],
        scope: StoreScope,
        host: Box<dyn HostFacts>,
    ) -> Result<GateCtx, GateSetupError> {
        Self::build(deny, selected, scope, host)
    }

    fn build(
        deny: DenyList,
        selected: &[ExecOp],
        scope: StoreScope,
        host: Box<dyn HostFacts>,
    ) -> Result<GateCtx, GateSetupError> {
        expose_placeholders()?;
        let removed_whole = selected
            .iter()
            .filter_map(|op| match op {
                ExecOp::QuarantineMove { path } => Some(path.clone()),
                _ => None,
            })
            .collect();
        Ok(GateCtx {
            deny,
            removed_whole,
            scope,
            host,
            validated: BTreeMap::new(),
        })
    }

    /// The deny-list.
    pub fn deny(&self) -> &DenyList {
        &self.deny
    }

    /// The paths this run removes whole.
    pub fn removed_whole(&self) -> &[String] {
        &self.removed_whole
    }

    /// This session's store directories.
    pub fn scope(&self) -> &StoreScope {
        &self.scope
    }

    /// Records the stamp of a validated op (done by [`validate_all`]; for a resumed run, rebuild it from
    /// the journal with [`Stamp::from_item_facts`]).
    pub fn record(&mut self, op: OpId, stamp: Stamp) {
        self.validated.insert(op, stamp);
    }

    /// The stamp recorded for `op`.
    pub fn stamp(&self, op: OpId) -> Option<&Stamp> {
        self.validated.get(&op)
    }
}

/// The plan-time exemptions of a candidate, derived exactly as `purge_plan::decide` derives them
/// (its public `exemptions`). `user_sid` and `long_names_resolved` must be the values of the scan that
/// produced the plan. The verify-gone result and the limits are not consulted by that derivation.
pub fn exemptions_for(
    candidate: &Candidate,
    deny: &DenyList,
    mode: ScanMode,
    user_sid: Option<&str>,
    long_names_resolved: bool,
) -> Exemptions {
    let mut ctx =
        purge_plan::decide::DecideCtx::new(deny, mode, VerifyGone::new(false, false, false));
    ctx.user_sid = user_sid;
    ctx.long_names_resolved = long_names_resolved;
    purge_plan::decide::exemptions(candidate, &ctx)
}

/// The journal form of the exemptions a verdict was given ([`Validation::exemptions`]), for the
/// `validated` record's `exemptions` field. Every field is carried over unchanged;
/// [`exemptions_from_journal`] is the exact inverse.
pub fn exemptions_to_journal(exemptions: &Exemptions) -> GateExemptions {
    // Destructured without `..`, so a field added to either type fails to compile here.
    let Exemptions {
        proven_owned_skeleton,
        environment_segment_edit,
        tier_a_start_menu_entry,
        long_names_resolved,
    } = *exemptions;
    GateExemptions {
        proven_owned_skeleton,
        environment_segment_edit,
        tier_a_start_menu_entry,
        long_names_resolved,
    }
}

/// The exemptions a journal `validated` record holds, as the gate takes them: what undo and recovery
/// pass to [`check_undo_path`], [`check_undo_key`] and the act-time gate, instead of deriving them again
/// from the scan. The exact inverse of [`exemptions_to_journal`].
pub fn exemptions_from_journal(exemptions: &GateExemptions) -> Exemptions {
    let GateExemptions {
        proven_owned_skeleton,
        environment_segment_edit,
        tier_a_start_menu_entry,
        long_names_resolved,
    } = *exemptions;
    Exemptions {
        proven_owned_skeleton,
        environment_segment_edit,
        tier_a_start_menu_entry,
        long_names_resolved,
    }
}

// ---------------------------------------------------------------------------------------------------
// Items and stamps
// ---------------------------------------------------------------------------------------------------

/// One item as the gate sees it.
#[derive(Debug, Clone, Copy)]
pub struct GateItem<'a> {
    /// What the executor does with the item.
    pub op: &'a ExecOp,
    /// The candidate's exemptions ([`exemptions_for`]).
    pub exemptions: Exemptions,
    /// The most files, and separately the most directories, the tree below a directory moved whole may
    /// hold; more is refused with [`Blocker::TooLarge`]. The plan's limit: 5,000, or 50,000 for a
    /// manifest-backed install root.
    pub max_files: u32,
}

impl<'a> GateItem<'a> {
    /// An item with the default blast-radius limit (`purge_plan::decide::Limits::default().max_files`).
    pub fn new(op: &'a ExecOp, exemptions: Exemptions) -> GateItem<'a> {
        GateItem {
            op,
            exemptions,
            max_files: purge_plan::decide::Limits::default().max_files,
        }
    }
}

/// What the validate pass binds an item to, and the act re-checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stamp {
    /// A file or directory: identity and kind.
    Path(PathStamp),
    /// A key action. Keys have no identity to bind; the act re-checks every rule but no identity.
    Key,
    /// A value or segment action: type, length and hash of the raw data.
    Value(ValueStamp),
    /// A package removal (no live facts).
    Package,
}

impl Stamp {
    /// The stamp a journal `validated` record stands for (crash recovery). `None` for
    /// [`ItemFacts::Absent`].
    pub fn from_item_facts(facts: &ItemFacts) -> Option<Stamp> {
        Some(match facts {
            ItemFacts::File(file) => Stamp::Path(PathStamp {
                identity: FileIdentity {
                    volume_serial: file.volume_serial,
                    file_id: file.file_id.0,
                },
                is_dir: file.is_dir,
            }),
            ItemFacts::Key(_) => Stamp::Key,
            ItemFacts::Value(value) => Stamp::Value(ValueStamp {
                ty: value.value_type,
                len: u64::from(value.size),
                sha256: value.data_sha256.0,
            }),
            ItemFacts::Package => Stamp::Package,
            ItemFacts::Absent => return None,
        })
    }
}

/// The result of the validate pass for one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validation {
    /// What the act is bound to.
    pub stamp: Stamp,
    /// The journal form of the facts.
    pub facts: ItemFacts,
    /// The exemptions the verdict was given ([`GateItem::exemptions`]), for the journal. The act must be
    /// gated with the same ones.
    pub exemptions: Exemptions,
}

impl GateOutcome<Validation> {
    /// The facts for the journal's `validated` record: the facts of a pass, [`ItemFacts::Absent`] for a
    /// vanished item, `None` otherwise.
    pub fn item_facts(&self) -> Option<ItemFacts> {
        match self {
            GateOutcome::Pass(validation) => Some(validation.facts.clone()),
            GateOutcome::Vanished => Some(ItemFacts::Absent),
            _ => None,
        }
    }
}

/// The validate pass for one item: read-only handles, [`Binding::Capture`].
pub fn validate(ctx: &GateCtx, item: &GateItem<'_>) -> GateOutcome<Validation> {
    match item.op {
        ExecOp::QuarantineMove { .. } | ExecOp::RemoveDirIfEmpty { .. } => match op_path(item) {
            Ok((path, op)) => validate_path(ctx, path, op, item).map(|(stamp, facts)| Validation {
                stamp: Stamp::Path(stamp),
                facts: ItemFacts::File(facts),
                exemptions: item.exemptions,
            }),
            Err(refusal) => GateOutcome::Refused(refusal),
        },
        ExecOp::DeleteKeyTree { .. }
        | ExecOp::DeleteKeyIfEmpty { .. }
        | ExecOp::DeleteValue { .. }
        | ExecOp::EditSegment { .. } => validate_key(ctx, item),
        // Packages are not locations: the guard has no live rule for them.
        ExecOp::RemovePackage { .. } => GateOutcome::Pass(Validation {
            stamp: Stamp::Package,
            facts: ItemFacts::Package,
            exemptions: item.exemptions,
        }),
    }
}

/// The validate pass over every selected item, in the order given. Records each pass's stamp in `ctx`.
/// The caller writes one journal `validated` record per item from
/// [`GateOutcome::item_facts`].
pub fn validate_all<'a>(
    ctx: &mut GateCtx,
    items: impl IntoIterator<Item = (OpId, GateItem<'a>)>,
) -> Vec<(OpId, GateOutcome<Validation>)> {
    let mut out = Vec::new();
    for (op, item) in items {
        let outcome = validate(ctx, &item);
        if let GateOutcome::Pass(validation) = &outcome {
            ctx.record(op, validation.stamp);
        }
        out.push((op, outcome));
    }
    out
}

fn path_op(op: &ExecOp) -> Option<PathOp> {
    match op {
        ExecOp::QuarantineMove { .. } => Some(PathOp::QuarantineMove),
        ExecOp::RemoveDirIfEmpty { .. } => Some(PathOp::RemoveDirIfEmpty),
        _ => None,
    }
}

fn key_op(op: &ExecOp) -> Option<KeyOp> {
    match op {
        ExecOp::DeleteKeyTree { .. } => Some(KeyOp::DeleteKeyTree),
        ExecOp::DeleteKeyIfEmpty { .. } => Some(KeyOp::DeleteKeyIfEmpty),
        ExecOp::DeleteValue { .. } => Some(KeyOp::DeleteValue),
        ExecOp::EditSegment { .. } => Some(KeyOp::EditSegment),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------------
// Files and directories
// ---------------------------------------------------------------------------------------------------

/// `path` with a `\\?\` prefix removed when a drive path follows it (the form the guard and the journal
/// use). Anything else is returned unchanged.
fn strip_verbatim(path: &str) -> &str {
    match path.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest,
        _ => path,
    }
}

/// The `\\?\` form of an absolute path, or `None` for a path that has none.
fn ext(path: &str) -> Option<PathBuf> {
    extended_path(Path::new(path)).ok()
}

/// The full paths of every name of the file at `path`, with the volume's mount path put in front.
fn link_names(path: &str) -> Option<Vec<String>> {
    let p = ext(path)?;
    let root = volume_info(&p).ok()?.root;
    let root = strip_verbatim(&root).trim_end_matches('\\').to_owned();
    let names = ffi::file_names(&p).ok()?;
    Some(
        names
            .into_iter()
            .map(|name| format!("{root}{name}"))
            .collect(),
    )
}

/// What a walk below a directory moved whole found.
#[derive(Debug, Clone, Default)]
struct Walk {
    facts: TreeFacts,
    entries: u64,
    bytes: u64,
}

fn too_large() -> Refusal {
    Refusal {
        blocker: Blocker::TooLarge,
        reason: reason::BLAST_RADIUS,
    }
}

/// Whether the directory at `dir` (plain form) is the plain directory its path names, and, for the root,
/// the object the acting handle is on.
fn plain_dir(dir: &str, identity: Option<FileIdentity>) -> Option<PathBuf> {
    let p = ext(dir)?;
    let handle = FileHandle::open(&p).ok()?;
    let meta = handle.metadata().ok()?;
    let final_path = handle.final_path().ok()?;
    let same_object = identity.is_none_or(|id| {
        meta.file_id.volume_serial == id.volume_serial && meta.file_id.id == id.file_id
    });
    (meta.is_dir
        && meta.reparse_tag == 0
        && same_object
        && prefix::is_same(strip_verbatim(&final_path), dir))
    .then_some(p)
}

/// The bounded walk below a directory that is moved whole (G6, G7, blast radius). Never descends into a
/// reparse point; opens every non-directory entry without following it to read its link count.
fn walk_tree(ctx: &GateCtx, root: &str, identity: FileIdentity, max: u32) -> Result<Walk, Refusal> {
    let max = u64::from(max);
    let mut walk = Walk {
        facts: TreeFacts {
            complete: true,
            ..TreeFacts::default()
        },
        ..Walk::default()
    };
    let (mut files, mut dirs) = (0u64, 0u64);
    let mut stack = vec![(root.to_owned(), Some(identity))];
    while let Some((dir, expect)) = stack.pop() {
        let Some(dir_ext) = plain_dir(&dir, expect) else {
            walk.facts.complete = false;
            continue;
        };
        let Ok(entries) = list_dir(&dir_ext) else {
            walk.facts.complete = false;
            continue;
        };
        for entry in entries {
            let child = format!(r"{}\{}", dir.trim_end_matches('\\'), entry.name);
            walk.entries += 1;
            if entry.attributes & PLACEHOLDER_ATTRIBUTES != 0
                || is_cloud_reparse_tag(entry.reparse_tag)
            {
                walk.facts.placeholders += 1;
            }
            if entry.is_dir() {
                dirs += 1;
                if dirs > max {
                    return Err(too_large());
                }
                if !entry.is_reparse_point() {
                    stack.push((child, None));
                }
                continue;
            }
            files += 1;
            walk.bytes = walk.bytes.saturating_add(entry.size);
            if files > max {
                return Err(too_large());
            }
            let n_links = ext(&child)
                .and_then(|p| FileHandle::open(&p).ok())
                .and_then(|h| h.metadata().ok())
                .map(|m| m.n_links);
            match n_links {
                None => walk.facts.complete = false,
                Some(n) if n > 1 => {
                    let inside = link_names(&child).is_some_and(|names| {
                        live::links_inside_plan(&names, n, &ctx.removed_whole)
                    });
                    if !inside {
                        walk.facts.hard_links_outside_plan += 1;
                    }
                }
                Some(_) => {}
            }
        }
    }
    Ok(walk)
}

/// What the gate read about a file-system item from one handle.
#[derive(Debug, Clone)]
struct PathSeen {
    facts: PathFacts,
    meta: Option<FileMeta>,
    walk: Option<Walk>,
}

/// Reads every fact [`live::check_path`] needs from `handle` (and `security`, read from the same handle).
/// Fails only with the blast-radius refusal of the walk.
fn collect_path(
    ctx: &GateCtx,
    lexical: &str,
    op: PathOp,
    handle: &FileHandle,
    security: Option<&Security>,
    max_files: u32,
) -> Result<PathSeen, Refusal> {
    let final_path = handle.final_path().ok();
    let meta = handle.metadata().ok();
    let identity = meta.as_ref().map(|m| FileIdentity {
        volume_serial: m.file_id.volume_serial,
        file_id: m.file_id.id,
    });
    let volume = match (&final_path, identity) {
        (Some(path), Some(id)) => ctx.host.volume(path, id.volume_serial),
        _ => None,
    };
    let security = ctx.host.file_security(security);
    let n_links = meta.as_ref().map(|m| m.n_links);
    let is_dir = meta.as_ref().map(|m| m.is_dir);
    let links_inside_plan = match (n_links, is_dir, final_path.as_deref()) {
        (Some(n), Some(false), Some(path)) if n > 1 => link_names(strip_verbatim(path))
            .map(|names| live::links_inside_plan(&names, n, &ctx.removed_whole)),
        (Some(n), _, _) if n > 1 => None,
        (Some(_), _, _) => Some(true),
        (None, _, _) => None,
    };

    // The walk runs only below the plain directory the plan names; anything else is refused before the
    // tree matters.
    let walk = match (&meta, identity, final_path.as_deref()) {
        (Some(m), Some(id), Some(path))
            if op == PathOp::QuarantineMove
                && m.is_dir
                && m.reparse_tag == 0
                && !m.is_reparse_point()
                && prefix::is_same(strip_verbatim(path), lexical) =>
        {
            Some(walk_tree(ctx, strip_verbatim(path), id, max_files)?)
        }
        _ => None,
    };

    let facts = PathFacts {
        final_path,
        reparse_tag: meta.as_ref().map(|m| m.reparse_tag),
        attributes: meta.as_ref().map(|m| m.attributes),
        identity,
        n_links,
        is_dir,
        volume,
        owner_is_ti: security.owner_is_ti,
        explicit_ti_ace: security.ti_ace,
        links_inside_plan,
        tree: walk.as_ref().map(|w| w.facts.clone()),
    };
    Ok(PathSeen { facts, meta, walk })
}

/// The journal form of facts that passed the gate. `None` if a field is missing (the guard refuses such
/// facts first).
fn file_facts(seen: &PathSeen) -> Option<FileFacts> {
    let facts = &seen.facts;
    let meta = seen.meta.as_ref()?;
    let identity = facts.identity?;
    Some(FileFacts {
        final_path: strip_verbatim(facts.final_path.as_deref()?).to_owned(),
        file_id: FileIdHex(identity.file_id),
        volume_serial: identity.volume_serial,
        reparse_tag: meta.reparse_tag,
        attributes: meta.attributes,
        n_links: meta.n_links,
        is_dir: meta.is_dir,
        size: if meta.is_dir { 0 } else { meta.size },
        tree_entries: seen.walk.as_ref().map(|w| w.entries),
        tree_bytes: seen.walk.as_ref().map(|w| w.bytes),
    })
}

/// Opens `path` read-only for facts: with `READ_CONTROL` when the object grants it, else without (then no
/// security facts).
fn open_read_only(path: &Path) -> Result<(FileHandle, Option<Security>), Win32Error> {
    match open_for_security(path) {
        Ok(handle) => {
            let security = handle_security(&handle).ok();
            Ok((handle, security))
        }
        Err(Win32Error::ACCESS_DENIED) => Ok((FileHandle::open(path)?, None)),
        Err(e) => Err(e),
    }
}

/// The path of a file-system op, or the refusal for an op that is not one.
fn op_path<'a>(item: &GateItem<'a>) -> Result<(&'a str, PathOp), Refusal> {
    match (item.op, path_op(item.op)) {
        (ExecOp::QuarantineMove { path } | ExecOp::RemoveDirIfEmpty { path }, Some(op)) => {
            Ok((path.as_str(), op))
        }
        _ => Err(rule(reason::OP_KIND)),
    }
}

fn validate_path(
    ctx: &GateCtx,
    path: &str,
    op: PathOp,
    item: &GateItem<'_>,
) -> GateOutcome<(PathStamp, FileFacts)> {
    let Some(p) = ext(path) else {
        return GateOutcome::Refused(rule(reason::PATH_FORM));
    };
    let (handle, security) = match open_read_only(&p) {
        Ok(opened) => opened,
        Err(e) if e.is_not_found() => return GateOutcome::Vanished,
        Err(e) => return GateOutcome::Failed(e),
    };
    let seen = match collect_path(ctx, path, op, &handle, security.as_ref(), item.max_files) {
        Ok(seen) => seen,
        Err(refusal) => return GateOutcome::Refused(refusal),
    };
    let check = PathCheck {
        lexical: path,
        op,
        binding: Binding::Capture,
        exemptions: item.exemptions,
    };
    if let Err(refusal) = live::check_path(&check, &seen.facts, &ctx.deny) {
        return GateOutcome::Refused(refusal);
    }
    match (seen.facts.stamp(), file_facts(&seen)) {
        (Some(stamp), Some(facts)) => GateOutcome::Pass((stamp, facts)),
        _ => GateOutcome::Refused(rule(reason::FACTS_UNREADABLE)),
    }
}

/// A file or directory that passed the gate, with the handle to act on.
///
/// The handle was opened with `DELETE | SYNCHRONIZE | FILE_READ_ATTRIBUTES` (and `READ_CONTROL`) without
/// following a final reparse point, and every fact in here was read from it. Perform the action on
/// [`CheckedPath::handle`]; never reopen the path.
#[derive(Debug)]
pub struct CheckedPath {
    path: String,
    handle: MoveHandle,
    facts: PathFacts,
    stamp: PathStamp,
    meta: FileMeta,
    security: Option<Security>,
    file_facts: FileFacts,
}

impl CheckedPath {
    /// The plan's (lexical) path of the item.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The handle the gate inspected; the action must use it.
    pub fn handle(&self) -> &MoveHandle {
        &self.handle
    }

    /// The facts the verdict was given.
    pub fn facts(&self) -> &PathFacts {
        &self.facts
    }

    /// The identity and kind of the item (equal to the validated stamp).
    pub fn stamp(&self) -> PathStamp {
        self.stamp
    }

    /// The item's metadata as read from the handle (attributes, times, size, link count).
    pub fn meta(&self) -> &FileMeta {
        &self.meta
    }

    /// The item's security descriptor (owner, group, DACL, SDDL) as read from the handle; always present
    /// on a pass.
    pub fn security(&self) -> Option<&Security> {
        self.security.as_ref()
    }

    /// The facts in journal form, for the intent's `pre` record.
    pub fn file_facts(&self) -> &FileFacts {
        &self.file_facts
    }

    /// The handle, giving up the rest.
    pub fn into_handle(self) -> MoveHandle {
        self.handle
    }
}

/// The act-time gate for a file-system item (`QuarantineMove`, `RemoveDirIfEmpty`): opens the acting
/// handle first, reads every fact from it, and checks them against `stamp` ([`Binding::Recheck`]). On a
/// pass the open handle is returned for the action.
///
/// When the acting handle cannot be opened (sharing violation, access denied, ...) the item is looked at
/// through a read-only handle: a refusal is reported as `Refused`; otherwise a sharing violation is
/// `Locked` and any other error `Failed`.
pub fn open_and_check_path(
    ctx: &GateCtx,
    item: &GateItem<'_>,
    stamp: &PathStamp,
) -> GateOutcome<CheckedPath> {
    let (path, op) = match op_path(item) {
        Ok(found) => found,
        Err(refusal) => return GateOutcome::Refused(refusal),
    };
    let Some(p) = ext(path) else {
        return GateOutcome::Refused(rule(reason::PATH_FORM));
    };
    let check = PathCheck {
        lexical: path,
        op,
        binding: Binding::Recheck(stamp),
        exemptions: item.exemptions,
    };
    let handle = match MoveHandle::open(&p) {
        Ok(handle) => handle,
        Err(FsError::NotFound) => return GateOutcome::Vanished,
        Err(error) => return look_without_acting(ctx, &p, &check, error, item.max_files),
    };
    let security = if handle.has_read_control() {
        handle.security().ok()
    } else {
        None
    };
    let seen = match collect_path(
        ctx,
        path,
        op,
        handle.as_file(),
        security.as_ref(),
        item.max_files,
    ) {
        Ok(seen) => seen,
        Err(refusal) => return GateOutcome::Refused(refusal),
    };
    if let Err(refusal) = live::check_path(&check, &seen.facts, &ctx.deny) {
        return GateOutcome::Refused(refusal);
    }
    let file_facts = file_facts(&seen);
    match (seen.facts.stamp(), seen.meta, file_facts) {
        (Some(now), Some(meta), Some(file_facts)) if security.is_some() => {
            GateOutcome::Pass(CheckedPath {
                path: path.to_owned(),
                handle,
                facts: seen.facts,
                stamp: now,
                meta,
                security,
                file_facts,
            })
        }
        _ => GateOutcome::Refused(rule(reason::FACTS_UNREADABLE)),
    }
}

/// The acting handle could not be opened: decide from a read-only handle what to report.
fn look_without_acting<T>(
    ctx: &GateCtx,
    p: &Path,
    check: &PathCheck<'_>,
    fs_error: FsError,
    max_files: u32,
) -> GateOutcome<T> {
    let error = Win32Error(fs_error.code());
    let (handle, security) = match open_read_only(p) {
        Ok(opened) => opened,
        Err(e) if e.is_not_found() => return GateOutcome::Vanished,
        Err(_) => return GateOutcome::Failed(error),
    };
    let seen = match collect_path(
        ctx,
        check.lexical,
        check.op,
        &handle,
        security.as_ref(),
        max_files,
    ) {
        Ok(seen) => seen,
        Err(refusal) => return GateOutcome::Refused(refusal),
    };
    if let Err(refusal) = live::check_path(check, &seen.facts, &ctx.deny) {
        return GateOutcome::Refused(refusal);
    }
    match seen.facts.stamp() {
        Some(stamp) if may_be_in_use(fs_error, stamp.is_dir) => GateOutcome::Locked(LockedPath {
            facts: seen.facts,
            stamp,
            error,
        }),
        _ => GateOutcome::Failed(error),
    }
}

/// **The one place** that decides whether an open error on the acting handle may mean "in use" (for the
/// locked-file ladder) rather than a final failure: a sharing or lock violation always; access denied on
/// a directory too, because a directory with an open handle anywhere below it can refuse with access
/// denied; and [`FsError::DirInUseOrDenied`], which `MoveHandle::rename_into` reports for exactly that
/// case on a directory. An open of the acting handle reports plain [`FsError::AccessDenied`], so that
/// variant still counts for a directory.
pub(crate) fn may_be_in_use(error: FsError, is_dir: bool) -> bool {
    match error {
        FsError::SharingViolation | FsError::DirInUseOrDenied => true,
        FsError::AccessDenied => is_dir,
        _ => false,
    }
}

// ---------------------------------------------------------------------------------------------------
// Destinations and the session's own store
// ---------------------------------------------------------------------------------------------------

/// A checked destination of a rename: the destination's parent directory, open as a
/// [`purge_win::fs_write::DestDir`] (no-follow), the leaf name, and the [`DestinationFacts`] the verdict
/// was given (read from that open directory handle). The one destination type the gate hands out.
///
/// Rename with `MoveHandle::rename_into(dest.dir(), dest.leaf())`, so the directory that was checked is
/// the one the item lands in, whatever happens to its path. There is no rename by path.
#[derive(Debug)]
pub struct CheckedDest {
    dir: DestDir,
    leaf: String,
    path: String,
    facts: DestinationFacts,
}

impl CheckedDest {
    /// The destination's parent directory, opened without following a reparse point
    /// (`FILE_READ_ATTRIBUTES | SYNCHRONIZE`); pass it to `MoveHandle::rename_into`.
    pub fn dir(&self) -> &DestDir {
        &self.dir
    }

    /// The facts of the destination, taken from [`CheckedDest::dir`].
    pub fn facts(&self) -> &DestinationFacts {
        &self.facts
    }

    /// The name the item gets inside [`CheckedDest::dir`].
    pub fn leaf(&self) -> &str {
        &self.leaf
    }

    /// The full destination path that was checked.
    pub fn path(&self) -> &str {
        &self.path
    }
}

/// Opens the parent directory of `destination` as a [`DestDir`] (without following a reparse point)
/// and reads the [`DestinationFacts`] from that handle ([`DestDir::facts`]). Whether the leaf is taken
/// is probed by path (there is no handle-relative open here) and counts only while the parent handle's
/// final path is the same before and after the probe. A rename into the handle never replaces
/// anything, so a name taken after the probe makes the rename fail, never overwrite.
fn destination_facts(destination: &str) -> Option<(DestDir, String, DestinationFacts)> {
    let target = Path::new(destination);
    let leaf = target.file_name()?.to_str()?.to_owned();
    let parent_ext = target.parent()?.to_str().and_then(ext)?;
    let dir = DestDir::open(&parent_ext).ok()?;
    let mut facts = DestinationFacts::default();
    if let Ok(dir_facts) = dir.facts() {
        facts.parent_reparse_tag = Some(dir_facts.reparse_tag);
        facts.parent_is_dir = Some(dir_facts.is_dir);
        facts.parent_volume_serial = Some(dir_facts.volume_serial());
        facts.parent_final_path = Some(dir_facts.final_path);
    }
    let occupied = match ext(destination).map(|p| FileHandle::open(&p)) {
        Some(Ok(_)) => Some(true),
        Some(Err(e)) if e.is_not_found() => Some(false),
        _ => None,
    };
    let unchanged = facts.parent_final_path.is_some()
        && dir.as_file().final_path().ok() == facts.parent_final_path;
    facts.occupied = occupied.filter(|_| unchanged);
    Some((dir, leaf, facts))
}

/// [`destination_facts`], or empty facts and no handle when the parent could not be opened at all (the
/// guard is still asked, with nothing known, so it names the rule).
fn open_destination(destination: &str) -> (DestinationFacts, Option<(DestDir, String)>) {
    match destination_facts(destination) {
        Some((dir, leaf, facts)) => (facts, Some((dir, leaf))),
        None => (DestinationFacts::default(), None),
    }
}

/// Whether `source` may be moved to `destination` in this session's quarantine
/// ([`live::check_quarantine_destination`]): `<quarantine dir>\<op>\<leaf>`, same volume, parent the plain
/// directory its path names, nothing there yet. The op directory must exist (the store creates it).
pub fn check_quarantine_destination(
    ctx: &GateCtx,
    source: &CheckedPath,
    destination: &str,
) -> Result<CheckedDest, Refusal> {
    let (facts, parent) = open_destination(destination);
    let check = QuarantineCheck {
        source: source.path(),
        source_volume_serial: Some(source.stamp().identity.volume_serial),
        destination,
    };
    live::check_quarantine_destination(&check, &facts, &ctx.scope)?;
    let (dir, leaf) = parent.ok_or_else(|| rule(reason::FACTS_UNREADABLE))?;
    Ok(CheckedDest {
        dir,
        leaf,
        path: destination.to_owned(),
        facts,
    })
}

/// Whether a quarantined item may be renamed back to `original` (§7.8, [`live::check_undo_path`]): G2 on
/// the original path as it is now, its parent the plain directory its path names on the item's volume,
/// nothing there.
pub fn check_undo_path(
    ctx: &GateCtx,
    original: &str,
    volume_serial: u64,
    exemptions: Exemptions,
) -> Result<CheckedDest, Refusal> {
    let (facts, parent) = open_destination(original);
    let check = UndoPathCheck {
        original,
        volume_serial,
        exemptions,
    };
    live::check_undo_path(&check, &facts, &ctx.deny)?;
    let (dir, leaf) = parent.ok_or_else(|| rule(reason::FACTS_UNREADABLE))?;
    Ok(CheckedDest {
        dir,
        leaf,
        path: original.to_owned(),
        facts,
    })
}

/// An item in the session's own store that passed [`live::check_store_item`], with the handle to act on.
#[derive(Debug)]
pub struct CheckedStoreItem {
    handle: MoveHandle,
    facts: PathFacts,
}

impl CheckedStoreItem {
    /// The handle the gate inspected; the action must use it.
    pub fn handle(&self) -> &MoveHandle {
        &self.handle
    }

    /// The facts the verdict was given.
    pub fn facts(&self) -> &PathFacts {
        &self.facts
    }

    /// The handle, giving up the rest.
    pub fn into_handle(self) -> MoveHandle {
        self.handle
    }
}

/// The gate for executor-internal work on an item in this session's store (undo's move back, expiry's
/// descend and remove): opens the acting handle (with `FILE_WRITE_ATTRIBUTES` too when
/// `attribute_write`), reads final path, tag, attributes, kind and identity from it and asks
/// [`live::check_store_item`].
pub fn open_store_item(
    ctx: &GateCtx,
    path: &str,
    op: StoreOp,
    binding: Binding<'_, PathStamp>,
    volume_serial: u64,
    attribute_write: bool,
) -> GateOutcome<CheckedStoreItem> {
    let Some(p) = ext(path) else {
        return GateOutcome::Refused(rule(reason::PATH_FORM));
    };
    let opened = if attribute_write {
        MoveHandle::open_with_attribute_write(&p)
    } else {
        MoveHandle::open(&p)
    };
    let handle = match opened {
        Ok(handle) => handle,
        Err(FsError::NotFound) => return GateOutcome::Vanished,
        Err(error) => return GateOutcome::Failed(Win32Error(error.code())),
    };
    let meta = handle.metadata().ok();
    let facts = PathFacts {
        final_path: handle.final_path().ok(),
        reparse_tag: meta.as_ref().map(|m| m.reparse_tag),
        attributes: meta.as_ref().map(|m| m.attributes),
        identity: meta.as_ref().map(|m| FileIdentity {
            volume_serial: m.file_id.volume_serial,
            file_id: m.file_id.id,
        }),
        n_links: meta.as_ref().map(|m| m.n_links),
        is_dir: meta.as_ref().map(|m| m.is_dir),
        ..PathFacts::default()
    };
    let check = StoreCheck {
        path,
        op,
        binding,
        volume_serial,
    };
    match live::check_store_item(&check, &facts, &ctx.scope) {
        Ok(()) => GateOutcome::Pass(CheckedStoreItem { handle, facts }),
        Err(refusal) => GateOutcome::Refused(refusal),
    }
}

// ---------------------------------------------------------------------------------------------------
// Boot-time moves (§7.6)
// ---------------------------------------------------------------------------------------------------

/// The facts [`live::admin_only_ancestors`] needs for `source` (absolute, plain form): one entry for the
/// item and each ancestor up to the drive root. `admin_only` comes from `sid::is_admin_only_writable`
/// on the item, which checks the whole chain at once (leaf mask for the item, ancestor mask above); its
/// answer is given to every component, so a chain with any user-writable part holds the item. `reparse`
/// is read per component from a handle opened without following it.
pub fn boot_move_chain(source: &str) -> Vec<AncestorWrite> {
    let path = Path::new(source);
    let admin_only = is_admin_only_writable(path).ok();
    path.ancestors()
        .filter_map(|component| component.to_str())
        .filter(|component| !component.is_empty())
        .map(|component| AncestorWrite {
            path: component.to_owned(),
            admin_only,
            reparse: ext(component)
                .and_then(|p| open_for_security(&p).ok())
                .and_then(|h| h.reparse_tag().ok())
                .map(|tag| tag != 0),
        })
        .collect()
}

/// Whether a locked item may be moved at boot (§7.6): [`live::admin_only_ancestors`] over
/// [`boot_move_chain`].
pub fn admin_only_ancestors(source: &str) -> BootMove {
    live::admin_only_ancestors(source, &boot_move_chain(source))
}

// ---------------------------------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------------------------------

/// **The one place** where a guard [`KeyAddress`] becomes the arguments of [`WKey::open`]: the root and
/// view one-to-one, the path as it is (the 32-bit view is reached by the view flag, never through a
/// `WOW6432Node` segment; see [`KeyAddress`]). Every component is opened with `REG_OPTION_OPEN_LINK`.
fn open_addr(addr: &KeyAddress, access: KeyAccess) -> Result<WKey, Win32Error> {
    let root = match addr.root {
        KeyRoot::Hklm => RegRoot::Hklm,
        KeyRoot::Hku => RegRoot::Hku,
    };
    let view = match addr.view {
        View::K64 => RegView::K64,
        View::K32 => RegView::K32,
    };
    WKey::open(root, &addr.path, view, access)
}

/// The link state of one key, probed by itself.
fn probe_node(addr: &KeyAddress) -> KeyNode {
    match open_addr(addr, KeyAccess::READ) {
        Ok(key) => match key.is_link() {
            Ok(true) => KeyNode::Link,
            Ok(false) => KeyNode::Plain,
            Err(_) => KeyNode::Unknown,
        },
        Err(e) if e.is_not_found() => KeyNode::Missing,
        // A link above this key: the chain holds a link, whatever this key is.
        Err(Win32Error::LINK_ON_PATH) => KeyNode::Link,
        Err(_) => KeyNode::Unknown,
    }
}

/// Every ancestor of the probe, each opened by itself at its own address (G11).
fn probe_ancestors(probe: &KeyProbe) -> Vec<KeyAncestor> {
    probe
        .ancestors
        .iter()
        .map(|addr| KeyAncestor {
            key: addr.clone(),
            node: probe_node(addr),
        })
        .collect()
}

fn value_name(target: &Target) -> Option<&str> {
    match target {
        Target::RegValue { name, .. } | Target::RegMultiSzSegment { name, .. } => Some(name),
        _ => None,
    }
}

fn value_stamp(value: &RegValue) -> Option<ValueStamp> {
    Some(ValueStamp {
        ty: value.ty,
        len: u64::try_from(value.data.len()).ok()?,
        sha256: Sha256::digest(&value.data).into(),
    })
}

/// What the gate read about a registry item from one key handle.
#[derive(Debug)]
struct KeySeen {
    facts: KeyFacts,
    info: Option<WKeyInfo>,
    owner: Option<String>,
    value: Option<RegValue>,
}

fn collect_key(ctx: &GateCtx, key: &WKey, probe: &KeyProbe, target: &Target) -> KeySeen {
    let node = match key.is_link() {
        Ok(true) => KeyNode::Link,
        Ok(false) => KeyNode::Plain,
        Err(_) => KeyNode::Unknown,
    };
    let security = ctx.host.key_security(key);
    let info = key.info().ok();
    let (value_state, value) = match value_name(target) {
        Some(name) => match key.value(name) {
            Ok(Some(value)) => match value_stamp(&value) {
                Some(stamp) => (ValueState::Present(stamp), Some(value)),
                None => (ValueState::Unknown, None),
            },
            Ok(None) => (ValueState::Absent, None),
            Err(_) => (ValueState::Unknown, None),
        },
        None => (ValueState::Unknown, None),
    };
    KeySeen {
        facts: KeyFacts {
            node,
            ancestors: probe_ancestors(probe),
            owner_is_ti: security.owner_is_ti,
            has_ti_ace: security.ti_ace,
            subkeys: info.as_ref().map(|i| i.n_subkeys),
            values: info.as_ref().map(|i| i.n_values),
            value: value_state,
        },
        info,
        owner: security.owner,
        value,
    }
}

/// The journal form of key facts that passed the gate.
fn key_item_facts(op: KeyOp, seen: &KeySeen) -> Option<ItemFacts> {
    match op {
        KeyOp::DeleteKeyTree | KeyOp::DeleteKeyIfEmpty => {
            let info = seen.info.as_ref()?;
            Some(ItemFacts::Key(RegFacts {
                subkeys: info.n_subkeys,
                values: info.n_values,
                is_link: seen.facts.node == KeyNode::Link,
                owner: seen.owner.clone()?,
                last_write_time: FileTime(info.last_write_time),
            }))
        }
        KeyOp::DeleteValue | KeyOp::EditSegment => {
            let ValueState::Present(stamp) = seen.facts.value else {
                return None;
            };
            Some(ItemFacts::Value(ValueFacts {
                value_type: stamp.ty,
                size: u32::try_from(stamp.len).ok()?,
                data_sha256: Sha256Hex(stamp.sha256),
            }))
        }
    }
}

/// Maps an error opening the item's key.
fn key_open_error<T>(e: Win32Error) -> GateOutcome<T> {
    if e.is_not_found() {
        GateOutcome::Vanished
    } else if e == Win32Error::LINK_ON_PATH {
        GateOutcome::Refused(Refusal {
            blocker: Blocker::RegLink,
            reason: live::reason::ANCESTOR_IS_LINK,
        })
    } else if e == NAME_NOT_REPRESENTABLE {
        GateOutcome::Refused(rule(reason::NAME_NOT_REPRESENTABLE))
    } else {
        GateOutcome::Failed(e)
    }
}

/// The access the act needs on the key.
fn act_access(op: KeyOp) -> KeyAccess {
    match op {
        KeyOp::DeleteKeyTree | KeyOp::DeleteKeyIfEmpty => KeyAccess::DELETE,
        KeyOp::DeleteValue | KeyOp::EditSegment => KeyAccess::SET_VALUE,
    }
}

/// Opens, reads and judges a registry item. `binding` is the guard's binding for value actions.
fn gate_key(
    ctx: &GateCtx,
    item: &GateItem<'_>,
    access: KeyAccess,
    binding: Binding<'_, ValueStamp>,
) -> GateOutcome<Gated> {
    let Some(op) = key_op(item.op) else {
        return GateOutcome::Refused(rule(reason::OP_KIND));
    };
    let target = item.op.target();
    let probe = match live::key_probe(&target, ctx.deny.env()) {
        Ok(probe) => probe,
        Err(refusal) => return GateOutcome::Refused(refusal),
    };
    let check = KeyCheck {
        target: &target,
        op,
        binding,
        exemptions: item.exemptions,
    };
    let key = match open_addr(&probe.open, access) {
        Ok(key) => key,
        Err(e) if e == Win32Error::ACCESS_DENIED => {
            // Report a refusal as a refusal: look through a read-only handle first.
            return match open_addr(&probe.open, KeyAccess::READ) {
                Ok(read) => {
                    let seen = collect_key(ctx, &read, &probe, &target);
                    if seen.facts.value == ValueState::Absent {
                        return GateOutcome::Vanished;
                    }
                    match live::check_key(&check, &seen.facts, &ctx.deny) {
                        Err(refusal) => GateOutcome::Refused(refusal),
                        Ok(()) => GateOutcome::Failed(e),
                    }
                }
                Err(read_error) if read_error.is_not_found() => GateOutcome::Vanished,
                Err(_) => GateOutcome::Failed(e),
            };
        }
        Err(e) => return key_open_error(e),
    };
    let seen = collect_key(ctx, &key, &probe, &target);
    // "Not found" is the executor's business, not the guard's.
    if seen.facts.value == ValueState::Absent {
        return GateOutcome::Vanished;
    }
    if let Err(refusal) = live::check_key(&check, &seen.facts, &ctx.deny) {
        return GateOutcome::Refused(refusal);
    }
    match (key_item_facts(op, &seen), seen.info) {
        (Some(item_facts), Some(info)) => GateOutcome::Pass(Gated {
            key,
            facts: seen.facts,
            info,
            value: seen.value,
            op,
            item_facts,
        }),
        _ => GateOutcome::Refused(rule(reason::FACTS_UNREADABLE)),
    }
}

/// A registry item that passed [`gate_key`].
#[derive(Debug)]
struct Gated {
    key: WKey,
    facts: KeyFacts,
    info: WKeyInfo,
    value: Option<RegValue>,
    op: KeyOp,
    item_facts: ItemFacts,
}

fn validate_key(ctx: &GateCtx, item: &GateItem<'_>) -> GateOutcome<Validation> {
    gate_key(ctx, item, KeyAccess::READ, Binding::Capture).map(|gated| {
        let stamp = match (gated.op, gated.facts.value) {
            (KeyOp::DeleteValue | KeyOp::EditSegment, ValueState::Present(stamp)) => {
                Stamp::Value(stamp)
            }
            _ => Stamp::Key,
        };
        Validation {
            stamp,
            facts: gated.item_facts,
            exemptions: item.exemptions,
        }
    })
}

/// A registry item that passed the gate, with the key handle to act on.
///
/// The key was opened component by component with `REG_OPTION_OPEN_LINK` at the guard's
/// [`KeyProbe::open`] address (root, view flag, logical path), with the
/// access the action needs (`DELETE` for key actions, `KEY_SET_VALUE` for value and segment actions,
/// `KEY_READ` always), and every fact here was read from it. Perform the action on
/// [`CheckedKey::key`]; never reopen the key.
#[derive(Debug)]
pub struct CheckedKey {
    key: WKey,
    facts: KeyFacts,
    info: WKeyInfo,
    value: Option<RegValue>,
    item_facts: ItemFacts,
}

impl CheckedKey {
    /// The key the gate inspected: the key itself for a key action, the key holding the value for a value
    /// or segment action.
    pub fn key(&self) -> &WKey {
        &self.key
    }

    /// The facts the verdict was given.
    pub fn facts(&self) -> &KeyFacts {
        &self.facts
    }

    /// Counts, class and last write time of the key, from the handle.
    pub fn info(&self) -> &WKeyInfo {
        &self.info
    }

    /// For a value or segment action: the value (raw type and bytes) as read from the handle; its hash is
    /// the validated one.
    pub fn value(&self) -> Option<&RegValue> {
        self.value.as_ref()
    }

    /// The facts in journal form, for the intent's `pre` record.
    pub fn item_facts(&self) -> &ItemFacts {
        &self.item_facts
    }

    /// The key handle, giving up the rest.
    pub fn into_key(self) -> WKey {
        self.key
    }
}

/// The act-time gate for a registry item (`DeleteKeyTree`, `DeleteKeyIfEmpty`, `DeleteValue`,
/// `EditSegment`): opens the key with the access the action needs, reads every fact from that handle and
/// probes each ancestor by itself (G11), then asks [`live::check_key`]; value actions are re-checked
/// against the stamped type and data. On a pass the open key is returned for the action.
///
/// A missing key or value is `Vanished`. Access denied is `Failed` unless a read-only look refuses the
/// item, which is then `Refused`.
pub fn open_and_check_key(
    ctx: &GateCtx,
    item: &GateItem<'_>,
    stamp: &Stamp,
) -> GateOutcome<CheckedKey> {
    let Some(op) = key_op(item.op) else {
        return GateOutcome::Refused(rule(reason::OP_KIND));
    };
    let binding = match (op, stamp) {
        (KeyOp::DeleteKeyTree | KeyOp::DeleteKeyIfEmpty, Stamp::Key) => Binding::Capture,
        (KeyOp::DeleteValue | KeyOp::EditSegment, Stamp::Value(value)) => Binding::Recheck(value),
        _ => return GateOutcome::Refused(rule(reason::STAMP_KIND)),
    };
    gate_key(ctx, item, act_access(op), binding).map(|gated| CheckedKey {
        key: gated.key,
        facts: gated.facts,
        info: gated.info,
        value: gated.value,
        item_facts: gated.item_facts,
    })
}

/// Whether a key, value or segment may be restored at `target` (§7.8, [`live::check_undo_key`]): the key
/// and every ancestor probed by itself with `REG_OPTION_OPEN_LINK`; missing ones are allowed as long as
/// everything below them is missing too.
pub fn check_undo_key(
    ctx: &GateCtx,
    target: &Target,
    exemptions: &Exemptions,
) -> Result<(), Refusal> {
    let probe = live::key_probe(target, ctx.deny.env())?;
    let facts = UndoKeyFacts {
        node: probe_node(&probe.open),
        ancestors: probe_ancestors(&probe),
    };
    live::check_undo_key(target, &facts, &ctx.deny, exemptions)
}
