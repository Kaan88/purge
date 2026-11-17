//! Execute-time verdicts from handle facts (ENGINE_PLAN.md §5.10, §7.2, §7.6, §7.8). Pure: no I/O.
//!
//! The plan-time gates decide from what the scan saw. Between the scan and the act the system can change,
//! by accident or on purpose: a directory is swapped for a junction, a file gains a second name, a key
//! becomes a registry link. The executor therefore opens each item once, reads every fact **from that
//! handle**, asks this module for a verdict, and acts on the same handle. This module never opens
//! anything: the facts arrive in plain structs ([`PathFacts`], [`KeyFacts`], ...) that the executor fills.
//!
//! # Failing closed
//!
//! Every fact that can fail to be read is an `Option` (or an enum with an `Unknown` case), and the
//! `Default` of every facts struct is "nothing known". An unknown fact refuses the action, and so does a
//! contradictory one (a reparse attribute without a tag, a directory bit that disagrees with `is_dir`, an
//! ancestor fact for a key that is not an ancestor). No verdict function has a path that returns `Ok`
//! without having seen every fact its rules need.
//!
//! # Verdicts
//!
//! A verdict is `Result<(), Refusal>`. A [`Refusal`] carries the [`Blocker`] to report and a stable
//! [`reason`] code that says which rule refused. [`Blocker::ChangedSinceScan`] is the only soft refusal
//! (the item is skipped and the batch goes on); every other refusal is hard.
//!
//! | Function | Rules |
//! |---|---|
//! | [`check_path`] | G1 (canonical, final path, reparse tag, identity), G2 on the lexical and the final path, G3, G6, G7, G10 |
//! | [`key_probe`], [`check_key`] | G1 (canonical key), G2 and structural containers, G11 on the key and every ancestor, G3, G13 |
//! | [`check_protected_descendants`] | a whole-tree removal must not take a protected plan item with it |
//! | [`check_quarantine_destination`] | the move target lies in this session's quarantine, on the same volume |
//! | [`StoreScope::new`], [`StoreScope::authorises`], [`check_store_item`] | the own-store exemption for executor-internal work |
//! | [`check_undo_path`], [`check_undo_key`] | §7.8: G2 and G11 on the place an item is restored to |
//! | [`admin_only_ancestors`] | §7.6: a boot-time move only below administrator-only ancestors |
//!
//! Missing items are not this module's business: the executor maps "not found" to `vanished` before it
//! asks for a verdict. A facts struct that says "missing" where a rule needs the item is refused.
//!
//! The verdicts that take a [`DenyList`] also refuse everything while its environment names none of
//! Purge's own directories ([`GuardEnv::purge_dirs`]): Purge's install directory is protected by that
//! fact alone ([`reason::NO_PURGE_DIRS`]).

use std::fmt;

use purge_model::exec::session::SessionId;
use purge_model::{Action, Band, Blocker, Candidate, Hive, Target, View};

use crate::canon::{CanonError, CanonKey, GuardEnv, canon_key, canon_path};
use crate::containers;
use crate::deny::{DenyList, Exemptions, key_of};
use crate::prefix::{self, Relation, SEP, eq_ci};

#[cfg(test)]
mod tests;

/// `FILE_ATTRIBUTE_DIRECTORY`.
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
/// `FILE_ATTRIBUTE_OFFLINE`: the data is not on this volume.
pub const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
/// `FILE_ATTRIBUTE_RECALL_ON_OPEN`: a cloud placeholder without local presence.
pub const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
/// `FILE_ATTRIBUTE_PINNED`: a cloud file the user keeps on the device.
pub const FILE_ATTRIBUTE_PINNED: u32 = 0x0008_0000;
/// `FILE_ATTRIBUTE_UNPINNED`: a cloud file the user keeps online only.
pub const FILE_ATTRIBUTE_UNPINNED: u32 = 0x0010_0000;
/// `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS`: a cloud placeholder whose data is fetched on read.
pub const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;

/// The deny rule [`key_probe`] refuses a key path with an empty segment with.
pub const EMPTY_SEGMENT_RULE: &str = "canon.empty-segment";

/// The attribute bits that mark an item as managed by a sync provider (gate G7).
pub const PLACEHOLDER_ATTRIBUTES: u32 = FILE_ATTRIBUTE_OFFLINE
    | FILE_ATTRIBUTE_RECALL_ON_OPEN
    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    | FILE_ATTRIBUTE_PINNED
    | FILE_ATTRIBUTE_UNPINNED;

/// Whether a reparse tag belongs to a sync or storage provider (gate G7): the `IO_REPARSE_TAG_CLOUD`
/// family (`0x9000001A` to `0x9000F01A`), OneDrive, the Windows 8.1 file placeholder, HSM and HSM2, and the
/// projected file system with its tombstones. Zero is not a tag.
pub fn is_cloud_reparse_tag(tag: u32) -> bool {
    const CLOUD_FAMILY_MASK: u32 = 0xFFFF_0FFF;
    const CLOUD: u32 = 0x9000_001A;
    const OTHERS: [u32; 6] = [
        0x8000_0021, // IO_REPARSE_TAG_ONEDRIVE
        0x8000_0015, // IO_REPARSE_TAG_FILE_PLACEHOLDER
        0xC000_0004, // IO_REPARSE_TAG_HSM
        0x8000_0006, // IO_REPARSE_TAG_HSM2
        0x9000_001C, // IO_REPARSE_TAG_PROJFS
        0xA000_0022, // IO_REPARSE_TAG_PROJFS_TOMBSTONE
    ];
    tag & CLOUD_FAMILY_MASK == CLOUD || OTHERS.contains(&tag)
}

/// Stable codes for [`Refusal::reason`]: which rule refused. Meant for the journal and for tests; the
/// user-facing reason is the blocker.
pub mod reason {
    /// G1: the lexical path does not canonicalise (the blocker names the `canon.*` rule).
    pub const LEXICAL_NOT_CANONICAL: &str = "live.g1.lexical-not-canonical";
    /// G2: a deny rule matches the lexical path.
    pub const DENY_LEXICAL: &str = "live.g2.lexical";
    /// G1: the final path of the handle was not read.
    pub const FINAL_UNKNOWN: &str = "live.g1.final-unknown";
    /// G1: the final path is not a local drive path (volume GUID, UNC, device namespace, bad segment).
    pub const FINAL_NOT_A_DRIVE_PATH: &str = "live.g1.final-not-a-drive-path";
    /// G2: a deny rule matches the final path.
    pub const DENY_FINAL: &str = "live.g2.final";
    /// G1: the final path names another item than the lexical path.
    pub const FINAL_DIFFERS: &str = "live.g1.final-differs";
    /// G1: attributes, reparse tag or item kind were not read.
    pub const HANDLE_FACTS_UNKNOWN: &str = "live.g1.handle-facts-unknown";
    /// G1: two handle facts contradict each other.
    pub const HANDLE_FACTS_CONTRADICT: &str = "live.g1.handle-facts-contradict";
    /// G1: the item itself is a reparse point (junction, symlink, mount point, ...).
    pub const ITEM_IS_REPARSE_POINT: &str = "live.g1.item-is-reparse-point";
    /// G1: file id or volume serial were not read, or are not valid ids.
    pub const IDENTITY_UNKNOWN: &str = "live.g1.identity-unknown";
    /// G1: the item is not the one that was validated (file id, volume serial or kind differ).
    pub const IDENTITY_CHANGED: &str = "live.g1.identity-changed";
    /// G1: the action needs a directory and the item is not one.
    pub const NOT_A_DIRECTORY: &str = "live.g1.not-a-directory";
    /// G7: the item carries a sync provider's reparse tag.
    pub const CLOUD_TAG: &str = "live.g7.cloud-reparse-tag";
    /// G7: the item carries placeholder attributes.
    pub const PLACEHOLDER: &str = "live.g7.placeholder-attributes";
    /// G7: the tree below the item holds placeholders.
    pub const PLACEHOLDER_IN_TREE: &str = "live.g7.placeholder-in-tree";
    /// G10: the volume facts were not read.
    pub const VOLUME_UNKNOWN: &str = "live.g10.volume-unknown";
    /// G10: the volume is not a fixed drive.
    pub const VOLUME_NOT_FIXED: &str = "live.g10.volume-not-fixed";
    /// G10: the file system is neither NTFS nor ReFS.
    pub const FILE_SYSTEM: &str = "live.g10.file-system";
    /// G3: owner or ACL were not read.
    pub const TI_UNKNOWN: &str = "live.g3.unknown";
    /// G3: TrustedInstaller owns the item.
    pub const TI_OWNER: &str = "live.g3.owner";
    /// G3: an ACE names TrustedInstaller.
    pub const TI_ACE: &str = "live.g3.ace";
    /// G6: the link count, or where the other names lie, was not read.
    pub const LINKS_UNKNOWN: &str = "live.g6.unknown";
    /// G6: the item has a name outside the plan.
    pub const LINK_OUTSIDE_PLAN: &str = "live.g6.link-outside-plan";
    /// G6: a file below the item has a name outside the plan.
    pub const LINK_OUTSIDE_PLAN_IN_TREE: &str = "live.g6.link-outside-plan-in-tree";
    /// G6, G7: the tree below a directory was not walked, or not to the end.
    pub const TREE_UNKNOWN: &str = "live.g6.tree-unknown";
    /// The item has no name left (it is being deleted).
    pub const NO_LINKS: &str = "live.g6.no-links";
    /// The operation does not fit the target type.
    pub const OP_TARGET_MISMATCH: &str = "live.op-target-mismatch";
    /// The environment names none of Purge's own directories, so the deny-list cannot protect them.
    pub const NO_PURGE_DIRS: &str = "live.env.no-purge-dirs";
    /// G1: the key path does not canonicalise (the blocker names the `canon.*` rule).
    pub const KEY_NOT_CANONICAL: &str = "live.g1.key-not-canonical";
    /// G1: the key is a hive root (`HKLM`), which is never opened or acted on.
    pub const KEY_IS_HIVE_ROOT: &str = "live.g1.key-is-hive-root";
    /// G2: a deny rule matches the registry target.
    pub const DENY_KEY: &str = "live.g2.key";
    /// The key is a value container and would be deleted as a key.
    pub const STRUCTURAL_CONTAINER: &str = "live.g2.structural-container";
    /// G11: whether the key is a link was not read.
    pub const KEY_LINK_UNKNOWN: &str = "live.g11.key-unknown";
    /// G11: the key is a registry link.
    pub const KEY_IS_LINK: &str = "live.g11.key-is-link";
    /// G11: an ancestor was not probed, or its fact is unknown.
    pub const ANCESTOR_UNKNOWN: &str = "live.g11.ancestor-unknown";
    /// G11: an ancestor is a registry link.
    pub const ANCESTOR_IS_LINK: &str = "live.g11.ancestor-is-link";
    /// G11: the ancestor facts contradict each other or the key.
    pub const ANCESTORS_CONTRADICT: &str = "live.g11.ancestors-contradict";
    /// The key is gone (the executor should have reported `vanished`).
    pub const KEY_MISSING: &str = "live.key-missing";
    /// G13: the subkey and value counts were not read.
    pub const EMPTINESS_UNKNOWN: &str = "live.g13.unknown";
    /// G13: the key is no longer empty.
    pub const NOT_EMPTY: &str = "live.g13.not-empty";
    /// The value was not read.
    pub const VALUE_UNKNOWN: &str = "live.value-unknown";
    /// The value is gone (the executor should have reported `vanished`).
    pub const VALUE_MISSING: &str = "live.value-missing";
    /// The value is not the one that was validated (type or data differ).
    pub const VALUE_CHANGED: &str = "live.value-changed";
    /// A protected plan item lies below a whole-tree removal.
    pub const PROTECTED_DESCENDANT: &str = "live.nesting.protected-descendant";
    /// The path is not strictly inside this session's own directories in a Purge store root.
    pub const OUTSIDE_STORE: &str = "live.store.outside-session";
    /// The store operation needs a recorded identity and none was given.
    pub const STORE_NEEDS_IDENTITY: &str = "live.store.needs-identity";
    /// The store item lies on another volume than its store.
    pub const STORE_OTHER_VOLUME: &str = "live.store.other-volume";
    /// The quarantine destination is not `<quarantine dir of the session>\<op>\<leaf>`.
    pub const QUARANTINE_OUTSIDE_STORE: &str = "live.quarantine.outside-store";
    /// The quarantine destination and the source overlap, or the source lies in or contains a Purge
    /// store root.
    pub const QUARANTINE_OVERLAP: &str = "live.quarantine.overlap";
    /// Source and destination are not known to be on one volume (a serial of 0 is not known).
    pub const QUARANTINE_OTHER_VOLUME: &str = "live.quarantine.other-volume";
    /// The destination's parent is not the plain directory its path names.
    pub const QUARANTINE_PARENT: &str = "live.quarantine.parent";
    /// Something already exists at the destination, or that could not be told.
    pub const QUARANTINE_OCCUPIED: &str = "live.quarantine.occupied";
    /// Undo: the parent of the original path is not the plain directory its path names.
    pub const UNDO_PARENT: &str = "live.undo.parent";
    /// Undo: the original path lies on another volume than the quarantined item, or a serial is 0.
    pub const UNDO_OTHER_VOLUME: &str = "live.undo.other-volume";
    /// Undo: something exists at the original path, or that could not be told.
    pub const UNDO_OCCUPIED: &str = "live.undo.occupied";
}

/// Why an action is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The blocker to report for the item.
    pub blocker: Blocker,
    /// Which rule refused: one of the codes in [`reason`].
    pub reason: &'static str,
}

impl Refusal {
    fn new(blocker: Blocker, reason: &'static str) -> Refusal {
        Refusal { blocker, reason }
    }

    /// A refusal for which no dedicated blocker exists: reported as a deny rule named after the reason.
    fn rule(reason: &'static str) -> Refusal {
        Refusal::new(
            Blocker::DenyListed {
                rule: reason.to_owned(),
            },
            reason,
        )
    }

    /// Whether the refusal is hard. Only [`Blocker::ChangedSinceScan`] is soft: the item is skipped and
    /// reported as such. Either way the action must not happen.
    pub fn is_hard(&self) -> bool {
        self.blocker.is_hard()
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.blocker.name(), self.reason)
    }
}

impl std::error::Error for Refusal {}

impl From<Refusal> for Blocker {
    fn from(refusal: Refusal) -> Blocker {
        refusal.blocker
    }
}

/// The result of a gate: `Ok` lets the action through, `Err` refuses it.
pub type Verdict = Result<(), Refusal>;

fn refuse(blocker: Blocker, reason: &'static str) -> Verdict {
    Err(Refusal::new(blocker, reason))
}

/// Whether the facts are compared with a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding<'a, T> {
    /// The validate pass at the start of a run: nothing is recorded yet. The caller records the stamp of
    /// the facts once the verdict is `Ok`.
    Capture,
    /// Immediately before the act: the facts must describe the item this stamp was taken from.
    Recheck(&'a T),
}

/// The identity of a file or directory on its volume (`FILE_ID_INFO`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    /// The 64-bit volume serial number.
    pub volume_serial: u64,
    /// The 128-bit file id.
    pub file_id: [u8; 16],
}

impl FileIdentity {
    /// Whether the id can identify anything: a file id of all zero bits or all one bits is what a file
    /// system reports when it has no id for the file, and a volume serial of 0 is what a volume without
    /// a serial reports. Either counts as unknown.
    pub fn is_valid(&self) -> bool {
        self.volume_serial != 0 && self.file_id != [0u8; 16] && self.file_id != [0xFFu8; 16]
    }
}

/// Whether two volume serials are known and name one volume: both equal and not 0 (a volume without a
/// serial reports 0, so two of them would look alike).
fn same_volume(a: Option<u64>, b: Option<u64>) -> bool {
    matches!((a, b), (Some(a), Some(b)) if a == b && a != 0)
}

/// Refuses while the environment names none of Purge's own directories: Purge's install directory is
/// protected only by that fact, so a verdict without it could let Purge remove itself.
fn purge_dirs_known(deny: &DenyList) -> Verdict {
    if deny
        .env()
        .purge_dirs
        .iter()
        .any(|dir| !dir.trim().is_empty())
    {
        Ok(())
    } else {
        Err(Refusal::rule(reason::NO_PURGE_DIRS))
    }
}

/// What the validate pass records about a file-system item, and what the act re-checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PathStamp {
    /// The item's identity.
    pub identity: FileIdentity,
    /// Whether it is a directory.
    pub is_dir: bool,
}

/// Facts about the volume an item lies on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeFacts {
    /// `GetDriveTypeW` says `DRIVE_FIXED`.
    pub drive_fixed: bool,
    /// The file system name (`NTFS`, `ReFS`, `FAT32`, ...).
    pub fs_name: String,
}

/// What a walk below a directory found. Needed when the directory is moved whole. The walk opens every
/// entry without following reparse points and never descends into one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TreeFacts {
    /// The walk reached every entry: no error, no entry skipped, no limit hit. `false` refuses.
    pub complete: bool,
    /// Files below the directory with more than one name, of which at least one name is not inside a
    /// path this run removes whole (see [`links_inside_plan`]). A file whose names could not all be
    /// listed counts here.
    pub hard_links_outside_plan: u64,
    /// Entries with placeholder attributes ([`PLACEHOLDER_ATTRIBUTES`]) or a sync provider's reparse tag
    /// ([`is_cloud_reparse_tag`]).
    pub placeholders: u64,
}

/// Facts read from the handle the executor will act on (opened with `FILE_FLAG_OPEN_REPARSE_POINT`).
/// `None` means the fact could not be read; the default knows nothing and is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathFacts {
    /// `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)` as returned (`\\?\C:\...`).
    pub final_path: Option<String>,
    /// The reparse tag; `0` when the item is not a reparse point.
    pub reparse_tag: Option<u32>,
    /// The `FILE_ATTRIBUTE_*` bits.
    pub attributes: Option<u32>,
    /// File id and volume serial.
    pub identity: Option<FileIdentity>,
    /// The number of names (hard links) the item has.
    pub n_links: Option<u32>,
    /// Whether the item is a directory.
    pub is_dir: Option<bool>,
    /// Facts about the volume.
    pub volume: Option<VolumeFacts>,
    /// The owner is `NT SERVICE\TrustedInstaller`.
    pub owner_is_ti: Option<bool>,
    /// The DACL holds an **explicit** (not inherited) ACE that names TrustedInstaller. Inherited ones do
    /// not count: every item below `Program Files` inherits one from that directory.
    pub explicit_ti_ace: Option<bool>,
    /// For an item with more than one name: every other name lies inside a path this run removes whole
    /// (compute it with [`links_inside_plan`]). Not consulted when `n_links` is 1.
    pub links_inside_plan: Option<bool>,
    /// For a directory that is moved whole: what the walk below it found.
    pub tree: Option<TreeFacts>,
}

impl PathFacts {
    /// The stamp to record for the item once the validate pass has let it through. `None` while the
    /// identity or the kind is unknown.
    pub fn stamp(&self) -> Option<PathStamp> {
        let identity = self.identity.filter(FileIdentity::is_valid)?;
        Some(PathStamp {
            identity,
            is_dir: self.is_dir?,
        })
    }
}

/// What the executor is about to do with a file-system item of the plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathOp {
    /// Move the file, or the directory with everything below it, into quarantine.
    QuarantineMove,
    /// Remove the directory if it is empty (a non-recursive `RemoveDirectory`).
    RemoveDirIfEmpty,
}

/// One request to [`check_path`].
#[derive(Debug, Clone, Copy)]
pub struct PathCheck<'a> {
    /// The path as the plan spells it.
    pub lexical: &'a str,
    /// The intended action.
    pub op: PathOp,
    /// Validate pass, or re-check against the recorded stamp.
    pub binding: Binding<'a, PathStamp>,
    /// What the candidate's evidence has earned, derived as at plan time.
    pub exemptions: Exemptions<'a>,
}

/// The canonical form of a path without any environment: a leading `%TOKEN%` is refused. Plans hold
/// expanded paths, and a final path never has a token.
fn canon_plain(path: &str) -> Result<String, CanonError> {
    canon_path(path, &GuardEnv::default(), None).map(|canon| canon.path)
}

fn path_target(path: &str) -> Target {
    Target::Path {
        path: path.to_owned(),
    }
}

/// The parent directory of a canonical path, in canonical form (`C:\` for an item in a drive root).
/// `None` for a drive root.
fn parent_dir(canonical: &str) -> Option<String> {
    let up = prefix::parent(canonical)?;
    Some(if up.contains(SEP) {
        up.to_owned()
    } else {
        format!("{up}{SEP}")
    })
}

/// The canonical final path, or the refusal for a final path that is unknown or not a drive path.
fn final_path_of(final_path: Option<&str>) -> Result<String, Refusal> {
    let raw =
        final_path.ok_or_else(|| Refusal::new(Blocker::ReparseMismatch, reason::FINAL_UNKNOWN))?;
    canon_plain(raw)
        .map_err(|_| Refusal::new(Blocker::ReparseMismatch, reason::FINAL_NOT_A_DRIVE_PATH))
}

/// The gate for one file-system item of the plan (G1, G2, G3, G6, G7, G10 of §7.2), from the facts of the
/// handle the executor acts on.
///
/// In order, the first failing rule decides:
///
/// 1. **G1** the lexical path canonicalises (`\\?\` stripped, separators unified; no environment token).
/// 2. **G2** the deny-list on the lexical path; the environment names Purge's own directories
///    ([`reason::NO_PURGE_DIRS`]).
/// 3. **G1** the final path is known and is a drive path; **G2** the deny-list on the final path (so a
///    clean path that resolves into a protected place reports the deny rule); the final path names the
///    same item as the lexical path, segment by segment and case-folded ([`crate::prefix`]), else
///    [`Blocker::ReparseMismatch`]. An 8.3 alias, a junction or a symlink anywhere on the way, a volume
///    GUID path and a trailing-dot alias all differ.
/// 4. **G1** the item itself is not a reparse point (**G7**: a sync provider's tag reports
///    [`Blocker::SyncRoot`]), and the handle facts agree with each other.
/// 5. **G7** no placeholder attributes.
/// 6. **G10** the volume is fixed and NTFS or ReFS, else [`Blocker::CannotBackUp`].
/// 7. **G3** TrustedInstaller neither owns the item nor has an explicit ACE on it.
/// 8. **G6** every other name of the item lies inside the plan.
/// 9. A directory moved whole: the walk below it is complete and found no hard link out of the plan and
///    no placeholder. `RemoveDirIfEmpty` needs a directory.
/// 10. **G1** the identity is known, and under [`Binding::Recheck`] it is the recorded one, else
///     [`Blocker::ChangedSinceScan`] (soft: skip).
///
/// Comparison is case-insensitive as on a default NTFS directory. In a directory marked case-sensitive
/// two names that differ only in case are two files; the identity re-check is what tells them apart.
pub fn check_path(check: &PathCheck<'_>, facts: &PathFacts, deny: &DenyList) -> Verdict {
    let lexical = canon_plain(check.lexical).map_err(|e| {
        Refusal::new(
            Blocker::DenyListed {
                rule: format!("canon.{}", e.code()),
            },
            reason::LEXICAL_NOT_CANONICAL,
        )
    })?;
    if let Some(blocker) = deny.check(&path_target(&lexical), &check.exemptions) {
        return refuse(blocker, reason::DENY_LEXICAL);
    }
    purge_dirs_known(deny)?;

    let final_path = final_path_of(facts.final_path.as_deref())?;
    // A final path comes from the file system in long form, whatever the caller knows about the
    // lexical one.
    let final_exemptions = Exemptions {
        long_names_resolved: true,
        ..check.exemptions
    };
    if let Some(blocker) = deny.check(&path_target(&final_path), &final_exemptions) {
        return refuse(blocker, reason::DENY_FINAL);
    }
    if !prefix::is_same(&lexical, &final_path) {
        return refuse(Blocker::ReparseMismatch, reason::FINAL_DIFFERS);
    }

    let (Some(attributes), Some(tag), Some(is_dir)) =
        (facts.attributes, facts.reparse_tag, facts.is_dir)
    else {
        return refuse(Blocker::ReparseMismatch, reason::HANDLE_FACTS_UNKNOWN);
    };
    let reparse_bit = attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    if is_cloud_reparse_tag(tag) {
        return refuse(Blocker::SyncRoot, reason::CLOUD_TAG);
    }
    if tag != 0 && reparse_bit {
        return refuse(Blocker::ReparseMismatch, reason::ITEM_IS_REPARSE_POINT);
    }
    if tag != 0 || reparse_bit || is_dir != (attributes & FILE_ATTRIBUTE_DIRECTORY != 0) {
        return refuse(Blocker::ReparseMismatch, reason::HANDLE_FACTS_CONTRADICT);
    }
    if attributes & PLACEHOLDER_ATTRIBUTES != 0 {
        return refuse(Blocker::SyncRoot, reason::PLACEHOLDER);
    }

    let Some(volume) = &facts.volume else {
        return refuse(Blocker::CannotBackUp, reason::VOLUME_UNKNOWN);
    };
    if !volume.drive_fixed {
        return refuse(Blocker::CannotBackUp, reason::VOLUME_NOT_FIXED);
    }
    if !["NTFS", "ReFS"]
        .iter()
        .any(|fs| volume.fs_name.eq_ignore_ascii_case(fs))
    {
        return refuse(Blocker::CannotBackUp, reason::FILE_SYSTEM);
    }

    trusted_installer(facts.owner_is_ti, facts.explicit_ti_ace)?;

    match facts.n_links {
        None => return refuse(Blocker::HardLinkOutsidePlan, reason::LINKS_UNKNOWN),
        Some(0) => return refuse(Blocker::ChangedSinceScan, reason::NO_LINKS),
        Some(1) => {}
        Some(_) => match facts.links_inside_plan {
            None => return refuse(Blocker::HardLinkOutsidePlan, reason::LINKS_UNKNOWN),
            Some(false) => return refuse(Blocker::HardLinkOutsidePlan, reason::LINK_OUTSIDE_PLAN),
            Some(true) => {}
        },
    }

    match (check.op, is_dir) {
        (PathOp::QuarantineMove, false) => {}
        (PathOp::QuarantineMove, true) => match &facts.tree {
            Some(tree) if tree.complete => {
                if tree.hard_links_outside_plan != 0 {
                    return refuse(
                        Blocker::HardLinkOutsidePlan,
                        reason::LINK_OUTSIDE_PLAN_IN_TREE,
                    );
                }
                if tree.placeholders != 0 {
                    return refuse(Blocker::SyncRoot, reason::PLACEHOLDER_IN_TREE);
                }
            }
            _ => return refuse(Blocker::HardLinkOutsidePlan, reason::TREE_UNKNOWN),
        },
        (PathOp::RemoveDirIfEmpty, true) => {}
        (PathOp::RemoveDirIfEmpty, false) => {
            return refuse(Blocker::ChangedSinceScan, reason::NOT_A_DIRECTORY);
        }
    }

    let Some(stamp) = facts.stamp() else {
        return refuse(Blocker::ReparseMismatch, reason::IDENTITY_UNKNOWN);
    };
    match check.binding {
        Binding::Capture => Ok(()),
        Binding::Recheck(recorded) if *recorded == stamp => Ok(()),
        Binding::Recheck(_) => refuse(Blocker::ChangedSinceScan, reason::IDENTITY_CHANGED),
    }
}

/// G3 from the two TrustedInstaller facts.
fn trusted_installer(owner: Option<bool>, ace: Option<bool>) -> Verdict {
    match (owner, ace) {
        (Some(true), _) => refuse(Blocker::TrustedInstallerOwned, reason::TI_OWNER),
        (_, Some(true)) => refuse(Blocker::TrustedInstallerOwned, reason::TI_ACE),
        (Some(false), Some(false)) => Ok(()),
        _ => refuse(Blocker::TrustedInstallerOwned, reason::TI_UNKNOWN),
    }
}

/// Whether every name of a hard-linked file lies inside the plan (gate G6): `names` are all names of the
/// file as full paths (`FindFirstFileNameW`, with the drive put in front), `n_links` is the link count
/// from the handle, and `removed_whole` are the paths this run moves to quarantine whole.
///
/// `false` when the list does not hold exactly `n_links` names, when a name does not canonicalise, or
/// when a name is neither one of `removed_whole` nor below one.
pub fn links_inside_plan<N: AsRef<str>, R: AsRef<str>>(
    names: &[N],
    n_links: u32,
    removed_whole: &[R],
) -> bool {
    if names.is_empty() || u32::try_from(names.len()) != Ok(n_links) {
        return false;
    }
    let Ok(roots) = removed_whole
        .iter()
        .map(|root| canon_plain(root.as_ref()))
        .collect::<Result<Vec<_>, _>>()
    else {
        return false;
    };
    names.iter().all(|name| {
        canon_plain(name.as_ref()).is_ok_and(|name| {
            roots
                .iter()
                .any(|root| prefix::is_same_or_inside(&name, root))
        })
    })
}

// ---------------------------------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------------------------------

/// What a probe of one registry key found. The key is opened with `REG_OPTION_OPEN_LINK`, so a link is
/// seen as a link and not followed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum KeyNode {
    /// The probe failed or was not made. Refused.
    #[default]
    Unknown,
    /// No such key.
    Missing,
    /// An ordinary key.
    Plain,
    /// A registry link (`REG_LINK`, a `SymbolicLinkValue`).
    Link,
}

/// The predefined registry root a [`KeyAddress`] is opened below. One-to-one with `RegRoot` of the
/// `purge-win` crate, which this crate does not depend on: `KeyRoot::Hklm` is `RegRoot::Hklm` and
/// `KeyRoot::Hku` is `RegRoot::Hku`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyRoot {
    /// `HKEY_LOCAL_MACHINE`.
    Hklm,
    /// `HKEY_USERS`. The path of the address starts with `<SID>` or `<SID>_Classes`.
    Hku,
}

impl KeyRoot {
    /// `HKLM` or `HKU`.
    pub fn name(self) -> &'static str {
        match self {
            KeyRoot::Hklm => "HKLM",
            KeyRoot::Hku => "HKU",
        }
    }
}

/// Where one registry key is opened: exactly the `root`, `path` and `view` arguments of
/// `WKey::open(root, path, view, access)` in `purge-win`'s `reg_write` module, which walks the path one
/// component at a time with `REG_OPTION_OPEN_LINK`.
///
/// | Field | `WKey::open` argument |
/// |---|---|
/// | `root`: [`KeyRoot::Hklm`] / [`KeyRoot::Hku`] | `root`: `RegRoot::Hklm` / `RegRoot::Hku` |
/// | `path`, as it is | `path` |
/// | `view`: [`View::K64`] / [`View::K32`] | `view`: `RegView::K64` / `RegView::K32` |
///
/// `path` is never empty (a hive root is not opened) and is relative to the root: under
/// [`KeyRoot::Hku`] its first segment is `<SID>` or `<SID>_Classes`.
///
/// # Registry view
///
/// A key in the 32-bit view is addressed with the view flag and its logical path, never through a
/// `WOW6432Node` segment: (`K32`, `SOFTWARE\Vendor`), not (`K64`, `SOFTWARE\WOW6432Node\Vendor`).
/// Windows documents `WOW6432Node` as the physical location of redirected keys, reserved by the system
/// and subject to change, and tells programs to reach the other view with `KEY_WOW64_32KEY` instead
/// ("Registry Redirector", "Accessing an Alternate Registry View"). Windows 11 shows why:
/// `HKLM\SOFTWARE\WOW6432Node\Classes` is a registry link to `HKLM\SOFTWARE\Classes\Wow6432Node`, so a
/// walk through the physical spelling meets a link and G11 refuses every 32-bit `HKLM` class key, while
/// the flag route has no link on its components (measured unelevated on Windows 11 build 26300 in the
/// M2 wave 1 review, finding S1).
///
/// Place by place (wire spelling of [`Target`] on the left):
///
/// - `HKLM\SOFTWARE\WOW6432Node\Classes\X` (32-bit machine classes; also spelled
///   `HKLM\SOFTWARE\Classes\WOW6432Node\X`): (`Hklm`, `K32`, `SOFTWARE\Classes\X`).
/// - `HKLM\SOFTWARE\WOW6432Node\X`, `X` not `Classes`: (`Hklm`, `K32`, `SOFTWARE\X`). The physical
///   `SOFTWARE\WOW6432Node` is a plain key today, but it is the reserved spelling; one rule for every
///   32-bit key keeps the executor free of special cases.
/// - `HKU\<SID>_Classes\WOW6432Node\X` (a user's 32-bit classes): (`Hku`, `K32`, `<SID>_Classes\X`).
///   The review measured no link there on either route.
/// - `HKU\<SID>\Software\WOW6432Node\X`: a user's `Software` is not redirected (only `HKLM\SOFTWARE`
///   and the classes roots are), so this `WOW6432Node` is an ordinary key name:
///   (`Hku`, `K64`, `<SID>\Software\WOW6432Node\X`).
/// - Everything else: the 64-bit view, with the two aliases of §5.10 already resolved
///   (`SYSTEM\ControlSet00N` for `SYSTEM\CurrentControlSet`, `<SID>_Classes` for
///   `<SID>\Software\Classes`).
///
/// A subkey Windows shares between the views (`SOFTWARE\Classes\AppID`, for one) is one key in both
/// views; the flag route reaches the key a 32-bit program wrote there.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyAddress {
    /// The predefined root.
    pub root: KeyRoot,
    /// The registry view.
    pub view: View,
    /// The path below the root, without a redirecting `WOW6432Node` segment. Never empty.
    pub path: String,
}

impl KeyAddress {
    /// The address of a canonical key, by the rule of the type documentation.
    fn of(key: &CanonKey) -> KeyAddress {
        let below = |top: String| {
            if key.path.is_empty() {
                top
            } else {
                format!("{top}{SEP}{}", key.path)
            }
        };
        let (root, path) = match &key.hive {
            Hive::Hklm => (KeyRoot::Hklm, key.path.clone()),
            Hive::Hku(sid) => (KeyRoot::Hku, below(sid.clone())),
            Hive::HkuClasses(sid) => (KeyRoot::Hku, below(format!("{sid}_Classes"))),
        };
        KeyAddress {
            root,
            view: key.view,
            path,
        }
    }

    /// Whether two addresses name one key the same way: same root and view, and paths equal as keys
    /// are compared (case-insensitively).
    pub fn is_same(&self, other: &KeyAddress) -> bool {
        self.root == other.root
            && self.view == other.view
            && prefix::is_same(&self.path, &other.path)
    }
}

impl fmt::Display for KeyAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{SEP}{} ({}-bit view)",
            self.root.name(),
            self.path,
            self.view.bits()
        )
    }
}

/// The probe of one ancestor of a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyAncestor {
    /// The ancestor as [`KeyProbe::ancestors`] lists it, opened by itself at exactly this address.
    pub key: KeyAddress,
    /// What the probe found.
    pub node: KeyNode,
}

/// What the validate pass records about a registry value, and what the act re-checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValueStamp {
    /// The raw value type.
    pub ty: u32,
    /// The length of the raw data in bytes.
    pub len: u64,
    /// SHA-256 of the raw data (computed by the caller; the guard only compares it).
    pub sha256: [u8; 32],
}

/// The state of the value a value-level action is about.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum ValueState {
    /// Not read, or the read failed. Refused.
    #[default]
    Unknown,
    /// The key has no such value.
    Absent,
    /// The value as it is now.
    Present(ValueStamp),
}

/// Facts about the key of a registry target: the key itself for a key action, the key that holds the
/// value for a value or segment action. Read from the handle the executor acts on. The default knows
/// nothing and is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyFacts {
    /// What the key is, opened at [`KeyProbe::open`].
    pub node: KeyNode,
    /// Every ancestor [`key_probe`] lists, each opened by itself at its [`KeyAddress`] with
    /// `REG_OPTION_OPEN_LINK`.
    pub ancestors: Vec<KeyAncestor>,
    /// The key's owner is `NT SERVICE\TrustedInstaller`.
    pub owner_is_ti: Option<bool>,
    /// An ACE of the key's DACL names TrustedInstaller.
    pub has_ti_ace: Option<bool>,
    /// The number of subkeys (`RegQueryInfoKey`). Needed for [`KeyOp::DeleteKeyIfEmpty`].
    pub subkeys: Option<u32>,
    /// The number of values, the default value included when set. Needed for
    /// [`KeyOp::DeleteKeyIfEmpty`].
    pub values: Option<u32>,
    /// The value, for [`KeyOp::DeleteValue`] and [`KeyOp::EditSegment`].
    pub value: ValueState,
}

/// What the executor is about to do with a registry target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyOp {
    /// Delete the key and everything below it ([`Target::RegKey`]).
    DeleteKeyTree,
    /// Delete the key if it has no subkey and no value ([`Target::RegKey`]).
    DeleteKeyIfEmpty,
    /// Delete one value ([`Target::RegValue`]).
    DeleteValue,
    /// Remove one segment of a list-like value ([`Target::RegMultiSzSegment`]).
    EditSegment,
}

/// One request to [`check_key`].
#[derive(Debug, Clone, Copy)]
pub struct KeyCheck<'a> {
    /// The registry target of the plan item.
    pub target: &'a Target,
    /// The intended action.
    pub op: KeyOp,
    /// For value and segment actions: validate pass, or re-check against the recorded value. Ignored
    /// for key actions.
    pub binding: Binding<'a, ValueStamp>,
    /// What the candidate's evidence has earned, derived as at plan time.
    pub exemptions: Exemptions<'a>,
}

/// Where the facts for a registry target must be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyProbe {
    /// The canonical key: hive, view and path below the hive.
    pub key: CanonKey,
    /// Where to open the key: the arguments of `WKey::open` (see [`KeyAddress`]). This is the key to
    /// open, read the facts from, and act on.
    pub open: KeyAddress,
    /// The key's wire spelling as [`Target`] has it, e.g. `HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{X}`.
    /// A label for reports and the journal only: it is **not** a path to open, since the spelling
    /// through `WOW6432Node` can run through a registry link.
    pub label: String,
    /// Every ancestor to probe, from the top downwards, in the root and view of [`KeyProbe::open`]:
    /// every proper prefix of its path, the path components `WKey::open` walks. For
    /// `HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{X}` these are (`Hklm`, `K32`) `SOFTWARE`,
    /// `SOFTWARE\Classes`, `SOFTWARE\Classes\CLSID`. Under `HKU` the list starts at the hive key
    /// (`<SID>` or `<SID>_Classes`). Empty for a key directly below its root.
    pub ancestors: Vec<KeyAddress>,
}

/// The key a registry target is read at, and the ancestors whose link state [`check_key`] and
/// [`check_undo_key`] need (G11). The two aliases of §5.10 are resolved here and nowhere else:
/// `CurrentControlSet` becomes `ControlSet00N` and `HKU\<SID>\Software\Classes` becomes
/// `HKU\<SID>_Classes`, so neither link is on the probed chain; the 32-bit view is addressed by its view
/// flag, so the `WOW6432Node\Classes` link is not on it either ([`KeyAddress`]). `HKCR`, an unbound
/// `HKCU` and every other spelling that does not canonicalise are refused with the `canon.*` rule; a hive
/// root (`HKLM`) and a target that is not a registry target are refused too.
///
/// A spelling with an empty segment (a trailing or a doubled backslash; one leading backslash, as in
/// `\REGISTRY\MACHINE\...`, is allowed) is refused with the rule [`EMPTY_SEGMENT_RULE`]: the key path is
/// also the text a registry backup records, and every later derivation of the key's leaf from that text
/// must give the leaf this probe opens (review M2 final S6: a key spelled `...\App\` was deleted and its
/// backup could then not be read back as the backup of the op). Canonicalising alone would accept it.
pub fn key_probe(target: &Target, env: &GuardEnv) -> Result<KeyProbe, Refusal> {
    let key_path = key_of(target).ok_or_else(|| Refusal::rule(reason::OP_TARGET_MISMATCH))?;
    let body = key_path.strip_prefix(SEP).unwrap_or(key_path);
    // An empty path is the canonicaliser's own refusal (`canon.empty`).
    if !body.is_empty() && body.split(SEP).any(str::is_empty) {
        return Err(Refusal::new(
            Blocker::DenyListed {
                rule: EMPTY_SEGMENT_RULE.to_owned(),
            },
            reason::KEY_NOT_CANONICAL,
        ));
    }
    let key = canon_key(key_path, None, env, None).map_err(|e| {
        Refusal::new(
            Blocker::DenyListed {
                rule: format!("canon.{}", e.code()),
            },
            reason::KEY_NOT_CANONICAL,
        )
    })?;
    let open = KeyAddress::of(&key);
    if prefix::depth(&open.path) == 0 {
        return Err(Refusal::rule(reason::KEY_IS_HIVE_ROOT));
    }
    // Nearest first, then turned around.
    let mut ancestors: Vec<KeyAddress> = prefix::ancestors(&open.path)
        .map(|path| KeyAddress {
            root: open.root,
            view: open.view,
            path: path.to_owned(),
        })
        .collect();
    ancestors.reverse();
    Ok(KeyProbe {
        label: key.key_path(),
        key,
        open,
        ancestors,
    })
}

/// G11 for the ancestors: every ancestor of the probe has exactly the states the facts give it, none is
/// a link or unknown, and no fact names a key off the chain (another root, another view, another path).
/// With `may_be_missing`, an ancestor may be missing as long as everything below it is missing too;
/// returns whether any ancestor is missing.
fn check_ancestors(
    probe: &KeyProbe,
    facts: &[KeyAncestor],
    may_be_missing: bool,
) -> Result<bool, Refusal> {
    let link = |reason| Refusal::new(Blocker::RegLink, reason);
    if facts
        .iter()
        .any(|fact| !probe.ancestors.iter().any(|a| a.is_same(&fact.key)))
    {
        return Err(link(reason::ANCESTORS_CONTRADICT));
    }
    let mut missing = false;
    for ancestor in &probe.ancestors {
        let mut nodes = facts
            .iter()
            .filter(|fact| fact.key.is_same(ancestor))
            .map(|fact| fact.node);
        let node = nodes.next().ok_or_else(|| link(reason::ANCESTOR_UNKNOWN))?;
        if nodes.any(|other| other != node) {
            return Err(link(reason::ANCESTORS_CONTRADICT));
        }
        match node {
            KeyNode::Unknown => return Err(link(reason::ANCESTOR_UNKNOWN)),
            KeyNode::Link => return Err(link(reason::ANCESTOR_IS_LINK)),
            KeyNode::Missing if may_be_missing => missing = true,
            KeyNode::Missing => return Err(link(reason::ANCESTORS_CONTRADICT)),
            KeyNode::Plain if missing => return Err(link(reason::ANCESTORS_CONTRADICT)),
            KeyNode::Plain => {}
        }
    }
    Ok(missing)
}

/// G2 for a registry target: the deny-list, then the structural containers.
fn deny_key(target: &Target, deny: &DenyList, exemptions: &Exemptions) -> Verdict {
    if let Some(blocker) = deny.check(target, exemptions) {
        return refuse(blocker, reason::DENY_KEY);
    }
    if let Some(blocker) = containers::check(target, deny.env()) {
        return refuse(blocker, reason::STRUCTURAL_CONTAINER);
    }
    Ok(())
}

/// The gate for one registry item of the plan (G1, G2, G3, G11, G13 of §7.2), from the facts of the key
/// handle the executor acts on.
///
/// In order, the first failing rule decides:
///
/// 1. The operation fits the target type ([`KeyOp`]); `RegValueChanged` and non-registry targets never do.
/// 2. **G1** the key canonicalises ([`key_probe`]).
/// 3. **G2** the deny-list on the target, then [`containers::check`]; the environment names Purge's own
///    directories ([`reason::NO_PURGE_DIRS`]).
/// 4. **G11** the key (read at [`KeyProbe::open`]) is an ordinary key, and so is every ancestor: the
///    facts must cover the whole chain of [`KeyProbe::ancestors`], each at its [`KeyAddress`]. A link or
///    an unknown reports [`Blocker::RegLink`].
/// 5. **G3** TrustedInstaller neither owns the key nor is named in its DACL.
/// 6. **G13** for [`KeyOp::DeleteKeyIfEmpty`]: no subkey and no value, else
///    [`Blocker::ChangedSinceScan`] (soft: "no longer empty").
/// 7. For a value or segment action: the value exists, and under [`Binding::Recheck`] it has the recorded
///    type and data, else [`Blocker::ChangedSinceScan`].
///
/// Links below a key that is deleted as a tree are not seen here: the backup walk of §7.4 opens every
/// subkey with `REG_OPTION_OPEN_LINK` and refuses them, and without a verified backup nothing is deleted.
pub fn check_key(check: &KeyCheck<'_>, facts: &KeyFacts, deny: &DenyList) -> Verdict {
    let fits = matches!(
        (check.op, check.target),
        (
            KeyOp::DeleteKeyTree | KeyOp::DeleteKeyIfEmpty,
            Target::RegKey { .. }
        ) | (KeyOp::DeleteValue, Target::RegValue { .. })
            | (KeyOp::EditSegment, Target::RegMultiSzSegment { .. })
    );
    if !fits {
        return Err(Refusal::rule(reason::OP_TARGET_MISMATCH));
    }
    let probe = key_probe(check.target, deny.env())?;
    deny_key(check.target, deny, &check.exemptions)?;
    purge_dirs_known(deny)?;

    match facts.node {
        KeyNode::Unknown => return refuse(Blocker::RegLink, reason::KEY_LINK_UNKNOWN),
        KeyNode::Link => return refuse(Blocker::RegLink, reason::KEY_IS_LINK),
        KeyNode::Missing | KeyNode::Plain => {}
    }
    check_ancestors(&probe, &facts.ancestors, false)?;
    if facts.node == KeyNode::Missing {
        return refuse(Blocker::ChangedSinceScan, reason::KEY_MISSING);
    }

    trusted_installer(facts.owner_is_ti, facts.has_ti_ace)?;

    match check.op {
        KeyOp::DeleteKeyTree => Ok(()),
        KeyOp::DeleteKeyIfEmpty => match (facts.subkeys, facts.values) {
            (Some(0), Some(0)) => Ok(()),
            (Some(_), Some(_)) => refuse(Blocker::ChangedSinceScan, reason::NOT_EMPTY),
            _ => refuse(Blocker::ChangedSinceScan, reason::EMPTINESS_UNKNOWN),
        },
        KeyOp::DeleteValue | KeyOp::EditSegment => match (facts.value, check.binding) {
            (ValueState::Unknown, _) => refuse(Blocker::ChangedSinceScan, reason::VALUE_UNKNOWN),
            (ValueState::Absent, _) => refuse(Blocker::ChangedSinceScan, reason::VALUE_MISSING),
            (ValueState::Present(_), Binding::Capture) => Ok(()),
            (ValueState::Present(now), Binding::Recheck(recorded)) if now == *recorded => Ok(()),
            (ValueState::Present(_), Binding::Recheck(_)) => {
                refuse(Blocker::ChangedSinceScan, reason::VALUE_CHANGED)
            }
        },
    }
}

// ---------------------------------------------------------------------------------------------------
// Whole-tree removals and protected plan items
// ---------------------------------------------------------------------------------------------------

/// Whether `child` lies inside `parent`: strictly for path in path and key in key, and a value lies
/// inside its own key. The rule of `purge_plan::collapse::nests_in`.
fn nests_in(child: &Target, parent: &Target) -> bool {
    match (child, parent) {
        (Target::Path { path: c }, Target::Path { path: p })
        | (Target::RegKey { path: c }, Target::RegKey { path: p }) => {
            prefix::relation(c, p) == Relation::Inside
        }
        (
            Target::RegValue { path: c, .. }
            | Target::RegValueChanged { path: c, .. }
            | Target::RegMultiSzSegment { path: c, .. },
            Target::RegKey { path: p },
        ) => matches!(prefix::relation(c, p), Relation::Inside | Relation::Same),
        _ => false,
    }
}

/// A selected whole-tree removal (`Quarantine` of a path, `DeleteKey` of a key) must not take a protected
/// plan item with it (the requirement of the M1a review on the executor, `docs/DECISIONS.md`
/// 2026-11-15).
///
/// `plan` is every candidate of the scan document, top-level and absorbed, the selected item included or
/// not. A candidate below `selected` is protected when it is in the Blocked band, carries a hard blocker,
/// or was never decided. The removal is then refused with that candidate's first hard blocker (a
/// `DenyListed` rule named after the reason when it has none), so the report says what lies below.
/// Actions that do not remove a tree always pass.
///
/// This is a verdict over the plan, not over handles: its place is the selection check when the plan is
/// loaded, before anything is touched. It may be called again per item.
pub fn check_protected_descendants<'a>(
    selected: &Candidate,
    plan: impl IntoIterator<Item = &'a Candidate>,
) -> Verdict {
    let whole_tree = matches!(
        (&selected.target, selected.action),
        (Target::Path { .. }, Action::Quarantine) | (Target::RegKey { .. }, Action::DeleteKey)
    );
    if !whole_tree {
        return Ok(());
    }
    for candidate in plan {
        if !nests_in(&candidate.target, &selected.target) {
            continue;
        }
        let hard = candidate.blockers.iter().find(|b| b.is_hard());
        let blocked = candidate
            .decision
            .as_ref()
            .is_none_or(|decision| decision.band == Band::Blocked);
        if blocked || hard.is_some() {
            return Err(match hard {
                Some(blocker) => Refusal::new(blocker.clone(), reason::PROTECTED_DESCENDANT),
                None => Refusal::rule(reason::PROTECTED_DESCENDANT),
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------
// Purge's own store
// ---------------------------------------------------------------------------------------------------

/// Name of the sessions directory under the data root. Must stay equal to `SESSIONS_DIR` of
/// `purge-exec`'s `storage` module, which owns the layout; this crate cannot depend on that one, so the
/// name is repeated here.
pub const SESSIONS_DIR: &str = "sessions";
/// Name of the quarantine directory under the data root. Must stay equal to `QUARANTINE_DIR` of
/// `purge-exec`'s `storage` module.
pub const QUARANTINE_DIR: &str = "Quarantine";
/// Name of the quarantine directory at the root of every other volume. Must stay equal to
/// `VOLUME_QUARANTINE_DIR` of `purge-exec`'s `storage` module.
pub const VOLUME_QUARANTINE_DIR: &str = ".purge-q";

/// Why a [`StoreScope`] could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreScopeError {
    /// The data root is not an absolute drive path below a drive root (`C:\ProgramData\Purge`).
    DataRoot(String),
    /// A quarantine root is neither `<data root>\Quarantine` nor `X:\.purge-q` at the root of a drive
    /// other than the data root's.
    QuarantineRoot(String),
}

impl fmt::Display for StoreScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DataRoot(path) => write!(f, "not a Purge data root: {path:?}"),
            Self::QuarantineRoot(path) => write!(f, "not a Purge quarantine root: {path:?}"),
        }
    }
}

impl std::error::Error for StoreScopeError {}

/// The directories one session owns in Purge's store. Everything in Purge's directories is deny-listed
/// (`fs.purge`); this is the one exemption, and it reaches no further than these directories.
///
/// Built only by [`StoreScope::new`], which derives every directory from the store's roots and the
/// session id with the layout of `purge-exec`'s `storage` module ([`SESSIONS_DIR`], [`QUARANTINE_DIR`],
/// [`VOLUME_QUARANTINE_DIR`]):
///
/// - the session directory `<data root>\sessions\<session>` (journal, registry backups, definitions);
/// - the quarantine directory `<data root>\Quarantine\<session>` on the data root's volume;
/// - `X:\.purge-q\<session>` on every other volume the session quarantines on.
///
/// So every directory of the scope ends in the session id, and lies one level below a Purge store root
/// (`<data root>\sessions`, `<data root>\Quarantine`, `X:\.purge-q`): another session, the index and the
/// rest of the disk are never in scope, whatever the caller passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreScope {
    session: SessionId,
    /// The canonical data root and the canonical `X:\.purge-q` roots: everything Purge's store holds.
    roots: Vec<String>,
    /// `<data root>\sessions\<session>`, canonical.
    session_dir: String,
    /// `<data root>\Quarantine\<session>` first, then `X:\.purge-q\<session>`, canonical.
    quarantine_dirs: Vec<String>,
}

impl StoreScope {
    /// The scope of `session` in the store at `data_root` (`C:\ProgramData\Purge`, or a test root in a
    /// temporary directory).
    ///
    /// `quarantine_roots` are the quarantine roots of the other volumes the session uses, each
    /// `X:\.purge-q` at the root of a drive other than the data root's. `<data root>\Quarantine` is
    /// always part of the scope and may be listed too; duplicates count once. Anything else, a drive root
    /// or a directory that does not canonicalise is refused, and so is a data root that does not
    /// canonicalise (`%TOKEN%`, UNC, relative) or is a drive root.
    pub fn new<S: AsRef<str>>(
        data_root: &str,
        quarantine_roots: &[S],
        session: &SessionId,
    ) -> Result<StoreScope, StoreScopeError> {
        let data = canon_plain(data_root)
            .ok()
            .filter(|root| prefix::depth(root) >= 2)
            .ok_or_else(|| StoreScopeError::DataRoot(data_root.to_owned()))?;
        let id = session.as_str();
        let below = |dir: &str, name: &str| format!("{}{SEP}{name}", dir.trim_end_matches(SEP));
        let drive = |path: &str| prefix::segments(path).next().unwrap_or_default().to_owned();
        let main_quarantine = below(&data, QUARANTINE_DIR);
        let data_drive = drive(&data);

        let mut roots = vec![data.clone()];
        let mut quarantine_dirs = vec![below(&main_quarantine, id)];
        for raw in quarantine_roots {
            let raw = raw.as_ref();
            let bad = || StoreScopeError::QuarantineRoot(raw.to_owned());
            let root = canon_plain(raw).map_err(|_| bad())?;
            if prefix::is_same(&root, &main_quarantine) {
                continue;
            }
            let volume_root = prefix::depth(&root) == 2
                && prefix::leaf(&root).is_some_and(|leaf| eq_ci(leaf, VOLUME_QUARANTINE_DIR))
                && !eq_ci(&drive(&root), &data_drive);
            if !volume_root {
                return Err(bad());
            }
            if roots.iter().any(|known| prefix::is_same(known, &root)) {
                continue;
            }
            quarantine_dirs.push(below(&root, id));
            roots.push(root);
        }
        Ok(StoreScope {
            session: session.clone(),
            session_dir: below(&below(&data, SESSIONS_DIR), id),
            roots,
            quarantine_dirs,
        })
    }

    /// The session the scope belongs to.
    pub fn session(&self) -> &SessionId {
        &self.session
    }

    /// `<data root>\sessions\<session>`, in canonical form.
    pub fn session_dir(&self) -> &str {
        &self.session_dir
    }

    /// `<data root>\Quarantine\<session>` first, then `X:\.purge-q\<session>` for every other volume, in
    /// canonical form.
    pub fn quarantine_dirs(&self) -> &[String] {
        &self.quarantine_dirs
    }

    /// The store roots: the data root, then every `X:\.purge-q`, in canonical form.
    pub fn store_roots(&self) -> &[String] {
        &self.roots
    }

    /// The directory of `dirs` that `canonical` lies strictly inside.
    fn dir_of<'a>(canonical: &str, dirs: &'a [String]) -> Option<&'a str> {
        dirs.iter()
            .map(String::as_str)
            .find(|dir| prefix::is_inside(canonical, dir))
    }

    /// Whether `canonical` lies strictly inside the session directory or a quarantine directory.
    fn contains(&self, canonical: &str) -> bool {
        prefix::is_inside(canonical, &self.session_dir)
            || Self::dir_of(canonical, &self.quarantine_dirs).is_some()
    }

    /// The own-store exemption: whether `path` lies **strictly inside** the session directory or one of
    /// the session's quarantine directories. The directories themselves, their parents, other sessions
    /// and the rest of Purge's directories are not authorised. Lexical only: pair it with
    /// [`check_store_item`] before acting on a handle.
    pub fn authorises(&self, path: &str) -> bool {
        canon_plain(path).is_ok_and(|path| self.contains(&path))
    }
}

/// An executor-internal operation on an item in the session's own store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreOp {
    /// Undo: rename a quarantined item back. Needs [`Binding::Recheck`] with the recorded identity.
    MoveBack,
    /// Expiry: list a directory in order to remove what is below it. Never allowed on a reparse point.
    Descend,
    /// Expiry: remove a file, an empty directory, or a link **as the link itself**. The one operation
    /// allowed on a reparse point; the handle is the link's own, so nothing behind it is touched.
    Remove,
}

/// One request to [`check_store_item`].
#[derive(Debug, Clone, Copy)]
pub struct StoreCheck<'a> {
    /// The item's path in the store.
    pub path: &'a str,
    /// The intended operation.
    pub op: StoreOp,
    /// The recorded identity of the item, when the journal has one.
    pub binding: Binding<'a, PathStamp>,
    /// The serial of the volume the item was quarantined on (from the journal).
    pub volume_serial: u64,
}

/// The gate for executor-internal work on an item in the session's own store (undo, expiry), from the
/// facts of the handle acted on. Of [`PathFacts`] it reads `final_path`, `reparse_tag`, `attributes`,
/// `is_dir` and `identity`.
///
/// 1. The path is authorised by the scope ([`StoreScope::authorises`]): strictly inside this session's
///    directory in a Purge store root. Else `DenyListed` (`fs.purge`).
/// 2. **G1** the final path is known and names the same item, else [`Blocker::ReparseMismatch`].
/// 3. The item is not a reparse point, unless the operation is [`StoreOp::Remove`]. [`StoreOp::Descend`]
///    needs a directory.
/// 4. The identity is known ([`FileIdentity::is_valid`]: no volume serial of 0) and on the recorded
///    volume, else [`Blocker::ReparseMismatch`].
/// 5. Under [`Binding::Recheck`] the identity and kind are the recorded ones, else
///    [`Blocker::ChangedSinceScan`]. [`StoreOp::MoveBack`] without a recorded identity is refused.
pub fn check_store_item(check: &StoreCheck<'_>, facts: &PathFacts, scope: &StoreScope) -> Verdict {
    let outside = || {
        Refusal::new(
            Blocker::DenyListed {
                rule: "fs.purge".to_owned(),
            },
            reason::OUTSIDE_STORE,
        )
    };
    let lexical = canon_plain(check.path).map_err(|_| outside())?;
    if !scope.contains(&lexical) {
        return Err(outside());
    }
    let final_path = final_path_of(facts.final_path.as_deref())?;
    if !prefix::is_same(&lexical, &final_path) {
        return refuse(Blocker::ReparseMismatch, reason::FINAL_DIFFERS);
    }

    let (Some(attributes), Some(tag), Some(is_dir)) =
        (facts.attributes, facts.reparse_tag, facts.is_dir)
    else {
        return refuse(Blocker::ReparseMismatch, reason::HANDLE_FACTS_UNKNOWN);
    };
    let reparse_bit = attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    if (tag != 0) != reparse_bit || is_dir != (attributes & FILE_ATTRIBUTE_DIRECTORY != 0) {
        return refuse(Blocker::ReparseMismatch, reason::HANDLE_FACTS_CONTRADICT);
    }
    if reparse_bit && check.op != StoreOp::Remove {
        return refuse(Blocker::ReparseMismatch, reason::ITEM_IS_REPARSE_POINT);
    }
    if check.op == StoreOp::Descend && !is_dir {
        return refuse(Blocker::ChangedSinceScan, reason::NOT_A_DIRECTORY);
    }

    let Some(stamp) = facts.stamp() else {
        return refuse(Blocker::ReparseMismatch, reason::IDENTITY_UNKNOWN);
    };
    if stamp.identity.volume_serial != check.volume_serial {
        return refuse(Blocker::ReparseMismatch, reason::STORE_OTHER_VOLUME);
    }
    match (check.binding, check.op) {
        (Binding::Recheck(recorded), _) if *recorded == stamp => Ok(()),
        (Binding::Recheck(_), _) => refuse(Blocker::ChangedSinceScan, reason::IDENTITY_CHANGED),
        (Binding::Capture, StoreOp::MoveBack) => Err(Refusal::rule(reason::STORE_NEEDS_IDENTITY)),
        (Binding::Capture, StoreOp::Descend | StoreOp::Remove) => Ok(()),
    }
}

/// Facts about a directory that an item is about to be renamed into, read from a handle on that
/// directory (opened with `FILE_FLAG_OPEN_REPARSE_POINT`), and about the name the item will get.
///
/// The verdict holds for that handle only. The executor keeps the handle open and renames the item into
/// it **by handle** (`MoveHandle::rename_into(&parent_handle, leaf)` in `purge-win`), never by a path to
/// the destination: a rename by path walks the path again and follows a reparse point planted after the
/// check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DestinationFacts {
    /// The final path of the destination's parent directory, as returned (`\\?\C:\...`).
    pub parent_final_path: Option<String>,
    /// The parent's reparse tag; `0` when it is not a reparse point.
    pub parent_reparse_tag: Option<u32>,
    /// Whether the parent is a directory.
    pub parent_is_dir: Option<bool>,
    /// The serial of the volume the parent lies on (from its `FILE_ID_INFO`). `0` counts as unknown.
    pub parent_volume_serial: Option<u64>,
    /// Whether anything exists at the destination path itself (probed without following links).
    pub occupied: Option<bool>,
}

/// The parent of `destination` is the plain directory its path names: final path equal, no reparse tag,
/// a directory. `reason` is reported with [`Blocker::ReparseMismatch`] otherwise.
fn check_destination_parent(
    destination: &str,
    facts: &DestinationFacts,
    reason: &'static str,
) -> Verdict {
    let mismatch = || Refusal::new(Blocker::ReparseMismatch, reason);
    let parent = parent_dir(destination).ok_or_else(mismatch)?;
    let parent_final = facts
        .parent_final_path
        .as_deref()
        .and_then(|raw| canon_plain(raw).ok())
        .ok_or_else(mismatch)?;
    let plain = prefix::is_same(&parent, &parent_final)
        && facts.parent_reparse_tag == Some(0)
        && facts.parent_is_dir == Some(true);
    if plain { Ok(()) } else { Err(mismatch()) }
}

/// One request to [`check_quarantine_destination`].
#[derive(Debug, Clone, Copy)]
pub struct QuarantineCheck<'a> {
    /// The item's path (already let through by [`check_path`]).
    pub source: &'a str,
    /// The serial of the volume the item lies on, from the identity of its handle. `0` counts as
    /// unknown.
    pub source_volume_serial: Option<u64>,
    /// Where the item is to be renamed to.
    pub destination: &'a str,
}

/// Whether a quarantine move may go to `destination` (§7.5).
///
/// 1. The destination is `<a quarantine directory of the session>\<op>\<leaf>` or deeper; anything else,
///    the session directory included, is refused. Every quarantine directory of a [`StoreScope`] lies in
///    a Purge store root, so nothing outside one is a destination.
/// 2. The source neither lies in nor contains a Purge store root of the scope
///    ([`StoreScope::store_roots`]), and neither path contains the other.
/// 3. Source and destination are on one volume: same drive letter, and both volume serials known (not 0)
///    and equal, else [`Blocker::CannotBackUp`].
/// 4. The destination's parent is the plain directory its path names (no reparse point on the way), else
///    [`Blocker::ReparseMismatch`].
/// 5. Nothing exists at the destination, else [`Blocker::CannotBackUp`]: a move never overwrites.
pub fn check_quarantine_destination(
    check: &QuarantineCheck<'_>,
    facts: &DestinationFacts,
    scope: &StoreScope,
) -> Verdict {
    let outside = || Refusal::rule(reason::QUARANTINE_OUTSIDE_STORE);
    let destination = canon_plain(check.destination).map_err(|_| outside())?;
    let dir = StoreScope::dir_of(&destination, &scope.quarantine_dirs).ok_or_else(outside)?;
    if prefix::depth(&destination) < prefix::depth(dir) + 2 {
        return Err(outside());
    }
    let source =
        canon_plain(check.source).map_err(|_| Refusal::rule(reason::QUARANTINE_OVERLAP))?;
    let in_store = scope
        .roots
        .iter()
        .any(|root| prefix::relation(&source, root) != Relation::Unrelated);
    if in_store || prefix::relation(&source, &destination) != Relation::Unrelated {
        return Err(Refusal::rule(reason::QUARANTINE_OVERLAP));
    }

    let same_drive = matches!(
        (prefix::segments(&source).next(), prefix::segments(&destination).next()),
        (Some(a), Some(b)) if eq_ci(a, b)
    );
    if !(same_drive && same_volume(check.source_volume_serial, facts.parent_volume_serial)) {
        return refuse(Blocker::CannotBackUp, reason::QUARANTINE_OTHER_VOLUME);
    }
    check_destination_parent(&destination, facts, reason::QUARANTINE_PARENT)?;
    if facts.occupied != Some(false) {
        return refuse(Blocker::CannotBackUp, reason::QUARANTINE_OCCUPIED);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------
// Undo destinations (§7.8)
// ---------------------------------------------------------------------------------------------------

/// One request to [`check_undo_path`].
#[derive(Debug, Clone, Copy)]
pub struct UndoPathCheck<'a> {
    /// The original path recorded in the journal.
    pub original: &'a str,
    /// The serial of the volume the quarantined item lies on (from the journal, re-checked on the item by
    /// [`check_store_item`]).
    pub volume_serial: u64,
    /// The exemptions the item had when it was removed.
    pub exemptions: Exemptions<'a>,
}

/// Whether a quarantined item may be renamed back to its original path (§7.8). The quarantined item
/// itself is checked by [`check_store_item`] with [`StoreOp::MoveBack`]; this is the destination half.
///
/// 1. **G1** the original path canonicalises; **G2** the deny-list on it, as it is now; the environment
///    names Purge's own directories ([`reason::NO_PURGE_DIRS`]).
/// 2. Its parent exists and is the plain directory the path names: the final path of the parent handle is
///    equal, it has no reparse tag and is a directory, else [`Blocker::ReparseMismatch`]. The final path
///    of the destination (parent's final path plus the leaf) passes the deny-list too.
/// 3. The parent is on the volume of the quarantined item (serials equal and not 0), else
///    [`Blocker::CannotBackUp`].
/// 4. Nothing exists at the original path, else [`Blocker::ChangedSinceScan`] (a conflict: skip and
///    report). Not knowing is refused the same way.
pub fn check_undo_path(
    check: &UndoPathCheck<'_>,
    facts: &DestinationFacts,
    deny: &DenyList,
) -> Verdict {
    let original = canon_plain(check.original).map_err(|e| {
        Refusal::new(
            Blocker::DenyListed {
                rule: format!("canon.{}", e.code()),
            },
            reason::LEXICAL_NOT_CANONICAL,
        )
    })?;
    if let Some(blocker) = deny.check(&path_target(&original), &check.exemptions) {
        return refuse(blocker, reason::DENY_LEXICAL);
    }
    purge_dirs_known(deny)?;
    check_destination_parent(&original, facts, reason::UNDO_PARENT)?;
    // The parent check has shown the two spellings equal; the deny-list still sees the one the file
    // system gave.
    let leaf = prefix::leaf(&original).unwrap_or_default();
    let parent_final = final_path_of(facts.parent_final_path.as_deref())?;
    let final_destination = format!("{}{SEP}{leaf}", parent_final.trim_end_matches(SEP));
    if let Some(blocker) = deny.check(&path_target(&final_destination), &check.exemptions) {
        return refuse(blocker, reason::DENY_FINAL);
    }
    if !same_volume(facts.parent_volume_serial, Some(check.volume_serial)) {
        return refuse(Blocker::CannotBackUp, reason::UNDO_OTHER_VOLUME);
    }
    if facts.occupied != Some(false) {
        return refuse(Blocker::ChangedSinceScan, reason::UNDO_OCCUPIED);
    }
    Ok(())
}

/// Facts about the place a registry backup is restored to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UndoKeyFacts {
    /// The key of the target as it is now, opened at [`KeyProbe::open`]: the key to re-create, or the
    /// key that receives the value.
    pub node: KeyNode,
    /// Every ancestor [`key_probe`] lists, each at its [`KeyAddress`]. Ancestors that no longer exist
    /// are [`KeyNode::Missing`].
    pub ancestors: Vec<KeyAncestor>,
}

/// Whether a key, a value or a segment may be restored at `target` (§7.8: G2 and G11 on the destination).
///
/// 1. **G1** the key canonicalises; **G2** the deny-list on the target as it is now, then the structural
///    containers; the environment names Purge's own directories ([`reason::NO_PURGE_DIRS`]).
/// 2. **G11** the key (read at [`KeyProbe::open`]) is an ordinary key or missing, and so is every
///    ancestor at its [`KeyAddress`]; a link or an unknown reports [`Blocker::RegLink`]. Below a missing
///    ancestor everything must be missing.
///
/// Whether an existing key or value is a conflict (§7.8: `Installer\*`, `Services`, COM; a value with
/// other data) is the undo's decision, not this gate's.
pub fn check_undo_key(
    target: &Target,
    facts: &UndoKeyFacts,
    deny: &DenyList,
    exemptions: &Exemptions,
) -> Verdict {
    if matches!(target, Target::RegValueChanged { .. }) {
        return Err(Refusal::rule(reason::OP_TARGET_MISMATCH));
    }
    let probe = key_probe(target, deny.env())?;
    deny_key(target, deny, exemptions)?;
    purge_dirs_known(deny)?;
    match facts.node {
        KeyNode::Unknown => return refuse(Blocker::RegLink, reason::KEY_LINK_UNKNOWN),
        KeyNode::Link => return refuse(Blocker::RegLink, reason::KEY_IS_LINK),
        KeyNode::Missing | KeyNode::Plain => {}
    }
    let ancestor_missing = check_ancestors(&probe, &facts.ancestors, true)?;
    if ancestor_missing && facts.node != KeyNode::Missing {
        return refuse(Blocker::RegLink, reason::ANCESTORS_CONTRADICT);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------
// Boot-time moves (§7.6)
// ---------------------------------------------------------------------------------------------------

/// Facts about one component of the path of a locked item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AncestorWrite {
    /// The component's path: the item itself, or one of its ancestors up to the drive root (`C:\`).
    pub path: String,
    /// Only administrative principals (SYSTEM, Administrators, TrustedInstaller) can change it.
    pub admin_only: Option<bool>,
    /// It is a reparse point.
    pub reparse: Option<bool>,
}

/// What to do with a locked item once retries and the Restart Manager have failed (§7.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BootMove {
    /// A boot-time move into quarantine may be registered.
    Allowed,
    /// The item is held for a retry at the next run, with the reason (a code for the journal).
    Hold(&'static str),
}

/// Whether a locked item may be moved at boot (§7.6): only when the item and every ancestor up to the
/// drive root can be changed by administrators only and none of them is a reparse point. Between now and
/// the reboot nobody checks the path again, so a component a user can replace would let the move hit
/// something else.
///
/// `chain` must hold a fact for the item itself and for every ancestor, the drive root included; a
/// missing, unknown, duplicated-and-different or off-chain fact holds the item. The item is included,
/// which is stricter than "every ancestor": a user who can write to an empty directory can turn it into a
/// junction.
pub fn admin_only_ancestors(source: &str, chain: &[AncestorWrite]) -> BootMove {
    let Ok(source) = canon_plain(source) else {
        return BootMove::Hold("live.boot.source-not-canonical");
    };
    let mut wanted: Vec<String> = vec![source.clone()];
    let mut at = source;
    while let Some(up) = parent_dir(&at) {
        wanted.push(up.clone());
        at = up;
    }
    let on_chain = |fact: &AncestorWrite| {
        canon_plain(&fact.path)
            .ok()
            .and_then(|path| wanted.iter().position(|w| prefix::is_same(w, &path)))
    };
    let mut seen = vec![false; wanted.len()];
    for fact in chain {
        let Some(index) = on_chain(fact) else {
            return BootMove::Hold("live.boot.fact-off-chain");
        };
        match (fact.admin_only, fact.reparse) {
            (Some(true), Some(false)) => seen[index] = true,
            (_, Some(true)) => return BootMove::Hold("live.boot.reparse-point"),
            (Some(false), _) => return BootMove::Hold("live.boot.user-writable"),
            _ => return BootMove::Hold("live.boot.fact-unknown"),
        }
    }
    if seen.iter().all(|covered| *covered) {
        BootMove::Allowed
    } else {
        BootMove::Hold("live.boot.chain-incomplete")
    }
}
