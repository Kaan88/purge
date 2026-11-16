//! Registry durability: which hives a session's registry changes live in, and flushing them before a
//! journal record claims those changes (gate case p902).
//!
//! Windows writes registry changes to disk lazily: a key deleted a moment ago is back after a power
//! loss unless its hive was flushed (`RegFlushKey`). The journal, by contrast, is flushed with
//! `FlushFileBuffers` at every intent. Without a flush of the registry, a `done` record of a registry op
//! can therefore survive a power loss that its change does not.
//!
//! # The rule
//!
//! A registry change is durable before the record that vouches for it is written:
//!
//! - **Run.** A registry op's `done` is not flushed by itself (the next intent carries it to disk), and
//!   a flush of the hive per op costs 3 to 4.5 ms on the host against 0.01 ms for the delete itself
//!   (200 value deletes under `HKCU`: 2 ms without a flush, 0.6 to 0.9 s with one per delete; one
//!   flush of the hive after all 200: 3 ms; a flush of a hive with nothing pending: 2 microseconds).
//!   So the writer flushes the hives touched since the last flush once, before each `group_end` (at
//!   most 64 intents apart), `commit` and `aborted`, and marks the `group_end` (`registry_flushed`). A
//!   registry `done` after the last marked `group_end` is **unconfirmed**
//!   ([`JournalState::unconfirmed`](crate::journal::JournalState::unconfirmed)): after an unclean stop
//!   recovery probes it again instead of trusting it. A journal written before the mark existed has
//!   no marked `group_end`, so all its registry `done` records are unconfirmed after an unclean stop.
//! - **Undo and recovery.** `undo_done` and `undo_conflict` are flushed one by one, so the hives an
//!   inverse may have written are flushed before each of them (one flush per registry inverse). What
//!   recovery writes forward (a completed key delete, an unconfirmed op done again) goes under the
//!   run's rule: it is flushed before the `group_end`, `commit` or `aborted` that ends the recovery.
//! - **Boot-time moves.** Registering one writes `PendingFileRenameOperations` in the `SYSTEM` hive;
//!   that hive is flushed before the `done` that records the pair, and before the `undo_done` of an
//!   undo that took a pair back.
//! - **Files.** A rename or directory removal is a change of the file system's metadata, which NTFS
//!   logs in order; `FlushFileBuffers` on the journal commits that log up to the journal's write, so a
//!   change on the journal's volume is on disk with the next flush of the journal (its intent, or the
//!   `done`'s group). A change on another volume is not: there the quarantine op directory
//!   (`QuarantineDir::sync`), the parent of a removed directory, or the parent of what an undo put back
//!   is flushed before the record (`act_fs`).
//!
//! A hive is addressed by its root key, `HKLM\<first component>` (`SOFTWARE`, `SYSTEM`, ...) or
//! `HKU\<SID>` / `HKU\<SID>_Classes`, opened read-only and without following links. A hive that is not
//! loaded holds no change of this process and is skipped.

use std::collections::BTreeSet;

use purge_model::exec::op::ExecOp;
use purge_win::os::Win32Error;
use purge_win::reg::{RegRoot, RegView};
use purge_win::reg_write::{KeyAccess, WKey};

/// One registry hive, by its root key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Hive {
    /// `HKLM` (else `HKU`).
    machine: bool,
    /// The hive's key below the root, upper-cased: `SOFTWARE`, `S-1-5-21-..._CLASSES`.
    name: String,
}

impl Hive {
    /// The `SYSTEM` hive, which holds the boot-time move list.
    pub(crate) fn system() -> Hive {
        Hive {
            machine: true,
            name: "SYSTEM".to_owned(),
        }
    }

    /// The hive of a key in the wire spelling of a target (`HKLM\SOFTWARE\Vendor`,
    /// `HKU\S-1-5-21-...\Software\Vendor`); `None` for another root or a key without a hive name.
    pub(crate) fn of_key(key: &str) -> Option<Hive> {
        let mut parts = key.split('\\').filter(|part| !part.is_empty());
        let root = parts.next()?;
        let machine = if root.eq_ignore_ascii_case("HKLM") {
            true
        } else if root.eq_ignore_ascii_case("HKU") {
            false
        } else {
            return None;
        };
        let name = parts.next()?.to_ascii_uppercase();
        Some(Hive { machine, name })
    }

    /// The hive a registry op acts in; `None` for a file or package op.
    pub(crate) fn of_op(op: &ExecOp) -> Option<Hive> {
        match op {
            ExecOp::DeleteKeyTree { key }
            | ExecOp::DeleteKeyIfEmpty { key }
            | ExecOp::DeleteValue { key, .. }
            | ExecOp::EditSegment { key, .. } => Hive::of_key(key),
            ExecOp::QuarantineMove { .. }
            | ExecOp::RemoveDirIfEmpty { .. }
            | ExecOp::RemovePackage { .. } => None,
        }
    }

    /// `HKLM\SOFTWARE`, `HKU\<SID>`: for messages.
    pub(crate) fn label(&self) -> String {
        format!(
            "{}\\{}",
            if self.machine { "HKLM" } else { "HKU" },
            self.name
        )
    }

    /// Flushes the hive (`RegFlushKey` on its root key, opened read-only). A hive that is not loaded is
    /// not flushed and is no error.
    fn flush(&self) -> Result<(), Win32Error> {
        let root = if self.machine {
            RegRoot::Hklm
        } else {
            RegRoot::Hku
        };
        let key = match WKey::open(root, &self.name, RegView::K64, KeyAccess::READ) {
            Ok(key) => key,
            Err(e) if e.is_not_found() => return Ok(()),
            Err(e) => return Err(e),
        };
        key.flush_key()?;
        #[cfg(any(test, feature = "test-support"))]
        observer::flushed(&self.label());
        Ok(())
    }
}

/// A hive flush that failed: nothing the journal would vouch for was written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("the registry hive {hive} could not be flushed: {error}")]
pub struct FlushError {
    /// The hive, `HKLM\SOFTWARE` or `HKU\<SID>`.
    pub hive: String,
    /// The error.
    pub error: Win32Error,
}

/// The hives changed (or possibly changed) since the last flush.
#[derive(Debug, Clone, Default)]
pub(crate) struct DirtyHives {
    hives: BTreeSet<Hive>,
}

impl DirtyHives {
    /// Notes that `hive` may hold changes that are not flushed yet.
    pub(crate) fn touch(&mut self, hive: Option<Hive>) {
        if let Some(hive) = hive {
            self.hives.insert(hive);
        }
    }

    /// Flushes every noted hive and forgets it. On a failure the hives not flushed stay noted.
    pub(crate) fn flush(&mut self) -> Result<(), FlushError> {
        while let Some(hive) = self.hives.first().cloned() {
            hive.flush().map_err(|error| FlushError {
                hive: hive.label(),
                error,
            })?;
            self.hives.remove(&hive);
        }
        Ok(())
    }
}

/// The test seam of the crash matrix: a power loss cannot be made in a test, so a test watches every
/// hive flush and, after it killed the process, puts its test keys back to what they were at the last
/// flush of their hive, as Windows would after a power loss.
#[cfg(any(test, feature = "test-support"))]
mod observer {
    use std::sync::Mutex;

    pub(super) static OBSERVER: Mutex<Option<fn(&str)>> = Mutex::new(None);

    pub(super) fn flushed(hive: &str) {
        let observer = OBSERVER.lock().map(|guard| *guard).unwrap_or(None);
        if let Some(observer) = observer {
            observer(hive);
        }
    }
}

/// Test seam (`test-support` only): `observer` is called with the hive's label (`HKU\<SID>`) after each
/// successful hive flush of this process; `None` removes it.
#[cfg(any(test, feature = "test-support"))]
pub fn set_flush_observer(observer: Option<fn(&str)>) {
    if let Ok(mut guard) = observer::OBSERVER.lock() {
        *guard = observer;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hives_are_named_by_their_root_key() {
        let hive = |key: &str| Hive::of_key(key).map(|h| h.label());
        assert_eq!(hive(r"HKLM\SOFTWARE\Vendor"), Some(r"HKLM\SOFTWARE".into()));
        assert_eq!(
            hive(r"HKLM\software\WOW6432Node\Vendor"),
            Some(r"HKLM\SOFTWARE".into())
        );
        assert_eq!(
            hive(r"HKLM\SYSTEM\ControlSet001\Control"),
            Some(r"HKLM\SYSTEM".into())
        );
        assert_eq!(
            hive(r"HKU\S-1-5-21-1-2-3-1001\Software\X"),
            Some(r"HKU\S-1-5-21-1-2-3-1001".into())
        );
        assert_eq!(
            hive(r"HKU\S-1-5-21-1-2-3-1001_Classes\CLSID"),
            Some(r"HKU\S-1-5-21-1-2-3-1001_CLASSES".into())
        );
        assert_eq!(hive(r"HKCU\Software\X"), None);
        assert_eq!(hive("HKLM"), None);
        assert_eq!(hive(""), None);
        assert_eq!(
            Hive::of_op(&ExecOp::RemovePackage {
                full_name: "x".into()
            }),
            None
        );
        assert_eq!(
            Hive::of_op(&ExecOp::DeleteValue {
                key: r"HKLM\SOFTWARE\V".into(),
                name: "n".into()
            }),
            Hive::of_key(r"HKLM\SOFTWARE")
        );
    }

    #[test]
    fn dirty_hives_are_flushed_once_and_forgotten() {
        let sid = purge_win::sid::current_user_sid().unwrap();
        let mut dirty = DirtyHives::default();
        dirty.touch(Hive::of_key(&format!(r"HKU\{sid}\Software")));
        dirty.touch(Hive::of_key(&format!(r"hku\{sid}\Software\Other")));
        dirty.touch(None);
        assert_eq!(dirty.hives.len(), 1);
        dirty.flush().unwrap();
        assert!(dirty.hives.is_empty());
        // A hive that is not loaded holds nothing of this process.
        dirty.touch(Hive::of_key(r"HKU\S-1-5-21-0-0-0-424242\Software"));
        dirty.flush().unwrap();
        assert!(dirty.hives.is_empty());
    }
}
