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
//!   The `reconcile` `Retried` that replaces an unconfirmed op's `Done` when its change is not there
//!   is written after a flush, since the attempt to make the change again may have written.
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
//!
//! # When a change can have been lost
//!
//! Only a restart of Windows (a power loss, a crash of the system) loses a registry change that was
//! made: after the process alone died, every change is in the live registry. So recovery probes the
//! unconfirmed ops again only when Windows may have started since the run began
//! ([`restart_possible`]): the system's start (now less `GetTickCount64`, which counts sleep and
//! hibernation too) is compared with the journal header's `created`, the earliest time any of the
//! session's records was written. When the system started before the run, with a margin of
//! [`RESTART_MARGIN`] for clock adjustments, every record and every change was made since, and nothing
//! can have been lost. In doubt (the start cannot be read, the clock is behind the run's start, the
//! start is not clearly before the run) the ops are probed again. The header's time is used rather
//! than the journal's last record because a recovery after the restart may have written that record.

use std::collections::BTreeSet;

use purge_model::FileTime;
use purge_model::exec::op::ExecOp;
use purge_win::os::Win32Error;
use purge_win::reg::{RegRoot, RegView};
use purge_win::reg_write::{KeyAccess, WKey};

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    /// `GetTickCount64`: milliseconds since the system started, sleep and hibernation included.
    fn GetTickCount64() -> u64;
}

/// How far before the run's start the system must have started for recovery to rule out a restart
/// since: ten minutes, in FILETIME ticks (100 ns). It absorbs clock adjustments made while the
/// session was open.
pub const RESTART_MARGIN: u64 = 10 * 60 * 10_000_000;

/// When the system started: the current time less the time since the start. `None` when that would
/// lie before 1601.
pub fn system_started() -> Option<FileTime> {
    // SAFETY: `GetTickCount64` takes no arguments and cannot fail.
    let ms = unsafe { GetTickCount64() };
    let now = crate::storage::now();
    now.0.checked_sub(ms.checked_mul(10_000)?).map(FileTime)
}

/// Whether Windows may have restarted since `since` (the journal header's `created`), so that a
/// registry change made since may have been lost: `started` is when the system started
/// ([`system_started`]), `now` the current time. `false` only when the system clearly started before
/// `since` ([`RESTART_MARGIN`]) and the clock is not behind `since`; `true` in every case of doubt.
pub fn restart_possible(since: FileTime, started: Option<FileTime>, now: FileTime) -> bool {
    let Some(started) = started else {
        return true;
    };
    now.0 < since.0 || started.0.saturating_add(RESTART_MARGIN) >= since.0
}

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

    /// The `SOFTWARE` hive, which holds the Task Scheduler's `TaskCache`.
    pub(crate) fn software() -> Hive {
        Hive {
            machine: true,
            name: "SOFTWARE".to_owned(),
        }
    }

    /// The hive an op acts in, which its inverse writes too: the key's hive for a registry op; for a
    /// typed object (C-ACT) the hive the object lives in: `SYSTEM` for a service (`Services\<name>`) and
    /// a firewall rule (`SharedAccess\Parameters\FirewallPolicy`), `SOFTWARE` for a scheduled task
    /// (`Schedule\TaskCache`; the task file's directory is flushed by the act module). `None` for a file
    /// or package op.
    pub(crate) fn of_op(op: &ExecOp) -> Option<Hive> {
        match op {
            ExecOp::DeleteKeyTree { key }
            | ExecOp::DeleteKeyIfEmpty { key }
            | ExecOp::DeleteValue { key, .. }
            | ExecOp::EditSegment { key, .. } => Hive::of_key(key),
            ExecOp::QuarantineMove { .. }
            | ExecOp::RemoveDirIfEmpty { .. }
            | ExecOp::RemovePackage { .. } => None,
            ExecOp::DeleteService { .. } | ExecOp::DeleteFirewallRule { .. } => {
                Some(Hive::system())
            }
            ExecOp::DeleteTask { .. } => Some(Hive::software()),
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

/// Flushes the hive `op` acts in ([`Hive::of_op`]), for an act module that must make its change durable
/// before the journal record that vouches for it (C-ACT: a typed object's delete is flushed before its
/// `done`). Nothing to flush for an op without a hive.
pub fn flush_op_hive(op: &ExecOp) -> Result<(), FlushError> {
    let mut dirty = DirtyHives::default();
    dirty.touch(Hive::of_op(op));
    dirty.flush()
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

    /// C-ACT: services and firewall rules live in `SYSTEM`, the task cache in `SOFTWARE`; the inverse
    /// of each op writes the same hive (the journal writer flushes the hive of the op's intent before
    /// an `undo_done`).
    #[test]
    fn hive_of_typed_ops() {
        let system = Some(Hive::system());
        let software = Hive::of_key(r"HKLM\SOFTWARE\Microsoft");
        assert_eq!(software, Some(Hive::software()));
        assert_eq!(
            Hive::of_op(&ExecOp::DeleteService {
                name: "VendorSvc".into()
            }),
            system
        );
        assert_eq!(
            Hive::of_op(&ExecOp::DeleteFirewallRule {
                id: "{0B7AC2E8-3A6B-4C1D-9E58-7F7B2B1E7A10}".into()
            }),
            system
        );
        assert_eq!(
            Hive::of_op(&ExecOp::DeleteTask {
                path: r"\Vendor\Update".into()
            }),
            software
        );
        assert_eq!(
            Hive::of_key(r"HKLM\SYSTEM\CurrentControlSet\Services\VendorSvc"),
            system
        );
        assert_eq!(Hive::system().label(), r"HKLM\SYSTEM");
        assert_eq!(Hive::software().label(), r"HKLM\SOFTWARE");
        // Flushing a machine hive through a read-only handle needs no elevation.
        flush_op_hive(&ExecOp::DeleteTask {
            path: r"\Vendor\Update".into(),
        })
        .unwrap();
        flush_op_hive(&ExecOp::RemovePackage {
            full_name: "x".into(),
        })
        .unwrap();
    }

    /// Review M1: only a restart of Windows can take a registry change, so recovery probes again only
    /// when the system may have started since the run began; in doubt it does.
    #[test]
    fn a_restart_is_ruled_out_only_when_the_system_started_well_before_the_run() {
        let minute = 60 * 10_000_000;
        let run = FileTime(1_000 * minute);
        let now = FileTime(run.0 + 5 * minute);
        // Started long before the run: nothing can have been lost.
        assert!(!restart_possible(
            run,
            Some(FileTime(run.0 - 60 * minute)),
            now
        ));
        // Started after the run began (a power loss), or within the margin before it.
        assert!(restart_possible(run, Some(FileTime(run.0 + minute)), now));
        assert!(restart_possible(
            run,
            Some(FileTime(run.0 - 9 * minute)),
            now
        ));
        // The start cannot be read, or the clock is behind the run's start.
        assert!(restart_possible(run, None, now));
        assert!(restart_possible(
            run,
            Some(FileTime(run.0 - 60 * minute)),
            FileTime(run.0 - minute)
        ));
        // The host's own start lies in the past.
        let started = system_started().unwrap();
        assert!(started.0 <= crate::storage::now().0);
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
