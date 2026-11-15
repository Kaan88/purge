//! The quarantine size cap (ENGINE_PLAN.md §7.8): per volume, min(10 GiB, 5 % of the volume). A run
//! that would exceed it is refused with the numbers; nothing is ever evicted to make room.

use purge_model::exec::session::{SessionIndex, VolumeUsage};

use super::StorageError;

/// The absolute part of the cap: 10 GiB per volume.
pub const CAP_ABSOLUTE_BYTES: u64 = 10 * (1 << 30);
/// The relative part of the cap: 5 % of the volume's total size.
pub const CAP_VOLUME_PERCENT: u64 = 5;

/// The cap for a volume of `volume_total` bytes: min([`CAP_ABSOLUTE_BYTES`], 5 % of the volume),
/// rounded down.
pub fn cap_bytes(volume_total: u64) -> u64 {
    let share = u128::from(volume_total) * u128::from(CAP_VOLUME_PERCENT) / 100;
    u64::try_from(share)
        .unwrap_or(u64::MAX)
        .min(CAP_ABSOLUTE_BYTES)
}

/// A run refused because its backups would push a volume over the cap.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "the quarantine on {root} (volume serial {serial:#x}) would hold {held} + {planned} bytes, \
     over its cap of {cap} bytes (min(10 GiB, 5 % of {volume_total} bytes)); nothing was changed, \
     expire older sessions to make room"
)]
pub struct CapExceeded {
    /// Serial of the volume.
    pub serial: u64,
    /// Root of the volume, for display.
    pub root: String,
    /// Bytes the sessions in the index already hold on the volume.
    pub held: u64,
    /// Bytes the refused run planned to add.
    pub planned: u64,
    /// The cap of the volume.
    pub cap: u64,
    /// Total size of the volume.
    pub volume_total: u64,
}

/// Checks the planned backup bytes of a run against the cap of every volume they land on.
///
/// `planned` may name a volume more than once; its entries are summed. A volume the run adds nothing
/// to is not checked, so a volume already over its cap (after a policy change, say) refuses only runs
/// that would add to it. `volume_total` gives the total size of a volume from its usage entry.
pub fn check_cap(
    index: &SessionIndex,
    planned: &[VolumeUsage],
    mut volume_total: impl FnMut(&VolumeUsage) -> Result<u64, StorageError>,
) -> Result<(), StorageError> {
    let mut merged: Vec<VolumeUsage> = Vec::new();
    for usage in planned {
        match merged.iter_mut().find(|m| m.serial == usage.serial) {
            Some(m) => m.bytes = m.bytes.saturating_add(usage.bytes),
            None => merged.push(usage.clone()),
        }
    }
    for usage in merged.iter().filter(|u| u.bytes > 0) {
        let total = volume_total(usage)?;
        let cap = cap_bytes(total);
        let held = index.bytes_on_volume(usage.serial);
        if held.saturating_add(usage.bytes) > cap {
            return Err(StorageError::Cap(Box::new(CapExceeded {
                serial: usage.serial,
                root: usage.root.clone(),
                held,
                planned: usage.bytes,
                cap,
                volume_total: total,
            })));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use purge_model::FileTime;
    use purge_model::exec::session::{Expiry, SessionId, SessionState, SessionSummary};

    const GIB: u64 = 1 << 30;

    fn usage(serial: u64, bytes: u64) -> VolumeUsage {
        VolumeUsage {
            serial,
            root: format!("V{serial}:\\"),
            bytes,
        }
    }

    fn index_holding(entries: &[(u64, u64)]) -> SessionIndex {
        let mut index = SessionIndex::default();
        for (n, &(serial, bytes)) in entries.iter().enumerate() {
            let started = FileTime::from_unix_secs(1_794_737_702 + n as i64);
            let summary = SessionSummary {
                id: SessionId::new(started, n as u64),
                app: "app".into(),
                owner: None,
                plan_hash: purge_model::exec::op::Sha256Hex([0; 32]),
                state: SessionState::Committed,
                started,
                finished: Some(started),
                counts: Default::default(),
                undone: 0,
                backup_bytes: bytes,
                usage: vec![usage(serial, bytes)],
                expires: Expiry::from_start(started),
                purged: Vec::new(),
                pending_reboot: false,
            };
            index.upsert(summary);
        }
        index
    }

    #[test]
    fn cap_is_the_smaller_of_10_gib_and_5_percent() {
        assert_eq!(cap_bytes(0), 0);
        assert_eq!(cap_bytes(100), 5);
        assert_eq!(cap_bytes(119), 5);
        // 5 % of 64 GiB is 3.2 GiB.
        assert_eq!(cap_bytes(64 * GIB), 64 * GIB / 20);
        // The two parts meet at 200 GiB.
        assert_eq!(cap_bytes(200 * GIB), 10 * GIB);
        assert_eq!(cap_bytes(200 * GIB - 20), 10 * GIB - 1);
        assert_eq!(cap_bytes(2_000 * GIB), CAP_ABSOLUTE_BYTES);
        assert_eq!(cap_bytes(u64::MAX), CAP_ABSOLUTE_BYTES);
    }

    #[test]
    fn runs_within_the_cap_pass_and_over_it_are_refused_with_numbers() {
        let index = index_holding(&[(1, 2 * GIB), (1, GIB), (2, 9 * GIB)]);
        let total = |u: &VolumeUsage| -> Result<u64, StorageError> {
            Ok(if u.serial == 1 {
                100 * GIB
            } else {
                1_000 * GIB
            })
        };
        // Volume 1: cap 5 GiB, 3 GiB held: 2 GiB fits exactly, one byte more does not.
        check_cap(&index, &[usage(1, 2 * GIB)], total).unwrap();
        let err = check_cap(&index, &[usage(1, GIB), usage(1, GIB + 1)], total).unwrap_err();
        let StorageError::Cap(cap) = &err else {
            panic!("{err}")
        };
        assert_eq!(
            **cap,
            CapExceeded {
                serial: 1,
                root: "V1:\\".into(),
                held: 3 * GIB,
                planned: 2 * GIB + 1,
                cap: 5 * GIB,
                volume_total: 100 * GIB,
            }
        );
        let text = err.to_string();
        assert!(text.contains(&(5 * GIB).to_string()) && text.contains("nothing was changed"));

        // Volume 2: cap 10 GiB, 9 GiB held.
        check_cap(&index, &[usage(1, 0), usage(2, GIB)], total).unwrap();
        assert!(check_cap(&index, &[usage(2, GIB + 1)], total).is_err());
        // A volume the run adds nothing to is not checked, even when its size is unknown.
        let failing = |_: &VolumeUsage| -> Result<u64, StorageError> {
            Err(StorageError::NotInstalled("x".into()))
        };
        check_cap(&index, &[usage(3, 0)], failing).unwrap();
        assert!(matches!(
            check_cap(&index, &[usage(3, 1)], failing),
            Err(StorageError::NotInstalled(_))
        ));
        // An empty index on a fresh volume.
        check_cap(&SessionIndex::default(), &[usage(9, 5 * GIB)], total).unwrap();
        // Saturating sums never wrap into a pass.
        assert!(check_cap(&index, &[usage(1, u64::MAX), usage(1, u64::MAX)], total).is_err());
    }
}
