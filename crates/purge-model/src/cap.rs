//! The quarantine size cap (ENGINE_PLAN.md §7.8): per volume, min(10 GiB, 5 % of the volume).
//!
//! The function is pure and lives here, not in `purge-exec`, so the medium engine can show the same
//! cap the executor enforces without linking the executor.

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

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

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
}
