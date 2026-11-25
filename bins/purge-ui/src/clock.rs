//! The system's clock for the models: today's local date and the local offset from UTC, with
//! daylight saving time as Windows' time zone rules have it at each date (an install date in July
//! and one in January are each read with their own offset, as .NET's `ToLocalTime` read them).

use purge_model::FileTime;
use purge_ui_model::local_time;
use purge_ui_model::programs::{CivilDate, Clock, LocalOffset};

/// 100-ns ticks between 1601-01-01 and 1970-01-01.
const UNIX_EPOCH_TICKS: i64 = 116_444_736_000_000_000;

/// The Programs page's clock: today, and the offset at each time.
pub fn programs() -> Clock {
    let now = now_unix();
    let local = now + offset_at(now);
    Clock {
        today: CivilDate::from_days(local.div_euclid(86_400)),
        offset: LocalOffset::At(offset_at),
    }
}

/// The History and Quarantine pages' clock: now, and the offset now.
// Those pages are wired in UI-PAGES; until then only the tests read it.
#[allow(dead_code)]
pub fn now() -> local_time::Clock {
    let now = now_unix();
    let ticks = now
        .saturating_mul(10_000_000)
        .saturating_add(UNIX_EPOCH_TICKS);
    local_time::Clock {
        now: FileTime(u64::try_from(ticks).unwrap_or(0)),
        utc_offset_minutes: i32::try_from(offset_at(now) / 60).unwrap_or(0),
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Local time minus UTC, in seconds, at the UTC time `unix_secs`: the current time zone's rules
/// for that date (`SystemTimeToTzSpecificLocalTimeEx` with the dynamic zone). 0 when Windows
/// cannot say (a time outside what a SYSTEMTIME holds).
#[cfg(windows)]
pub fn offset_at(unix_secs: i64) -> i64 {
    use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
    use windows_sys::Win32::System::Time::{
        FileTimeToSystemTime, SystemTimeToFileTime, SystemTimeToTzSpecificLocalTimeEx,
    };
    let Some(ticks) = unix_secs
        .checked_mul(10_000_000)
        .and_then(|t| t.checked_add(UNIX_EPOCH_TICKS))
        .filter(|t| *t >= 0)
    else {
        return 0;
    };
    let ft = FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    };
    let zero = SYSTEMTIME {
        wYear: 0,
        wMonth: 0,
        wDayOfWeek: 0,
        wDay: 0,
        wHour: 0,
        wMinute: 0,
        wSecond: 0,
        wMilliseconds: 0,
    };
    let (mut utc, mut local) = (zero, zero);
    let mut back = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    // SAFETY: each call reads and writes only the structs owned by this frame; a null zone is the
    // current dynamic time zone.
    let ok = unsafe {
        FileTimeToSystemTime(&ft, &mut utc) != 0
            && SystemTimeToTzSpecificLocalTimeEx(std::ptr::null(), &utc, &mut local) != 0
            && SystemTimeToFileTime(&local, &mut back) != 0
    };
    if !ok {
        return 0;
    }
    let local_ticks = (i64::from(back.dwHighDateTime) << 32) | i64::from(back.dwLowDateTime);
    // Whole seconds: the conversion drops nothing below a millisecond of a whole-second input.
    (local_ticks - ticks).div_euclid(10_000_000)
}

#[cfg(not(windows))]
pub fn offset_at(_unix_secs: i64) -> i64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_offset_is_whole_minutes_and_within_a_day() {
        for t in [0_i64, 1_700_000_000, 1_784_000_000, 1_800_000_000] {
            let o = offset_at(t);
            assert!(o.abs() <= 14 * 3600, "{o}");
            assert_eq!(o % 60, 0, "{o}");
        }
    }

    #[test]
    fn today_is_the_local_date_now() {
        let c = programs();
        let n = now();
        let t = n.today();
        assert_eq!(c.today.to_string(), t.d_mmm_yyyy());
    }
}
