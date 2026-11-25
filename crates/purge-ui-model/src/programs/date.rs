//! Calendar dates without a date crate: what the Programs page needs of `DateTime` (today, an install
//! time as a local date, days between two dates, "d MMM yyyy").

use std::fmt;

use purge_model::FileTime;

/// A day of the proleptic Gregorian calendar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CivilDate {
    /// The year, e.g. 2026.
    pub year: i32,
    /// 1 to 12.
    pub month: u8,
    /// 1 to 31.
    pub day: u8,
}

impl CivilDate {
    /// The date. No check is made that the day exists in the month.
    pub const fn new(year: i32, month: u8, day: u8) -> Self {
        Self { year, month, day }
    }

    /// The date `days` days after 1970-01-01 (H. Hinnant's `civil_from_days`).
    pub fn from_days(days: i64) -> Self {
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        Self {
            year: i32::try_from(year).unwrap_or(i32::MAX),
            month: u8::try_from(month).unwrap_or(1),
            day: u8::try_from(day).unwrap_or(1),
        }
    }

    /// Days since 1970-01-01 (H. Hinnant's `days_from_civil`).
    pub fn days(self) -> i64 {
        let month = i64::from(self.month);
        let year = i64::from(self.year) - i64::from(month <= 2);
        let era = year.div_euclid(400);
        let yoe = year.rem_euclid(400);
        let mp = (month + 9) % 12;
        let doy = (153 * mp + 2) / 5 + i64::from(self.day) - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    /// The date `n` days later (earlier for a negative `n`).
    pub fn add_days(self, n: i64) -> Self {
        Self::from_days(self.days() + n)
    }

    /// Whole days from `earlier` to `self` (negative when `earlier` is later).
    pub fn days_since(self, earlier: CivilDate) -> i64 {
        self.days() - earlier.days()
    }
}

/// "5 Nov 2026": the WinUI app's `d MMM yyyy` in an English culture.
impl fmt::Display for CivilDate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let month = MONTHS
            .get(usize::from(self.month).wrapping_sub(1))
            .copied()
            .unwrap_or("?");
        write!(f, "{} {month} {:04}", self.day, self.year)
    }
}

/// How the UI's local time is found: the offset from UTC, in seconds, at a given UTC time (seconds since
/// the Unix epoch). The shell gives the real one (it changes with daylight saving time); tests give a
/// fixed one.
#[derive(Debug, Clone, Copy)]
pub enum LocalOffset {
    /// The same offset at every time.
    Fixed(i64),
    /// The offset at a UTC time.
    At(fn(i64) -> i64),
}

impl LocalOffset {
    fn at(self, unix_secs: i64) -> i64 {
        match self {
            LocalOffset::Fixed(offset) => offset,
            LocalOffset::At(f) => f(unix_secs),
        }
    }
}

/// Today and the local offset: what `DateTime.Today` and `ToLocalTime()` gave the WinUI page.
#[derive(Debug, Clone, Copy)]
pub struct Clock {
    /// The local date today.
    pub today: CivilDate,
    /// The local offset.
    pub offset: LocalOffset,
}

impl Clock {
    /// The largest FILETIME a .NET `DateTime` holds (`DateTime.MaxValue.ToFileTimeUtc()`); a later one is
    /// a damaged value.
    pub const MAX_FILETIME: u64 = 2_650_467_743_999_999_999;

    /// The local date of a FILETIME; `None` for a damaged one.
    pub fn local_date(&self, time: FileTime) -> Option<CivilDate> {
        if time.0 > Self::MAX_FILETIME {
            return None;
        }
        let utc = time.to_unix_secs();
        let local = utc + self.offset.at(utc);
        Some(CivilDate::from_days(local.div_euclid(86_400)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_round_trip_and_read_as_the_app_wrote_them() {
        for days in [-800_000, -1, 0, 1, 20_000, 20_782, 2_000_000] {
            assert_eq!(CivilDate::from_days(days).days(), days);
        }
        assert_eq!(CivilDate::from_days(0), CivilDate::new(1970, 1, 1));
        let d = CivilDate::new(2026, 11, 21);
        assert_eq!(d.add_days(-14), CivilDate::new(2026, 11, 7));
        assert_eq!(d.add_days(11), CivilDate::new(2026, 12, 2));
        assert_eq!(d.days_since(CivilDate::new(2026, 11, 7)), 14);
        assert_eq!(CivilDate::new(2026, 3, 5).to_string(), "5 Mar 2026");
    }

    #[test]
    fn a_filetime_is_a_local_date() {
        let clock = Clock {
            today: CivilDate::new(2026, 11, 21),
            offset: LocalOffset::Fixed(3600),
        };
        // 2025-11-17 23:30 UTC is the 18th an hour east of Greenwich.
        let t = FileTime::from_unix_secs(CivilDate::new(2025, 11, 17).days() * 86_400 + 84_600);
        assert_eq!(clock.local_date(t), Some(CivilDate::new(2025, 11, 18)));
        assert_eq!(clock.local_date(FileTime(u64::MAX)), None);
    }
}
