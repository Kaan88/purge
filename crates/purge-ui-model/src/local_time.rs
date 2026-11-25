//! Local dates and times for the History and Quarantine pages, without a time crate: the UI hands
//! the models a [`Clock`] (now, and the local offset from UTC), and the models format the
//! `FileTime`s of `history.index` with it. The formats are the WinUI app's (`HH:mm`, `d MMM yyyy`,
//! `d MMMM`) in English.

use purge_model::FileTime;

/// 100-ns ticks in a second and a day.
const TICKS_PER_SEC: i128 = 10_000_000;
const TICKS_PER_DAY: i128 = 86_400 * TICKS_PER_SEC;

const MONTHS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

/// What time it is and how far local time is from UTC, read by the UI when it hands a result to a
/// model (the C# models read `DateTimeOffset.Now`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    /// Now, in UTC.
    pub now: FileTime,
    /// Local time minus UTC, in minutes (e.g. 60 for CET).
    pub utc_offset_minutes: i32,
}

impl Clock {
    /// A clock at `now` in UTC.
    pub fn utc(now: FileTime) -> Self {
        Self {
            now,
            utc_offset_minutes: 0,
        }
    }

    /// `t` in local time.
    pub fn local(&self, t: FileTime) -> LocalTime {
        let ticks = i128::from(t.0) + i128::from(self.utc_offset_minutes) * 60 * TICKS_PER_SEC;
        let days = ticks.div_euclid(TICKS_PER_DAY);
        let in_day = ticks.rem_euclid(TICKS_PER_DAY) / TICKS_PER_SEC;
        // Day 0 is 1601-01-01; 134774 days later is 1970-01-01.
        let (year, month, day) = civil_from_days(days - 134_774);
        LocalTime {
            day_number: days,
            year,
            month,
            day,
            hour: (in_day / 3600) as u32,
            minute: (in_day / 60 % 60) as u32,
        }
    }

    /// Now in local time.
    pub fn today(&self) -> LocalTime {
        self.local(self.now)
    }

    /// Whole days from now until `expiry`, rounded up; 0 once it has passed.
    pub fn days_left(&self, expiry: FileTime) -> i32 {
        let left = i128::from(expiry.0) - i128::from(self.now.0);
        if left <= 0 {
            return 0;
        }
        i32::try_from((left + TICKS_PER_DAY - 1) / TICKS_PER_DAY).unwrap_or(i32::MAX)
    }

    /// `t` plus `days` (negative: earlier), for tests and samples.
    pub fn add_days(t: FileTime, days: f64) -> FileTime {
        let ticks = i128::from(t.0) + (days * TICKS_PER_DAY as f64) as i128;
        FileTime(u64::try_from(ticks.max(0)).unwrap_or(u64::MAX))
    }

    /// Days from `from` to `to`, with the fraction.
    pub fn days_between(from: FileTime, to: FileTime) -> f64 {
        (i128::from(to.0) - i128::from(from.0)) as f64 / TICKS_PER_DAY as f64
    }
}

/// A local date and time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LocalTime {
    /// Days since 1601-01-01 (local): equal for the same local date.
    pub day_number: i128,
    /// The year.
    pub year: i64,
    /// 1 to 12.
    pub month: u32,
    /// 1 to 31.
    pub day: u32,
    /// 0 to 23.
    pub hour: u32,
    /// 0 to 59.
    pub minute: u32,
}

impl LocalTime {
    /// `HH:mm`.
    pub fn hh_mm(&self) -> String {
        format!("{:02}:{:02}", self.hour, self.minute)
    }

    /// The short month name (`Nov`).
    pub fn short_month(&self) -> &'static str {
        &self.long_month()[..3]
    }

    /// The month name (`November`).
    pub fn long_month(&self) -> &'static str {
        MONTHS[(self.month.clamp(1, 12) - 1) as usize]
    }

    /// `d MMM yyyy` (`15 Nov 2025`).
    pub fn d_mmm_yyyy(&self) -> String {
        format!("{} {} {}", self.day, self.short_month(), self.year)
    }

    /// `d MMM yyyy HH:mm`.
    pub fn d_mmm_yyyy_hh_mm(&self) -> String {
        format!("{} {}", self.d_mmm_yyyy(), self.hh_mm())
    }

    /// `d MMM HH:mm`.
    pub fn d_mmm_hh_mm(&self) -> String {
        format!("{} {} {}", self.day, self.short_month(), self.hh_mm())
    }

    /// `d MMMM` (`15 November`).
    pub fn d_mmmm(&self) -> String {
        format!("{} {}", self.day, self.long_month())
    }

    /// `d MMMM yyyy`.
    pub fn d_mmmm_yyyy(&self) -> String {
        format!("{} {}", self.d_mmmm(), self.year)
    }
}

/// Year, month and day of a day count since 1970-01-01 (H. Hinnant's `civil_from_days`).
fn civil_from_days(z: i128) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    ((if m <= 2 { y + 1 } else { y }) as i64, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fixture_session_starts_on_15_november_2025() {
        // 20251115T101502Z, the id of the fixture's session.
        let clock = Clock::utc(FileTime(134_076_753_020_000_000));
        let t = clock.today();
        assert_eq!(t.d_mmm_yyyy_hh_mm(), "15 Nov 2025 10:15");
        assert_eq!(t.d_mmmm(), "15 November");
        let cet = Clock {
            utc_offset_minutes: 60,
            ..clock
        };
        assert_eq!(cet.today().hh_mm(), "11:15");
    }

    #[test]
    fn days_left_round_up_and_stop_at_zero() {
        let now = FileTime(134_076_753_020_000_000);
        let clock = Clock::utc(now);
        assert_eq!(clock.days_left(Clock::add_days(now, 28.0)), 28);
        assert_eq!(clock.days_left(Clock::add_days(now, 0.1)), 1);
        assert_eq!(clock.days_left(Clock::add_days(now, -3.0)), 0);
        assert_eq!(clock.days_left(FileTime(0)), 0);
    }
}
