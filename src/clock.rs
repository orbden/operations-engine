//! The wall clock as Unix seconds, shared by every operation that stamps a record.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch; `0` if the system clock is set before it.
pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// [`unix_now_secs`] as a signed value for callers whose timestamps are `i64`.
pub fn unix_now_secs_i64() -> i64 {
    i64::try_from(unix_now_secs()).unwrap_or(i64::MAX)
}

/// Days since 1970-01-01 of a civil date in the proleptic Gregorian calendar (Howard
/// Hinnant's algorithm). `month` is 1 to 12 and `day` 1 to 31; the caller validates them,
/// and a day past the end of the month counts on into the next one.
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_from_civil_matches_a_table_of_dates() {
        for (year, month, day, days) in [
            (1970, 1, 1, 0),
            (1969, 12, 31, -1),
            (2000, 2, 29, 11016),
            (1999, 12, 31, 10956),
            (2100, 2, 28, 47540),
            (2100, 3, 1, 47541),
            (2038, 1, 19, 24855),
            (2024, 2, 29, 19782),
            (1900, 3, 1, -25508),
            (2026, 11, 18, 20775),
            (1600, 1, 1, -135140),
        ] {
            assert_eq!(
                days_from_civil(year, month, day),
                days,
                "{year}-{month}-{day}"
            );
        }
        // Day 31 of a 30-day month rolls into the next month.
        assert_eq!(days_from_civil(2026, 4, 31), days_from_civil(2026, 5, 1));
    }

    #[test]
    fn the_clock_is_after_2020_and_the_signed_form_agrees() {
        let before = unix_now_secs();
        let signed = unix_now_secs_i64();
        let after = unix_now_secs();
        assert!(before > 1_577_836_800);
        assert!(after >= before);
        assert!(signed >= before as i64 && signed <= after as i64);
    }
}
