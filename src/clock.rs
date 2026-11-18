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

#[cfg(test)]
mod tests {
    use super::*;

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
