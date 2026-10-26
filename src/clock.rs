use std::time::{SystemTime, UNIX_EPOCH};

pub fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

pub fn unix_now() -> u64 {
    unix_seconds(SystemTime::now())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn unix_seconds_count_whole_seconds_since_the_epoch() {
        assert_eq!(unix_seconds(UNIX_EPOCH + Duration::from_millis(90_999)), 90);
    }

    #[test]
    fn a_time_before_the_epoch_is_zero_unix_seconds() {
        assert_eq!(unix_seconds(UNIX_EPOCH - Duration::from_secs(1)), 0);
    }
}
