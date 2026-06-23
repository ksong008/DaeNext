use super::*;

pub(super) fn system_time_iso8601(time: SystemTime) -> String {
    let timestamp = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    iso8601_utc(timestamp)
}

pub(super) fn system_time_date(time: SystemTime) -> String {
    let timestamp = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (timestamp as i64).div_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}
