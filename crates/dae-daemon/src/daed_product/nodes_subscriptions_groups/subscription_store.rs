use super::*;

pub(super) struct SubscriptionTagConflict;

impl SubscriptionTagConflict {
    pub(super) fn matches(error: &rusqlite::Error) -> bool {
        matches!(
            error,
            rusqlite::Error::SqliteFailure(sqlite_error, _)
                if sqlite_error.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
        )
    }

    pub(super) fn response() -> HttpResponse {
        HttpResponse::json(
            409,
            json!({
                "error": "a subscription with this tag already exists; update it or choose a different tag",
                "errorCode": "subscription_tag_conflict",
                "retryable": false,
            }),
        )
    }
}

pub(super) fn subscription_tag_exists(conn: &Connection, tag: Option<&str>) -> io::Result<bool> {
    let Some(tag) = tag else {
        return Ok(false);
    };
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM subscriptions WHERE tag = ?1)",
        params![tag],
        |row| row.get::<_, i64>(0),
    )
    .map(|exists| exists != 0)
    .map_err(sqlite_io_error)
}

pub(super) fn subscription_write_guard() -> io::Result<std::sync::MutexGuard<'static, ()>> {
    static SUBSCRIPTION_WRITE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    SUBSCRIPTION_WRITE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| io::Error::other("subscription write lock poisoned"))
}
