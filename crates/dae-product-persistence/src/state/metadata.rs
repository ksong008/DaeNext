use super::*;

pub fn get_metadata(state: &Path, key: &str) -> io::Result<Option<String>> {
    pool::with_initialized_connection(state, |conn| {
        conn.query_row(
            "SELECT value FROM daed_product_metadata WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_io_error)
    })
}

pub fn set_metadata(state: &Path, key: &str, value: &str) -> io::Result<()> {
    set_metadata_batch(state, &[(key, value)])
}

pub fn set_metadata_batch(state: &Path, values: &[(&str, &str)]) -> io::Result<()> {
    pool::with_initialized_connection(state, |conn| {
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sqlite_io_error)?;
        for (key, value) in values {
            set_metadata_with_connection(&transaction, key, value)?;
        }
        transaction.commit().map_err(sqlite_io_error)
    })
}

pub fn set_metadata_with_connection(conn: &Connection, key: &str, value: &str) -> io::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
        params![key, value],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}
