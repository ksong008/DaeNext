use super::*;

pub(in crate::daed_product) fn get_metadata(state: &Path, key: &str) -> io::Result<Option<String>> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT value FROM daed_product_metadata WHERE key = ?1",
        params![key],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(sqlite_io_error)
}

pub(in crate::daed_product) fn set_metadata(
    state: &Path,
    key: &str,
    value: &str,
) -> io::Result<()> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    set_metadata_with_connection(&conn, key, value)
}

pub(in crate::daed_product) fn set_metadata_with_connection(
    conn: &Connection,
    key: &str,
    value: &str,
) -> io::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
        params![key, value],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}
