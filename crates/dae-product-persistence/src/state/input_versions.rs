use std::io;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};

use super::{
    RUNTIME_EXTERNAL_INPUT_VERSION_METADATA_KEY, ensure_state_schema, open_state_connection,
    sqlite_io_error,
};

pub const RUNTIME_GEODATA_INPUT_VERSION_METADATA_KEY: &str = "runtime_geodata_input_version";

pub fn current_runtime_external_input_version(conn: &Connection) -> io::Result<i64> {
    runtime_input_version(conn, RUNTIME_EXTERNAL_INPUT_VERSION_METADATA_KEY)
}

pub fn current_runtime_geodata_input_version(conn: &Connection) -> io::Result<i64> {
    runtime_input_version(conn, RUNTIME_GEODATA_INPUT_VERSION_METADATA_KEY)
}

fn runtime_input_version(conn: &Connection, key: &str) -> io::Result<i64> {
    let value = conn
        .query_row(
            "SELECT value FROM daed_product_metadata WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_io_error)?;
    Ok(value
        .as_deref()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0))
}

pub fn bump_runtime_external_input_version(state: &Path) -> io::Result<i64> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    bump_runtime_external_input_version_with_connection(&conn)
}

pub fn bump_runtime_external_input_version_with_connection(conn: &Connection) -> io::Result<i64> {
    bump_runtime_input_version_with_connection(conn, RUNTIME_EXTERNAL_INPUT_VERSION_METADATA_KEY)?;
    current_runtime_external_input_version(conn)
}

pub fn bump_runtime_geodata_input_version_with_connection(conn: &Connection) -> io::Result<i64> {
    bump_runtime_input_version_with_connection(conn, RUNTIME_GEODATA_INPUT_VERSION_METADATA_KEY)?;
    current_runtime_geodata_input_version(conn)
}

fn bump_runtime_input_version_with_connection(conn: &Connection, key: &str) -> io::Result<()> {
    conn.execute(
        "INSERT INTO daed_product_metadata(key, value)
         VALUES(?1, '1')
         ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)",
        params![key],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_versions_default_to_zero_and_increment_independently() {
        let root =
            std::env::temp_dir().join(format!("dae-product-input-versions-{}", fastrand::u64(..)));
        let state = root.join("daed.db");
        ensure_state_schema(&state).unwrap();
        let conn = open_state_connection(&state).unwrap();
        assert_eq!(current_runtime_external_input_version(&conn).unwrap(), 0);
        assert_eq!(current_runtime_geodata_input_version(&conn).unwrap(), 0);
        assert_eq!(bump_runtime_external_input_version(&state).unwrap(), 1);
        assert_eq!(
            bump_runtime_geodata_input_version_with_connection(&conn).unwrap(),
            1
        );
        assert_eq!(current_runtime_external_input_version(&conn).unwrap(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }
}
