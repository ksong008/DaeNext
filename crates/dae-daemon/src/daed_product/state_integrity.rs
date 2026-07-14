use super::*;

const STATE_REQUIRED_TABLES: &[&str] =
    &["daed_product_metadata", "daed_schema_migrations", "users"];

#[derive(Debug)]
pub(super) struct StateIntegritySnapshot {
    pub(super) schema_version: i64,
    pub(super) schema_current: bool,
    pub(super) migration_required: bool,
    pub(super) tables: Vec<String>,
    pub(super) user_count: Option<i64>,
}

pub(super) fn state_schema_version(conn: &Connection) -> io::Result<i64> {
    conn.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)
}

pub(super) fn reject_newer_state_schema(version: i64) -> io::Result<()> {
    if version > STATE_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "state schema version {version} is newer than supported version {STATE_SCHEMA_VERSION}; refusing to mutate or downgrade"
            ),
        ));
    }
    Ok(())
}

pub(super) fn validate_state_connection_read_only(
    conn: &Connection,
) -> io::Result<StateIntegritySnapshot> {
    inspect_state_connection_read_only(conn, true)
}

pub(super) fn inspect_state_connection_read_only(
    conn: &Connection,
    require_current: bool,
) -> io::Result<StateIntegritySnapshot> {
    quick_check_state_connection(conn)?;

    let schema_version = state_schema_version(conn)?;
    reject_newer_state_schema(schema_version)?;
    let schema_current = schema_version == STATE_SCHEMA_VERSION;
    let migration_required = schema_version < STATE_SCHEMA_VERSION;
    if require_current && migration_required {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "state schema version {schema_version} requires migration to {STATE_SCHEMA_VERSION}"
            ),
        ));
    }

    let tables = list_tables(conn)?;
    if schema_current {
        let missing = STATE_REQUIRED_TABLES
            .iter()
            .copied()
            .filter(|required| !tables.iter().any(|table| table == required))
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "state schema is incomplete; missing required tables: {}",
                    missing.join(", ")
                ),
            ));
        }
    }
    let user_count = if tables.iter().any(|table| table == "users") {
        Some(
            conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get::<_, i64>(0))
                .map_err(sqlite_io_error)?,
        )
    } else {
        None
    };
    Ok(StateIntegritySnapshot {
        schema_version,
        schema_current,
        migration_required,
        tables,
        user_count,
    })
}

pub(super) fn quick_check_state_connection(conn: &Connection) -> io::Result<()> {
    let quick_check = conn
        .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("state SQLite quick check failed: {err}"),
            )
        })?;
    if quick_check != "ok" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("state SQLite quick check reported corruption: {quick_check}"),
        ));
    }
    Ok(())
}

pub(super) fn state_check_report(state: &Path) -> io::Result<Value> {
    let conn = open_state_connection_read_only(state)?;
    let snapshot = inspect_state_connection_read_only(&conn, false)?;
    Ok(json!({
        "status": "pass",
        "state": path_string(state),
        "exists_before_check": true,
        "exists_after_check": true,
        "read_only": true,
        "mutation_executed": false,
        "quick_check": "ok",
        "schema_version": snapshot.schema_version,
        "supported_schema_version": STATE_SCHEMA_VERSION,
        "schema_ready": snapshot.schema_current,
        "schema_current": snapshot.schema_current,
        "migration_required": snapshot.migration_required,
        "primary_state_store": path_string(state),
        "legacy_import_state_store": LEGACY_IMPORT_STATE_STORE,
        "rust_daed_writes_wing_db_by_default": false,
        "wing_db_import_supported": true,
        "wing_db_import_destructive_by_default": false,
        "user_count": snapshot.user_count,
        "tables": snapshot.tables,
    }))
}
