use super::*;
pub(super) fn ensure_state_schema(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_private_state_dir_permissions(parent)?;
    }
    let conn = open_state_connection(path)?;
    apply_state_schema(&conn)?;
    set_private_db_permissions(path)?;
    Ok(())
}

pub(super) fn open_state_connection(path: &Path) -> io::Result<Connection> {
    if let Some(parent) = path.parent()
        && parent.exists()
    {
        set_private_state_dir_permissions(parent)?;
    }
    let conn = Connection::open(path).map_err(sqlite_io_error)?;
    conn.busy_timeout(STATE_DB_BUSY_TIMEOUT)
        .map_err(sqlite_io_error)?;
    set_private_db_permissions(path)?;
    conn.execute_batch("PRAGMA foreign_keys = OFF;")
        .map_err(sqlite_io_error)?;
    Ok(conn)
}

fn set_private_state_dir_permissions(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o750))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(super) fn apply_state_schema(conn: &Connection) -> io::Result<()> {
    conn.execute_batch(
        r#"
        PRAGMA foreign_keys = OFF;
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            jwt_secret TEXT NOT NULL,
            json_storage TEXT NOT NULL DEFAULT '{}',
            avatar TEXT NULL,
            name TEXT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

        CREATE TABLE IF NOT EXISTS configs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT '',
            global TEXT NOT NULL,
            selected INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS dns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT '',
            dns TEXT NOT NULL,
            selected INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS routings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL DEFAULT '',
            routing TEXT NOT NULL,
            selected INTEGER NOT NULL DEFAULT 0,
            version INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            updated_at TEXT NOT NULL DEFAULT '',
            link TEXT NOT NULL,
            cron_exp TEXT DEFAULT '10 */6 * * *',
            cron_enable INTEGER DEFAULT 1,
            status TEXT NOT NULL DEFAULT '',
            info TEXT NOT NULL DEFAULT '',
            tag TEXT UNIQUE,
            use_proxy INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS nodes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            link TEXT NOT NULL,
            name TEXT NOT NULL,
            address TEXT NOT NULL,
            protocol TEXT NOT NULL,
            tag TEXT UNIQUE,
            subscription_id INTEGER NULL
        );
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            policy TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 0,
            system_id INTEGER NULL
        );
        CREATE TABLE IF NOT EXISTS group_nodes (
            group_id INTEGER NOT NULL,
            node_id INTEGER NOT NULL,
            PRIMARY KEY(group_id, node_id)
        );
        CREATE TABLE IF NOT EXISTS group_subscriptions (
            group_id INTEGER NOT NULL,
            subscription_id INTEGER NOT NULL,
            name_filter_regex TEXT NULL,
            PRIMARY KEY(group_id, subscription_id)
        );
        CREATE TABLE IF NOT EXISTS group_policy_params (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL,
            value TEXT NOT NULL,
            group_id INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS systems (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            running INTEGER NOT NULL DEFAULT 0,
            running_config_version INTEGER NOT NULL DEFAULT 0,
            running_dns_version INTEGER NOT NULL DEFAULT 0,
            running_routing_version INTEGER NOT NULL DEFAULT 0,
            running_group_version_sum INTEGER NOT NULL DEFAULT 0,
            running_group_ids TEXT NOT NULL DEFAULT '',
            running_config_id INTEGER NULL,
            running_dns_id INTEGER NULL,
            running_routing_id INTEGER NULL
        );
        CREATE TABLE IF NOT EXISTS log_settings (
            id INTEGER PRIMARY KEY,
            max_entries INTEGER NOT NULL,
            max_bytes INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS node_latency_results (
            node_id INTEGER PRIMARY KEY,
            latency_ms INTEGER NULL,
            alive INTEGER NOT NULL,
            tested_at TEXT NOT NULL,
            message TEXT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS daed_product_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS daed_schema_migrations (
            id TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
        DELETE FROM group_policy_params
            WHERE group_id IS NULL
               OR group_id NOT IN (SELECT id FROM groups);
        INSERT OR IGNORE INTO daed_schema_migrations(id, applied_at)
            VALUES('production-daed-product-schema', datetime('now'));
        INSERT OR IGNORE INTO daed_schema_migrations(id, applied_at)
            VALUES('production-local-product-surface', datetime('now'));
        INSERT OR IGNORE INTO log_settings(id, max_entries, max_bytes)
            VALUES(1, 10000, 52428800);
        "#,
    )
    .map_err(sqlite_io_error)?;
    conn.execute(
        "INSERT OR IGNORE INTO daed_product_metadata(key, value)
            VALUES('runtime_log_level', ?1)",
        params![DEFAULT_RUNTIME_LOG_LEVEL],
    )
    .map_err(sqlite_io_error)?;
    ensure_table_column(
        conn,
        "subscriptions",
        "use_proxy",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    Ok(())
}

fn ensure_table_column(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> io::Result<()> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sqlite_io_error)?;
    for row in rows {
        if row.map_err(sqlite_io_error)? == column {
            return Ok(());
        }
    }
    conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}

pub(super) fn state_check_report(state: &Path) -> io::Result<Value> {
    let existed_before = state.exists();
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let tables = list_tables(&conn)?;
    let user_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .map_err(sqlite_io_error)?;
    let metadata_ready = tables.iter().any(|name| name == "daed_product_metadata")
        && tables.iter().any(|name| name == "daed_schema_migrations");
    Ok(json!({
        "status": "pass",
        "state": path_string(state),
        "exists_before_check": existed_before,
        "exists_after_check": state.exists(),
        "schema_ready": metadata_ready,
        "primary_state_store": path_string(state),
        "legacy_import_state_store": LEGACY_IMPORT_STATE_STORE,
        "rust_daed_writes_wing_db_by_default": false,
        "wing_db_import_supported": true,
        "wing_db_import_destructive_by_default": false,
        "user_count": user_count,
        "tables": tables,
    }))
}

pub(super) fn migrate_wing_db(from_wing_db: &Path, to: &Path, force: bool) -> io::Result<Value> {
    if !from_wing_db.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "wing.db source does not exist: {}",
                path_string(from_wing_db)
            ),
        ));
    }
    let wing_hash_before = sha256_file_hex(from_wing_db)?;
    let target_existed = to.exists();
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    let copied = if target_existed && !force {
        false
    } else {
        fs::copy(from_wing_db, to)?;
        set_private_db_permissions(to)?;
        true
    };
    ensure_state_schema(to)?;
    let conn = open_state_connection(to)?;
    conn.execute(
        "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
        params!["source_wing_db_path", path_string(from_wing_db)],
    )
    .map_err(sqlite_io_error)?;
    conn.execute(
        "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, datetime('now'))",
        params!["last_wing_db_import_at"],
    )
    .map_err(sqlite_io_error)?;
    let wing_hash_after = sha256_file_hex(from_wing_db)?;
    let wing_db_unchanged = wing_hash_before == wing_hash_after;
    if !wing_db_unchanged {
        return Err(io::Error::other("wing.db hash changed during import"));
    }
    Ok(json!({
        "status": "pass",
        "from_wing_db": path_string(from_wing_db),
        "to": path_string(to),
        "target_existed": target_existed,
        "copied": copied,
        "force": force,
        "wing_db_sha256_before": wing_hash_before,
        "wing_db_sha256_after": wing_hash_after,
        "wing_db_unchanged": wing_db_unchanged,
        "rust_daed_writes_wing_db_by_default": false,
        "wing_db_import_destructive": false,
    }))
}
