use super::*;

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
        CREATE INDEX IF NOT EXISTS idx_nodes_subscription_id ON nodes(subscription_id);
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
            binding_mode TEXT NOT NULL DEFAULT 'manual',
            source_subscription_id INTEGER NULL,
            PRIMARY KEY(group_id, node_id)
        );
        CREATE INDEX IF NOT EXISTS idx_group_nodes_node_id ON group_nodes(node_id);
        CREATE TABLE IF NOT EXISTS group_subscriptions (
            group_id INTEGER NOT NULL,
            subscription_id INTEGER NOT NULL,
            name_filter_regex TEXT NULL,
            PRIMARY KEY(group_id, subscription_id)
        );
        CREATE INDEX IF NOT EXISTS idx_group_subscriptions_subscription_id
            ON group_subscriptions(subscription_id);
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
            running_routing_id INTEGER NULL,
            running_external_input_version INTEGER NOT NULL DEFAULT 0
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
        DELETE FROM group_nodes
            WHERE group_id NOT IN (SELECT id FROM groups)
               OR node_id NOT IN (SELECT id FROM nodes);
        DELETE FROM group_subscriptions
            WHERE group_id NOT IN (SELECT id FROM groups)
               OR subscription_id NOT IN (SELECT id FROM subscriptions);
        DELETE FROM node_latency_results
            WHERE node_id NOT IN (SELECT id FROM nodes);
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
    conn.execute(
        "INSERT OR IGNORE INTO daed_product_metadata(key, value)
            VALUES(?1, '0')",
        params![RUNTIME_EXTERNAL_INPUT_VERSION_METADATA_KEY],
    )
    .map_err(sqlite_io_error)?;
    ensure_table_column(
        conn,
        "subscriptions",
        "use_proxy",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_table_column(
        conn,
        "systems",
        "running_external_input_version",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_table_column(
        conn,
        "group_nodes",
        "binding_mode",
        "TEXT NOT NULL DEFAULT 'manual'",
    )?;
    ensure_table_column(
        conn,
        "group_nodes",
        "source_subscription_id",
        "INTEGER NULL",
    )?;
    conn.execute(
        "UPDATE group_nodes
         SET binding_mode = 'subscription',
             source_subscription_id = (
                 SELECT n.subscription_id FROM nodes n WHERE n.id = group_nodes.node_id
             )
         WHERE EXISTS (
             SELECT 1 FROM nodes n
             WHERE n.id = group_nodes.node_id AND n.subscription_id IS NOT NULL
         )",
        [],
    )
    .map_err(sqlite_io_error)?;
    migrate_legacy_geodata_reload_pending(conn)?;
    conn.pragma_update(None, "user_version", STATE_SCHEMA_VERSION)
        .map_err(sqlite_io_error)?;
    Ok(())
}

fn migrate_legacy_geodata_reload_pending(conn: &Connection) -> io::Result<()> {
    let migration_id = "runtime-external-input-version-from-geodata-pending";
    let already_applied = conn
        .query_row(
            "SELECT 1 FROM daed_schema_migrations WHERE id = ?1",
            params![migration_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(sqlite_io_error)?
        .is_some();
    if already_applied {
        return Ok(());
    }
    let pending = conn
        .query_row(
            "SELECT value FROM daed_product_metadata WHERE key = ?1",
            params![LEGACY_GEODATA_RELOAD_PENDING_METADATA_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map(|value| matches!(value.as_deref(), Some("true") | Some("1")))
        .map_err(sqlite_io_error)?;
    if pending {
        conn.execute(
            "INSERT INTO daed_product_metadata(key, value)
             VALUES(?1, '1')
             ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)",
            params![RUNTIME_EXTERNAL_INPUT_VERSION_METADATA_KEY],
        )
        .map_err(sqlite_io_error)?;
        conn.execute(
            "INSERT OR REPLACE INTO daed_product_metadata(key, value)
             VALUES(?1, 'false')",
            params![LEGACY_GEODATA_RELOAD_PENDING_METADATA_KEY],
        )
        .map_err(sqlite_io_error)?;
    }
    conn.execute(
        "INSERT INTO daed_schema_migrations(id, applied_at) VALUES(?1, datetime('now'))",
        params![migration_id],
    )
    .map_err(sqlite_io_error)?;
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
