use std::io;
use std::path::Path;

use dae_product_persistence::open_state_connection;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::node_view::{NodeListScope, list_nodes_by_scope_with_connection, sqlite_io_error};

const DEFAULT_SUBSCRIPTION_CRON_EXPRESSION: &str = "10 */6 * * *";

pub fn list_subscriptions_value(state: &Path, expand_nodes: bool) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    let mut stmt = conn
        .prepare(
            "SELECT id, updated_at, link, cron_exp, cron_enable, status, info, tag, use_proxy
             FROM subscriptions ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], subscription_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        let mut value = row.map_err(sqlite_io_error)?;
        let id = value["id"].as_i64().unwrap_or(0);
        let node_count = count_nodes_for_subscription(&conn, id)?;
        if let Value::Object(map) = &mut value {
            map.insert("nodeCount".to_owned(), json!(node_count));
            if expand_nodes {
                map.insert(
                    "nodes".to_owned(),
                    list_nodes_by_scope_with_connection(&conn, NodeListScope::Subscription(id))?,
                );
            }
        }
        items.push(value);
    }
    Ok(json!({"items": items}))
}

pub fn get_subscription_value(state: &Path, id: i64) -> io::Result<Option<Value>> {
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT id, updated_at, link, cron_exp, cron_enable, status, info, tag, use_proxy
         FROM subscriptions WHERE id = ?1",
        params![id],
        subscription_row_value,
    )
    .optional()
    .map_err(sqlite_io_error)
}

pub fn subscription_row_value(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({
        "id": row.get::<_, i64>(0)?,
        "updatedAt": row.get::<_, String>(1)?,
        "link": row.get::<_, String>(2)?,
        "cronExp": row
            .get::<_, Option<String>>(3)?
            .unwrap_or_else(|| DEFAULT_SUBSCRIPTION_CRON_EXPRESSION.to_owned()),
        "cronEnable": row.get::<_, i64>(4)? != 0,
        "status": row.get::<_, String>(5)?,
        "info": row.get::<_, String>(6)?,
        "tag": row.get::<_, Option<String>>(7)?,
        "useProxy": row.get::<_, i64>(8)? != 0,
    }))
}

pub fn count_nodes_for_subscription(conn: &Connection, subscription_id: i64) -> io::Result<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM nodes WHERE subscription_id = ?1",
        params![subscription_id],
        |row| row.get(0),
    )
    .map_err(sqlite_io_error)
}
