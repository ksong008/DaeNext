use std::io;
use std::path::Path;

use dae_product_core::RuntimeNodeTag;
use dae_product_persistence::open_state_connection;
use regex::Regex;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::decode_node_label;

#[derive(Clone, Copy)]
pub enum NodeListScope {
    Independent,
    SubscriptionBacked,
    Subscription(i64),
    All,
}

pub fn list_nodes_value(state: &Path, subscription_id: Option<i64>) -> io::Result<Value> {
    let scope = subscription_id
        .map(NodeListScope::Subscription)
        .unwrap_or(NodeListScope::Independent);
    list_nodes_by_scope(state, scope)
}

pub fn list_all_nodes_value(state: &Path) -> io::Result<Value> {
    list_nodes_by_scope(state, NodeListScope::All)
}

pub fn list_nodes_by_scope(state: &Path, scope: NodeListScope) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    list_nodes_by_scope_with_connection(&conn, scope)
}

pub(crate) fn list_nodes_by_scope_with_connection(
    conn: &Connection,
    scope: NodeListScope,
) -> io::Result<Value> {
    let (query, subscription_id) = match scope {
        NodeListScope::Independent => (
            "SELECT id, link, name, address, protocol, tag, subscription_id
             FROM nodes WHERE subscription_id IS NULL ORDER BY id",
            None,
        ),
        NodeListScope::SubscriptionBacked => (
            "SELECT id, link, name, address, protocol, tag, subscription_id
             FROM nodes WHERE subscription_id IS NOT NULL ORDER BY id",
            None,
        ),
        NodeListScope::Subscription(subscription_id) => (
            "SELECT id, link, name, address, protocol, tag, subscription_id
             FROM nodes WHERE subscription_id = ?1 ORDER BY id",
            Some(subscription_id),
        ),
        NodeListScope::All => (
            "SELECT id, link, name, address, protocol, tag, subscription_id
             FROM nodes ORDER BY id",
            None,
        ),
    };
    let mut stmt = conn.prepare(query).map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    if let Some(subscription_id) = subscription_id {
        let rows = stmt
            .query_map([subscription_id], subscription_node_row_value)
            .map_err(sqlite_io_error)?;
        for row in rows {
            items.push(row.map_err(sqlite_io_error)?);
        }
    } else {
        let rows = stmt
            .query_map([], subscription_node_row_value)
            .map_err(sqlite_io_error)?;
        for row in rows {
            items.push(row.map_err(sqlite_io_error)?);
        }
    }
    Ok(json!({
        "items": items,
        "totalCount": items.len(),
        "nextAfterId": Value::Null,
    }))
}

pub fn get_node_value(state: &Path, id: i64) -> io::Result<Option<Value>> {
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT id, link, name, address, protocol, tag, subscription_id
         FROM nodes WHERE id = ?1",
        params![id],
        subscription_node_row_value,
    )
    .optional()
    .map_err(sqlite_io_error)
}

pub fn subscription_node_row_value(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    let id = row.get::<_, i64>(0)?;
    let subscription_id: Option<i64> = row.get(6)?;
    let name = row.get::<_, String>(2)?;
    let tag = row.get::<_, Option<String>>(5)?;
    let runtime_tag = RuntimeNodeTag::from_node_id(id).into_string();
    Ok(json!({
        "id": id,
        "link": row.get::<_, String>(1)?,
        "name": decode_node_label(&name),
        "address": row.get::<_, String>(3)?,
        "protocol": row.get::<_, String>(4)?,
        "transport": Value::Null,
        "tag": tag.as_deref().map(decode_node_label),
        "runtimeTag": runtime_tag,
        "subscriptionId": subscription_id,
        "subscriptionID": subscription_id.map(|value| value.to_string()),
    }))
}

pub fn compile_subscription_name_filter(
    name_filter_regex: Option<&str>,
) -> io::Result<Option<Regex>> {
    let Some(raw) = name_filter_regex
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    Regex::new(raw)
        .map(Some)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))
}

pub fn subscription_node_matches_name_filter(node: &Value, filter: Option<&Regex>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    node.get("name")
        .and_then(Value::as_str)
        .map(|name| filter.is_match(name))
        .unwrap_or(false)
}

pub fn subscription_nodes_matching_filter(
    conn: &Connection,
    subscription_id: i64,
    name_filter_regex: Option<&str>,
) -> io::Result<Vec<Value>> {
    let filter = compile_subscription_name_filter(name_filter_regex)?;
    let mut items = Vec::new();
    visit_subscription_nodes_matching_filter(conn, subscription_id, filter.as_ref(), |node| {
        items.push(node);
    })?;
    Ok(items)
}

pub fn visit_subscription_nodes_matching_filter(
    conn: &Connection,
    subscription_id: i64,
    filter: Option<&Regex>,
    mut visit: impl FnMut(Value),
) -> io::Result<()> {
    let mut stmt = conn
        .prepare(
            "SELECT id, link, name, address, protocol, tag, subscription_id
             FROM nodes WHERE subscription_id = ?1 ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([subscription_id], subscription_node_row_value)
        .map_err(sqlite_io_error)?;
    for row in rows {
        let node = row.map_err(sqlite_io_error)?;
        if subscription_node_matches_name_filter(&node, filter) {
            visit(node);
        }
    }
    Ok(())
}

pub(crate) fn sqlite_io_error(error: rusqlite::Error) -> io::Error {
    io::Error::other(error)
}
