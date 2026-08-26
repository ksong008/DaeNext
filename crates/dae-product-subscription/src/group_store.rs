use std::io;
use std::path::Path;

use dae_product_core::{
    RuntimeNodeTag, push_unique_runtime_node_tag as push_unique, runtime_node_tag,
};
use dae_product_persistence::open_state_connection;
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

use crate::node_view::sqlite_io_error;
use crate::{
    compile_subscription_name_filter, subscription_node_row_value,
    subscription_nodes_matching_filter,
};

const GROUP_POLICY_FIXED: &str = "fixed";
const SUPPORTED_GROUP_POLICIES: &[&str] = &[
    "random",
    GROUP_POLICY_FIXED,
    "min",
    "min_avg10",
    "min_moving_avg",
];
const DEFAULT_SUBSCRIPTION_CRON_EXPRESSION: &str = "10 */6 * * *";

pub fn list_groups_value(state: &Path) -> io::Result<Value> {
    let conn = open_state_connection(state)?;
    list_groups_value_with_connection(&conn)
}

pub fn list_groups_value_with_connection(conn: &Connection) -> io::Result<Value> {
    let mut stmt = conn
        .prepare("SELECT id FROM groups ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?);
    }
    let mut items = Vec::new();
    for id in ids {
        if let Some(group) = get_group_value_with_conn(conn, id)? {
            items.push(group);
        }
    }
    Ok(json!({"items": items}))
}

pub fn get_group_value(state: &Path, id: i64) -> io::Result<Option<Value>> {
    let conn = open_state_connection(state)?;
    get_group_value_with_conn(&conn, id)
}

pub fn get_group_value_with_conn(conn: &Connection, id: i64) -> io::Result<Option<Value>> {
    let Some((group_id, name, policy, version)) = conn
        .query_row(
            "SELECT id, name, policy, version FROM groups WHERE id = ?1",
            params![id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(sqlite_io_error)?
    else {
        return Ok(None);
    };
    Ok(Some(json!({
        "id": group_id,
        "name": name,
        "policy": policy,
        "policyParams": group_policy_params_value(conn, group_id)?,
        "nodes": group_nodes_value(conn, group_id)?,
        "subscriptions": group_subscriptions_value(conn, group_id)?,
        "version": version,
    })))
}

pub fn validate_group_policy(policy: &str) -> Result<&str, String> {
    let policy = policy.trim();
    if SUPPORTED_GROUP_POLICIES.contains(&policy) {
        return Ok(policy);
    }
    Err(format!(
        "unsupported group policy {policy:?}; allowed values: {}",
        SUPPORTED_GROUP_POLICIES.join(", ")
    ))
}

pub fn group_policy_is_fixed(policy: &str) -> bool {
    policy.trim() == GROUP_POLICY_FIXED
}

pub fn ensure_fixed_group_runtime_node_limit(
    conn: &Connection,
    group_id: i64,
    extra_node_ids: &[i64],
    extra_subscription_ids: &[i64],
    name_filter_regex: Option<&str>,
) -> io::Result<()> {
    if !group_has_fixed_policy(conn, group_id)? {
        return Ok(());
    }
    let mut tags = fixed_group_runtime_node_tags(conn, group_id)?;
    for node in nodes_by_ids_value(conn, extra_node_ids)? {
        push_unique(&mut tags, runtime_node_tag(&node));
    }
    for subscription_id in extra_subscription_ids {
        for node in subscription_nodes_matching_filter(conn, *subscription_id, name_filter_regex)? {
            push_unique(&mut tags, runtime_node_tag(&node));
        }
    }
    validate_fixed_group_runtime_node_tags(&tags)
}

pub fn validate_fixed_group_runtime_node_tags(tags: &[RuntimeNodeTag]) -> io::Result<()> {
    if tags.len() <= 1 {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "fixed group can match only one node; current selection would match {} nodes",
            tags.len()
        ),
    ))
}

pub fn fixed_group_runtime_node_tags(
    conn: &Connection,
    group_id: i64,
) -> io::Result<Vec<RuntimeNodeTag>> {
    let mut tags = Vec::new();
    for node in group_nodes_value(conn, group_id)? {
        push_unique(&mut tags, runtime_node_tag(&node));
    }
    for subscription in group_subscriptions_value(conn, group_id)? {
        for node in subscription["matchedNodes"]
            .as_array()
            .into_iter()
            .flatten()
        {
            push_unique(&mut tags, runtime_node_tag(node));
        }
    }
    Ok(tags)
}

pub fn group_nodes_value(conn: &Connection, group_id: i64) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT n.id, n.link, n.name, n.address, n.protocol, n.tag, n.subscription_id
             FROM nodes n JOIN group_nodes gn ON gn.node_id = n.id
             WHERE gn.group_id = ?1 ORDER BY n.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], subscription_node_row_value)
        .map_err(sqlite_io_error)?;
    collect_values(rows)
}

pub fn group_subscriptions_value(conn: &Connection, group_id: i64) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT s.id, s.updated_at, s.link, s.cron_exp, s.cron_enable, s.status, s.info,
                    s.tag, gs.name_filter_regex
             FROM subscriptions s
             JOIN group_subscriptions gs ON gs.subscription_id = s.id
             WHERE gs.group_id = ?1 ORDER BY s.id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?
                    .unwrap_or_else(|| DEFAULT_SUBSCRIPTION_CRON_EXPRESSION.to_owned()),
                row.get::<_, i64>(4)? != 0,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut out = Vec::new();
    for row in rows {
        let (id, updated_at, link, _, _, status, info, tag, name_filter_regex) =
            row.map_err(sqlite_io_error)?;
        let matched_nodes =
            subscription_nodes_matching_filter(conn, id, name_filter_regex.as_deref())?;
        out.push(json!({
            "subscriptionId": id,
            "nameFilterRegex": name_filter_regex,
            "matchedCount": matched_nodes.len(),
            "matchedNodes": matched_nodes,
            "updatedAt": updated_at,
            "status": status,
            "info": info,
            "link": link,
            "tag": tag,
        }));
    }
    Ok(out)
}

pub fn group_policy_params_value(conn: &Connection, group_id: i64) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare("SELECT key, value FROM group_policy_params WHERE group_id = ?1 ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok(json!({
                "key": row.get::<_, String>(0)?,
                "val": row.get::<_, String>(1)?,
            }))
        })
        .map_err(sqlite_io_error)?;
    collect_values(rows)
}

pub fn replace_group_policy_params(
    conn: &Connection,
    group_id: i64,
    params_value: Option<&Value>,
) -> io::Result<()> {
    conn.execute(
        "DELETE FROM group_policy_params WHERE group_id = ?1",
        params![group_id],
    )
    .map_err(sqlite_io_error)?;
    if let Some(values) = params_value.and_then(Value::as_array) {
        for item in values {
            let key = item.get("key").and_then(Value::as_str).unwrap_or("");
            let value = item
                .get("val")
                .or_else(|| item.get("value"))
                .and_then(Value::as_str)
                .unwrap_or("");
            conn.execute(
                "INSERT INTO group_policy_params(key, value, group_id) VALUES(?1, ?2, ?3)",
                params![key, value, group_id],
            )
            .map_err(sqlite_io_error)?;
        }
    }
    Ok(())
}

pub fn apply_group_node_ids(
    conn: &Connection,
    group_id: i64,
    ids: &[i64],
    add: bool,
) -> io::Result<()> {
    if add {
        ensure_fixed_group_runtime_node_limit(conn, group_id, ids, &[], None)?;
    }
    for id in ids {
        if add {
            conn.execute(
                "INSERT INTO group_nodes(group_id, node_id, binding_mode, source_subscription_id)
                 SELECT ?1, id,
                        CASE WHEN subscription_id IS NULL THEN 'manual' ELSE 'subscription' END,
                        subscription_id
                 FROM nodes WHERE id = ?2
                 ON CONFLICT(group_id, node_id) DO UPDATE SET
                    binding_mode = excluded.binding_mode,
                    source_subscription_id = excluded.source_subscription_id",
                params![group_id, id],
            )
        } else {
            conn.execute(
                "DELETE FROM group_nodes WHERE group_id = ?1 AND node_id = ?2",
                params![group_id, id],
            )
        }
        .map_err(sqlite_io_error)?;
    }
    Ok(())
}

pub fn validate_group_node_ids_exist(conn: &Connection, ids: &[i64]) -> io::Result<()> {
    for id in ids {
        let exists = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM nodes WHERE id = ?1)",
                params![id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(sqlite_io_error)?;
        if !exists {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("node {id} not found"),
            ));
        }
    }
    Ok(())
}

pub fn apply_group_subscription_ids(
    conn: &Connection,
    group_id: i64,
    ids: &[i64],
    name_filter_regex: Option<&str>,
    add: bool,
) -> io::Result<()> {
    let name_filter_regex = name_filter_regex
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if add {
        let _ = compile_subscription_name_filter(name_filter_regex)?;
        ensure_fixed_group_runtime_node_limit(conn, group_id, &[], ids, name_filter_regex)?;
    }
    for id in ids {
        if add {
            conn.execute(
                "INSERT OR REPLACE INTO group_subscriptions(
                    group_id, subscription_id, name_filter_regex
                 ) VALUES(?1, ?2, ?3)",
                params![group_id, id, name_filter_regex],
            )
        } else {
            conn.execute(
                "DELETE FROM group_subscriptions WHERE group_id = ?1 AND subscription_id = ?2",
                params![group_id, id],
            )
        }
        .map_err(sqlite_io_error)?;
    }
    Ok(())
}

fn group_has_fixed_policy(conn: &Connection, group_id: i64) -> io::Result<bool> {
    let policy = conn
        .query_row(
            "SELECT policy FROM groups WHERE id = ?1",
            params![group_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_io_error)?;
    Ok(policy
        .as_deref()
        .map(group_policy_is_fixed)
        .unwrap_or(false))
}

fn nodes_by_ids_value(conn: &Connection, ids: &[i64]) -> io::Result<Vec<Value>> {
    let mut items = Vec::new();
    for id in ids {
        if let Some(node) = conn
            .query_row(
                "SELECT id, link, name, address, protocol, tag, subscription_id
                 FROM nodes WHERE id = ?1",
                params![id],
                subscription_node_row_value,
            )
            .optional()
            .map_err(sqlite_io_error)?
        {
            items.push(node);
        }
    }
    Ok(items)
}

fn collect_values(rows: impl Iterator<Item = rusqlite::Result<Value>>) -> io::Result<Vec<Value>> {
    let mut values = Vec::new();
    for row in rows {
        values.push(row.map_err(sqlite_io_error)?);
    }
    Ok(values)
}
