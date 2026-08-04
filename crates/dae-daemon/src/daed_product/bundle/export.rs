use super::*;

pub(in crate::daed_product) fn export_bundle(state: &Path, user: &UserRecord) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let storage = serde_json::from_str::<Value>(&user.json_storage).unwrap_or_else(|_| json!({}));
    Ok(json!({
        "schemaVersion": 1,
        "exportedAt": now_text(),
        "mode": storage
            .get("mode")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_PRODUCT_MODE),
        "defaults": {
            "configId": numeric_storage_value(&storage, "defaultConfigID"),
            "dnsId": numeric_storage_value(&storage, "defaultDNSID"),
            "routingId": numeric_storage_value(&storage, "defaultRoutingID"),
            "groupId": numeric_storage_value(&storage, "defaultGroupID"),
        },
        "selected": {
            "configId": selected_id(&conn, SectionKind::Config)?,
            "dnsId": selected_id(&conn, SectionKind::Dns)?,
            "routingId": selected_id(&conn, SectionKind::Routing)?,
        },
        "configs": bundle_sections(&conn, SectionKind::Config)?,
        "dnss": bundle_sections(&conn, SectionKind::Dns)?,
        "routings": bundle_sections(&conn, SectionKind::Routing)?,
        "subscriptions": bundle_subscriptions(&conn)?,
        "nodes": bundle_nodes(&conn)?,
        "groups": bundle_groups(&conn)?,
        "groupSortState": exported_group_sort_state(&storage),
    }))
}

fn exported_group_sort_state(storage: &Value) -> Value {
    storage
        .get("groupSortStateV1")
        .and_then(Value::as_str)
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or(Value::Null)
}

fn bundle_sections(conn: &Connection, kind: SectionKind) -> io::Result<Vec<Value>> {
    let sql = format!(
        "SELECT id, name, {} FROM {} ORDER BY id",
        kind.value_column(),
        kind.table()
    );
    let mut stmt = conn.prepare(&sql).map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            let id = row.get::<_, i64>(0)?;
            let name = row.get::<_, String>(1)?;
            let raw = row.get::<_, String>(2)?;
            Ok(match kind {
                SectionKind::Config => json!({"id": id, "name": name, "global": raw}),
                SectionKind::Dns => json!({"id": id, "name": name, "dns": raw}),
                SectionKind::Routing => json!({"id": id, "name": name, "routing": raw}),
            })
        })
        .map_err(sqlite_io_error)?;
    collect_rows(rows)
}

fn bundle_subscriptions(conn: &Connection) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, updated_at, link, cron_exp, cron_enable, status, info, tag, use_proxy FROM subscriptions ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], subscription_row_value)
        .map_err(sqlite_io_error)?;
    collect_rows(rows)
}

fn bundle_nodes(conn: &Connection) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, link, name, address, protocol, tag, subscription_id FROM nodes ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], node_row_value)
        .map_err(sqlite_io_error)?;
    collect_rows(rows)
}

fn bundle_groups(conn: &Connection) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare("SELECT id, name, policy FROM groups ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut groups = Vec::new();
    for row in rows {
        let (id, name, policy) = row.map_err(sqlite_io_error)?;
        groups.push(json!({
            "id": id,
            "name": name,
            "policy": policy,
            "policyParams": group_policy_params_value(conn, id)?,
            "nodeIds": group_node_ids(conn, id)?,
            "subscriptionBindings": group_subscription_bindings(conn, id)?,
        }));
    }
    Ok(groups)
}

fn group_node_ids(conn: &Connection, group_id: i64) -> io::Result<Vec<i64>> {
    let mut stmt = conn
        .prepare("SELECT node_id FROM group_nodes WHERE group_id = ?1 ORDER BY node_id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    collect_rows(rows)
}

fn group_subscription_bindings(conn: &Connection, group_id: i64) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT subscription_id, name_filter_regex FROM group_subscriptions WHERE group_id = ?1 ORDER BY subscription_id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok(json!({
                "subscriptionId": row.get::<_, i64>(0)?,
                "nameFilterRegex": row.get::<_, Option<String>>(1)?,
            }))
        })
        .map_err(sqlite_io_error)?;
    collect_rows(rows)
}

fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
) -> io::Result<Vec<T>> {
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

fn numeric_storage_value(storage: &Value, key: &str) -> Option<i64> {
    storage
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<i64>().ok())
}
