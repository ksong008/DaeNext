use super::*;
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ImportBundleOutcome {
    pub(super) imported: bool,
    pub(super) runtime_reload_required: bool,
}

pub(super) fn export_bundle(state: &Path, user: &UserRecord) -> io::Result<Value> {
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
    }))
}

pub(super) fn import_bundle(
    state: &Path,
    config_dir: &Path,
    body: &Value,
    user: &UserRecord,
) -> io::Result<ImportBundleOutcome> {
    ensure_state_schema(state)?;
    let mut conn = open_state_connection(state)?;
    let running_state = running_runtime_state(&conn)?;
    let tx = conn.transaction().map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM group_policy_params", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM group_subscriptions", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM group_nodes", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM node_latency_results", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM nodes", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM subscriptions", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM groups", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM configs", [])
        .map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM dns", []).map_err(sqlite_io_error)?;
    tx.execute("DELETE FROM routings", [])
        .map_err(sqlite_io_error)?;

    import_bundle_sections(&tx, body.get("configs"), SectionKind::Config)?;
    import_bundle_sections(&tx, body.get("dnss"), SectionKind::Dns)?;
    import_bundle_sections(&tx, body.get("routings"), SectionKind::Routing)?;
    import_bundle_subscriptions(&tx, body.get("subscriptions"))?;
    import_bundle_nodes(&tx, body.get("nodes"))?;
    import_bundle_groups(&tx, body.get("groups"))?;

    let selected = body.get("selected").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "bundle selected resources are required",
        )
    })?;
    set_selected_from_bundle(&tx, selected, "configId", SectionKind::Config)?;
    set_selected_from_bundle(&tx, selected, "dnsId", SectionKind::Dns)?;
    set_selected_from_bundle(&tx, selected, "routingId", SectionKind::Routing)?;
    validate_imported_selected_sections(&tx)?;
    if running_state.is_some() {
        mark_imported_bundle_modified_if_running(&tx)?;
    }
    tx.commit().map_err(sqlite_io_error)?;

    let mut storage =
        serde_json::from_str::<Value>(&user.json_storage).unwrap_or_else(|_| json!({}));
    if !storage.is_object() {
        storage = json!({});
    }
    if let Some(mode) = body.get("mode").and_then(Value::as_str) {
        set_value_at_path(&mut storage, "mode", Value::String(mode.to_owned()))
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    }
    if let Some(defaults) = body.get("defaults") {
        for (key, path) in [
            ("configId", "defaultConfigID"),
            ("dnsId", "defaultDNSID"),
            ("routingId", "defaultRoutingID"),
            ("groupId", "defaultGroupID"),
        ] {
            if let Some(value) = defaults.get(key).and_then(Value::as_i64) {
                set_value_at_path(&mut storage, path, Value::String(value.to_string()))
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
            }
        }
    }
    save_json_storage(state, user.id, &storage.to_string())?;
    append_log_for_config(
        config_dir,
        state,
        "info",
        "DAE bundle imported by Rust daed",
    )?;
    Ok(ImportBundleOutcome {
        imported: true,
        runtime_reload_required: running_state.is_some(),
    })
}

pub(super) fn bundle_sections(conn: &Connection, kind: SectionKind) -> io::Result<Vec<Value>> {
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
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

pub(super) fn bundle_subscriptions(conn: &Connection) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, updated_at, link, cron_exp, cron_enable, status, info, tag, use_proxy FROM subscriptions ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], subscription_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

pub(super) fn bundle_nodes(conn: &Connection) -> io::Result<Vec<Value>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, link, name, address, protocol, tag, subscription_id FROM nodes ORDER BY id",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], node_row_value)
        .map_err(sqlite_io_error)?;
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

pub(super) fn bundle_groups(conn: &Connection) -> io::Result<Vec<Value>> {
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

pub(super) fn group_node_ids(conn: &Connection, group_id: i64) -> io::Result<Vec<i64>> {
    let mut stmt = conn
        .prepare("SELECT node_id FROM group_nodes WHERE group_id = ?1 ORDER BY node_id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?);
    }
    Ok(ids)
}

pub(super) fn group_subscription_bindings(
    conn: &Connection,
    group_id: i64,
) -> io::Result<Vec<Value>> {
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
    let mut items = Vec::new();
    for row in rows {
        items.push(row.map_err(sqlite_io_error)?);
    }
    Ok(items)
}

pub(super) fn import_bundle_sections(
    conn: &Connection,
    sections: Option<&Value>,
    kind: SectionKind,
) -> io::Result<()> {
    if let Some(items) = sections.and_then(Value::as_array) {
        for item in items {
            let Some(id) = item.get("id").and_then(Value::as_i64) else {
                continue;
            };
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(kind.default_name());
            let raw = item
                .get(kind.request_value_key())
                .and_then(Value::as_str)
                .unwrap_or("");
            let sql = format!(
                "INSERT INTO {}(id, name, {}, selected, version) VALUES(?1, ?2, ?3, 0, 0)",
                kind.table(),
                kind.value_column()
            );
            conn.execute(&sql, params![id, name, raw])
                .map_err(sqlite_io_error)?;
        }
    }
    Ok(())
}

pub(super) fn import_bundle_subscriptions(
    conn: &Connection,
    subscriptions: Option<&Value>,
) -> io::Result<()> {
    if let Some(items) = subscriptions.and_then(Value::as_array) {
        for item in items {
            let Some(id) = item.get("id").and_then(Value::as_i64) else {
                continue;
            };
            let updated_at = item
                .get("updatedAt")
                .and_then(Value::as_str)
                .map(str::to_owned)
                .unwrap_or_else(now_text);
            conn.execute(
                "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag, use_proxy)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    id,
                    updated_at,
                    item.get("link").and_then(Value::as_str).unwrap_or(""),
                    item.get("cronExp")
                        .and_then(Value::as_str)
                        .unwrap_or(DEFAULT_SUBSCRIPTION_CRON_EXP),
                    item.get("cronEnable")
                        .and_then(Value::as_bool)
                        .unwrap_or(DEFAULT_SUBSCRIPTION_CRON_ENABLE) as i64,
                    item.get("status")
                        .and_then(Value::as_str)
                        .unwrap_or(DEFAULT_SUBSCRIPTION_STATUS),
                    item.get("info").and_then(Value::as_str).unwrap_or(""),
                    item.get("tag").and_then(Value::as_str),
                    item.get("useProxy")
                        .and_then(Value::as_bool)
                        .unwrap_or(false) as i64,
                ],
            )
            .map_err(sqlite_io_error)?;
        }
    }
    Ok(())
}

pub(super) fn import_bundle_nodes(conn: &Connection, nodes: Option<&Value>) -> io::Result<()> {
    if let Some(items) = nodes.and_then(Value::as_array) {
        for item in items {
            let Some(id) = item.get("id").and_then(Value::as_i64) else {
                continue;
            };
            let link = item.get("link").and_then(Value::as_str).unwrap_or("");
            let parsed = parse_node_link(link, item.get("tag").and_then(Value::as_str));
            conn.execute(
                "INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id,
                    link,
                    item.get("name")
                        .and_then(Value::as_str)
                        .unwrap_or(&parsed.name),
                    item.get("address")
                        .and_then(Value::as_str)
                        .unwrap_or(&parsed.address),
                    item.get("protocol")
                        .and_then(Value::as_str)
                        .unwrap_or(&parsed.protocol),
                    item.get("tag").and_then(Value::as_str),
                    item.get("subscriptionId").and_then(Value::as_i64),
                ],
            )
            .map_err(sqlite_io_error)?;
        }
    }
    Ok(())
}

pub(super) fn import_bundle_groups(conn: &Connection, groups: Option<&Value>) -> io::Result<()> {
    if let Some(items) = groups.and_then(Value::as_array) {
        for item in items {
            let Some(id) = item.get("id").and_then(Value::as_i64) else {
                continue;
            };
            conn.execute(
                "INSERT INTO groups(id, name, policy, version) VALUES(?1, ?2, ?3, 0)",
                params![
                    id,
                    item.get("name")
                        .and_then(Value::as_str)
                        .unwrap_or(DEFAULT_PRODUCT_GROUP_NAME),
                    item.get("policy")
                        .and_then(Value::as_str)
                        .unwrap_or(DEFAULT_PRODUCT_GROUP_POLICY),
                ],
            )
            .map_err(sqlite_io_error)?;
            replace_group_policy_params(conn, id, item.get("policyParams"))?;
            apply_group_node_ids(conn, id, &integer_array(item, "nodeIds"), true)?;
            if let Some(bindings) = item.get("subscriptionBindings").and_then(Value::as_array) {
                for binding in bindings {
                    if let Some(subscription_id) =
                        binding.get("subscriptionId").and_then(Value::as_i64)
                    {
                        apply_group_subscription_ids(
                            conn,
                            id,
                            &[subscription_id],
                            binding.get("nameFilterRegex").and_then(Value::as_str),
                            true,
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) fn validate_imported_selected_sections(conn: &Connection) -> io::Result<()> {
    for kind in [SectionKind::Config, SectionKind::Dns, SectionKind::Routing] {
        if selected_id(conn, kind)?.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bundle selected {} resource is missing", kind.table()),
            ));
        }
    }
    Ok(())
}

pub(super) fn mark_imported_bundle_modified_if_running(conn: &Connection) -> io::Result<()> {
    for kind in [SectionKind::Config, SectionKind::Dns, SectionKind::Routing] {
        let sql = format!(
            "UPDATE {} SET version = version + 1 WHERE selected = 1",
            kind.table()
        );
        conn.execute(&sql, []).map_err(sqlite_io_error)?;
    }
    conn.execute("UPDATE groups SET version = version + 1", [])
        .map_err(sqlite_io_error)?;
    Ok(())
}

pub(super) fn set_selected_from_bundle(
    conn: &Connection,
    selected: &Value,
    key: &str,
    kind: SectionKind,
) -> io::Result<()> {
    let Some(id) = selected.get(key).and_then(Value::as_i64) else {
        return Ok(());
    };
    let clear = format!("UPDATE {} SET selected = 0", kind.table());
    let set = format!("UPDATE {} SET selected = 1 WHERE id = ?1", kind.table());
    conn.execute(&clear, []).map_err(sqlite_io_error)?;
    conn.execute(&set, params![id]).map_err(sqlite_io_error)?;
    Ok(())
}

pub(super) fn numeric_storage_value(storage: &Value, key: &str) -> Option<i64> {
    storage
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| value.parse::<i64>().ok())
}
