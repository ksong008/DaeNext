use super::*;
pub(crate) fn ensure_default_resources(state: &Path, body: &Value) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let config_name = body
        .get("configName")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PRODUCT_CONFIG_NAME);
    let dns_name = body
        .get("dnsName")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PRODUCT_DNS_NAME);
    let routing_name = body
        .get("routingName")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PRODUCT_ROUTING_NAME);
    let group_name = body
        .get("groupName")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PRODUCT_GROUP_NAME);
    let policy = body
        .get("policy")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PRODUCT_GROUP_POLICY);
    let mode = body
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PRODUCT_MODE);
    let global = body
        .get("global")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| body.get("global").map(Value::to_string))
        .unwrap_or_else(|| DEFAULT_GLOBAL_RESOURCE_TEXT.to_owned());
    let dns = body
        .get("dns")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let routing = body
        .get("routing")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let config = upsert_named_resource(
        &conn,
        "configs",
        "global",
        config_name,
        &global,
        "selected, version",
        "0, 0",
    )?;
    let dns = upsert_named_resource(
        &conn,
        "dns",
        "dns",
        dns_name,
        &dns,
        "selected, version",
        "0, 0",
    )?;
    let routing = upsert_named_resource(
        &conn,
        "routings",
        "routing",
        routing_name,
        &routing,
        "selected, version",
        "0, 0",
    )?;
    let group = ensure_default_group(&conn, group_name, policy, body)?;
    let group_id = group.id;
    let mut group_changed = false;
    if group.created {
        if let Some(params_value) = body.get("policyParams").and_then(Value::as_array) {
            let desired = desired_policy_params(params_value);
            if group_policy_param_pairs(&conn, group_id)? != desired {
                conn.execute(
                    "DELETE FROM group_policy_params WHERE group_id = ?1",
                    params![group_id],
                )
                .map_err(sqlite_io_error)?;
                for (key, value) in &desired {
                    conn.execute(
                        "INSERT INTO group_policy_params(key, value, group_id) VALUES(?1, ?2, ?3)",
                        params![key, value, group_id],
                    )
                    .map_err(sqlite_io_error)?;
                }
                group_changed = true;
            }
        }
        if body.get("nodeIds").is_some() {
            let desired = integer_array(body, "nodeIds")
                .into_iter()
                .collect::<BTreeSet<_>>();
            if group_node_id_set(&conn, group_id)? != desired {
                conn.execute(
                    "DELETE FROM group_nodes WHERE group_id = ?1",
                    params![group_id],
                )
                .map_err(sqlite_io_error)?;
                let desired_ids = desired.iter().copied().collect::<Vec<_>>();
                apply_group_node_ids(&conn, group_id, &desired_ids, true)?;
                group_changed = true;
            }
        }
        if body.get("subscriptionIds").is_some() {
            let ids = integer_array(body, "subscriptionIds");
            let name_filter_regex = body
                .get("nameFilterRegex")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            let desired = ids
                .iter()
                .map(|id| (*id, name_filter_regex.clone()))
                .collect::<BTreeSet<_>>();
            if group_subscription_binding_set(&conn, group_id)? != desired {
                conn.execute(
                    "DELETE FROM group_subscriptions WHERE group_id = ?1",
                    params![group_id],
                )
                .map_err(sqlite_io_error)?;
                apply_group_subscription_ids(
                    &conn,
                    group_id,
                    &ids,
                    name_filter_regex.as_deref(),
                    true,
                )?;
                group_changed = true;
            }
        }
    }
    if group_changed {
        conn.execute(
            "UPDATE groups SET version = version + 1 WHERE id = ?1",
            params![group_id],
        )
        .map_err(sqlite_io_error)?;
    }
    Ok(json!({
        "defaultConfigID": config.id.to_string(),
        "defaultRoutingID": routing.id.to_string(),
        "defaultDNSID": dns.id.to_string(),
        "defaultGroupID": group_id.to_string(),
        "mode": mode,
    }))
}

pub(crate) fn desired_policy_params(items: &[Value]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|item| {
            let key = item
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            let value = item
                .get("val")
                .or_else(|| item.get("value"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned();
            (key, value)
        })
        .collect()
}

pub(crate) fn group_policy_param_pairs(
    conn: &Connection,
    group_id: i64,
) -> io::Result<Vec<(String, String)>> {
    let mut stmt = conn
        .prepare("SELECT key, value FROM group_policy_params WHERE group_id = ?1 ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(sqlite_io_error)?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row.map_err(sqlite_io_error)?);
    }
    Ok(out)
}

pub(crate) fn group_node_id_set(conn: &Connection, group_id: i64) -> io::Result<BTreeSet<i64>> {
    let mut stmt = conn
        .prepare("SELECT node_id FROM group_nodes WHERE group_id = ?1")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut out = BTreeSet::new();
    for row in rows {
        out.insert(row.map_err(sqlite_io_error)?);
    }
    Ok(out)
}

pub(crate) fn group_subscription_binding_set(
    conn: &Connection,
    group_id: i64,
) -> io::Result<BTreeSet<(i64, Option<String>)>> {
    let mut stmt = conn
        .prepare(
            "SELECT subscription_id, name_filter_regex FROM group_subscriptions WHERE group_id = ?1",
        )
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map(params![group_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<String>>(1)?
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty()),
            ))
        })
        .map_err(sqlite_io_error)?;
    let mut out = BTreeSet::new();
    for row in rows {
        out.insert(row.map_err(sqlite_io_error)?);
    }
    Ok(out)
}

pub(crate) struct EnsuredResource {
    pub(super) id: i64,
    pub(super) created: bool,
}

pub(crate) fn ensure_default_group(
    conn: &Connection,
    name: &str,
    policy: &str,
    body: &Value,
) -> io::Result<EnsuredResource> {
    if let Some(id) = group_id_by_name(conn, name)? {
        return Ok(EnsuredResource { id, created: false });
    }
    if name == DEFAULT_PRODUCT_GROUP_NAME
        && !body_requests_group_membership(body)
        && existing_group_count(conn)? > 0
    {
        if let Some(id) = existing_group_referenced_by_selected_routing(conn)? {
            return Ok(EnsuredResource { id, created: false });
        }
        if let Some(id) = first_existing_group_id(conn)? {
            return Ok(EnsuredResource { id, created: false });
        }
    }
    insert_group(conn, name, policy)
}

pub(crate) fn body_requests_group_membership(body: &Value) -> bool {
    body.get("nodeIds").is_some() || body.get("subscriptionIds").is_some()
}

pub(crate) fn existing_group_referenced_by_selected_routing(
    conn: &Connection,
) -> io::Result<Option<i64>> {
    let Some((_, _, routing, _)) = selected_section_raw(conn, SectionKind::Routing)? else {
        return Ok(None);
    };
    let Some(names) = preferred_group_names_from_routing(&routing) else {
        return Ok(None);
    };
    for name in names {
        if let Some(id) = group_id_by_name(conn, &name)? {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

pub(crate) fn existing_group_count(conn: &Connection) -> io::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM groups", [], |row| row.get(0))
        .map_err(sqlite_io_error)
}

pub(crate) fn first_existing_group_id(conn: &Connection) -> io::Result<Option<i64>> {
    conn.query_row("SELECT id FROM groups ORDER BY id LIMIT 1", [], |row| {
        row.get::<_, i64>(0)
    })
    .optional()
    .map_err(sqlite_io_error)
}

pub(crate) fn group_id_by_name(conn: &Connection, name: &str) -> io::Result<Option<i64>> {
    conn.query_row(
        "SELECT id FROM groups WHERE name = ?1 LIMIT 1",
        params![name],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .map_err(sqlite_io_error)
}

pub(crate) fn upsert_named_resource(
    conn: &Connection,
    table: &str,
    value_column: &str,
    name: &str,
    value: &str,
    extra_columns: &str,
    extra_values: &str,
) -> io::Result<EnsuredResource> {
    let select_sql = format!("SELECT id FROM {table} WHERE name = ?1 LIMIT 1");
    if let Some(id) = conn
        .query_row(&select_sql, params![name], |row| row.get::<_, i64>(0))
        .optional()
        .map_err(sqlite_io_error)?
    {
        return Ok(EnsuredResource { id, created: false });
    }
    let insert_sql = format!(
        "INSERT INTO {table}(name, {value_column}, {extra_columns}) VALUES(?1, ?2, {extra_values})"
    );
    conn.execute(&insert_sql, params![name, value])
        .map_err(sqlite_io_error)?;
    Ok(EnsuredResource {
        id: conn.last_insert_rowid(),
        created: true,
    })
}

pub(crate) fn insert_group(
    conn: &Connection,
    name: &str,
    policy: &str,
) -> io::Result<EnsuredResource> {
    conn.execute(
        "INSERT INTO groups(name, policy, version) VALUES(?1, ?2, 0)",
        params![name, policy],
    )
    .map_err(sqlite_io_error)?;
    Ok(EnsuredResource {
        id: conn.last_insert_rowid(),
        created: true,
    })
}
