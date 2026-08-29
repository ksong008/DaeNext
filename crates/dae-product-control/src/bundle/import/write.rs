use super::*;

pub(super) fn clear_bundle_resources(conn: &Connection) -> io::Result<()> {
    for table in [
        "group_policy_params",
        "group_subscriptions",
        "group_nodes",
        "node_latency_results",
        "nodes",
        "subscriptions",
        "groups",
        "configs",
        "dns",
        "routings",
    ] {
        conn.execute(&format!("DELETE FROM {table}"), [])
            .map_err(sqlite_io_error)?;
    }
    Ok(())
}

pub(super) fn write_bundle_resources(conn: &Connection, body: &Value) -> io::Result<()> {
    write_bundle_sections(conn, body, "configs", SectionKind::Config)?;
    write_bundle_sections(conn, body, "dnss", SectionKind::Dns)?;
    write_bundle_sections(conn, body, "routings", SectionKind::Routing)?;
    write_bundle_subscriptions(conn, body)?;
    write_bundle_nodes(conn, body)?;
    write_bundle_groups(conn, body)
}

pub(super) fn write_bundle_selected(conn: &Connection, body: &Value) -> io::Result<()> {
    let selected = required_object_field(body, "selected")?;
    set_selected(conn, selected, "configId", SectionKind::Config)?;
    set_selected(conn, selected, "dnsId", SectionKind::Dns)?;
    set_selected(conn, selected, "routingId", SectionKind::Routing)?;
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

pub(super) fn write_user_storage(conn: &Connection, user_id: i64, storage: &str) -> io::Result<()> {
    let updated = conn
        .execute(
            "UPDATE users SET json_storage = ?1 WHERE id = ?2",
            params![storage, user_id],
        )
        .map_err(sqlite_io_error)?;
    if updated == 1 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "bundle import user no longer exists",
        ))
    }
}

fn write_bundle_sections(
    conn: &Connection,
    body: &Value,
    key: &str,
    kind: SectionKind,
) -> io::Result<()> {
    for item in required_array_field(body, key)? {
        let id = required_i64_field(item, "id")?;
        let name = required_string_field(item, "name")?;
        let raw = required_string_field(item, kind.request_value_key())?;
        let sql = format!(
            "INSERT INTO {}(id, name, {}, selected, version) VALUES(?1, ?2, ?3, 0, 0)",
            kind.table(),
            kind.value_column()
        );
        conn.execute(&sql, params![id, name, raw])
            .map_err(sqlite_io_error)?;
    }
    Ok(())
}

fn write_bundle_subscriptions(conn: &Connection, body: &Value) -> io::Result<()> {
    for item in required_array_field(body, "subscriptions")? {
        conn.execute(
            "INSERT INTO subscriptions(id, updated_at, link, cron_exp, cron_enable, status, info, tag, use_proxy)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                required_i64_field(item, "id")?,
                item.get("updatedAt")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(now_text),
                required_string_field(item, "link")?,
                required_string_field(item, "cronExp")?,
                item.get("cronEnable")
                    .and_then(Value::as_bool)
                    .unwrap_or(DEFAULT_SUBSCRIPTION_CRON_ENABLE) as i64,
                required_string_field(item, "status")?,
                required_string_field(item, "info")?,
                item.get("tag").and_then(Value::as_str),
                item.get("useProxy").and_then(Value::as_bool).unwrap_or(false) as i64,
            ],
        )
        .map_err(sqlite_io_error)?;
    }
    Ok(())
}

fn write_bundle_nodes(conn: &Connection, body: &Value) -> io::Result<()> {
    for item in required_array_field(body, "nodes")? {
        conn.execute(
            "INSERT INTO nodes(id, link, name, address, protocol, tag, subscription_id)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                required_i64_field(item, "id")?,
                required_string_field(item, "link")?,
                required_string_field(item, "name")?,
                required_string_field(item, "address")?,
                required_string_field(item, "protocol")?,
                item.get("tag").and_then(Value::as_str),
                item.get("subscriptionId").and_then(Value::as_i64),
            ],
        )
        .map_err(sqlite_io_error)?;
    }
    Ok(())
}

fn write_bundle_groups(conn: &Connection, body: &Value) -> io::Result<()> {
    for item in required_array_field(body, "groups")? {
        let id = required_i64_field(item, "id")?;
        conn.execute(
            "INSERT INTO groups(id, name, policy, version) VALUES(?1, ?2, ?3, 0)",
            params![
                id,
                required_string_field(item, "name")?,
                required_string_field(item, "policy")?,
            ],
        )
        .map_err(sqlite_io_error)?;
        replace_group_policy_params(conn, id, item.get("policyParams"))?;
        apply_group_node_ids(conn, id, &integer_array(item, "nodeIds"), true)?;
        for binding in required_array_field(item, "subscriptionBindings")? {
            apply_group_subscription_ids(
                conn,
                id,
                &[required_i64_field(binding, "subscriptionId")?],
                binding.get("nameFilterRegex").and_then(Value::as_str),
                true,
            )?;
        }
    }
    Ok(())
}

fn set_selected(
    conn: &Connection,
    selected: &Map<String, Value>,
    key: &str,
    kind: SectionKind,
) -> io::Result<()> {
    let id = selected
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| invalid_data(&format!("bundle selected.{key} is required")))?;
    let clear = format!("UPDATE {} SET selected = 0", kind.table());
    let set = format!("UPDATE {} SET selected = 1 WHERE id = ?1", kind.table());
    conn.execute(&clear, []).map_err(sqlite_io_error)?;
    let updated = conn.execute(&set, params![id]).map_err(sqlite_io_error)?;
    if updated == 1 {
        Ok(())
    } else {
        Err(invalid_data(&format!(
            "bundle selected.{key} references missing id {id}"
        )))
    }
}

fn required_array_field<'a>(value: &'a Value, key: &str) -> io::Result<&'a Vec<Value>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_data(&format!("bundle {key} must be an array")))
}

fn required_object_field<'a>(value: &'a Value, key: &str) -> io::Result<&'a Map<String, Value>> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_data(&format!("bundle {key} must be an object")))
}

fn required_i64_field(value: &Value, key: &str) -> io::Result<i64> {
    value
        .get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| invalid_data(&format!("bundle field {key} must be an integer")))
}

fn required_string_field<'a>(value: &'a Value, key: &str) -> io::Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_data(&format!("bundle field {key} must be a string")))
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
