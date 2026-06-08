fn general_state_report(
    state: &Path,
    config_dir: &Path,
    runtime: &ProductRuntimeManager,
) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let runtime_state = runtime.summary();
    let running = runtime_state["running"].as_bool().unwrap_or(false);
    let modified = runtime_modified(&conn, running)?;
    let selected_config_id = selected_id(&conn, SectionKind::Config)?;
    let selected_dns_id = selected_id(&conn, SectionKind::Dns)?;
    let selected_routing_id = selected_id(&conn, SectionKind::Routing)?;
    Ok(json!({
        "running": running,
        "modified": modified,
        "version": crate::version::version_from_env(),
        "netnsLinkMode": runtime_state["netnsLinkMode"].clone(),
        "attachBackend": runtime_state["attachBackend"].clone(),
        "runtime": runtime_state,
        "updatedAt": now_text(),
        "state": path_string(state),
        "selected": {
            "configId": selected_config_id,
            "dnsId": selected_dns_id,
            "routingId": selected_routing_id,
        },
        "counts": {
            "configs": count_table(&conn, "configs")?,
            "dns": count_table(&conn, "dns")?,
            "routings": count_table(&conn, "routings")?,
            "groups": count_table(&conn, "groups")?,
            "nodes": count_table(&conn, "nodes")?,
            "subscriptions": count_table(&conn, "subscriptions")?,
            "logs": count_log_file_entries(config_dir)?,
        }
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RuntimeSectionState {
    id: i64,
    version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RunningRuntimeState {
    config_id: Option<i64>,
    config_version: i64,
    dns_id: Option<i64>,
    dns_version: i64,
    routing_id: Option<i64>,
    routing_version: i64,
    group_version_sum: i64,
    group_ids: String,
}

fn runtime_modified(conn: &Connection, running: bool) -> io::Result<bool> {
    if !running {
        return Ok(false);
    }
    let Some(config) = selected_section_state(conn, SectionKind::Config)? else {
        return Ok(true);
    };
    let Some(dns) = selected_section_state(conn, SectionKind::Dns)? else {
        return Ok(true);
    };
    let Some(routing) = selected_section_state(conn, SectionKind::Routing)? else {
        return Ok(true);
    };
    let Some(running_state) = running_runtime_state(conn)? else {
        return Ok(true);
    };

    Ok(running_state.config_id != Some(config.id)
        || running_state.config_version != config.version
        || running_state.dns_id != Some(dns.id)
        || running_state.dns_version != dns.version
        || running_state.routing_id != Some(routing.id)
        || running_state.routing_version != routing.version
        || running_state.group_version_sum != group_version_sum(conn)?
        || running_state.group_ids != group_ids_text(conn)?)
}

fn selected_section_state(
    conn: &Connection,
    kind: SectionKind,
) -> io::Result<Option<RuntimeSectionState>> {
    let sql = format!(
        "SELECT id, version FROM {} WHERE selected = 1 ORDER BY id LIMIT 1",
        kind.table()
    );
    conn.query_row(&sql, [], |row| {
        Ok(RuntimeSectionState {
            id: row.get(0)?,
            version: row.get(1)?,
        })
    })
    .optional()
    .map_err(sqlite_io_error)
}

fn running_runtime_state(conn: &Connection) -> io::Result<Option<RunningRuntimeState>> {
    conn.query_row(
        "SELECT running_config_id, running_config_version,
                running_dns_id, running_dns_version,
                running_routing_id, running_routing_version,
                running_group_version_sum, running_group_ids
         FROM systems
         WHERE running != 0
         ORDER BY id
         LIMIT 1",
        [],
        |row| {
            Ok(RunningRuntimeState {
                config_id: row.get(0)?,
                config_version: row.get(1)?,
                dns_id: row.get(2)?,
                dns_version: row.get(3)?,
                routing_id: row.get(4)?,
                routing_version: row.get(5)?,
                group_version_sum: row.get(6)?,
                group_ids: row.get(7)?,
            })
        },
    )
    .optional()
    .map_err(sqlite_io_error)
}

fn build_runtime_config_from_content(content: &str) -> Result<Config, String> {
    let sections = parse_config(content).map_err(|err| err.to_string())?;
    build_config(&sections).map_err(|err| err.to_string())
}

fn mark_system_stopped(state: &Path) -> io::Result<()> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let updated = conn
        .execute("UPDATE systems SET running = 0", [])
        .map_err(sqlite_io_error)?;
    if updated == 0 {
        conn.execute(
            "INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids)
             VALUES(0, 0, 0, 0, 0, '')",
            [],
        )
        .map_err(sqlite_io_error)?;
    }
    set_metadata(state, "runtime_running", "false")?;
    Ok(())
}

fn mark_runtime_process_stopped(state: &Path) -> io::Result<()> {
    ensure_state_schema(state)?;
    set_metadata(state, "runtime_running", "false")
}

fn materialize_runtime(state: &Path, config_dir: Option<&Path>, dry: bool) -> io::Result<Value> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    let config = selected_section_raw(&conn, SectionKind::Config)?;
    let dns = selected_section_raw(&conn, SectionKind::Dns)?;
    let routing = selected_section_raw(&conn, SectionKind::Routing)?;
    let groups = list_groups_value(state)?;
    let nodes = list_all_nodes_value(state)?;
    let generated_at = now_text();
    let content = render_generated_config(
        &generated_at,
        config.as_ref(),
        dns.as_ref(),
        routing.as_ref(),
        &groups,
        &nodes,
    )?;
    let output_path = config_dir.map(|dir| dir.join("runtime").join("generated.dae"));
    if !dry {
        if let Some(path) = &output_path {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, &content)?;
            set_private_runtime_file_permissions(path)?;
            set_metadata(state, "last_generated_config_path", &path_string(path))?;
        }
        set_metadata(state, "last_materialized_at", &generated_at)?;
        conn.execute("DELETE FROM systems", [])
            .map_err(sqlite_io_error)?;
        conn.execute(
            "INSERT INTO systems(running, running_config_version, running_dns_version, running_routing_version, running_group_version_sum, running_group_ids, running_config_id, running_dns_id, running_routing_id)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                1_i64,
                config.as_ref().map(|(_, _, _, version)| *version).unwrap_or(0),
                dns.as_ref().map(|(_, _, _, version)| *version).unwrap_or(0),
                routing.as_ref().map(|(_, _, _, version)| *version).unwrap_or(0),
                group_version_sum(&conn)?,
                group_ids_text(&conn)?,
                config.as_ref().map(|(id, _, _, _)| *id),
                dns.as_ref().map(|(id, _, _, _)| *id),
                routing.as_ref().map(|(id, _, _, _)| *id),
            ],
        )
        .map_err(sqlite_io_error)?;
        set_metadata(state, "runtime_running", "true")?;
    }
    let content_len = content.len();
    let mut report = Map::new();
    report.insert("filename".to_owned(), json!("generated.dae"));
    report.insert(
        "path".to_owned(),
        json!(output_path.as_ref().map(|path| path_string(path))),
    );
    report.insert("bytes".to_owned(), json!(content_len));
    report.insert("contentIncluded".to_owned(), json!(dry));
    if dry {
        report.insert("content".to_owned(), json!(content));
    }
    report.insert("generatedAt".to_owned(), json!(generated_at));
    report.insert(
        "selected".to_owned(),
        json!({
            "configId": config.as_ref().map(|(id, _, _, _)| *id),
            "dnsId": dns.as_ref().map(|(id, _, _, _)| *id),
            "routingId": routing.as_ref().map(|(id, _, _, _)| *id),
        }),
    );
    report.insert(
        "groups".to_owned(),
        json!(groups["items"].as_array().map(Vec::len).unwrap_or(0)),
    );
    report.insert(
        "nodes".to_owned(),
        json!(nodes["items"].as_array().map(Vec::len).unwrap_or(0)),
    );
    Ok(Value::Object(report))
}

fn render_generated_config(
    generated_at: &str,
    config: Option<&(i64, String, String, i64)>,
    dns: Option<&(i64, String, String, i64)>,
    routing: Option<&(i64, String, String, i64)>,
    groups: &Value,
    nodes: &Value,
) -> io::Result<String> {
    let mut out = String::new();
    out.push_str("# generated by Rust daed C10 local product surface\n");
    out.push_str(&format!("# generated_at: {generated_at}\n\n"));
    out.push_str("# selected config\n");
    let config_text = config
        .map(|(_, _, raw, _)| display_global_config_text(raw))
        .unwrap_or_else(|| "global {}\n".to_owned());
    out.push_str(&config_text);
    out.push_str("\n\n# selected dns\n");
    out.push_str(
        dns.map(|(_, _, raw, _)| raw.as_str())
            .filter(|raw| !raw.trim().is_empty())
            .unwrap_or("dns {}\n"),
    );
    out.push_str("\n\n# selected routing\n");
    out.push_str(
        routing
            .map(|(_, _, raw, _)| raw.as_str())
            .filter(|raw| !raw.trim().is_empty())
            .unwrap_or("routing {}\n"),
    );
    out.push_str("\n\n# local product nodes\n");
    out.push_str(&render_node_section(nodes));
    out.push_str("\n\n# local product groups\n");
    out.push_str(&render_group_section(groups)?);
    out.push('\n');
    Ok(out)
}

fn render_node_section(nodes: &Value) -> String {
    let mut out = String::from("node {\n");
    for node in nodes["items"].as_array().into_iter().flatten() {
        let Some(link) = node.get("link").and_then(Value::as_str) else {
            continue;
        };
        if link.trim().is_empty() {
            continue;
        }
        let tag = runtime_node_tag(node);
        out.push_str(&format!(
            "    {}: {}\n",
            dae_key_literal(&tag),
            dae_string_literal(link)
        ));
    }
    out.push_str("}\n");
    out
}

fn render_group_section(groups: &Value) -> io::Result<String> {
    let mut out = String::from("group {\n");
    for group in groups["items"].as_array().into_iter().flatten() {
        let Some(name) = group.get("name").and_then(Value::as_str) else {
            continue;
        };
        if name.trim().is_empty() {
            continue;
        }
        out.push_str(&format!("    {} {{\n", dae_key_literal(name)));
        let node_tags = runtime_group_node_tags(group);
        if node_tags.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("group {name} has no matched nodes"),
            ));
        }
        let names = node_tags
            .iter()
            .map(|tag| dae_string_literal(tag))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("        filter: name({names})\n"));
        let policy = render_group_policy(group);
        out.push_str(&format!("        policy: {policy}\n"));
        out.push_str("    }\n");
    }
    out.push_str("}\n");
    Ok(out)
}

fn render_group_policy(group: &Value) -> String {
    let policy = group
        .get("policy")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|policy| !policy.is_empty())
        .unwrap_or("fixed");
    let params = group
        .get("policyParams")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| Param {
                    key: item
                        .get("key")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned(),
                    val: item
                        .get("val")
                        .or_else(|| item.get("value"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned(),
                    and_functions: Vec::new(),
                    annotation: Vec::new(),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if params.is_empty() {
        return policy.to_owned();
    }

    Function {
        name: policy.to_owned(),
        not: false,
        params,
    }
    .to_config_string(true, true, false)
}

fn runtime_group_node_tags(group: &Value) -> Vec<String> {
    let mut tags = Vec::<String>::new();
    for node in group["nodes"].as_array().into_iter().flatten() {
        push_unique(&mut tags, runtime_node_tag(node));
    }
    for subscription in group["subscriptions"].as_array().into_iter().flatten() {
        for node in subscription["matchedNodes"]
            .as_array()
            .into_iter()
            .flatten()
        {
            push_unique(&mut tags, runtime_node_tag(node));
        }
    }
    tags
}

fn runtime_node_tag(node: &Value) -> String {
    node.get("runtimeTag")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            node.get("tag")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        })
        .or_else(|| {
            node.get("name")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        })
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|| {
            let id = node.get("id").and_then(Value::as_i64).unwrap_or(0);
            format!("node_{id}")
        })
}

fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|seen| seen == &value) {
        values.push(value);
    }
}

fn dae_key_literal(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
        && value
            .chars()
            .next()
            .map(|ch| ch.is_ascii_alphabetic() || ch == '_')
            .unwrap_or(false)
    {
        value.to_owned()
    } else {
        dae_string_literal(value)
    }
}

fn dae_string_literal(value: &str) -> String {
    let mut out = String::from("'");
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            _ => out.push(ch),
        }
    }
    out.push('\'');
    out
}

fn selected_section_raw(
    conn: &Connection,
    kind: SectionKind,
) -> io::Result<Option<(i64, String, String, i64)>> {
    let sql = format!(
        "SELECT id, name, {}, version FROM {} WHERE selected = 1 ORDER BY id LIMIT 1",
        kind.value_column(),
        kind.table()
    );
    let selected = conn
        .query_row(&sql, [], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })
        .optional()
        .map_err(sqlite_io_error)?;
    if selected.is_some() {
        return Ok(selected);
    }
    let sql = format!(
        "SELECT id, name, {}, version FROM {} ORDER BY id LIMIT 1",
        kind.value_column(),
        kind.table()
    );
    conn.query_row(&sql, [], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })
    .optional()
    .map_err(sqlite_io_error)
}

fn selected_id(conn: &Connection, kind: SectionKind) -> io::Result<Option<i64>> {
    let sql = format!(
        "SELECT id FROM {} WHERE selected = 1 ORDER BY id LIMIT 1",
        kind.table()
    );
    conn.query_row(&sql, [], |row| row.get::<_, i64>(0))
        .optional()
        .map_err(sqlite_io_error)
}

fn group_version_sum(conn: &Connection) -> io::Result<i64> {
    conn.query_row("SELECT COALESCE(SUM(version), 0) FROM groups", [], |row| {
        row.get(0)
    })
    .map_err(sqlite_io_error)
}

fn group_ids_text(conn: &Connection) -> io::Result<String> {
    let mut stmt = conn
        .prepare("SELECT id FROM groups ORDER BY id")
        .map_err(sqlite_io_error)?;
    let rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(sqlite_io_error)?;
    let mut ids = Vec::new();
    for row in rows {
        ids.push(row.map_err(sqlite_io_error)?.to_string());
    }
    Ok(ids.join(","))
}

fn get_metadata(state: &Path, key: &str) -> io::Result<Option<String>> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    conn.query_row(
        "SELECT value FROM daed_product_metadata WHERE key = ?1",
        params![key],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(sqlite_io_error)
}

fn set_metadata(state: &Path, key: &str, value: &str) -> io::Result<()> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    conn.execute(
        "INSERT OR REPLACE INTO daed_product_metadata(key, value) VALUES(?1, ?2)",
        params![key, value],
    )
    .map_err(sqlite_io_error)?;
    Ok(())
}
