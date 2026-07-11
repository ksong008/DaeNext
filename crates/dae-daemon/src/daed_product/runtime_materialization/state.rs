use super::*;

pub(in crate::daed_product) fn general_state_report(
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
pub(in crate::daed_product) struct RuntimeSectionState {
    pub(in crate::daed_product) id: i64,
    pub(in crate::daed_product) version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::daed_product) struct RunningRuntimeState {
    pub(in crate::daed_product) config_id: Option<i64>,
    pub(in crate::daed_product) config_version: i64,
    pub(in crate::daed_product) dns_id: Option<i64>,
    pub(in crate::daed_product) dns_version: i64,
    pub(in crate::daed_product) routing_id: Option<i64>,
    pub(in crate::daed_product) routing_version: i64,
    pub(in crate::daed_product) group_version_sum: i64,
    pub(in crate::daed_product) group_ids: String,
    pub(in crate::daed_product) external_input_version: i64,
}

pub(in crate::daed_product) fn runtime_modified(
    conn: &Connection,
    running: bool,
) -> io::Result<bool> {
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
        || running_state.group_ids != group_ids_text(conn)?
        || running_state.external_input_version != current_runtime_external_input_version(conn)?)
}

pub(in crate::daed_product) fn selected_section_state(
    conn: &Connection,
    kind: SectionKind,
) -> io::Result<Option<RuntimeSectionState>> {
    let sql = format!(
        "SELECT id, version FROM {} WHERE selected = 1 ORDER BY id LIMIT 1",
        kind.table()
    );
    let selected = conn
        .query_row(&sql, [], |row| {
            Ok(RuntimeSectionState {
                id: row.get(0)?,
                version: row.get(1)?,
            })
        })
        .optional()
        .map_err(sqlite_io_error)?;
    if selected.is_some() {
        return Ok(selected);
    }
    Ok(None)
}

pub(in crate::daed_product) fn running_runtime_state(
    conn: &Connection,
) -> io::Result<Option<RunningRuntimeState>> {
    conn.query_row(
        "SELECT running_config_id, running_config_version,
                running_dns_id, running_dns_version,
                running_routing_id, running_routing_version,
                running_group_version_sum, running_group_ids,
                running_external_input_version
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
                external_input_version: row.get(8)?,
            })
        },
    )
    .optional()
    .map_err(sqlite_io_error)
}

pub(in crate::daed_product) fn running_section_references_id(
    conn: &Connection,
    kind: SectionKind,
    id: i64,
) -> io::Result<bool> {
    let Some(running_state) = running_runtime_state(conn)? else {
        return Ok(false);
    };
    let running_id = match kind {
        SectionKind::Config => running_state.config_id,
        SectionKind::Dns => running_state.dns_id,
        SectionKind::Routing => running_state.routing_id,
    };
    Ok(running_id == Some(id))
}

pub(in crate::daed_product) fn running_group_references_id(
    conn: &Connection,
    group_id: i64,
) -> io::Result<bool> {
    let Some(running_state) = running_runtime_state(conn)? else {
        return Ok(false);
    };
    Ok(running_group_ids_contain(
        &running_state.group_ids,
        group_id,
    ))
}

fn running_group_ids_contain(group_ids: &str, group_id: i64) -> bool {
    group_ids
        .split(',')
        .filter_map(|value| value.trim().parse::<i64>().ok())
        .any(|id| id == group_id)
}

pub(in crate::daed_product) fn current_runtime_external_input_version(
    conn: &Connection,
) -> io::Result<i64> {
    let value = conn
        .query_row(
            "SELECT value FROM daed_product_metadata WHERE key = ?1",
            params![RUNTIME_EXTERNAL_INPUT_VERSION_METADATA_KEY],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sqlite_io_error)?;
    Ok(value
        .as_deref()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0))
}

pub(in crate::daed_product) fn bump_runtime_external_input_version(
    state: &Path,
) -> io::Result<i64> {
    ensure_state_schema(state)?;
    let conn = open_state_connection(state)?;
    bump_runtime_external_input_version_with_connection(&conn)
}

pub(in crate::daed_product) fn bump_runtime_external_input_version_with_connection(
    conn: &Connection,
) -> io::Result<i64> {
    conn.execute(
        "INSERT INTO daed_product_metadata(key, value)
         VALUES(?1, '1')
         ON CONFLICT(key) DO UPDATE SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)",
        params![RUNTIME_EXTERNAL_INPUT_VERSION_METADATA_KEY],
    )
    .map_err(sqlite_io_error)?;
    current_runtime_external_input_version(conn)
}

pub(in crate::daed_product) fn mark_runtime_process_stopped(state: &Path) -> io::Result<()> {
    ensure_state_schema(state)?;
    set_metadata(state, "runtime_running", "false")
}
